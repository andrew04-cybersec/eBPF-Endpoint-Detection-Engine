"""
tests for rapid_spawn.py
every event here is a !!constructed fixture, not captured output!!
"""
import copy
import io
import json
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
DET_DIR = os.path.dirname(HERE)
sys.path.insert(0, DET_DIR)

import rapid_spawn as rs  # noqa: E402
import runner  # noqa: E402

REQUIRED = ("alert_schema_version", "alert_seq", "detection", "technique", "ts_ns", "process",
            "ancestry", "ancestry_stop", "evidence", "evidence_dropped", "data_quality")
T = rs.SPAWN_THRESHOLD
MS = 1000000
SEC = 1000000000
BASE = 10 * SEC


def child(pid, ppid, ts, comm="true"):
    return {"schema_version": 1, "type": "exec_success", "ts_ns": ts, "pid": pid, "tid": pid, "comm": comm,
            "ppid": ppid, "uid": 0, "gid": 0, "start_time_ns": pid * 10, "process_key": "%d:%d" % (pid, pid * 10),
            "filename": "/bin/true", "exe": "/bin/true", "argv": ["true"], "cmdline": "true"}


def parent(pid=500):
    event = child(pid, 1, 1, comm="bash")
    event["filename"] = event["exe"] = "/bin/bash"
    return event


def burst(count, ppid=500, first_pid=1000, start=BASE, step=MS):
    return [child(first_pid + i, ppid, start + i * step) for i in range(count)]


def run_events(events):
    lines = [(json.dumps(e) + "\n").encode() for e in events]
    out = io.StringIO()
    graph, ctx, stats = runner.run(lines, runner.alert.AlertSink(out, None), detections=[rs.detect])
    return [json.loads(l) for l in out.getvalue().splitlines()], graph, ctx, stats


def counts(ctx):
    return {k: v for k, v in ctx["counts"].items() if k != "unevaluable"}


#how many children inside the window make a burst
class Threshold(unittest.TestCase):

    def test_one_below_the_threshold_does_not_alert(self):
        alerts, _, ctx, _ = run_events([parent()] + burst(T - 1))
        self.assertEqual(alerts, [])

    def test_exactly_the_threshold_alerts_once(self):
        alerts, _, ctx, stats = run_events([parent()] + burst(T))
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        for field in REQUIRED:
            self.assertIn(field, a)
        self.assertEqual(a["detection"], "rapid_spawn")
        self.assertIsNone(a["technique"])
        self.assertEqual(a["process"]["pid"], 1000 + T - 1)
        self.assertEqual(a["ts_ns"], BASE + (T - 1) * MS)
        self.assertEqual(stats["alerts"], {"rapid_spawn": 1})
        self.assertEqual(a["ancestry_stop"], "root")
        self.assertEqual([c["comm"] for c in a["ancestry"]], ["true", "bash"])

    def test_more_than_the_threshold_alerts_only_once(self):
        alerts, _, _, _ = run_events([parent()] + burst(T + 40))
        self.assertEqual(len(alerts), 1)

    def test_children_spread_over_more_than_the_window_do_not_alert(self):
        alerts, _, _, _ = run_events([parent()] + burst(T * 2, step=rs.WINDOW_NS // 5))
        self.assertEqual(alerts, [])

    def test_window_edge_is_inclusive(self):
        events = burst(T - 1)
        events.append(child(2000, 500, BASE + rs.WINDOW_NS))
        self.assertEqual(len(run_events([parent()] + events)[0]), 1)
        events[-1] = child(2000, 500, BASE + rs.WINDOW_NS + 1)
        self.assertEqual(run_events([parent()] + events)[0], [])

    def test_re_arms_after_the_count_drops(self):
        events = burst(T) + burst(T, first_pid=2000, start=BASE + 5 * SEC)
        alerts, _, _, _ = run_events([parent()] + events)
        self.assertEqual([a["process"]["pid"] for a in alerts], [1000 + T - 1, 2000 + T - 1])

    def test_a_sustained_stream_stays_quiet_after_the_first_alert(self):
        events = burst(T * 4, step=MS)
        alerts, _, _, _ = run_events([parent()] + events)
        self.assertEqual(len(alerts), 1)

    def test_the_same_child_is_counted_once(self):
        events = burst(T - 1) + [child(1000, 500, BASE + (T + i) * MS) for i in range(10)]
        self.assertEqual(run_events([parent()] + events)[0], [])
        events.append(child(3000, 500, BASE + 100 * MS))
        self.assertEqual(len(run_events([parent()] + events)[0]), 1)

    def test_other_events_are_ignored(self):
        events = [parent(), {"schema_version": 1, "type": "file_open", "path": "/etc/passwd"},
                  {"schema_version": 1, "type": "exec_attempt", "pid": 5}] + burst(T - 1)
        alerts, _, ctx, stats = run_events(events)
        self.assertEqual((alerts, stats["detection_errors"]), ([], 0))


#grouping by parent
class Parents(unittest.TestCase):

    def test_two_parents_below_the_threshold_do_not_combine(self):
        events = [parent(500), parent(501)] + burst(T - 1, ppid=500) + burst(T - 1, ppid=501, first_pid=3000)
        self.assertEqual(run_events(events)[0], [])

    def test_two_parents_over_the_threshold_alert_once_each(self):
        events = [parent(500), parent(501)] + burst(T, ppid=500) + burst(T, ppid=501, first_pid=3000)
        alerts, _, _, _ = run_events(events)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(sorted(a["process"]["ppid"] for a in alerts), [500, 501])

    def test_interleaved_parents_are_counted_apart(self):
        events = [parent(500), parent(501)]
        for i in range(T):
            events.append(child(1000 + i, 500, BASE + i * 2 * MS))
            events.append(child(3000 + i, 501, BASE + i * 2 * MS + MS))
        self.assertEqual(len(run_events(events)[0]), 2)

    def test_a_placeholder_parent_groups_and_alerts(self):
        alerts, graph, ctx, _ = run_events(burst(T, ppid=999))
        self.assertTrue(graph.nodes["999:unknown"].placeholder)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ancestry_stop"], "placeholder")

    def test_unevaluable_processes_are_counted(self):
        missing = child(3000, 500, BASE)
        del missing["start_time_ns"]
        no_ts = child(3001, 500, None)
        alerts, _, ctx, _ = run_events([parent(), missing, no_ts, child(3002, 1, BASE), child(3003, 0, BASE)])
        self.assertEqual(alerts, [])
        self.assertEqual(counts(ctx), {"unevaluable_not_in_graph": 1, "unevaluable_no_timestamp": 1,
                                       "unevaluable_no_parent": 3})

    def test_oldest_tracked_parent_is_evicted(self):
        events = [parent(500), parent(501), parent(502)]
        events += burst(T - 1, ppid=500) + [child(3000, 501, BASE), child(3001, 502, BASE)]
        events.append(child(4000, 500, BASE + 50 * MS))
        self.assertEqual(len(run_events(events)[0]), 1)
        with mock.patch.object(rs, "MAX_TRACKED_PARENTS", 2):
            alerts, _, _, _ = run_events(events)
        self.assertEqual(alerts, [])


#evidence, ordering, and counters
class Evidence(unittest.TestCase):

    def test_evidence_is_capped_at_the_alert_modules_cap_with_the_crossing_event_last(self):
        alerts, _, _, _ = run_events([parent()] + burst(T))
        a = alerts[0]
        cap = runner.alert.MAX_EVIDENCE_EVENTS
        self.assertEqual(len(a["evidence"]), cap)
        self.assertEqual(a["evidence_dropped"], 0)
        pids = [e["pid"] for e in a["evidence"]]
        self.assertEqual(pids, list(range(1000 + T - cap, 1000 + T)))
        self.assertEqual(a["evidence"][-1]["pid"], a["process"]["pid"])

    def test_a_lower_cap_is_followed(self):
        with mock.patch.object(runner.alert, "MAX_EVIDENCE_EVENTS", 3):
            alerts, _, _, _ = run_events([parent()] + burst(T))
        self.assertEqual(len(alerts[0]["evidence"]), 3)
        self.assertEqual(alerts[0]["evidence_dropped"], 0)

    def test_out_of_order_timestamps_do_not_crash_and_are_counted(self):
        events = [parent()] + burst(T - 2)
        events.append(child(2000, 500, BASE - 5 * SEC))
        events.append(child(2001, 500, BASE + 100 * MS))
        alerts, _, ctx, stats = run_events(events)
        self.assertEqual(ctx["counts"]["out_of_order"], 1)
        self.assertEqual(stats["detection_errors"], 0)
        self.assertEqual(len(alerts), 1)

    def test_inputs_are_not_changed_and_output_is_repeatable(self):
        events = [parent()] + burst(T + 5)
        before = copy.deepcopy(events)
        first = run_events(events)
        self.assertEqual(events, before)
        graph_before = json.dumps(first[1].to_dict(), sort_keys=True)
        rs.detect(first[1], events[-1], {"counts": {}, "attempts": {}})
        self.assertEqual(json.dumps(first[1].to_dict(), sort_keys=True), graph_before)
        self.assertEqual(events, before)
        self.assertEqual(first[0], run_events(copy.deepcopy(events))[0])

    def test_registered_in_the_runner(self):
        self.assertEqual(runner.DETECTIONS[5].__module__, "rapid_spawn")


if __name__ == "__main__":
    unittest.main()
