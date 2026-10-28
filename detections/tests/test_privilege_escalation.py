"""
tests for privilege_escalation.py
every event here is a !!constructed fixture, not captured output!!
"""
import copy
import io
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DET_DIR = os.path.dirname(HERE)
sys.path.insert(0, DET_DIR)

import runner  #noqa: E402
import privilege_escalation as priv  #noqa: E402

REQUIRED = ("alert_schema_version", "alert_seq", "detection", "technique", "ts_ns", "process",
            "ancestry", "ancestry_stop", "evidence", "evidence_dropped", "data_quality")
NO = object()
NO_CHANGE = 4294967295


def key_of(pid):
    return "%d:%d" % (pid, pid * 10)


def request(pid, syscall, ids, uid=1000, comm="python3", ts=None, **extra):
    event = {"schema_version": 1, "type": "priv_change", "ts_ns": pid if ts is None else ts, "pid": pid, "tid": pid,
             "comm": comm, "syscall": syscall, "ids": ids, "ppid": 1, "gid": 1000, "start_time_ns": pid * 10,
             "process_key": key_of(pid)}
    if uid is not NO:
        event["uid"] = uid
    if ids is NO:
        del event["ids"]
    event.update(extra)
    return event


def seen(pid, uid, comm="python3", typ="file_open", ts=None):
    return {"schema_version": 1, "type": typ, "ts_ns": pid if ts is None else ts, "pid": pid, "tid": pid,
            "comm": comm, "ppid": 1, "uid": uid, "gid": uid, "start_time_ns": pid * 10, "process_key": key_of(pid),
            "path": "/etc/hostname", "flags": 0, "ret": 3}


def run_events(events):
    lines = [(json.dumps(e) + "\n").encode() for e in events]
    out = io.StringIO()
    graph, ctx, stats = runner.run(lines, runner.alert.AlertSink(out, None), detections=[priv.detect])
    return [json.loads(l) for l in out.getvalue().splitlines()], graph, ctx, stats


def priv_counts(ctx):
    return {k: v for k, v in ctx["counts"].items() if k.startswith("priv_")}


class RequestSignal(unittest.TestCase):

    def test_each_syscall_requesting_zero_alerts_once(self):
        events = [request(100 + i, name, ids) for i, (name, ids) in enumerate(
            (("setuid", [0]), ("setreuid", [0, 0]), ("setresuid", [0, 0, 0])))]
        alerts, _, ctx, stats = run_events(events)
        self.assertEqual([a["detection"] for a in alerts], ["privilege_escalation"] * 3)
        self.assertEqual(stats["detection_errors"], 0)
        for a, e in zip(alerts, events):
            self.assertIsNone(a["technique"])
            self.assertEqual(a["process"]["uid"], 1000)
            self.assertEqual(a["evidence"], [e])
        self.assertEqual(priv_counts(ctx), {})

    def test_zero_as_second_or_third_id_alerts(self):
        events = [request(100, "setreuid", [1000, 0]), request(101, "setresuid", [1000, 1000, 0]),
                  request(102, "setresuid", [1000, 0, 1000])]
        alerts, _, _, _ = run_events(events)
        self.assertEqual(len(alerts), 3)

    def test_no_change_marker_is_not_zero(self):
        events = [request(100, "setreuid", [NO_CHANGE, 1000]), request(101, "setresuid", [NO_CHANGE] * 3),
                  request(102, "setreuid", [NO_CHANGE, NO_CHANGE])]
        alerts, _, ctx, _ = run_events(events)
        self.assertEqual(alerts, [])
        self.assertEqual(priv_counts(ctx), {})

    def test_request_for_own_uid_does_not_alert(self):
        alerts, _, ctx, _ = run_events([request(100, "setuid", [1000]), request(101, "setresuid", [1000] * 3)])
        self.assertEqual(alerts, [])
        self.assertEqual(priv_counts(ctx), {})

    def test_root_caller_counts_already_root(self):
        alerts, _, ctx, _ = run_events([request(100, "setuid", [0], uid=0), request(101, "setresuid", [0, 0, 0], uid=0)])
        self.assertEqual(alerts, [])
        self.assertEqual(priv_counts(ctx), {"priv_already_root": 2})

    def test_every_expected_escalator_is_suppressed_and_counted(self):
        for i, comm in enumerate(priv.EXPECTED_ESCALATORS):
            alerts, _, ctx, _ = run_events([request(100 + i, "setresuid", [0, 0, 0], comm=comm)])
            self.assertEqual(alerts, [], comm)
            self.assertEqual(priv_counts(ctx), {"priv_expected_escalator": 1}, comm)

    def test_near_miss_names_are_not_suppressed(self):
        for i, comm in enumerate(("sudoers", "su2", "Sudo", "sud", "sudo ", "")):
            alerts, _, ctx, _ = run_events([request(100 + i, "setuid", [0], comm=comm)])
            self.assertEqual(len(alerts), 1, repr(comm))
            self.assertEqual(priv_counts(ctx), {}, repr(comm))

    def test_group_syscalls_are_out_of_scope(self):
        alerts, _, ctx, _ = run_events([request(100, "setgid", [0]), request(101, "setresgid", [0, 0, 0])])
        self.assertEqual(alerts, [])
        self.assertEqual(priv_counts(ctx), {})

    def test_missing_or_odd_fields_are_counted_not_fatal(self):
        events = [request(100, "setuid", [0], uid=NO), request(101, "setuid", [0], uid="1000"),
                  request(102, "setuid", [0], uid=None), request(103, "setuid", [0], uid=True),
                  request(104, "setuid", NO), request(105, "setuid", []), request(106, "setuid", "0"),
                  request(107, "setresuid", [0, "0", 0]), request(108, "setresuid", [0, None, 0]),
                  request(109, "setuid", [True])]
        alerts, _, ctx, stats = run_events(events)
        self.assertEqual(alerts, [])
        self.assertEqual(stats["detection_errors"], 0)
        self.assertEqual(priv_counts(ctx), {"priv_no_uid": 4, "priv_no_ids": 6})

    def test_missing_syscall_and_odd_syscall_are_ignored(self):
        events = [request(100, "setuid", [0]), request(101, ["setuid"], [0]), request(102, None, [0])]
        del events[0]["syscall"]
        alerts, _, ctx, stats = run_events(events)
        self.assertEqual(alerts, [])
        self.assertEqual(stats["detection_errors"], 0)
        self.assertEqual(priv_counts(ctx), {})

    def test_two_requests_from_one_key_alert_once(self):
        alerts, _, ctx, _ = run_events([request(100, "setuid", [0], ts=1), request(100, "setresuid", [0, 0, 0], ts=2)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ts_ns"], 1)
        self.assertEqual(priv_counts(ctx), {"priv_already_alerted": 1})

    def test_two_keys_alert_once_each(self):
        alerts, _, _, _ = run_events([request(100, "setuid", [0]), request(101, "setuid", [0]),
                                      request(100, "setuid", [0]), request(101, "setuid", [0])])
        self.assertEqual([a["process"]["pid"] for a in alerts], [100, 101])

    def test_evidence_carries_the_uid_at_the_request(self):
        alerts, _, _, _ = run_events([seen(100, 0, ts=1), request(100, "setuid", [0], uid=1000, ts=2)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["evidence"][0]["uid"], 1000)

    def test_every_alert_has_every_required_field(self):
        alerts, _, _, _ = run_events([request(100, "setuid", [0]), seen(200, 1000), seen(200, 0, typ="exec_attempt")])
        self.assertEqual(len(alerts), 2)
        for a in alerts:
            for field in REQUIRED:
                self.assertIn(field, a)
            self.assertEqual(a["alert_schema_version"], 1)


class ObservedChange(unittest.TestCase):

    def test_change_with_no_request_alerts_with_both_events(self):
        before, after = seen(100, 1000, ts=1), seen(100, 0, typ="exec_attempt", ts=2)
        alerts, _, ctx, _ = run_events([before, after])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["detection"], "privilege_escalation")
        self.assertEqual(alerts[0]["evidence"], [before, after])
        self.assertEqual(alerts[0]["ts_ns"], 2)
        self.assertEqual(priv_counts(ctx), {})

    def test_evidence_is_the_latest_nonzero_uid_event(self):
        first, second, after = seen(100, 1000, ts=1), seen(100, 1001, ts=2), seen(100, 0, ts=3)
        alerts, _, _, _ = run_events([first, second, after])
        self.assertEqual(alerts[0]["evidence"], [second, after])

    def test_change_after_an_alerted_request_is_counted(self):
        alerts, _, ctx, _ = run_events([request(100, "setuid", [0], ts=1), seen(100, 0, typ="exec_attempt", ts=2)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["evidence"][0]["type"], "priv_change")
        self.assertEqual(priv_counts(ctx), {"priv_transition_after_alert": 1})

    def test_change_after_a_suppressed_request_counts_after_request(self):
        #pinned: request_seen is checked before expected_seen so a suppressed request followed by change is priv_transition_after_request
        alerts, _, ctx, _ = run_events([request(100, "setuid", [0], comm="sudo", ts=1), seen(100, 0, ts=2)])
        self.assertEqual(alerts, [])
        self.assertEqual(priv_counts(ctx), {"priv_expected_escalator": 1, "priv_transition_after_request": 1})

    def test_suppressed_request_after_an_earlier_event_then_change(self):
        alerts, _, ctx, _ = run_events([seen(100, 1000, ts=1), request(100, "setuid", [0], uid=1000, comm="sudo", ts=2),
                                        seen(100, 0, ts=3)])
        self.assertEqual(alerts, [])
        self.assertEqual(priv_counts(ctx), {"priv_expected_escalator": 1, "priv_transition_after_request": 1})

    def test_earlier_expected_comm_suppresses_a_later_change(self):
        events = [seen(100, 1000, comm="sudo", ts=1), seen(100, 0, comm="bash", ts=2)]
        alerts, _, ctx, _ = run_events(events)
        self.assertEqual(alerts, [])
        self.assertEqual(priv_counts(ctx), {"priv_transition_expected": 1})

    def test_expected_comm_on_the_change_event_suppresses_it(self):
        alerts, _, ctx, _ = run_events([seen(100, 1000, ts=1), seen(100, 0, comm="su", ts=2)])
        self.assertEqual(alerts, [])
        self.assertEqual(priv_counts(ctx), {"priv_transition_expected": 1})

    def test_key_that_starts_at_root_never_changes(self):
        alerts, _, ctx, _ = run_events([seen(100, 0, ts=1), seen(100, 0, ts=2), seen(100, 0, ts=3)])
        self.assertEqual(alerts, [])
        self.assertEqual(priv_counts(ctx), {})

    def test_drop_from_root_never_alerts(self):
        alerts, _, ctx, _ = run_events([seen(100, 0, ts=1), seen(100, 1000, ts=2), seen(100, 1000, ts=3)])
        self.assertEqual(alerts, [])
        self.assertEqual(priv_counts(ctx), {})

    def test_other_keys_do_not_influence_each_other(self):
        alerts, _, _, _ = run_events([seen(100, 1000, ts=1), seen(101, 0, ts=2), seen(102, 0, ts=3)])
        self.assertEqual(alerts, [])

    def test_unusable_uid_is_ignored_for_the_change(self):
        events = [seen(100, 1000, ts=1), seen(100, "0", ts=2), seen(100, None, ts=3), seen(100, 0, ts=4)]
        alerts, _, _, stats = run_events(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ts_ns"], 4)
        self.assertEqual(stats["detection_errors"], 0)

    def test_second_change_after_the_alert_is_counted(self):
        events = [seen(100, 1000, ts=1), seen(100, 0, ts=2), seen(100, 1000, ts=3), seen(100, 0, ts=4)]
        alerts, _, ctx, _ = run_events(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(priv_counts(ctx), {"priv_transition_after_alert": 1})


class Bounds(unittest.TestCase):

    def test_eviction_restarts_the_key_and_is_counted(self):
        old = priv.MAX_TRACKED_PROCESSES
        priv.MAX_TRACKED_PROCESSES = 2
        self.addCleanup(setattr, priv, "MAX_TRACKED_PROCESSES", old)
        events = [seen(100, 1000, ts=1), seen(101, 1000, ts=2), seen(102, 1000, ts=3), seen(100, 0, ts=4)]
        alerts, _, ctx, _ = run_events(events)
        self.assertEqual(alerts, [])
        self.assertEqual(priv_counts(ctx), {"priv_state_evicted": 2})
        self.assertEqual(old, 8192)

    def test_a_key_in_use_is_not_evicted_first(self):
        old = priv.MAX_TRACKED_PROCESSES
        priv.MAX_TRACKED_PROCESSES = 2
        self.addCleanup(setattr, priv, "MAX_TRACKED_PROCESSES", old)
        events = [seen(100, 1000, ts=1), seen(101, 1000, ts=2), seen(100, 1000, ts=3), seen(102, 1000, ts=4),
                  seen(100, 0, ts=5)]
        alerts, _, ctx, _ = run_events(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(priv_counts(ctx), {"priv_state_evicted": 1})

    def test_events_without_a_usable_key_are_counted_and_skipped(self):
        events = []
        for bad in (NO, None, "", 5, ["1:2"]):
            e = request(100, "setuid", [0])
            if bad is NO:
                del e["process_key"]
            else:
                e["process_key"] = bad
            events.append(e)
        events.append({"schema_version": 1, "type": "lost", "ts_ns": 1, "process_key": None, "dropped": 3})
        alerts, _, ctx, stats = run_events(events)
        self.assertEqual(alerts, [])
        self.assertEqual(stats["detection_errors"], 0)
        self.assertEqual(priv_counts(ctx), {"priv_no_key": 6})

    def test_placeholder_style_key_does_not_crash(self):
        e = request(100, "setuid", [0])
        e["process_key"] = "placeholder:?"
        alerts, _, _, stats = run_events([e])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(stats["detection_errors"], 0)

    def test_non_dict_event_is_ignored(self):
        ctx = {"counts": {}}
        for odd in (None, [], "x", 5):
            self.assertIsNone(priv.detect(None, odd, ctx))
        self.assertEqual(ctx["counts"], {})


class Properties(unittest.TestCase):

    def stream(self):
        return [seen(100, 1000, ts=1), request(100, "setuid", [0], ts=2), seen(100, 0, ts=3),
                seen(200, 1000, ts=4), seen(200, 0, ts=5), request(300, "setresuid", [0, 0, 0], comm="sudo", ts=6),
                seen(300, 0, ts=7), request(400, "setreuid", [NO_CHANGE, 1000], ts=8)]

    def test_events_and_graph_are_not_changed(self):
        events = self.stream()
        lines = [(json.dumps(e) + "\n").encode() for e in events]
        plain_graph = runner.process_graph.ProcessGraph()
        runner.run(lines, runner.alert.AlertSink(io.StringIO(), None), detections=[], graph=plain_graph)
        graph, ctx = runner.process_graph.ProcessGraph(), {"counts": {}}
        for line in lines:
            graph.ingest_line(line)
        before_graph, before_events = copy.deepcopy(graph.summary()), copy.deepcopy(events)
        before_nodes = {k: copy.deepcopy(vars(n)) for k, n in graph.nodes.items()}
        for e in events:
            priv.detect(graph, e, ctx)
        self.assertEqual(events, before_events)
        self.assertEqual(graph.summary(), before_graph)
        self.assertEqual({k: vars(n) for k, n in graph.nodes.items()}, before_nodes)
        self.assertEqual(graph.summary(), plain_graph.summary())

    def test_identical_output_on_two_runs(self):
        first = run_events(self.stream())
        second = run_events(self.stream())
        self.assertEqual(first[0], second[0])
        self.assertEqual(priv_counts(first[2]), priv_counts(second[2]))
        self.assertEqual(len(first[0]), 2)

    def test_registered_last_in_the_runner(self):
        self.assertEqual(runner.DETECTIONS[8].__module__, "privilege_escalation")
        self.assertEqual(len(runner.DETECTIONS), 10)

    def test_registration_changes_no_existing_count(self):
        lines = [(json.dumps(e) + "\n").encode() for e in self.stream()]
        sink = runner.alert.AlertSink(io.StringIO(), None)
        _, with_all, stats_all = runner.run(lines, sink)
        _, without, stats_old = runner.run(lines, runner.alert.AlertSink(io.StringIO(), None),
                                           detections=runner.DETECTIONS[:8])
        keep = lambda ctx: {k: v for k, v in ctx["counts"].items() if not k.startswith("priv_")}
        self.assertEqual(keep(with_all), keep(without))
        self.assertEqual(stats_all["detection_errors"], 0)
        self.assertEqual(stats_all["alerts"].get("privilege_escalation"), 2)
        self.assertNotIn("privilege_escalation", stats_old["alerts"])


if __name__ == "__main__":
    unittest.main()
