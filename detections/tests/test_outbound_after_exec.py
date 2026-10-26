"""
tests for outbound_after_exec.py
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

import outbound_after_exec as oae  # noqa: E402
import runner  # noqa: E402

REQUIRED = ("alert_schema_version", "alert_seq", "detection", "technique", "ts_ns", "process",
            "ancestry", "ancestry_stop", "evidence", "evidence_dropped", "data_quality")
SEC = 1000000000
BASE = 100 * SEC
PUBLIC = "93.184.216.34"


def started(pid, ts, exe, typ="exec_success", ppid=1):
    return {"schema_version": 1, "type": typ, "ts_ns": ts, "pid": pid, "tid": pid, "comm": os.path.basename(exe)[:15],
            "ppid": ppid, "uid": 0, "gid": 0, "start_time_ns": pid * 10, "process_key": "%d:%d" % (pid, pid * 10),
            "filename": exe, "exe": exe, "argv": [os.path.basename(exe)], "cmdline": os.path.basename(exe)}


def connect(pid, ts, addr=PUBLIC, port=4444, family=None):
    family = family if family is not None else (10 if isinstance(addr, str) and ":" in addr else 2)
    return {"schema_version": 1, "type": "net_connect", "ts_ns": ts, "pid": pid, "tid": pid, "comm": "x",
            "family": family, "remote_addr": addr, "remote_port": port, "ppid": 1, "uid": 0, "gid": 0,
            "start_time_ns": pid * 10, "lossy_encoding": False}


def run_events(events):
    lines = [(json.dumps(e) + "\n").encode() for e in events]
    out = io.StringIO()
    graph, ctx, stats = runner.run(lines, runner.alert.AlertSink(out, None), detections=[oae.detect])
    return [json.loads(l) for l in out.getvalue().splitlines()], graph, ctx, stats


def after(exe, addr=PUBLIC, gap=SEC, port=4444, pid=200):
    return [started(pid, BASE, exe), connect(pid, BASE + gap, addr, port)]


def counters(ctx):
    return {k: v for k, v in ctx["counts"].items() if k != "unevaluable"}


#which processes and which destinations make a connect alert
class Rule(unittest.TestCase):

    def test_interpreter_to_a_public_ipv4_address_alerts_once(self):
        alerts, _, ctx, stats = run_events(after("/usr/bin/python3"))
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        for field in REQUIRED:
            self.assertIn(field, a)
        self.assertEqual(a["detection"], "outbound_after_exec")
        self.assertIsNone(a["technique"])
        self.assertEqual(a["ts_ns"], BASE + SEC)
        self.assertEqual(a["process"]["pid"], 200)
        self.assertEqual([e["type"] for e in a["evidence"]], ["exec_success", "net_connect"])
        self.assertEqual(a["evidence"][1]["remote_addr"], PUBLIC)
        self.assertEqual(stats["alerts"], {"outbound_after_exec": 1})
        self.assertEqual(counters(ctx), {})

    def test_watched_programs_and_suspect_directories_alert(self):
        for exe in ("/usr/bin/python3", "/usr/bin/python3.12", "/bin/bash", "/bin/sh", "/usr/bin/nc", "/usr/bin/socat",
                    "/usr/bin/perl", "/tmp/payload", "/var/tmp/x/payload", "/dev/shm/payload", "/tmp/../tmp/a"):
            alerts, _, _, _ = run_events(after(exe))
            self.assertEqual(len(alerts), 1, exe)

    def test_curl_and_wget_are_not_suspect_by_name(self):
        for exe in ("/usr/bin/curl", "/usr/bin/wget", "/usr/bin/ls", "/opt/app/server", "./local"):
            alerts, _, ctx, _ = run_events(after(exe))
            self.assertEqual(alerts, [], exe)
            self.assertEqual(counters(ctx), {"connect_not_suspect_process": 1}, exe)

    def test_loopback_and_unspecified_addresses_do_not_alert(self):
        for addr in ("127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::"):
            alerts, _, ctx, _ = run_events(after("/usr/bin/python3", addr))
            self.assertEqual(alerts, [], addr)
            self.assertEqual(counters(ctx), {"connect_loopback": 1}, addr)

    def test_private_addresses_alert_unless_excluded(self):
        for addr in ("10.1.2.3", "192.168.1.5", "172.16.0.9", "fd00::1", "fe80::1"):
            self.assertEqual(len(run_events(after("/usr/bin/python3", addr))[0]), 1, addr)
        with mock.patch.object(oae, "EXCLUDE_PRIVATE_RANGES", True):
            for addr in ("10.1.2.3", "192.168.1.5", "172.16.0.9", "fd00::1", "fe80::1", "::ffff:10.0.0.1"):
                alerts, _, ctx, _ = run_events(after("/usr/bin/python3", addr))
                self.assertEqual(alerts, [], addr)
                self.assertEqual(counters(ctx), {"connect_loopback": 1}, addr)
            self.assertEqual(len(run_events(after("/usr/bin/python3", PUBLIC))[0]), 1)
        self.assertFalse(oae.EXCLUDE_PRIVATE_RANGES)

    def test_public_ipv6_alerts(self):
        alerts, _, _, _ = run_events(after("/usr/bin/python3", "2001:4860:4860::8888"))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["evidence"][1]["family"], 10)

    def test_bad_addresses_are_counted(self):
        for addr in ("not-an-ip", "", None, 5, "1.2.3", "300.1.1.1"):
            alerts, _, ctx, _ = run_events(after("/usr/bin/python3", addr))
            self.assertEqual(alerts, [], addr)
            self.assertEqual(counters(ctx), {"unevaluable_net_bad_address": 1}, addr)

    def test_other_events_are_ignored(self):
        events = [started(200, BASE, "/usr/bin/python3"), {"schema_version": 1, "type": "file_open", "path": "/etc/passwd"},
                  {"schema_version": 1, "type": "net_connect"}, {"schema_version": 1}]
        alerts, _, ctx, stats = run_events(events)
        self.assertEqual((alerts, stats["detection_errors"]), ([], 0))


#the process and window
class Process(unittest.TestCase):

    def test_window_edge(self):
        exe = "/usr/bin/python3"
        self.assertEqual(len(run_events(after(exe, gap=oae.CONNECT_WINDOW_NS))[0]), 1)
        alerts, _, ctx, _ = run_events(after(exe, gap=oae.CONNECT_WINDOW_NS + 1))
        self.assertEqual((alerts, counters(ctx)), ([], {"connect_outside_window": 1}))
        self.assertEqual(len(run_events(after(exe, gap=0))[0]), 1)

    def test_out_of_order_timestamps_do_not_crash(self):
        alerts, _, ctx, stats = run_events(after("/usr/bin/python3", gap=-1))
        self.assertEqual((alerts, counters(ctx), stats["detection_errors"]), ([], {"out_of_order": 1}, 0))

    def test_a_process_missing_from_the_graph(self):
        event = connect(200, BASE)
        del event["start_time_ns"]
        alerts, _, ctx, _ = run_events([started(200, BASE, "/usr/bin/python3"), event])
        self.assertEqual((alerts, counters(ctx)), ([], {"unevaluable_net_not_in_graph": 1}))

    def test_a_process_with_no_exec_history(self):
        alerts, graph, ctx, _ = run_events([connect(200, BASE)])
        self.assertEqual(graph.nodes["200:2000"].execs, [])
        self.assertEqual((alerts, counters(ctx)), ([], {"unevaluable_net_no_exec_seen": 1}))

    def test_an_exec_history_of_failed_attempts_only(self):
        events = [started(200, BASE, "/usr/bin/python3", typ="exec_failed"), connect(200, BASE + SEC)]
        alerts, graph, ctx, _ = run_events(events)
        self.assertTrue(graph.nodes["200:2000"].execs[0]["failed"])
        self.assertEqual((alerts, counters(ctx)), ([], {"unevaluable_net_no_exec_seen": 1}))

    def test_a_failed_attempt_is_skipped_for_the_latest_successful_exec(self):
        events = [started(200, BASE, "/usr/bin/python3"), started(200, BASE + SEC, "/usr/bin/missing", typ="exec_failed"),
                  connect(200, BASE + 2 * SEC)]
        self.assertEqual(len(run_events(events)[0]), 1)

    def test_an_in_place_exec_uses_the_latest_entry(self):
        events = [started(200, BASE, "/usr/bin/python3"), started(200, BASE + 70 * SEC, "/bin/ls"),
                  connect(200, BASE + 71 * SEC)]
        alerts, _, ctx, _ = run_events(events)
        self.assertEqual((alerts, counters(ctx)), ([], {"connect_not_suspect_process": 1}))
        events = [started(200, BASE, "/bin/ls"), started(200, BASE + 70 * SEC, "/usr/bin/python3"),
                  connect(200, BASE + 71 * SEC)]
        alerts, _, _, _ = run_events(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["evidence"][0]["ts_ns"], BASE + 70 * SEC)

    def test_comm_is_not_used(self):
        event = connect(200, BASE + SEC)
        event["comm"] = "python3"
        alerts, _, ctx, _ = run_events([started(200, BASE, "/usr/bin/curl"), event])
        self.assertEqual((alerts, counters(ctx)), ([], {"connect_not_suspect_process": 1}))


#dedup, limits, and purity
class Dedup(unittest.TestCase):

    def test_repeats_alert_once_and_a_new_port_or_address_alerts_again(self):
        events = [started(200, BASE, "/usr/bin/python3")] + [connect(200, BASE + (i + 1) * SEC) for i in range(5)]
        alerts, _, ctx, _ = run_events(events)
        self.assertEqual((len(alerts), counters(ctx)), (1, {"duplicate_connect": 4}))
        events += [connect(200, BASE + 8 * SEC, port=80), connect(200, BASE + 9 * SEC, addr="8.8.8.8")]
        alerts, _, ctx, _ = run_events(events)
        self.assertEqual((len(alerts), counters(ctx)), (3, {"duplicate_connect": 4}))

    def test_another_process_to_the_same_destination_alerts(self):
        events = after("/usr/bin/python3", pid=200) + after("/usr/bin/python3", pid=201)
        self.assertEqual(len(run_events(events)[0]), 2)

    def test_the_oldest_remembered_connection_is_evicted(self):
        events = [started(200, BASE, "/usr/bin/python3")]
        for i, port in enumerate((1, 2, 3, 1)):
            events.append(connect(200, BASE + (i + 1) * SEC, port=port))
        self.assertEqual(len(run_events(events)[0]), 3)
        with mock.patch.object(oae, "MAX_SEEN_CONNECTIONS", 2):
            alerts, _, ctx, _ = run_events(events)
        self.assertEqual((len(alerts), counters(ctx)), (4, {}))
        self.assertEqual(oae.MAX_SEEN_CONNECTIONS, 4096)

    def test_exec_evidence_is_dropped_when_not_held(self):
        events = after("/usr/bin/python3")
        with mock.patch.object(oae, "MAX_TRACKED_EXECS", 1):
            alerts, _, _, _ = run_events(events[:1] + [started(300, BASE + 1, "/bin/ls")] + events[1:])
        self.assertEqual([e["type"] for e in alerts[0]["evidence"]], ["net_connect"])

    def test_inputs_are_not_changed_and_output_is_repeatable(self):
        events = after("/usr/bin/python3") + after("/tmp/x", pid=201) + after("/usr/bin/curl", pid=202)
        before = copy.deepcopy(events)
        first = run_events(events)
        self.assertEqual(events, before)
        graph_before = json.dumps(first[1].to_dict(), sort_keys=True)
        oae.detect(first[1], events[1], {"counts": {}, "attempts": {}})
        self.assertEqual(json.dumps(first[1].to_dict(), sort_keys=True), graph_before)
        self.assertEqual(events, before)
        self.assertEqual(first[0], run_events(copy.deepcopy(events))[0])
        self.assertEqual(len(first[0]), 2)

    def test_registered_in_the_runner(self):
        self.assertEqual(runner.DETECTIONS[6].__module__, "outbound_after_exec")


if __name__ == "__main__":
    unittest.main()
