"""
tests for unusual_ancestry.py
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

import runner  # noqa: E402
import unusual_ancestry as ua  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(DET_DIR), "graph"))
import process_graph  # noqa: E402

REQUIRED = ("alert_schema_version", "alert_seq", "detection", "technique", "ts_ns", "process",
            "ancestry", "ancestry_stop", "evidence", "evidence_dropped", "data_quality")


def ex(pid, ppid, exe, comm=None, ts=None, typ="exec_success", argv=None):
    comm = os.path.basename(exe)[:15] if comm is None else comm
    ts = pid if ts is None else ts
    return {"schema_version": 1, "type": typ, "ts_ns": ts, "pid": pid, "tid": pid, "comm": comm,
            "ppid": ppid, "uid": 0, "gid": 0, "start_time_ns": pid * 10, "process_key": "%d:%d" % (pid, pid * 10),
            "filename": exe, "exe": exe, "filename_truncated": False, "user_read_failed": False,
            "argv": argv if argv is not None else [os.path.basename(exe)], "attempt_joined": True}


def run_events(events, detections=None, graph=None):
    lines = [(json.dumps(e) + "\n").encode() for e in events]
    out = io.StringIO()
    graph, ctx, stats = runner.run(lines, runner.alert.AlertSink(out, None), detections=detections, graph=graph)
    alerts = [json.loads(l) for l in out.getvalue().splitlines()]
    return alerts, graph, ctx, stats


def only_ancestry(events, graph=None):
    return run_events(events, detections=[ua.detect], graph=graph)


def service(comm="nginx", pid=100):
    return ex(pid, 1, "/usr/sbin/" + comm, comm=comm)


#which programs and which ancestors make the rule fire
class Rule(unittest.TestCase):

    def test_interpreter_as_a_direct_child_of_a_service_alerts(self):
        alerts, _, ctx, stats = only_ancestry([service(), ex(200, 100, "/usr/bin/python3")])
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        for field in REQUIRED:
            self.assertIn(field, a)
        self.assertEqual(a["detection"], "unusual_ancestry")
        self.assertIsNone(a["technique"])
        self.assertEqual(a["process"]["pid"], 200)
        self.assertEqual([c["comm"] for c in a["ancestry"]], ["python3", "nginx"])
        self.assertEqual(a["ancestry_stop"], "root")
        self.assertEqual(stats["alerts"], {"unusual_ancestry": 1})
        self.assertEqual(ctx["counts"].get("unevaluable", 0), 0)

    def test_every_interpreter_and_network_tool_is_watched(self):
        for exe in ("python", "python3", "python3.12", "perl", "ruby", "php", "node", "nc", "ncat", "netcat", "socat"):
            alerts, _, _, _ = only_ancestry([service(), ex(200, 100, "/usr/bin/" + exe)])
            self.assertEqual(len(alerts), 1, exe)
        for exe in ("ls", "pythonista-not", "perl5-not-a-name", "cat", "ncx", "nodejs"):
            expected = 1 if exe.startswith("python") else 0
            alerts, _, _, _ = only_ancestry([service(), ex(200, 100, "/usr/bin/" + exe)])
            self.assertEqual(len(alerts), expected, exe)

    def test_shell_as_a_grandchild_of_a_service_alerts(self):
        alerts, _, _, _ = only_ancestry([service(), ex(150, 100, "/usr/bin/env"), ex(200, 150, "/bin/sh")])
        self.assertEqual([a["process"]["pid"] for a in alerts], [200])

    def test_shell_as_a_direct_child_is_left_to_shell_from_service(self):
        events = [service(), ex(200, 100, "/bin/sh")]
        self.assertEqual(only_ancestry(events)[0], [])
        alerts, _, _, _ = run_events(events)
        self.assertEqual([a["detection"] for a in alerts], ["shell_from_service"])

    def test_shell_below_a_shell_below_a_service(self):
        alerts, _, _, _ = run_events([service(), ex(200, 100, "/bin/sh"), ex(300, 200, "/bin/sh")])
        self.assertEqual([(a["detection"], a["process"]["pid"]) for a in alerts],
                         [("shell_from_service", 200), ("unusual_ancestry", 300)])

    def test_python_below_a_shell_below_a_service(self):
        alerts, _, _, _ = run_events([service(), ex(200, 100, "/bin/sh"), ex(300, 200, "/usr/bin/python3")])
        self.assertEqual([(a["detection"], a["process"]["pid"]) for a in alerts],
                         [("shell_from_service", 200), ("unusual_ancestry", 300)])

    def test_network_tool_three_levels_below_a_service(self):
        events = [service(), ex(150, 100, "/usr/bin/env"), ex(160, 150, "/usr/bin/env"), ex(200, 160, "/usr/bin/nc")]
        alerts, _, _, _ = only_ancestry(events)
        self.assertEqual([c["comm"] for c in alerts[0]["ancestry"]], ["nc", "env", "env", "nginx"])

    def test_a_program_that_is_not_watched_does_not_alert(self):
        alerts, _, ctx, _ = only_ancestry([service(), ex(200, 100, "/bin/ls"), ex(300, 200, "/bin/ls")])
        self.assertEqual(alerts, [])
        self.assertEqual(ctx["counts"].get("unevaluable", 0), 0)

    def test_php_fpm_prefix(self):
        alerts, _, _, _ = only_ancestry([service("php-fpm8.1"), ex(200, 100, "/usr/bin/python3")])
        self.assertEqual(len(alerts), 1)

    def test_names_not_on_the_list_do_not_alert(self):
        for comm in ("sshd", "systemd", "cron", "login", "nginxd", "bash"):
            alerts, _, _, _ = only_ancestry([service(comm), ex(200, 100, "/usr/bin/python3")])
            self.assertEqual(alerts, [], comm)

    def test_evidence_has_the_attempt_and_the_success(self):
        events = [service(), ex(200, 100, "/usr/bin/python3", typ="exec_attempt"), ex(200, 100, "/usr/bin/python3")]
        alerts, _, _, _ = only_ancestry(events)
        self.assertEqual([e["type"] for e in alerts[0]["evidence"]], ["exec_attempt", "exec_success"])

    def test_one_alert_per_exec_with_no_dedup(self):
        events = [service(), ex(200, 100, "/usr/bin/python3"), ex(200, 100, "/usr/bin/perl", ts=300)]
        alerts, _, _, _ = only_ancestry(events)
        self.assertEqual([a["alert_seq"] for a in alerts], [1, 2])


#chains that end somewhere other than a service
class Chains(unittest.TestCase):

    def test_full_chain_to_root_without_a_service_is_not_counted(self):
        events = [ex(100, 1, "/bin/bash"), ex(200, 100, "/bin/sh"), ex(300, 200, "/usr/bin/python3")]
        alerts, _, ctx, _ = only_ancestry(events)
        self.assertEqual(alerts, [])
        self.assertEqual(ctx["counts"].get("unevaluable", 0), 0)

    def test_chain_stopping_at_a_placeholder_is_counted(self):
        alerts, graph, ctx, _ = only_ancestry([ex(300, 999, "/usr/bin/python3")])
        self.assertEqual(alerts, [])
        self.assertTrue(graph.nodes["999:unknown"].placeholder)
        self.assertEqual(ctx["counts"]["unevaluable"], 1)
        self.assertEqual(ctx["counts"]["unevaluable_ancestry_incomplete"], 1)

    def test_a_placeholder_is_never_matched_as_a_service(self):
        alerts, _, ctx, _ = only_ancestry([ex(200, 999, "/bin/sh"), ex(300, 200, "/usr/bin/python3")])
        self.assertEqual(alerts, [])
        self.assertEqual(ctx["counts"]["unevaluable_ancestry_incomplete"], 2)

    def test_service_found_above_the_stop_still_alerts(self):
        events = [service(), ex(150, 100, "/usr/bin/env"), ex(300, 150, "/usr/bin/python3")]
        alerts, _, ctx, _ = only_ancestry(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(ctx["counts"].get("unevaluable", 0), 0)

    def test_process_missing_from_the_graph_is_counted(self):
        event = ex(300, 100, "/usr/bin/python3")
        del event["start_time_ns"]
        alerts, _, ctx, _ = only_ancestry([service(), event])
        self.assertEqual(alerts, [])
        self.assertEqual(ctx["counts"]["unevaluable_not_in_graph"], 1)

    def test_depth_cap_is_respected(self):
        events = [service(), ex(101, 100, "/usr/bin/env"), ex(102, 101, "/usr/bin/env"),
                  ex(103, 102, "/usr/bin/env"), ex(200, 103, "/usr/bin/python3")]
        alerts, graph, ctx, _ = only_ancestry(events, graph=process_graph.ProcessGraph(max_depth=3))
        self.assertEqual(alerts, [])
        self.assertEqual(graph.ancestry("200:2000")["stop"], "depth_cap")
        self.assertEqual(ctx["counts"]["unevaluable_ancestry_incomplete"], 1)
        alerts, _, _, _ = only_ancestry(events, graph=process_graph.ProcessGraph(max_depth=5))
        self.assertEqual(len(alerts), 1)


#process that execs in place keeps one node (i.e. -> shell_from_service)
class InPlace(unittest.TestCase):

    def test_a_service_that_execs_a_watched_program_in_place_is_judged_by_its_parent(self):
        events = [service(), ex(100, 1, "/usr/bin/python3", ts=200)]
        alerts, _, ctx, _ = only_ancestry(events)
        self.assertEqual(alerts, [])
        self.assertEqual(ctx["counts"].get("unevaluable", 0), 0)

    def test_a_parent_that_became_a_service_by_exec_in_place_counts_as_the_service(self):
        events = [ex(100, 1, "/bin/sh"), ex(100, 1, "/usr/sbin/nginx", ts=200), ex(200, 100, "/usr/bin/python3", ts=300)]
        alerts, graph, _, _ = only_ancestry(events)
        self.assertEqual(len(graph.nodes["100:1000"].execs), 2)
        self.assertEqual(len(alerts), 1)

    def test_the_watched_program_that_execs_in_place_alerts_once_per_exec(self):
        events = [service(), ex(200, 100, "/usr/bin/env"), ex(200, 100, "/usr/bin/python3", ts=300)]
        alerts, _, _, _ = only_ancestry(events)
        self.assertEqual(len(alerts), 1)


#purity and all four detections on one stream
class Together(unittest.TestCase):

    def events(self):
        return [service(), ex(150, 100, "/usr/bin/env"), ex(200, 150, "/usr/bin/python3"),
                ex(300, 100, "/bin/sh"), ex(400, 999, "/usr/bin/perl")]

    def test_inputs_are_not_changed_and_output_is_repeatable(self):
        events = self.events()
        before = copy.deepcopy(events)
        first = run_events(events)
        self.assertEqual(events, before)
        graph_before = json.dumps(first[1].to_dict(), sort_keys=True)
        ua.detect(first[1], events[2], {"counts": {}, "attempts": {}})
        self.assertEqual(json.dumps(first[1].to_dict(), sort_keys=True), graph_before)
        self.assertEqual(events, before)
        self.assertEqual(first[0], run_events(copy.deepcopy(events))[0])

    def test_registered_in_the_runner(self):
        self.assertEqual([d.__module__ for d in runner.DETECTIONS[:4]],
                         ["shell_from_service", "exec_from_tmp", "download_chmod_exec", "unusual_ancestry"])

    def test_four_detections_on_one_stream(self):
        url = "http://127.0.0.1:1/x"
        sh = "/tmp/work/sh"
        events = [service(), ex(150, 100, "/usr/bin/env"),
                  ex(200, 150, "/usr/bin/curl", argv=["curl", "-o", sh, url], ts=1000),
                  ex(210, 150, "/bin/chmod", argv=["chmod", "+x", sh], ts=2000),
                  ex(160, 150, sh, argv=[sh], ts=3000),
                  ex(170, 100, "/bin/sh", ts=4000)]
        alerts, _, _, stats = run_events(events)
        by_pid = {}
        for a in alerts:
            by_pid.setdefault(a["process"]["pid"], []).append(a["detection"])
        self.assertEqual(sorted(by_pid[160]), ["download_chmod_exec", "exec_from_tmp", "unusual_ancestry"])
        self.assertEqual(by_pid[170], ["shell_from_service"])
        self.assertEqual(sorted(by_pid), [160, 170])
        self.assertEqual(stats["alerts"], {"download_chmod_exec": 1, "exec_from_tmp": 1,
                                           "shell_from_service": 1, "unusual_ancestry": 1})
        for a in alerts:
            for field in REQUIRED:
                self.assertIn(field, a)

    def test_odd_events_do_not_crash(self):
        odd = [{"schema_version": 1, "type": "exec_success"}, {"schema_version": 1, "type": "exec_success", "exe": 5},
               {"schema_version": 1, "type": "exec_success", "exe": "/usr/bin/python3", "pid": "x"}]
        alerts, _, ctx, stats = run_events([service()] + odd + [ex(200, 100, "/usr/bin/python3")])
        self.assertEqual(stats["detection_errors"], 0)
        self.assertEqual([a["process"]["pid"] for a in alerts], [200])
        self.assertEqual(ctx["counts"]["unevaluable_not_in_graph"], 1)


if __name__ == "__main__":
    unittest.main()
