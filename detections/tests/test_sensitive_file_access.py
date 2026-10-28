"""
tests for sensitive_file_access.py
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

import attack_map  # noqa: E402
import runner  # noqa: E402
import sensitive_file_access as sfa  # noqa: E402

REQUIRED = ("alert_schema_version", "alert_seq", "detection", "technique", "ts_ns", "process",
            "ancestry", "ancestry_stop", "evidence", "evidence_dropped", "data_quality")
NO_RET = object()


def opened(pid, ppid, path, ret=3, comm="cat", ts=None):
    event = {"schema_version": 1, "type": "file_open", "ts_ns": pid if ts is None else ts, "pid": pid, "tid": pid,
             "comm": comm, "path": path, "path_truncated": False, "flags": 0, "ppid": ppid, "uid": 0, "gid": 0,
             "start_time_ns": pid * 10, "user_read_failed": False}
    if ret is not NO_RET:
        event["ret"] = ret
    return event


def started(pid, ppid, exe, comm=None):
    comm = os.path.basename(exe)[:15] if comm is None else comm
    return {"schema_version": 1, "type": "exec_success", "ts_ns": pid, "pid": pid, "tid": pid, "comm": comm,
            "ppid": ppid, "uid": 0, "gid": 0, "start_time_ns": pid * 10, "filename": exe, "exe": exe,
            "argv": [os.path.basename(exe)]}


def run_events(events):
    lines = [(json.dumps(e) + "\n").encode() for e in events]
    out = io.StringIO()
    graph, ctx, stats = runner.run(lines, runner.alert.AlertSink(out, None), detections=[sfa.detect])
    return [json.loads(l) for l in out.getvalue().splitlines()], graph, ctx, stats


def counts(ctx):
    return {k[len("unevaluable_"):]: v for k, v in ctx["counts"].items() if k.startswith("unevaluable_")}


#which paths and which readers make a tier 1 open alert
class Tier1(unittest.TestCase):

    def test_each_tier1_path_alerts_when_read_by_an_unlisted_program(self):
        for path in ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d/90-cloud",
                     "/root/.ssh/id_rsa", "/home/bob/.ssh/id_ed25519", "/home/bob/.ssh/id_rsa_backup"):
            alerts, _, ctx, stats = run_events([opened(200, 1, path)])
            self.assertEqual(len(alerts), 1, path)
            self.assertEqual(ctx["counts"].get("unevaluable", 0), 0, path)
            self.assertEqual(stats["alerts"], {"sensitive_file_access": 1})

    def test_alert_fields(self):
        alerts, _, _, _ = run_events([opened(200, 1, "/etc/shadow", comm="cat")])
        a = alerts[0]
        for field in REQUIRED:
            self.assertIn(field, a)
        self.assertEqual(a["detection"], "sensitive_file_access")
        self.assertEqual(a["technique"], attack_map.technique_for("sensitive_file_access", "shadow"))
        self.assertEqual(a["process"]["pid"], 200)
        self.assertEqual(len(a["evidence"]), 1)
        self.assertEqual((a["evidence"][0]["type"], a["evidence"][0]["path"], a["evidence"][0]["ret"]),
                         ("file_open", "/etc/shadow", 3))

    def test_each_expected_reader_is_suppressed_and_counted(self):
        for comm in sfa.EXPECTED_READERS:
            alerts, _, ctx, _ = run_events([opened(200, 1, "/etc/shadow", comm=comm)])
            self.assertEqual(alerts, [], comm)
            self.assertEqual(counts(ctx), {"expected_reader": 1}, comm)

    def test_the_reader_name_is_exact(self):
        for comm in ("sudo2", "Sudo", "ssh-agent2", "", None, 5):
            alerts, _, _, _ = run_events([opened(200, 1, "/etc/shadow", comm=comm)])
            self.assertEqual(len(alerts), 1, comm)

    def test_a_renamed_binary_is_suppressed(self):
        alerts, _, ctx, _ = run_events([opened(200, 1, "/etc/shadow", comm="sudo")])
        self.assertEqual((alerts, counts(ctx)), ([], {"expected_reader": 1}))

    def test_public_keys_and_ssh_bookkeeping_files_do_not_alert(self):
        for name in ("id_rsa.pub", "known_hosts", "known_hosts.old", "config", "authorized_keys", "authorized_keys2"):
            for home in ("/root", "/home/bob"):
                alerts, _, ctx, _ = run_events([opened(200, 1, "%s/.ssh/%s" % (home, name))])
                self.assertEqual(alerts, [], name)
                self.assertEqual(counts(ctx), {}, name)

    def test_paths_that_are_not_keys_do_not_match(self):
        for path in ("/home/bob/.ssh/sub/id_rsa", "/home/bob/.ssh/", "/home/bob/.ssh", "/etc/sudoers.d/", "/etc/sudoers.d",
                     "/etc/sudoers2", "/etc/shadow-", "/home/.ssh/id_rsa", "/opt/.ssh/id_rsa", "/etc/os-release"):
            alerts, _, ctx, _ = run_events([opened(200, 1, path)])
            self.assertEqual((alerts, counts(ctx)), ([], {}), path)

    def test_failed_and_missing_return_values_are_counted(self):
        for ret in (-2, -13):
            alerts, _, ctx, _ = run_events([opened(200, 1, "/etc/shadow", ret=ret)])
            self.assertEqual((alerts, counts(ctx)), ([], {"failed_open": 1}), ret)
        for ret in (NO_RET, None, "3", True, 1.5):
            alerts, _, ctx, _ = run_events([opened(200, 1, "/etc/shadow", ret=ret)])
            self.assertEqual((alerts, counts(ctx)), ([], {"no_return_value": 1}), ret)
        alerts, _, _, _ = run_events([opened(200, 1, "/etc/shadow", ret=0)])
        self.assertEqual(len(alerts), 1)

    def test_a_listed_reader_that_failed_is_counted_as_failed(self):
        alerts, _, ctx, _ = run_events([opened(200, 1, "/etc/shadow", ret=-13, comm="sudo")])
        self.assertEqual((alerts, counts(ctx)), ([], {"failed_open": 1}))

    def test_paths_are_cleaned_first(self):
        for path in ("/etc/../etc/shadow", "//etc//shadow", "/etc/./shadow", "/home/bob/../bob/.ssh/id_rsa"):
            alerts, _, _, _ = run_events([opened(200, 1, path)])
            self.assertEqual(len(alerts), 1, path)
        alerts, _, _, _ = run_events([opened(200, 1, "/etc/shadow/../os-release")])
        self.assertEqual(alerts, [])

    def test_relative_or_missing_paths_are_counted(self):
        alerts, _, ctx, _ = run_events([opened(200, 1, "etc/shadow"), opened(201, 1, ""), opened(202, 1, None)])
        self.assertEqual(alerts, [])
        self.assertEqual(counts(ctx), {"relative_path": 1, "no_path": 2})

    def test_one_alert_per_open_with_no_dedup(self):
        events = [opened(200, 1, "/etc/shadow", ts=10), opened(200, 1, "/etc/shadow", ts=20),
                  opened(200, 1, "/etc/gshadow", ts=30)]
        alerts, _, _, _ = run_events(events)
        self.assertEqual([a["alert_seq"] for a in alerts], [1, 2, 3])

    def test_other_events_are_ignored(self):
        events = [started(200, 1, "/bin/cat"), {"schema_version": 1, "type": "file_open"},
                  {"schema_version": 1, "type": "net_connect", "path": "/etc/shadow"}, {"schema_version": 1}]
        alerts, _, ctx, stats = run_events(events)
        self.assertEqual(alerts, [])
        self.assertEqual(stats["detection_errors"], 0)


#/etc/passwd alerts only below a service
class Tier2(unittest.TestCase):

    def service(self, comm="nginx", pid=100):
        return started(pid, 1, "/usr/sbin/" + comm, comm=comm)

    def test_service_ancestor_at_depth_one_and_two(self):
        alerts, _, ctx, _ = run_events([self.service(), opened(200, 100, "/etc/passwd")])
        self.assertEqual(len(alerts), 1)
        self.assertEqual([c["comm"] for c in alerts[0]["ancestry"]], ["cat", "nginx"])
        self.assertEqual(ctx["counts"].get("unevaluable", 0), 0)
        events = [self.service(), started(150, 100, "/usr/bin/env"), opened(200, 150, "/etc/passwd")]
        self.assertEqual(len(run_events(events)[0]), 1)

    def test_php_fpm_prefix(self):
        alerts, _, _, _ = run_events([self.service("php-fpm8.1"), opened(200, 100, "/etc/passwd")])
        self.assertEqual(len(alerts), 1)

    def test_the_service_reading_it_does_not_alert(self):
        alerts, _, ctx, _ = run_events([self.service(), opened(100, 1, "/etc/passwd", comm="nginx")])
        self.assertEqual((alerts, counts(ctx)), ([], {}))

    def test_a_chain_to_root_without_a_service_is_not_counted(self):
        events = [started(100, 1, "/bin/bash"), started(150, 100, "/bin/sh"), opened(200, 150, "/etc/passwd")]
        alerts, _, ctx, _ = run_events(events)
        self.assertEqual((alerts, counts(ctx)), ([], {}))

    def test_a_placeholder_stop_is_counted(self):
        alerts, graph, ctx, _ = run_events([opened(200, 999, "/etc/passwd")])
        self.assertTrue(graph.nodes["999:unknown"].placeholder)
        self.assertEqual((alerts, counts(ctx)), ([], {"ancestry_incomplete": 1}))

    def test_a_reader_missing_from_the_graph_is_counted(self):
        event = opened(200, 100, "/etc/passwd")
        del event["start_time_ns"]
        alerts, _, ctx, _ = run_events([self.service(), event])
        self.assertEqual((alerts, counts(ctx)), ([], {"not_in_graph": 1}))

    def test_failed_or_missing_return_value_comes_first(self):
        alerts, _, ctx, _ = run_events([self.service(), opened(200, 100, "/etc/passwd", ret=-2),
                                        opened(201, 100, "/etc/passwd", ret=NO_RET)])
        self.assertEqual((alerts, counts(ctx)), ([], {"failed_open": 1, "no_return_value": 1}))

    def test_tier1_does_not_need_a_service(self):
        alerts, _, _, _ = run_events([self.service(), opened(200, 100, "/etc/shadow")])
        self.assertEqual(len(alerts), 1)


#purity and the other detections next to it
class Purity(unittest.TestCase):

    def events(self):
        return [started(100, 1, "/usr/sbin/nginx", comm="nginx"), opened(200, 100, "/etc/passwd"),
                opened(201, 100, "/etc/shadow"), opened(202, 999, "/etc/passwd"), opened(203, 1, "/etc/shadow", comm="sudo")]

    def test_inputs_are_not_changed_and_output_is_repeatable(self):
        events = self.events()
        before = copy.deepcopy(events)
        first = run_events(events)
        self.assertEqual(events, before)
        graph_before = json.dumps(first[1].to_dict(), sort_keys=True)
        sfa.detect(first[1], events[1], {"counts": {}, "attempts": {}})
        self.assertEqual(json.dumps(first[1].to_dict(), sort_keys=True), graph_before)
        self.assertEqual(events, before)
        self.assertEqual(first[0], run_events(copy.deepcopy(events))[0])
        self.assertEqual(len(first[0]), 2)

    def test_registered_in_the_runner_and_the_others_still_work(self):
        self.assertEqual(runner.DETECTIONS[4].__module__, "sensitive_file_access")
        lines = [(json.dumps(e) + "\n").encode() for e in self.events() + [started(300, 100, "/bin/sh")]]
        out = io.StringIO()
        _, _, stats = runner.run(lines, runner.alert.AlertSink(out, None))
        self.assertEqual(stats["alerts"].get("sensitive_file_access"), 2)
        self.assertEqual(stats["alerts"].get("shell_from_service"), 1)


if __name__ == "__main__":
    unittest.main()
