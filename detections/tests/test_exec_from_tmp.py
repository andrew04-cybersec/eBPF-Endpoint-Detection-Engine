"""
Tests for exec_from_tmp.py
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

import exec_from_tmp  # noqa: E402
import runner  # noqa: E402
import shell_from_service  # noqa: E402

REQUIRED = ("alert_schema_version", "alert_seq", "detection", "technique", "ts_ns", "process",
            "ancestry", "ancestry_stop", "evidence", "evidence_dropped", "data_quality")


def ev(typ, pid, start, ts, ppid, comm, **extra):
    event = {"schema_version": 1, "type": typ, "ts_ns": ts, "pid": pid, "tid": pid,
             "comm": comm, "ppid": ppid, "uid": 0, "gid": 0, "start_time_ns": start,
             "process_key": "%d:%d" % (pid, start)}
    event.update(extra)
    return event


def attempt(pid, start, ts, ppid, comm, filename):
    return ev("exec_attempt", pid, start, ts, ppid, comm, filename=filename, exe=filename,
              cmdline=filename, argv=[filename], filename_truncated=False, user_read_failed=False)


def success(pid, start, ts, ppid, comm, filename, **extra):
    fields = dict(filename=filename, exe=filename, cmdline=filename, argv=[filename],
                  filename_truncated=False, user_read_failed=False, attempt_joined=True)
    fields.update(extra)
    return ev("exec_success", pid, start, ts, ppid, comm, **fields)


def exec_of(filename, pid=200, start=20, **extra):
    return [attempt(pid, start, start + 1, 1, "bash", filename),
            success(pid, start, start + 2, 1, os.path.basename(filename) or "x", filename, **extra)]


def run_events(events, detections=None):
    lines = [(json.dumps(e) + "\n").encode() for e in events]
    out = io.StringIO()
    graph, ctx, stats = runner.run(lines, runner.alert.AlertSink(out, None), detections=detections)
    alerts = [json.loads(l) for l in out.getvalue().splitlines()]
    return alerts, graph, ctx, stats


def only_tmp(events):
    return run_events(events, detections=[exec_from_tmp.detect])


#which filenames the rule matches
class Paths(unittest.TestCase):

    def test_each_suspect_directory_alerts(self):
        for directory in ("/tmp", "/var/tmp", "/dev/shm"):
            alerts, _, _, _ = only_tmp(exec_of(directory + "/payload"))
            self.assertEqual(len(alerts), 1, directory)

    def test_alert_has_every_field_and_the_evidence(self):
        alerts, _, ctx, stats = only_tmp(exec_of("/tmp/payload"))
        a = alerts[0]
        for field in REQUIRED:
            self.assertIn(field, a)
        self.assertEqual(a["detection"], "exec_from_tmp")
        self.assertIsNone(a["technique"])
        self.assertEqual([e["type"] for e in a["evidence"]], ["exec_attempt", "exec_success"])
        self.assertEqual(a["process"]["exe"], "/tmp/payload")
        self.assertEqual(stats["alerts"], {"exec_from_tmp": 1})
        self.assertEqual(ctx["counts"].get("unevaluable", 0), 0)

    def test_nested_subdirectory_alerts(self):
        alerts, _, _, _ = only_tmp(exec_of("/tmp/a/b/c/payload"))
        self.assertEqual(len(alerts), 1)

    def test_lookalike_and_bare_names_do_not_alert(self):
        for filename in ("/tmpfoo/x", "/var/tmpfoo/x", "/dev/shmx/x", "/tmp", "/tmp/", "/var/tmp", "/usr/bin/tmp/x"):
            alerts, _, ctx, _ = only_tmp(exec_of(filename))
            self.assertEqual(alerts, [], filename)
            self.assertEqual(ctx["counts"].get("unevaluable", 0), 0, filename)

    def test_dot_dot_is_resolved_lexically(self):
        alerts, _, _, _ = only_tmp(exec_of("/tmp/../usr/bin/ls"))
        self.assertEqual(alerts, [])
        alerts, _, _, _ = only_tmp(exec_of("/usr/bin/../../tmp/x"))
        self.assertEqual(len(alerts), 1)
        alerts, _, _, _ = only_tmp(exec_of("/tmp/./a//b/../payload"))
        self.assertEqual(len(alerts), 1)
        alerts, _, _, _ = only_tmp(exec_of("/../tmp/x"))
        self.assertEqual(len(alerts), 1)

    def test_double_leading_slash_is_treated_as_a_single_slash(self):
        self.assertEqual(exec_from_tmp.clean_path("//tmp/x"), "/tmp/x")
        self.assertEqual(exec_from_tmp.clean_path("///tmp/x"), "/tmp/x")
        for filename in ("//tmp/x", "///var/tmp/x", "//dev//shm/x"):
            alerts, _, _, _ = only_tmp(exec_of(filename))
            self.assertEqual(len(alerts), 1, filename)
        alerts, _, _, _ = only_tmp(exec_of("//usr/bin/ls"))
        self.assertEqual(alerts, [])


#filenames the rule cannot judge and events that are not successes
class Unevaluable(unittest.TestCase):

    def test_relative_path(self):
        for filename in ("./payload", "payload", "../tmp/x", "tmp/x"):
            alerts, _, ctx, _ = only_tmp(exec_of(filename))
            self.assertEqual(alerts, [], filename)
            self.assertEqual(ctx["counts"]["unevaluable_relative_path"], 1, filename)

    def test_missing_filename(self):
        for filename in ("", None, 5):
            alerts, _, ctx, _ = only_tmp([success(200, 20, 22, 1, "x", filename)])
            self.assertEqual(alerts, [])
            self.assertEqual(ctx["counts"]["unevaluable_no_filename"], 1)
        event = success(200, 20, 22, 1, "x", "/tmp/x")
        del event["filename"]
        alerts, _, ctx, _ = only_tmp([event])
        self.assertEqual((alerts, ctx["counts"]["unevaluable_no_filename"]), ([], 1))

    def test_read_failed(self):
        alerts, _, ctx, _ = only_tmp([success(200, 20, 22, 1, "x", "", user_read_failed=True)])
        self.assertEqual(alerts, [])
        self.assertEqual(ctx["counts"]["unevaluable_read_failed"], 1)
        alerts, _, ctx, _ = only_tmp([success(200, 20, 22, 1, "x", "/tmp/x", user_read_failed=True)])
        self.assertEqual((alerts, ctx["counts"]["unevaluable_read_failed"]), ([], 1))

    def test_truncated_filename_both_ways(self):
        alerts, _, ctx, _ = only_tmp([success(200, 20, 22, 1, "x", "/tmp/aaaa", filename_truncated=True)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(ctx["counts"].get("unevaluable", 0), 0)
        for prefix in ("/usr/lib/aaaa", "/tmp", "/tm"):
            alerts, _, ctx, _ = only_tmp([success(200, 20, 22, 1, "x", prefix, filename_truncated=True)])
            self.assertEqual(alerts, [], prefix)
            self.assertEqual(ctx["counts"]["unevaluable_truncated"], 1, prefix)

    def test_failed_attempt_without_a_success_does_not_alert(self):
        failed = ev("exec_failed", 200, 20, 21, 1, "bash", filename="/tmp/missing", exe="/tmp/missing",
                    cmdline="/tmp/missing", reason="exit")
        events = [attempt(200, 20, 21, 1, "bash", "/tmp/missing"), failed,
                  ev("exit", 200, 20, 22, 1, "bash", exit_code=32512, exit_status=127, exit_signal=0)]
        alerts, _, ctx, stats = only_tmp(events)
        self.assertEqual(alerts, [])
        self.assertEqual(ctx["counts"].get("unevaluable", 0), 0)
        self.assertEqual(stats["detection_errors"], 0)

    def test_other_event_types_and_odd_events_are_ignored(self):
        events = [ev("file_open", 7, 70, 1, 1, "x", path="/tmp/x", flags=0),
                  {"schema_version": 1, "type": "exec_success"}, {"schema_version": 1}]
        alerts, _, _, stats = only_tmp(events)
        self.assertEqual(alerts, [])
        self.assertEqual(stats["detection_errors"], 0)


#counts, determinism, purity, and running next to shell_from_service
class Together(unittest.TestCase):

    def events(self):
        return (exec_of("/tmp/a", pid=200, start=20) + exec_of("/dev/shm/b", pid=201, start=30)
                + exec_of("/usr/bin/ls", pid=202, start=40))

    def test_one_alert_per_exec_with_no_dedup(self):
        alerts, _, _, _ = only_tmp(exec_of("/tmp/a", pid=200, start=20) + exec_of("/tmp/a", pid=201, start=30)
                                   + [success(200, 20, 99, 1, "a", "/tmp/a")])
        self.assertEqual([a["alert_seq"] for a in alerts], [1, 2, 3])

    def test_inputs_are_not_changed_and_output_is_repeatable(self):
        events = self.events()
        before = copy.deepcopy(events)
        first = run_events(events)
        self.assertEqual(events, before)
        graph_before = json.dumps(first[1].to_dict(), sort_keys=True)
        exec_from_tmp.detect(first[1], events[1], {"counts": {}, "attempts": {}})
        self.assertEqual(json.dumps(first[1].to_dict(), sort_keys=True), graph_before)
        self.assertEqual(events, before)
        second = run_events(self.events())
        self.assertEqual(first[0], second[0])
        self.assertEqual([a["process"]["pid"] for a in first[0]], [200, 201])

    def test_registered_in_the_runner_next_to_shell_from_service(self):
        self.assertEqual(runner.DETECTIONS[:2], [shell_from_service.detect, exec_from_tmp.detect])

    def test_shell_from_service_still_alerts(self):
        service = success(100, 10, 11, 1, "nginx", "/usr/sbin/nginx")
        shell = [attempt(200, 20, 21, 100, "nginx", "/bin/sh"), success(200, 20, 22, 100, "sh", "/bin/sh")]
        alerts, _, _, stats = run_events([service] + shell)
        self.assertEqual([a["detection"] for a in alerts], ["shell_from_service"])
        self.assertEqual(stats["alerts"], {"shell_from_service": 1})

    def test_service_parent_shell_run_from_tmp_gives_both_alerts(self):
        service = success(100, 10, 11, 1, "nginx", "/usr/sbin/nginx")
        shell = [attempt(200, 20, 21, 100, "nginx", "/tmp/sh"), success(200, 20, 22, 100, "sh", "/tmp/sh")]
        alerts, _, _, stats = run_events([service] + shell)
        self.assertEqual(sorted(a["detection"] for a in alerts), ["exec_from_tmp", "shell_from_service"])
        self.assertEqual([a["alert_seq"] for a in alerts], [1, 2])
        for a in alerts:
            for field in REQUIRED:
                self.assertIn(field, a)
        self.assertEqual(stats["alerts"], {"exec_from_tmp": 1, "shell_from_service": 1})

    def test_unevaluable_reasons_are_summarized(self):
        _, graph, ctx, stats = run_events(exec_of("./x") + exec_of("", pid=201, start=30))
        text = "\n".join(runner.summary_lines(graph, ctx, stats))
        self.assertIn("unevaluable: 2", text)
        self.assertIn("relative_path 1", text)
        self.assertIn("no_filename 1", text)


if __name__ == "__main__":
    unittest.main()
