"""
tests for shell_from_service.py and runner.py
every event here is a !!constructed fixture, not captured output!!
"""
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DET_DIR = os.path.dirname(HERE)
sys.path.insert(0, DET_DIR)

import runner  # noqa: E402

REQUIRED = ("alert_schema_version", "alert_seq", "detection", "technique", "ts_ns", "process",
            "ancestry", "ancestry_stop", "evidence", "evidence_dropped", "data_quality")


def ev(typ, pid, start, ts, ppid, comm, **extra):
    event = {"schema_version": 1, "type": typ, "ts_ns": ts, "pid": pid, "tid": pid,
             "comm": comm, "ppid": ppid, "uid": 0, "gid": 0, "start_time_ns": start,
             "process_key": "%d:%d" % (pid, start)}
    event.update(extra)
    return event


def attempt(pid, start, ts, ppid, comm, exe, cmdline):
    return ev("exec_attempt", pid, start, ts, ppid, comm, filename=exe, exe=exe, cmdline=cmdline,
              argv=cmdline.split())


def success(pid, start, ts, ppid, comm, exe, cmdline=""):
    return ev("exec_success", pid, start, ts, ppid, comm, filename=exe, exe=exe, cmdline=cmdline,
              argv=cmdline.split(), attempt_joined=True)


def service(comm="nginx", pid=100, start=10):
    return [success(pid, start, start + 1, 1, comm, "/usr/sbin/" + comm, comm)]


def shell_from(parent_pid, pid=200, start=20, exe="/bin/sh", marker="x"):
    cmd = "sh -c %s" % marker
    return [attempt(pid, start, start + 1, parent_pid, "nginx", exe, cmd),
            success(pid, start, start + 2, parent_pid, "sh", exe, cmd)]


def run_events(events, **kwargs):
    text = "".join(json.dumps(e) + "\n" for e in events)
    out = io.StringIO()
    sink = runner.alert.AlertSink(out, None)
    graph, ctx, stats = runner.run(text.encode().splitlines(True), sink, **kwargs)
    alerts = [json.loads(l) for l in out.getvalue().splitlines()]
    return alerts, graph, ctx, stats


#which parents and children make the rule fire
class Rule(unittest.TestCase):

    def test_service_parent_spawning_a_shell_alerts(self):
        alerts, _, ctx, stats = run_events(service() + shell_from(100, marker="EVT"))
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        for field in REQUIRED:
            self.assertIn(field, a)
        self.assertEqual(a["detection"], "shell_from_service")
        self.assertIsNone(a["technique"])
        self.assertEqual(a["alert_seq"], 1)
        self.assertEqual(a["process"]["comm"], "sh")
        self.assertEqual(a["process"]["ppid"], 100)
        self.assertEqual([e["type"] for e in a["evidence"]], ["exec_attempt", "exec_success"])
        self.assertEqual([c["comm"] for c in a["ancestry"]], ["sh", "nginx"])
        self.assertEqual(a["ancestry_stop"], "root")
        self.assertEqual(stats["alerts"], {"shell_from_service": 1})
        self.assertEqual(ctx["counts"].get("unevaluable", 0), 0)

    def test_every_shell_name_is_a_trigger(self):
        names = ("sh", "bash", "dash", "zsh", "ash", "ksh", "csh", "tcsh", "fish")
        events = service()
        for i, name in enumerate(names):
            events += shell_from(100, pid=200 + i, start=20 + i, exe="/usr/bin/" + name)
        alerts, _, _, _ = run_events(events)
        self.assertEqual(len(alerts), len(names))

    def test_non_service_parent_does_not_alert(self):
        alerts, _, ctx, _ = run_events(service("python3") + shell_from(100))
        self.assertEqual(alerts, [])
        self.assertEqual(ctx["counts"].get("unevaluable", 0), 0)

    def test_service_parent_spawning_a_non_shell_does_not_alert(self):
        events = service() + [success(200, 20, 22, 100, "ls", "/usr/bin/ls", "ls /")]
        alerts, _, _, _ = run_events(events)
        self.assertEqual(alerts, [])

    def test_names_must_match_the_list(self):
        for comm in ("nginxd", "sshd", "systemd", "cron", "login", "mysqld-safe"):
            alerts, _, _, _ = run_events(service(comm) + shell_from(100))
            self.assertEqual(alerts, [], comm)
        for comm in ("apache2", "httpd", "mysqld", "postgres", "redis-server", "mongod"):
            alerts, _, _, _ = run_events(service(comm) + shell_from(100))
            self.assertEqual(len(alerts), 1, comm)

    def test_php_fpm_prefix_match(self):
        for comm in ("php-fpm", "php-fpm8.1"):
            alerts, _, _, _ = run_events(service(comm) + shell_from(100))
            self.assertEqual(len(alerts), 1, comm)

    def test_one_alert_per_shell_with_no_dedup(self):
        events = service() + shell_from(100, pid=200, start=20) + shell_from(100, pid=201, start=30)
        alerts, _, _, _ = run_events(events)
        self.assertEqual([a["alert_seq"] for a in alerts], [1, 2])
        self.assertEqual([a["process"]["pid"] for a in alerts], [200, 201])

    def test_service_that_exec_in_place_is_still_a_service(self):
        events = [success(100, 10, 11, 1, "sh", "/bin/sh", "sh"),
                  success(100, 10, 12, 1, "nginx", "/usr/sbin/nginx", "nginx")] + shell_from(100)
        alerts, graph, _, _ = run_events(events)
        self.assertEqual(len(graph.nodes["100:10"].execs), 2)
        self.assertEqual(len(alerts), 1)

    def test_shell_that_exec_in_place_alerts_once(self):
        events = service() + [success(200, 20, 21, 100, "env", "/usr/bin/env", "env"),
                              success(200, 20, 22, 100, "sh", "/bin/sh", "sh -c x")]
        alerts, _, _, _ = run_events(events)
        self.assertEqual(len(alerts), 1)

    def test_a_service_that_execs_a_shell_in_place_is_not_its_own_parent(self):
        events = service() + [success(100, 10, 12, 1, "sh", "/bin/sh", "sh")]
        alerts, _, _, _ = run_events(events)
        self.assertEqual(alerts, [])


#shells the rule cannot judge
class Unevaluable(unittest.TestCase):

    def test_placeholder_parent(self):
        alerts, graph, ctx, _ = run_events(shell_from(999))
        self.assertEqual(alerts, [])
        self.assertEqual(ctx["counts"]["unevaluable"], 1)
        self.assertEqual(ctx["counts"]["unevaluable_placeholder_parent"], 1)
        self.assertTrue(graph.nodes["999:unknown"].placeholder)

    def test_shell_with_no_known_parent(self):
        alerts, _, ctx, _ = run_events(shell_from(1, pid=300, start=30) + shell_from(0, pid=301, start=31))
        self.assertEqual(alerts, [])
        self.assertEqual(ctx["counts"]["unevaluable_no_parent"], 2)

    def test_parent_without_a_comm(self):
        parent = service()
        parent[0]["comm"] = None
        graph_events = parent + shell_from(100)
        alerts, _, ctx, _ = run_events(graph_events)
        self.assertEqual(alerts, [])
        self.assertEqual(ctx["counts"]["unevaluable_parent_no_comm"], 1)

    def test_shell_event_without_identity(self):
        bad = success(200, 20, 22, 100, "sh", "/bin/sh", "sh")
        del bad["start_time_ns"]
        alerts, _, ctx, _ = run_events(service() + [bad])
        self.assertEqual(alerts, [])
        self.assertEqual(ctx["counts"]["unevaluable_shell_not_in_graph"], 1)

    def test_odd_events_and_a_failing_detection_do_not_stop_the_run(self):
        def broken(graph, event, ctx):
            raise RuntimeError("boom")
        text = [b"{not json\n", b"[1]\n", b'{"schema_version":1}\n', b'{"schema_version":1,"type":5}\n',
                json.dumps(service()[0]).encode() + b"\n"]
        out = io.StringIO()
        graph, ctx, stats = runner.run(text, runner.alert.AlertSink(out, None), detections=[broken])
        self.assertEqual(stats["events"], 3)
        self.assertEqual(stats["detection_errors"], 3)

    def test_odd_exec_events_do_not_crash_or_alert(self):
        odd = [{"schema_version": 1, "type": "exec_success", "exe": 7},
               {"schema_version": 1, "type": "exec_success", "exe": "/bin/sh", "pid": "x"},
               {"schema_version": 1, "type": "exec_success", "filename": "/bin/sh", "pid": 5, "start_time_ns": 6}]
        alerts, _, ctx, stats = run_events(service() + odd + shell_from(100))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(stats["detection_errors"], 0)
        self.assertEqual(ctx["counts"]["unevaluable"], 2)


#determinism and inputs are only read
class Purity(unittest.TestCase):

    def events(self):
        return service() + shell_from(100, marker="EVT") + shell_from(999, pid=300, start=30)

    def test_inputs_are_not_changed(self):
        events = self.events()
        before = copy.deepcopy(events)
        alerts, graph, _, _ = run_events(events)
        self.assertEqual(events, before)
        graph_before = json.dumps(graph.to_dict(), sort_keys=True)
        runner.shell_from_service.detect(graph, events[-1], {"counts": {}, "attempts": {}})
        runner.shell_from_service.detect(graph, events[2], {"counts": {}, "attempts": {}})
        self.assertEqual(json.dumps(graph.to_dict(), sort_keys=True), graph_before)
        self.assertEqual(events, before)

    def test_same_input_gives_same_output(self):
        first = run_events(self.events())[0]
        second = run_events(self.events())[0]
        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)


#the runner command line by file and stdin
class CommandLine(unittest.TestCase):

    def setUp(self):
        events = service() + shell_from(100, marker="EVT") + shell_from(999, pid=300, start=30)
        self.data = "".join(json.dumps(e) + "\n" for e in events)
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "in.jsonl")
        with open(self.path, "w") as f:
            f.write(self.data)

    def tearDown(self):
        self.dir.cleanup()

    def run_cli(self, *args, stdin=None):
        return subprocess.run([sys.executable, os.path.join(DET_DIR, "runner.py")] + list(args),
                              input=stdin, capture_output=True, text=True)

    def test_from_file(self):
        done = self.run_cli(self.path)
        self.assertEqual(done.returncode, 0)
        lines = done.stdout.splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["detection"], "shell_from_service")
        self.assertIn("ALERT 1  shell_from_service  [technique unassigned]", done.stderr)
        self.assertIn("events processed: 5", done.stderr)
        self.assertIn("alerts emitted: 1, shell_from_service 1", done.stderr)
        self.assertIn("unevaluable: 1, placeholder_parent 1", done.stderr)
        self.assertIn("lost events: 0", done.stderr)

    def test_from_stdin_with_outputs_disabled_or_redirected(self):
        done = self.run_cli(stdin=self.data)
        self.assertEqual(len(done.stdout.splitlines()), 1)
        quiet = self.run_cli("--no-json", "--no-cli", stdin=self.data)
        self.assertEqual((quiet.stdout, quiet.returncode), ("", 0))
        self.assertNotIn("ALERT", quiet.stderr)
        self.assertIn("alerts emitted: 1", quiet.stderr)
        saved = os.path.join(self.dir.name, "alerts.jsonl")
        self.run_cli("-o", saved, "--no-cli", stdin=self.data)
        with open(saved) as f:
            self.assertEqual(len(f.read().splitlines()), 1)

    def test_missing_input_file(self):
        done = self.run_cli(os.path.join(self.dir.name, "nope"))
        self.assertEqual(done.returncode, 2)


if __name__ == "__main__":
    unittest.main()
