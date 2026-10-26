import json
import os
import subprocess
import sys
import tempfile
import unittest

import normalize

NORMALIZER_PATH = os.path.join(os.path.dirname(os.path.abspath(normalize.__file__)), "normalize.py")


def raw(typ, pid=100, start=5000, ts=1000, **extra):
    ev = {"schema_version": 1, "type": typ, "ts_ns": ts, "pid": pid, "tid": pid,
          "comm": "bash", "ppid": 1, "uid": 1000, "gid": 1000,
          "start_time_ns": start, "lossy_encoding": False}
    ev.update(extra)
    return ev


def attempt(filename, argv, **kw):
    return raw("exec_attempt", filename=filename, filename_truncated=False, argv=argv,
               argv_truncated=False, user_read_failed=False, **kw)


def success(filename, **kw):
    return raw("exec_success", filename=filename, filename_truncated=False,
               old_pid=kw.get("pid", 100), user_read_failed=False, **kw)


def exit_ev(code=0, **kw):
    return raw("exit", exit_code=code, exit_status=(code >> 8) & 0xFF,
               exit_signal=code & 0x7F, **kw)


def normalize_all(events):
    """feed list of events through a fresh Normalizer and return"""
    n = normalize.Normalizer()
    out = []
    for ev in events:
        line = ev if isinstance(ev, str) else json.dumps(ev)
        out.extend(n.feed_line(line))
    n.finish()
    return out, n


def types(events):
    return [e["type"] for e in events]


class NormalChain(unittest.TestCase):
    #constructed fixture and not the captured output: attempt, success, exit
    def test_normal_chain(self):
        out, n = normalize_all([
            attempt("/usr/bin/ls", ["ls", "-l"], ts=10),
            success("/usr/bin/ls", ts=11),
            exit_ev(0, ts=12),
        ])
        self.assertEqual(types(out), ["exec_attempt", "exec_success", "exit"])
        self.assertTrue(all(e["process_key"] == "100:5000" for e in out))
        self.assertEqual(out[0]["exe"], "/usr/bin/ls")
        self.assertEqual(out[0]["cmdline"], "ls -l")
        self.assertEqual(out[1]["argv"], ["ls", "-l"])
        self.assertEqual(out[1]["cmdline"], "ls -l")
        self.assertTrue(out[1]["attempt_joined"])
        self.assertEqual(out[2]["exit_status"], 0)
        self.assertEqual(n.exec_failed, 0)
        self.assertEqual(sum(n.anomalies.values()), 0)
        self.assertEqual(n.pending_at_end, 0)


class FailedExec(unittest.TestCase):
    #constructed fixture and not the captured output: a nonexistent path is tried and nothing succeeds; the shell then gives up with status 127
    def test_failed_exec_then_exit(self):
        out, n = normalize_all([
            attempt("/nonexistent/prog", ["prog", "x"], ts=10),
            exit_ev(127 << 8, ts=20),
        ])
        self.assertEqual(types(out), ["exec_attempt", "exec_failed", "exit"])
        failed = out[1]
        self.assertEqual(failed["reason"], "exit")
        self.assertEqual(failed["filename"], "/nonexistent/prog")
        self.assertEqual(failed["argv"], ["prog", "x"])
        self.assertEqual(failed["ts_ns"], 10)
        self.assertEqual(failed["process_key"], "100:5000")
        self.assertFalse(failed["gap_uncertain"])
        self.assertEqual(out[2]["exit_status"], 127)
        self.assertEqual(n.exec_failed, 1)
        self.assertEqual(sum(n.anomalies.values()), 0)

    #constructed fixture... not captured output: several attempts in one process as a shell searches PATH, then the one that works
    def test_path_search_sequence(self):
        out, n = normalize_all([
            attempt("/usr/local/bin/foo", ["foo"], ts=10),
            attempt("/usr/bin/foo", ["foo"], ts=11),
            attempt("/bin/foo", ["foo"], ts=12),
            success("/bin/foo", ts=13),
            exit_ev(0, ts=14),
        ])
        self.assertEqual(types(out), [
            "exec_attempt", "exec_failed", "exec_attempt", "exec_failed",
            "exec_attempt", "exec_success", "exit"])
        self.assertEqual(out[1]["filename"], "/usr/local/bin/foo")
        self.assertEqual(out[3]["filename"], "/usr/bin/foo")
        self.assertEqual(out[1]["reason"], "next_attempt")
        self.assertEqual(out[3]["reason"], "next_attempt")
        self.assertEqual(out[5]["exe"], "/bin/foo")
        self.assertTrue(out[5]["attempt_joined"])
        self.assertEqual(n.exec_failed, 2)

    #constructed fixture
    #not captured output: a process that execs twice successfully doesnt produce a failure
    def test_two_successful_execs(self):
        out, n = normalize_all([
            attempt("/bin/sh", ["sh"], ts=10), success("/bin/sh", ts=11),
            attempt("/bin/ls", ["ls"], ts=12), success("/bin/ls", ts=13),
            exit_ev(0, ts=14),
        ])
        self.assertEqual(n.exec_failed, 0)
        self.assertEqual(out[3]["argv"], ["ls"])


class Anomalies(unittest.TestCase):
    #constructed fixture
    #not captured output: the loader started after the process so its exit is the first event seen for it
    def test_exit_with_no_prior_exec(self):
        out, n = normalize_all([exit_ev(0, pid=900, start=1)])
        self.assertEqual(types(out), ["exit"])
        self.assertEqual(out[0]["process_key"], "900:1")
        self.assertEqual(n.anomalies["exit_without_exec"], 1)

    #constructed fixture
    #not captured output: the attempt record was missed
    def test_exec_success_without_attempt(self):
        out, n = normalize_all([success("/bin/ls")])
        self.assertEqual(types(out), ["exec_success"])
        self.assertEqual(out[0]["argv"], [])
        self.assertFalse(out[0]["attempt_joined"])
        self.assertEqual(n.anomalies["exec_success_without_attempt"], 1)

    #constructed fixture
    #not captured output: three kinds of unusable line around one good event
    def test_bad_json_lines(self):
        good = attempt("/bin/ls", ["ls"])
        out, n = normalize_all(["{this is not json", good, "[1, 2]", "NaN", ""])
        self.assertEqual(types(out), ["exec_attempt"])
        self.assertEqual(n.anomalies["bad_json_lines"], 3)
        self.assertEqual(n.blank_lines, 1)

    #constructed fixture
    #not captured output: a line that is not UTF-8
    def test_invalid_utf8_line(self):
        n = normalize.Normalizer()
        line = json.dumps(attempt("/bin/ls", ["ls"])).encode("utf-8").replace(b"/bin/ls", b"/bin/l\xff", 1)
        out = n.feed_line(line)
        self.assertEqual(len(out), 1)
        self.assertEqual(n.anomalies["invalid_utf8_lines"], 1)

    #constructed fixture
    #not captured output: a type this version of the schema does not define; it is kept with the process key added
    def test_unknown_event_type(self):
        ev = raw("module_load", name="x", pid=300, start=7)
        out, n = normalize_all([ev])
        self.assertEqual(types(out), ["module_load"])
        self.assertEqual(out[0]["process_key"], "300:7")
        self.assertEqual(out[0]["name"], "x")
        self.assertEqual(n.anomalies["unknown_event_type"], 1)
        self.assertEqual(n.unknown_names, ["module_load"])

    #constructed fixture
    #not captured output: version 2 and a missing version are both refused
    def test_unsupported_schema_version(self):
        v2 = attempt("/bin/ls", ["ls"])
        v2["schema_version"] = 2
        none = attempt("/bin/ls", ["ls"])
        del none["schema_version"]
        boolean = attempt("/bin/ls", ["ls"])
        boolean["schema_version"] = True
        out, n = normalize_all([v2, none, boolean, attempt("/bin/ls", ["ls"])])
        self.assertEqual(len(out), 1)
        self.assertEqual(n.anomalies["unsupported_schema_version"], 3)

    #constructed fixture
    #not captured output: events that break the schema are counted and cant raise
    def test_missing_and_wrong_fields_do_not_crash(self):
        no_identity = {"schema_version": 1, "type": "exec_attempt", "filename": "/bin/ls", "argv": ["ls"]}
        bad_argv = attempt("/bin/ls", "ls", pid=200, start=1)
        mixed_argv = attempt("/bin/ls", ["ls", 5, None], pid=201, start=1)
        no_filename = {"schema_version": 1, "type": "exec_success", "pid": 202, "start_time_ns": 1}
        no_code = {"schema_version": 1, "type": "exit", "pid": 203, "start_time_ns": 1}
        bare = {"schema_version": 1, "type": "file_open"}
        float_pid = raw("net_connect", pid=1.5)
        out, n = normalize_all([no_identity, bad_argv, mixed_argv, no_filename, no_code, bare, float_pid])
        self.assertEqual(len(out), 7)
        self.assertEqual(out[0]["process_key"], None)
        self.assertEqual(out[1]["argv"], [])
        self.assertEqual(out[2]["argv"], ["ls", "5", "None"])
        self.assertEqual(n.anomalies["missing_identity"], 3)
        self.assertGreaterEqual(n.anomalies["malformed_field"], 4)

    #constructed fixture
    #not captured output: second exit for one process key; as all-thread mode produces it is counted
    def test_repeat_exit(self):
        out, n = normalize_all([
            attempt("/bin/ls", ["ls"], ts=1), success("/bin/ls", ts=2),
            exit_ev(0, ts=3), exit_ev(0, ts=4),
        ])
        self.assertEqual(n.repeat_exits, 1)
        self.assertEqual(n.anomalies["exit_without_exec"], 0)


class EndOfInput(unittest.TestCase):
    #constructed fixture
    #not captured output: input stops with an attempt that has neither success nor a later event
    def test_pending_attempt_at_end_is_not_failed(self):
        out, n = normalize_all([attempt("/bin/ls", ["ls"])])
        self.assertEqual(types(out), ["exec_attempt"])
        self.assertEqual(n.exec_failed, 0)
        self.assertEqual(n.pending_at_end, 1)
        self.assertIn("exec attempts still pending at end of input: 1", n.summary_lines())


class ProcessKey(unittest.TestCase):
    #constructed fixture
    #not captured output: the same pid with two start times is two processes so the second attempt does not fail the first
    def test_pid_reuse_keeps_processes_apart(self):
        out, n = normalize_all([
            attempt("/bin/a", ["a"], pid=100, start=5, ts=1),
            attempt("/bin/b", ["b"], pid=100, start=9, ts=2),
        ])
        self.assertEqual(types(out), ["exec_attempt", "exec_attempt"])
        self.assertEqual(out[0]["process_key"], "100:5")
        self.assertEqual(out[1]["process_key"], "100:9")
        self.assertEqual(n.pending_at_end, 2)

    #constructed fixture
    #not captured output: the table is limited to two processes so the third new process pushes out the oldest
    def test_tracking_table_is_bounded(self):
        n = normalize.Normalizer(max_tracked=2)
        for pid in (1, 2, 3):
            n.feed_line(json.dumps(attempt("/bin/x", ["x"], pid=pid, start=pid)))
        n.finish()
        self.assertEqual(n.anomalies["state_evicted"], 1)
        self.assertEqual(n.pending_at_end, 2)


class PassThrough(unittest.TestCase):
    #constructed fixture
    #not captured output: the three later event types
    def test_file_net_priv_pass_through(self):
        events = [
            raw("file_open", path="/etc/shadow", path_truncated=False, flags=0, ret=3),
            raw("net_connect", family=2, remote_addr="127.0.0.1", remote_port=80),
            raw("priv_change", syscall="setuid", ids=[0]),
        ]
        out, n = normalize_all(events)
        self.assertEqual(types(out), ["file_open", "net_connect", "priv_change"])
        for src, dst in zip(events, out):
            self.assertEqual(dst["process_key"], "100:5000")
            for k, v in src.items():
                self.assertEqual(dst[k], v)
        self.assertEqual(n.type_counts["file_open"], 1)

    #constructed fixture
    #not captured output: lost events carry the loader's own pid and no start time so the key is null
    def test_lost_events_are_counted(self):
        lost1 = {"schema_version": 1, "type": "lost", "ts_ns": 5, "pid": 50, "tid": 50,
                 "comm": "exec_exit_loade", "dropped": 3, "lossy_encoding": False}
        lost2 = dict(lost1, dropped=4)
        out, n = normalize_all([lost1, lost2])
        self.assertEqual(types(out), ["lost", "lost"])
        self.assertIsNone(out[0]["process_key"])
        self.assertEqual(n.lost_events, 2)
        self.assertEqual(n.lost_dropped, 7)
        self.assertIn("lost events: 2, records dropped: 7", n.summary_lines())

    #constructed fixture
    #not captured output: lost event between attempt and exit makes failure decision uncertain
    def test_failure_after_lost_event_is_marked_uncertain(self):
        lost = {"schema_version": 1, "type": "lost", "ts_ns": 5, "pid": 50, "tid": 50,
                "comm": "loader", "dropped": 1}
        out, n = normalize_all([attempt("/bin/ls", ["ls"], ts=1), lost, exit_ev(0, ts=9)])
        failed = [e for e in out if e["type"] == "exec_failed"]
        self.assertEqual(len(failed), 1)
        self.assertTrue(failed[0]["gap_uncertain"])

    #constructed fixture
    #not captured output: exit that has no decoded fields gets them from exit_code (exit 7 is 0x700, signal 9 is 9)
    def test_exit_status_is_decoded_when_missing(self):
        a = raw("exit", exit_code=7 << 8)
        b = raw("exit", exit_code=9, pid=101)
        out, n = normalize_all([a, b])
        self.assertEqual((out[0]["exit_status"], out[0]["exit_signal"]), (7, 0))
        self.assertEqual((out[1]["exit_status"], out[1]["exit_signal"]), (0, 9))

    #constructed fixture
    #not captured output: every input field survives on normalized event and the input dict is not modified
    def test_input_information_is_kept(self):
        src = attempt("/bin/ls", ["ls", "a b"], unexpected_field={"x": [1, 2]})
        before = json.dumps(src, sort_keys=True)
        out, n = normalize_all([src])
        for k, v in src.items():
            self.assertEqual(out[0][k], v)
        self.assertEqual(json.dumps(src, sort_keys=True), before)
        self.assertEqual(out[0]["cmdline"], "ls a b")


class CommandLine(unittest.TestCase):
    #constructed fixture
    #not captured output: run the program as a user would: from a file to a file and from standard input to standard output
    def setUp(self):
        self.lines = [json.dumps(e) for e in (
            attempt("/nonexistent/prog", ["prog"], ts=1),
            exit_ev(127 << 8, ts=2),
        )]

    def test_file_to_file(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "in.jsonl")
            dst = os.path.join(d, "out.jsonl")
            with open(src, "w") as f:
                f.write("\n".join(self.lines) + "\n")
            r = subprocess.run([sys.executable, "-I", NORMALIZER_PATH, src, "-o", dst],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(dst) as f:
                out = [json.loads(x) for x in f]
        self.assertEqual(types(out), ["exec_attempt", "exec_failed", "exit"])
        self.assertIn("derived exec_failed: 1", r.stderr)

    def test_stdin_to_stdout(self):
        r = subprocess.run([sys.executable, "-I", NORMALIZER_PATH],
                           input="\n".join(self.lines) + "\n", capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = [json.loads(x) for x in r.stdout.splitlines()]
        self.assertEqual(types(out), ["exec_attempt", "exec_failed", "exit"])

    def test_missing_input_file(self):
        r = subprocess.run([sys.executable, "-I", NORMALIZER_PATH, "/nonexistent/in.jsonl"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
