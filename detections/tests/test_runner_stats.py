"""
tests for the per-detection counters of runner.py
every event here is a !!constructed fixture, not captured output!!
"""
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


def event(pid, typ, ppid=1, comm="bash", **fields):
    e = {"schema_version": 1, "type": typ, "ts_ns": pid, "pid": pid, "tid": pid, "comm": comm, "ppid": ppid,
         "uid": 0, "gid": 0, "start_time_ns": pid * 10, "process_key": "%d:%d" % (pid, pid * 10)}
    e.update(fields)
    return e


def started(pid, exe, ppid=1, **fields):
    argv = [os.path.basename(exe)]
    return event(pid, "exec_success", ppid=ppid, exe=exe, filename=exe, argv=argv, cmdline=" ".join(argv), **fields)


def stream():
    nameless = started(900, "/usr/bin/python3")
    del nameless["start_time_ns"]
    del nameless["process_key"]
    return [started(100, "/tmp/payload"), started(101, "./relative"), nameless,
            event(110, "file_open", comm="cat", path="etc/shadow", ret=3),
            event(111, "file_open", comm="cat", path="/etc/shadow", ret=3),
            event(120, "file_open", comm="cat", path="/etc/shadow", ret=-2),
            started(130, "/bin/sh", ppid=999)]


def lines_of(events):
    return [(json.dumps(e) + "\n").encode() for e in events]


def run_all(events):
    out = io.StringIO()
    graph, ctx, stats = runner.run(lines_of(events), runner.alert.AlertSink(out, None))
    return graph, ctx, stats


def fake(name, body):
    body.__module__ = name
    return body


class Attribution(unittest.TestCase):

    def test_attributions_add_up_to_the_merged_totals(self):
        _, ctx, stats = run_all(stream())
        credited = {}
        for d in stats["by_detection"].values():
            for name, value in d["counters"].items():
                credited[name] = credited.get(name, 0) + value
        self.assertEqual(credited, ctx["counts"])
        self.assertEqual(runner.unattributed(ctx, stats), {})
        self.assertGreater(len(credited), 3)

    def test_a_shared_counter_goes_to_the_detection_that_counted_it(self):
        _, ctx, stats = run_all([stream()[2]])
        by = stats["by_detection"]
        self.assertEqual(ctx["counts"]["unevaluable_not_in_graph"], 2)
        self.assertEqual(by["unusual_ancestry"]["counters"]["unevaluable_not_in_graph"], 1)
        self.assertEqual(by["rapid_spawn"]["counters"]["unevaluable_not_in_graph"], 1)
        self.assertNotIn("unevaluable_not_in_graph", by["shell_from_service"]["counters"])

    def test_relative_path_is_split_between_two_detections(self):
        _, ctx, stats = run_all([stream()[1], stream()[3]])
        by = stats["by_detection"]
        self.assertEqual(ctx["counts"]["unevaluable_relative_path"], 2)
        self.assertEqual(by["exec_from_tmp"]["counters"]["unevaluable_relative_path"], 1)
        self.assertEqual(by["sensitive_file_access"]["counters"]["unevaluable_relative_path"], 1)

    def test_alerts_are_credited_to_the_detection_that_raised_them(self):
        _, _, stats = run_all(stream())
        self.assertEqual(stats["by_detection"]["exec_from_tmp"]["alerts"], 1)
        self.assertEqual(stats["by_detection"]["sensitive_file_access"]["alerts"], 1)
        self.assertEqual(sum(d["alerts"] for d in stats["by_detection"].values()), sum(stats["alerts"].values()))

    def test_every_registered_detection_has_an_entry_in_registration_order(self):
        _, _, stats = run_all([])
        self.assertEqual(list(stats["by_detection"]), [d.__module__ for d in runner.DETECTIONS])

    def test_a_detection_that_raises_is_charged_and_the_run_continues(self):
        def good(graph, ev, ctx):
            ctx["counts"]["good_seen"] = ctx["counts"].get("good_seen", 0) + 1

        def bad(graph, ev, ctx):
            ctx["counts"]["bad_seen"] = ctx["counts"].get("bad_seen", 0) + 1
            raise ValueError("odd event")

        events = [started(100, "/bin/sh"), started(101, "/bin/sh")]
        out = io.StringIO()
        _, ctx, stats = runner.run(lines_of(events), runner.alert.AlertSink(out, None),
                                   detections=[fake("fake_bad", bad), fake("fake_good", good)])
        self.assertEqual(stats["detection_errors"], 2)
        self.assertEqual(stats["by_detection"]["fake_bad"], {"alerts": 0, "errors": 2, "counters": {"bad_seen": 2}})
        self.assertEqual(stats["by_detection"]["fake_good"], {"alerts": 0, "errors": 0, "counters": {"good_seen": 2}})
        self.assertEqual(runner.unattributed(ctx, stats), {})

    def test_a_change_made_outside_a_detect_call_is_reported_as_unattributed(self):
        _, ctx, stats = run_all([stream()[1]])
        ctx["counts"]["made_outside"] = 3
        self.assertEqual(runner.unattributed(ctx, stats), {"made_outside": 3})
        self.assertIn("counters not attributed to a detection: 3", runner.detection_lines(ctx, stats)[-1])


class Output(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "in.jsonl")
        with open(self.path, "wb") as f:
            f.writelines(lines_of(stream()))

    def tearDown(self):
        self.dir.cleanup()

    def cli(self, *extra):
        return subprocess.run([sys.executable, "-B", os.path.join(DET_DIR, "runner.py"), self.path, "--no-json"] + list(extra),
                              capture_output=True, text=True)

    def test_the_existing_summary_lines_come_first_and_are_unchanged(self):
        graph, ctx, stats = run_all(stream())
        done = self.cli("--no-cli")
        lines = done.stderr.splitlines()
        self.assertEqual(lines[:7], runner.summary_lines(graph, ctx, stats))
        self.assertEqual([l.split(":")[0] for l in lines[:7]], ["runner summary", "events processed", "alerts emitted",
                                                              "unevaluable", "detection errors", "graph", "lost events"])
        self.assertTrue(lines[7].startswith("per detection, in registration order"))
        self.assertEqual(len(lines), 7 + 1 + len(runner.DETECTIONS) + 1)

    def test_the_detection_lines_name_each_detection_with_its_counters(self):
        done = self.cli("--no-cli")
        self.assertIn("  exec_from_tmp: alerts 1, errors 0, counters: unevaluable 1, unevaluable_relative_path 1", done.stderr)
        self.assertIn("  download_chmod_exec: alerts 0, errors 0\n", done.stderr)
        self.assertIn("  shell_from_service: alerts 0, errors 0, counters: unevaluable 1, unevaluable_placeholder_parent 1\n", done.stderr)

    def test_stats_json_parses_is_sorted_and_is_the_same_on_two_runs(self):
        first, second = os.path.join(self.dir.name, "a.json"), os.path.join(self.dir.name, "b.json")
        self.assertEqual(self.cli("--no-cli", "--stats-json", first).returncode, 0)
        self.assertEqual(self.cli("--no-cli", "--stats-json", second).returncode, 0)
        with open(first, "rb") as a, open(second, "rb") as b:
            raw = a.read()
            self.assertEqual(raw, b.read())
        doc = json.loads(raw)
        self.assertEqual(raw.decode("ascii"), json.dumps(doc, sort_keys=True, indent=1) + "\n")
        self.assertEqual([d["name"] for d in doc["detections"]], [d.__module__ for d in runner.DETECTIONS])
        self.assertEqual(doc["events_processed"], len(stream()))
        self.assertEqual(doc["unattributed_counters"], {})
        self.assertEqual(doc["counters"]["unevaluable_relative_path"], 2)

    def test_default_behavior_writes_no_stats_file(self):
        self.assertEqual(self.cli("--no-cli").returncode, 0)
        self.assertEqual(os.listdir(self.dir.name), ["in.jsonl"])


if __name__ == "__main__":
    unittest.main()
