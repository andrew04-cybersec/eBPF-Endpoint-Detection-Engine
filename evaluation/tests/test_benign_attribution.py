"""
tests for attribution by window, harness process test, zero false positive bound, --predictions, and --seed helpers of run_eval.py and benign_rate.py
every scenario, alert, window and results folder here is a !!constructed fixture, not captured output!!
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL_DIR = os.path.dirname(HERE)
sys.path.insert(0, EVAL_DIR)
sys.path.insert(0, HERE)

import benign_rate  #noqa: E402
import evaluate  #noqa: E402
import run_eval  #noqa: E402
import scenario_lib  #noqa: E402
from test_scorer import Folder, alert, scenario, window  #noqa: E402

SEC = 1000000000
START = 10 * SEC
HOUR = 3600 * SEC
SHELL = "shell_from_service"
HARNESS = [{"role": "runner", "pid": 77, "start_ns_min": 100 * SEC, "start_ns_max": 101 * SEC},
           {"role": "driver", "pid": 88, "start_ns_min": None, "start_ns_max": None},
           {"role": "bpftool", "pid": None, "ran_from_ns": 1, "ran_to_ns": 2}]


def w_scenario(sid="W1"):
    return dict(scenario(sid, kind="benign"), attribution="window", group=None)


def process_alert(ts, pid=5, key=None, ancestry_pids=()):
    a = alert(SHELL, ts, "nothing to match")
    a["process"].update(pid=pid, process_key=key)
    a["ancestry"] = [{"pid": p, "cmdline": None} for p in ancestry_pids]
    return a


def window_folder(test, alerts, hours=1.0, harness=HARNESS, events=None, scenarios=None, windows=None):
    scs = scenarios or [w_scenario()]
    wins = windows or {"W1": window(START, START + int(hours * HOUR))}
    doc = {"scenarios": wins, "clock_check": {"passed": True, "max_skew_ns": 0}}
    if harness is not None:
        doc["harness_processes"] = harness
    extra = {"scenario_windows.json": json.dumps(doc)}
    if events is not None:
        extra["events.jsonl"] = "".join(json.dumps(e) + "\n" for e in events)
    f = Folder(scs, wins, alerts, extra=extra)
    test.addCleanup(f.cleanup)
    return f


class ThreeWayRule(unittest.TestCase):

    def test_inside_the_window_counts_and_needs_no_marker(self):
        scores, _ = window_folder(self, [process_alert(START + 5 * SEC)]).score()
        w = scores["window_attribution"]["scenarios"]["W1"]
        self.assertEqual((w["fp"], w["alerts_by_detection"]), (1, {SHELL: 1}))
        self.assertEqual(scores["scenarios"]["W1"]["outcome"], "false alerts")
        self.assertEqual(scores["unattributed_in_window"], [])

    def test_a_harness_process_inside_the_window_is_listed_and_not_counted(self):
        key = "77:%d" % (100 * SEC + 5)
        scores, report = window_folder(self, [process_alert(START + SEC, pid=77, key=key)]).score()
        section = scores["window_attribution"]
        self.assertEqual(section["scenarios"]["W1"]["fp"], 0)
        self.assertEqual([a["window"] for a in section["harness_alerts"]], ["W1"])
        self.assertIn("Harness alerts inside a window (not counted): 1.", report)

    def test_outside_every_window_and_without_a_timestamp_is_machine_noise(self):
        early = process_alert(START - 5 * SEC)
        late = process_alert(START + 2 * HOUR)
        none = process_alert(None)
        scores, report = window_folder(self, [early, late, none]).score()
        section = scores["window_attribution"]
        self.assertEqual(len(section["machine_noise"]), 3)
        self.assertEqual(section["scenarios"]["W1"]["fp"], 0)
        self.assertIn("Machine noise, outside every window (not counted): 3.", report)

    def test_the_window_edges_are_inside(self):
        edges = [process_alert(START), process_alert(START + HOUR)]
        scores, _ = window_folder(self, edges).score()
        self.assertEqual(scores["window_attribution"]["scenarios"]["W1"]["fp"], 2)


class HarnessTest(unittest.TestCase):

    def test_only_the_triggering_process_is_tested_and_never_its_ancestry(self):
        ancestry_only = process_alert(START + SEC, pid=5, key="5:%d" % START, ancestry_pids=(77, 88))
        scores, _ = window_folder(self, [ancestry_only]).score()
        self.assertEqual(scores["window_attribution"]["scenarios"]["W1"]["fp"], 1)
        self.assertEqual(scores["window_attribution"]["harness_alerts"], [])

    def test_the_pid_alone_is_not_enough_when_a_start_bracket_was_recorded(self):
        reused = process_alert(START + SEC, pid=77, key="77:%d" % (500 * SEC))
        placeholder = process_alert(START + SEC, pid=77, key="77:unknown")
        scores, _ = window_folder(self, [reused, placeholder]).score()
        self.assertEqual(scores["window_attribution"]["scenarios"]["W1"]["fp"], 2)

    def test_the_driver_has_no_bracket_and_is_matched_by_pid(self):
        self.assertTrue(evaluate.is_harness(process_alert(1, pid=88), HARNESS))
        self.assertFalse(evaluate.is_harness(process_alert(1, pid=89), HARNESS))

    def test_a_helper_without_a_pid_never_matches(self):
        self.assertFalse(evaluate.is_harness(process_alert(1, pid=None), HARNESS))

    def test_a_folder_without_the_list_warns_and_counts_everything(self):
        scores, _ = window_folder(self, [process_alert(START + SEC, pid=77, key="77:%d" % (100 * SEC))], harness=None).score()
        self.assertEqual(scores["window_attribution"]["scenarios"]["W1"]["fp"], 1)
        self.assertTrue(any("no harness process list" in w for w in scores["warnings"]))

    def test_key_start(self):
        self.assertEqual(evaluate.key_start("26520:112872582253696"), 112872582253696)
        self.assertIsNone(evaluate.key_start("26520:unknown"))
        self.assertIsNone(evaluate.key_start(None))


class ZeroBound(unittest.TestCase):

    def test_zero_false_positives_give_three_over_the_hours(self):
        scores, report = window_folder(self, [], hours=2.0).score()
        w = scores["window_attribution"]["scenarios"]["W1"]
        self.assertEqual((w["window_hours"], w["fp"], w["fp_per_hour"], w["rule_of_three_per_hour"]), (2.0, 0, 0.0, 1.5))
        self.assertIn("rule of three", report)
        self.assertIn("approximate, scripted workload, one machine, WSL2", report)

    def test_no_bound_when_there_is_a_false_positive(self):
        scores, report = window_folder(self, [process_alert(START + SEC)]).score()
        w = scores["window_attribution"]["scenarios"]["W1"]
        self.assertEqual((w["fp"], w["fp_per_hour"], w["rule_of_three_per_hour"]), (1, 1.0, None))
        self.assertNotIn("rule of three", report)

    def test_events_per_hour_by_type_count_only_the_window(self):
        events = [{"type": "exec_success", "ts_ns": START + SEC}, {"type": "exec_success", "ts_ns": START + 2 * SEC},
                  {"type": "file_open", "ts_ns": START + 3 * SEC}, {"type": "exec_success", "ts_ns": START - SEC}]
        scores, _ = window_folder(self, [], hours=2.0, events=events).score()
        w = scores["window_attribution"]["scenarios"]["W1"]
        self.assertEqual(w["events_by_type"], {"exec_success": 2, "file_open": 1})
        self.assertEqual(w["events_per_hour_by_type"], {"exec_success": 1.0, "file_open": 0.5})

    def test_rescoring_is_byte_identical(self):
        f = window_folder(self, [process_alert(START + SEC)])
        f.score()
        first = [open(os.path.join(f.results, n), "rb").read() for n in ("scores.json", "report.md")]
        f.score()
        second = [open(os.path.join(f.results, n), "rb").read() for n in ("scores.json", "report.md")]
        self.assertEqual(first, second)


class DefaultMarkerPath(unittest.TestCase):

    def folder(self, with_list=True):
        sc = scenario("B1", kind="benign")
        wins = {"B1": window(START, START + SEC)}
        doc = {"scenarios": wins, "clock_check": {"passed": True, "max_skew_ns": 0}}
        if with_list:
            doc["harness_processes"] = HARNESS
        hit = alert(SHELL, START + 5, "EVT_EVAL_B1")
        miss = alert(SHELL, START + 6, "no marker here")
        hit["process"].update(pid=77, process_key="77:%d" % (100 * SEC))
        f = Folder([sc], wins, [hit, miss], extra={"scenario_windows.json": json.dumps(doc)})
        self.addCleanup(f.cleanup)
        return f

    def test_without_the_key_the_marker_still_decides(self):
        scores, report = self.folder().score()
        self.assertEqual(scores["scenarios"]["B1"]["alerts_attributed"], 1)
        self.assertEqual(len(scores["unattributed_in_window"]), 1)
        self.assertNotIn("window_attribution", scores)
        self.assertNotIn("attributed by window", report)

    def test_a_harness_pid_does_not_change_a_marker_scenario(self):
        with_list = self.folder(True).score()[0]
        without = self.folder(False).score()[0]
        self.assertEqual(with_list["scenarios"], without["scenarios"])

    def test_the_attribution_key_marker_is_the_same_as_no_key(self):
        sc = dict(scenario("B1", kind="benign"), attribution="marker", group=None)
        wins = {"B1": window(START, START + SEC)}
        f = Folder([sc], wins, [alert(SHELL, START + 5, "EVT_EVAL_B1"), alert(SHELL, START + 6, "no marker here")])
        self.addCleanup(f.cleanup)
        scores, _ = f.score()
        self.assertEqual(scores["scenarios"]["B1"]["alerts_attributed"], 1)
        self.assertNotIn("window_attribution", scores)


class Validation(unittest.TestCase):

    def make(self, over):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        base = {"id": "T1", "title": "t", "kind": "benign", "technique": None, "threat_model": "x", "phase": "after_loader",
                "marker": "EVT_EVAL_T1", "expected": [], "acceptable": [], "timeout_seconds": 30, "known_gap": None, "notes": "x", "group": None}
        base.update(over)
        os.makedirs(os.path.join(root, "T1"))
        with open(os.path.join(root, "T1", "scenario.json"), "w") as f:
            json.dump(base, f)
        with open(os.path.join(root, "T1", "action.sh"), "w") as f:
            f.write("true\n")
        return scenario_lib.load_scenarios(root)[1]

    def test_a_benign_scenario_may_use_window(self):
        self.assertEqual(self.make({"attribution": "window"}), [])
        self.assertEqual(self.make({"attribution": "marker"}), [])
        self.assertEqual(self.make({}), [])

    def test_an_attack_scenario_may_not_use_window(self):
        attack = {"kind": "attack", "technique": "T1059.004", "group": "ordinary", "expected": [{"detection": SHELL, "min_count": 1}]}
        self.assertEqual(self.make(dict(attack, attribution="marker")), [])
        problems = self.make(dict(attack, attribution="window"))
        self.assertIn("T1: attribution window is only allowed for a benign scenario", problems)

    def test_an_unknown_value_is_refused(self):
        self.assertIn("T1: attribution must be one of marker, window", self.make({"attribution": "pid"}))


class RunEvalHelpers(unittest.TestCase):

    def test_the_default_predictions_for_the_standard_folder_are_the_standard_file(self):
        self.assertEqual(run_eval.resolve_predictions(None, os.path.join(EVAL_DIR, "scenarios")), os.path.join(EVAL_DIR, "predictions.json"))

    def test_the_default_is_the_file_next_to_the_scenarios_folder_or_none(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        os.makedirs(os.path.join(root, "set", "scenarios"))
        scen = os.path.join(root, "set", "scenarios")
        self.assertIsNone(run_eval.resolve_predictions(None, scen))
        beside = os.path.join(root, "set", "predictions.json")
        with open(beside, "w") as f:
            f.write("{}")
        self.assertEqual(run_eval.resolve_predictions(None, scen), beside)

    def test_none_and_an_explicit_path(self):
        self.assertIsNone(run_eval.resolve_predictions("none", os.path.join(EVAL_DIR, "scenarios")))
        self.assertEqual(run_eval.resolve_predictions("p.json", "/x/scenarios"), os.path.abspath("p.json"))

    def test_the_main_refuses_a_missing_predictions_file_and_a_negative_seed(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(run_eval.main(["--dry-run", "--predictions", "/nonexistent/p.json"]), 2)
            self.assertEqual(run_eval.main(["--dry-run", "--seed", "-1"]), 2)
        self.assertIn("does not exist", err.getvalue())

    def test_the_dry_run_names_the_predictions_and_the_seed(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(run_eval.main(["--dry-run", "--predictions", "none", "--seed", "3"]), 0)
        self.assertIn("predictions: none", out.getvalue())
        self.assertIn("seed: 3", out.getvalue())

    def test_the_seed_reaches_the_scripts_only_through_the_option(self):
        sc = {"id": "S01_x", "marker": "EVT_EVAL_S01"}
        self.assertEqual(run_eval.script_env(sc, seed=7)["EVT_EVAL_SEED"], "7")
        with mock.patch.dict(os.environ, {"EVT_EVAL_SEED": "99"}):
            self.assertNotIn("EVT_EVAL_SEED", run_eval.script_env(sc))
            self.assertEqual(run_eval.script_env(sc, seed=0)["EVT_EVAL_SEED"], "0")

    def test_run_script_records_the_pid_and_the_clock_readings_only_when_asked(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        record = []
        run_eval.run_script([sys.executable, "-c", "pass"], dict(os.environ), os.path.join(root, "log"), 30, record=record)
        self.assertEqual(len(record), 1)
        self.assertGreater(record[0]["pid"], 0)
        self.assertLessEqual(record[0]["before_ns"], record[0]["after_ns"])

    def test_the_harness_list_has_the_driver_the_stages_the_scripts_and_the_helpers(self):
        stages = {"loader": {"pid": 10, "before_ns": 1, "after_ns": 2}}
        scripts = [("setup S1", {"pid": 11, "before_ns": 3, "after_ns": 4})]
        rows = run_eval.harness_processes(stages, scripts, [("bpftool", 5, 6)], 99)
        self.assertEqual([(r["role"], r["pid"]) for r in rows], [("driver", 99), ("loader", 10), ("setup S1", 11), ("bpftool", None)])
        self.assertEqual((rows[1]["start_ns_min"], rows[1]["start_ns_max"]), (1, 2))
        self.assertEqual((rows[3]["ran_from_ns"], rows[3]["ran_to_ns"]), (5, 6))


class RecordedLocations(unittest.TestCase):

    def test_a_folder_with_no_record_is_scored_as_before(self):
        f = window_folder(self, [])
        self.assertEqual(evaluate.recorded_locations(f.results), (None, None))

    def test_the_recorded_directory_is_used_when_none_is_given(self):
        f = window_folder(self, [])
        with open(os.path.join(f.results, "label_hashes.json")) as fh:
            hashes = json.load(fh)
        hashes["scenarios_dir"] = f.live
        hashes["predictions_path"] = None
        with open(os.path.join(f.results, "label_hashes.json"), "w") as fh:
            json.dump(hashes, fh)
        self.assertEqual(evaluate.recorded_locations(f.results), (f.live, None))
        scores, _ = evaluate.score_folder(f.results)
        self.assertEqual(scores["warnings"], [])

    def test_a_recorded_directory_that_is_gone_falls_back_to_the_standard_one(self):
        f = window_folder(self, [])
        with open(os.path.join(f.results, "label_hashes.json")) as fh:
            hashes = json.load(fh)
        hashes["scenarios_dir"] = "/nonexistent/scenarios"
        with open(os.path.join(f.results, "label_hashes.json"), "w") as fh:
            json.dump(hashes, fh)
        self.assertEqual(evaluate.recorded_locations(f.results), (None, None))


class BenignRate(unittest.TestCase):

    def scores_file(self, root, name, hours, fp):
        path = os.path.join(root, name)
        with open(path, "w") as f:
            json.dump({"window_attribution": {"scenarios": {"E01": {"window_hours": hours, "fp": fp}}}}, f)
        return path

    def test_pooled_rate_and_the_bound_at_zero(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        paths = [self.scores_file(root, "a.json", 1.0, 0), self.scores_file(root, "b.json", 1.0, 0), self.scores_file(root, "c.json", 1.0, 0)]
        rows, problems = benign_rate.read_runs(paths)
        self.assertEqual(problems, [])
        total = benign_rate.pooled(rows)
        self.assertEqual((total["hours"], total["fp"], total["per_hour"], total["rule_of_three"]), (3.0, 0, 0.0, 1.0))
        text = "\n".join(benign_rate.report_lines(rows))
        self.assertIn("rule of three upper bound 1.000 per hour", text)
        self.assertIn("approximate; scripted workload, one machine, WSL2", text)

    def test_no_bound_when_there_are_false_positives(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        rows, _ = benign_rate.read_runs([self.scores_file(root, "a.json", 2.0, 1), self.scores_file(root, "b.json", 2.0, 3)])
        total = benign_rate.pooled(rows)
        self.assertEqual((total["fp"], total["per_hour"], total["rule_of_three"]), (4, 1.0, None))
        self.assertNotIn("rule of three", "\n".join(benign_rate.report_lines(rows)))

    def test_main_prints_one_line_per_run_and_fails_on_a_bad_file(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        good = self.scores_file(root, "a.json", 1.0, 0)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(benign_rate.main([good]), 0)
        self.assertIn("runs: 1", out.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(benign_rate.main([good, os.path.join(root, "missing.json")]), 2)
            self.assertEqual(benign_rate.main([]), 2)

    def test_it_changes_nothing(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        path = self.scores_file(root, "a.json", 1.0, 0)
        before = open(path, "rb").read()
        with contextlib.redirect_stdout(io.StringIO()):
            benign_rate.main([path])
        self.assertEqual(open(path, "rb").read(), before)
        self.assertEqual(os.listdir(root), ["a.json"])


if __name__ == "__main__":
    unittest.main()
