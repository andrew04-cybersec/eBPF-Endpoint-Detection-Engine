"""
tests for group tables and scenarios not run and also the predicted-versus-actual section and lastly the attribution counts of evaluate.py
every scenario, alert, window, prediction and results folder here is a !!constructed fixture, not captured output!!
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL_DIR = os.path.dirname(HERE)
sys.path.insert(0, EVAL_DIR)
sys.path.insert(0, HERE)

import scenario_lib  #noqa: E402
from test_scorer import Folder, alert, read_bytes, scenario, window  #noqa: E402

SHELL = "shell_from_service"


def grouped(sid, group, technique="T1059.004", **over):
    return dict(scenario(sid, technique=technique), group=group, **over)


def hit(sid, ts, det=SHELL):
    return alert(det, ts, "EVT_EVAL_" + sid)


def predictions(rows, label_set=None):
    return {"label_set_sha256": label_set, "note": "constructed", "written_before_any_run_of": "S06 to S29",
            "predictions": {sid: {"assumptions": [], "basis": "constructed, section 15", "predicted_other_alerts": other, "predicted_outcome": outcome}
                            for sid, (outcome, other) in rows.items()}}


def attach(folder, data, live=True, changed_live=None):
    """save predictions into results folder with hash recorded at run time and live copy next to live scenario directory"""
    text = json.dumps(data, sort_keys=True, indent=1) + "\n"
    folder.write("predictions.json", text)
    with open(os.path.join(folder.results, "label_hashes.json")) as f:
        hashes = json.load(f)
    hashes["predictions_sha256"] = scenario_lib.sha256_bytes(text.encode("ascii"))
    folder.write("label_hashes.json", json.dumps(hashes))
    if live:
        with open(os.path.join(folder.tmp, "predictions.json"), "w") as f:
            f.write(text if changed_live is None else changed_live)


def skip(folder, skipped):
    with open(os.path.join(folder.results, "scenario_windows.json")) as f:
        doc = json.load(f)
    doc["skipped"] = skipped
    folder.write("scenario_windows.json", json.dumps(doc))


class Groups(unittest.TestCase):

    def folder(self):
        scs = [grouped("S1", "ordinary"), grouped("S2", "ordinary"), grouped("S3", "ordinary"), grouped("S4", "gap"), grouped("S5", "gap"),
               dict(scenario("B1", kind="benign"), group=None)]
        windows = {"S1": window(1000, 2000), "S2": window(3000, 4000), "S3": window(5000, 6000), "S4": window(7000, 8000),
                   "S5": window(9000, 10000), "B1": window(20 * 10**9, 40 * 10**9)}
        f = Folder(scs, windows, [hit("S1", 1100), hit("S2", 3100)])
        self.addCleanup(f.cleanup)
        return f

    def test_two_group_tables_with_denominators(self):
        scores, report = self.folder().score()
        self.assertEqual(scores["groups"]["ordinary"], {"scenarios": 3, "detected": 2, "missed": 1, "recall": {"num": 2, "den": 3, "value": round(2 / 3, 6)}})
        self.assertEqual(scores["groups"]["gap"], {"scenarios": 2, "detected": 0, "missed": 2, "recall": {"num": 0, "den": 2, "value": 0.0}})
        self.assertNotIn("ungrouped", scores["groups"])
        self.assertIn("## Headline: attack scenarios by group", report)
        self.assertIn("| ordinary | 3 | 2 | 1 | 2/3 (0.667) |", report)
        self.assertIn("| gap | 2 | 0 | 2 | 0/2 (0.000) |", report)
        self.assertIn("best case and not a detection rate", report)
        self.assertIn("built to miss", report)

    def test_the_pooled_number_is_secondary_and_says_why(self):
        report = self.folder().score()[1]
        self.assertIn("Pooled recall (scenario level, secondary): 2/5 (0.400)", report)
        self.assertIn("the mix is a design choice and not a population", report)
        self.assertLess(report.index("## Headline"), report.index("Pooled recall"))

    def test_the_per_technique_table_has_a_column_per_group(self):
        scores, report = self.folder().score()
        row = scores["per_technique"]["T1059.004"]
        self.assertEqual((row["by_group"]["ordinary"], row["by_group"]["gap"]),
                         ({"num": 2, "den": 3, "value": round(2 / 3, 6)}, {"num": 0, "den": 2, "value": 0.0}))
        self.assertIn("| technique | attacks | detected | missed | recall | ordinary | gap |", report)
        self.assertIn("| T1059.004 | 5 | 2 | 3 | 2/5 (0.400) | 2/3 (0.667) | 0/2 (0.000) |", report)

    def test_a_technique_with_attacks_in_one_group_only_shows_an_empty_ratio_for_the_other(self):
        f = Folder([grouped("S1", "ordinary")], {"S1": window(1000, 2000)}, [hit("S1", 1100)])
        self.addCleanup(f.cleanup)
        row = f.score()[0]["per_technique"]["T1059.004"]["by_group"]
        self.assertEqual(row["gap"], {"num": 0, "den": 0, "value": None})

    def test_scenarios_without_a_group_are_listed_apart_and_still_score(self):
        f = Folder([scenario("S1"), grouped("S2", "gap")], {"S1": window(1000, 2000), "S2": window(3000, 4000)}, [hit("S1", 1100)])
        self.addCleanup(f.cleanup)
        scores, report = f.score()
        self.assertEqual(scores["groups"]["ungrouped"]["detected"], 1)
        self.assertEqual(scores["groups"]["ordinary"]["recall"], {"num": 0, "den": 0, "value": None})
        self.assertIn("| ordinary | 0 | 0 | 0 | 0/0 (n/a) |", report)
        self.assertIn("| ungrouped | 1 | 1 | 0 | 1/1 (1.000) |", report)


class NotRun(unittest.TestCase):

    def folder(self):
        scs = [grouped("S1", "ordinary"), grouped("S2", "gap"), grouped("S3", "ordinary")]
        f = Folder(scs, {"S1": window(1000, 2000), "S3": window(5000, 6000)}, [hit("S1", 1100)])
        self.addCleanup(f.cleanup)
        skip(f, {"S2": "needs a non-loopback IPv4 address and the machine has none"})
        return f

    def test_a_scenario_not_run_is_listed_with_its_reason_and_excluded_from_every_count(self):
        scores, report = self.folder().score()
        self.assertEqual(scores["not_run"], ["S2"])
        self.assertEqual(scores["not_run_reasons"]["S2"], "needs a non-loopback IPv4 address and the machine has none")
        self.assertNotIn("S2", scores["scenarios"])
        self.assertEqual(scores["groups"]["gap"], {"scenarios": 0, "detected": 0, "missed": 0, "recall": {"num": 0, "den": 0, "value": None}})
        self.assertEqual(scores["pooled"]["recall"], {"num": 1, "den": 2, "value": 0.5})
        self.assertIn("## Scenarios not run\n\n- S2: needs a non-loopback IPv4 address and the machine has none", report)
        self.assertNotIn("| S2 |", report.split("## Scenarios not run")[0])

    def test_a_scenario_without_a_window_and_without_a_reason_gets_a_default_reason(self):
        f = Folder([grouped("S1", "ordinary"), grouped("S2", "gap")], {"S1": window(1000, 2000)}, [])
        self.addCleanup(f.cleanup)
        self.assertIn("no window was recorded", f.score()[0]["not_run_reasons"]["S2"])

    def test_the_section_says_none_when_everything_ran(self):
        f = Folder([grouped("S1", "ordinary")], {"S1": window(1000, 2000)}, [])
        self.addCleanup(f.cleanup)
        self.assertIn("## Scenarios not run\n\nnone", f.score()[1])

    def test_rescoring_is_byte_identical(self):
        f = self.folder()
        f.score()
        first = [read_bytes(f.results, n) for n in ("scores.json", "report.md")]
        f.score()
        self.assertEqual(first, [read_bytes(f.results, n) for n in ("scores.json", "report.md")])


class PredictedVersusActual(unittest.TestCase):

    def folder(self, rows=None, **kw):
        scs = [grouped("S1", "ordinary"), grouped("S2", "ordinary"), grouped("S3", "gap"), grouped("S4", "gap"), dict(scenario("B1", kind="benign"), group=None)]
        windows = {"S1": window(1000, 2000), "S2": window(3000, 4000), "S3": window(5000, 6000), "B1": window(10 * 10**9, 30 * 10**9)}
        alerts = [hit("S1", 1100), alert("exec_from_tmp", 1200, "EVT_EVAL_S1"), hit("S2", 3100)]
        f = Folder(scs, windows, alerts)
        self.addCleanup(f.cleanup)
        rows = rows or {"S1": ("detected", ["exec_from_tmp"]), "S2": ("missed", []), "S3": ("missed", []), "S4": ("detected", []), "B1": ("no alerts", [])}
        attach(f, predictions(rows), **kw)
        skip(f, {"S4": "needs a non-loopback IPv4 address and the machine has none"})
        return f

    def test_match_mismatch_not_run_and_the_list_of_mismatches(self):
        scores, report = self.folder().score()
        by = {r["id"]: r for r in scores["predictions"]["rows"]}
        self.assertEqual(by["S1"]["status"], "MATCH")
        self.assertEqual((by["S2"]["predicted"], by["S2"]["actual"], by["S2"]["status"]), ("missed", "detected", "MISMATCH"))
        self.assertEqual(by["S3"]["status"], "MATCH")
        self.assertEqual((by["S4"]["actual"], by["S4"]["status"]), ("not run", "not run"))
        self.assertEqual(by["B1"]["status"], "MATCH")
        self.assertEqual(scores["predictions"]["mismatches"], ["S2"])
        self.assertIn("## Predicted versus actual", report)
        self.assertIn("| S2 | missed | detected | none | none | MISMATCH |", report)
        self.assertIn("| S1 | detected | detected | exec_from_tmp | exec_from_tmp | MATCH |", report)
        self.assertIn("Mismatches (listed, never scored): S2.", report)

    def test_other_alerts_that_differ_are_a_mismatch(self):
        rows = {"S1": ("detected", []), "S2": ("detected", []), "S3": ("missed", []), "S4": ("detected", []), "B1": ("no alerts", [])}
        scores, _ = self.folder(rows).score()
        by = {r["id"]: r for r in scores["predictions"]["rows"]}
        self.assertEqual((by["S1"]["status"], by["S1"]["other_predicted"], by["S1"]["other_actual"]), ("MISMATCH", [], ["exec_from_tmp"]))
        self.assertEqual(scores["predictions"]["mismatches"], ["S1"])

    def test_a_benign_scenario_with_alerts_against_a_prediction_of_none(self):
        f = self.folder()
        scs_alert = alert("rapid_spawn", 11 * 10**9, "EVT_EVAL_B1")
        with open(os.path.join(f.results, "alerts.stamped.tsv"), "a") as fh:
            fh.write("%d\t%s\n" % (11 * 10**9 + 1000, json.dumps(scs_alert)))
        by = {r["id"]: r for r in f.score()[0]["predictions"]["rows"]}
        self.assertEqual((by["B1"]["actual"], by["B1"]["status"]), ("false alerts", "MISMATCH"))

    def test_a_mismatch_never_changes_a_score(self):
        right = self.folder({"S1": ("detected", ["exec_from_tmp"]), "S2": ("detected", []), "S3": ("missed", []), "S4": ("detected", []), "B1": ("no alerts", [])})
        wrong = self.folder()
        a, b = right.score()[0], wrong.score()[0]
        for key in ("groups", "pooled", "per_detection", "per_technique", "scenarios", "benign"):
            self.assertEqual(a[key], b[key], key)

    def test_a_scenario_with_no_prediction_is_shown(self):
        f = self.folder({"S1": ("detected", ["exec_from_tmp"])})
        by = {r["id"]: r for r in f.score()[0]["predictions"]["rows"]}
        self.assertEqual(by["S2"]["status"], "no prediction")

    def test_no_warning_when_the_live_predictions_match(self):
        self.assertEqual(self.folder().score()[0]["warnings"], [])

    def test_changed_live_predictions_warn_loudly_and_the_copy_is_used(self):
        f = self.folder(changed_live="{}\n")
        scores, report = f.score()
        self.assertEqual(scores["warnings"], ["WARNING: the live predictions file was changed after the run; the copy in the folder is used"])
        self.assertTrue(report.startswith("# Evaluation report: 20000101-000000-eval\n\nWARNING: the live predictions file was changed"))
        self.assertEqual(scores["predictions"]["mismatches"], ["S2"])

    def test_missing_live_predictions_a_tampered_copy_and_another_label_set_warn(self):
        gone = self.folder(live=False).score()[0]["warnings"]
        self.assertEqual(gone, ["WARNING: the live predictions file is gone; the copy in the folder is used"])
        tampered = self.folder()
        with open(os.path.join(tampered.results, "predictions.json"), "a") as fh:
            fh.write(" ")
        self.assertIn("WARNING: the predictions in this folder do not match the hash recorded at run time", tampered.score()[0]["warnings"])
        other = Folder([grouped("S1", "ordinary")], {"S1": window(1000, 2000)}, [])
        self.addCleanup(other.cleanup)
        attach(other, predictions({"S1": ("detected", [])}, label_set="0" * 64))
        self.assertIn("WARNING: the predictions were written against a different label set than the one of this run", other.score()[0]["warnings"])

    def test_rescoring_is_byte_identical(self):
        f = self.folder()
        f.score()
        first = [read_bytes(f.results, n) for n in ("scores.json", "report.md")]
        f.score()
        self.assertEqual(first, [read_bytes(f.results, n) for n in ("scores.json", "report.md")])


class OldFormat(unittest.TestCase):

    def test_a_folder_without_groups_predictions_or_skipped_still_scores(self):
        f = Folder([scenario("S1"), scenario("B1", kind="benign")], {"S1": window(1000, 2000), "B1": window(5 * 10**9, 25 * 10**9)}, [hit("S1", 1100)])
        self.addCleanup(f.cleanup)
        scores, report = f.score()
        self.assertIsNone(scores["predictions"])
        self.assertEqual(scores["scenarios"]["S1"]["outcome"], "detected")
        self.assertIn("No predictions file was saved with this folder.", report)
        self.assertIn("## Scenarios not run\n\nnone", report)
        self.assertEqual(scores["warnings"], [])
        again = [read_bytes(f.results, n) for n in ("scores.json", "report.md")]
        f.score()
        self.assertEqual(again, [read_bytes(f.results, n) for n in ("scores.json", "report.md")])


class Attribution(unittest.TestCase):

    def test_alerts_in_a_window_without_the_marker_are_counted_beside_the_outcome(self):
        f = Folder([grouped("S1", "ordinary"), grouped("S2", "gap")], {"S1": window(1000, 2000), "S2": window(3000, 4000)},
                   [hit("S1", 1100), alert(SHELL, 1200, "no marker"), alert("exec_from_tmp", 1300, "other"), alert(SHELL, 3100, "no marker")])
        self.addCleanup(f.cleanup)
        scores, report = f.score()
        self.assertEqual((scores["scenarios"]["S1"]["in_window_without_marker"], scores["scenarios"]["S2"]["in_window_without_marker"]), (2, 1))
        self.assertIn("| S1 | attack | ordinary | T1059.004 | detected | shell_from_service 1 | none | none | - | 2 | no |", report)
        self.assertIn("| S2 | attack | gap | T1059.004 | missed | none | none | none | shell_from_service needs 1, got 0 | 1 | no |", report)
        self.assertIn("not attributable by its marker", report)

    def test_a_scenario_with_no_stray_alerts_shows_zero(self):
        f = Folder([grouped("S1", "ordinary")], {"S1": window(1000, 2000)}, [hit("S1", 1100)])
        self.addCleanup(f.cleanup)
        self.assertEqual(f.score()[0]["scenarios"]["S1"]["in_window_without_marker"], 0)


if __name__ == "__main__":
    unittest.main()
