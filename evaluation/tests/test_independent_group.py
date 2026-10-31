import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import evaluate  #noqa: E402
import scenario_lib  #noqa: E402


def attack(sid, marker, group):
    return {"id": sid, "kind": "attack", "technique": "T1105", "group": group, "marker": marker, "known_gap": None,
            "expected": [{"detection": "download_chmod_exec", "min_count": 1}], "acceptable": []}


def alert_for(marker, ts_ns):
    return {"detection": "download_chmod_exec", "ts_ns": ts_ns, "_arrival_ns": ts_ns + 1000,
            "process": {"pid": 1, "cmdline": "bash " + marker}}


def data_for(scenarios, alerts):
    windows = {s["id"]: {"start_ns": i * 2000, "end_ns": i * 2000 + 1000, "timed_out": False} for i, s in enumerate(scenarios)}
    return {"scenarios": scenarios, "windows": windows, "windows_file": {}, "alerts": alerts, "warnings": [], "bad_alert_lines": 0,
            "env": {}, "resources": [], "event_ts": [], "lost_events": 0, "lost_dropped": 0, "loader_lines": [], "bpf": None,
            "event_types": {}, "openat_seen": None, "predictions": None, "hashes": {}, "events_path": None}


class IndependentGroupValidation(unittest.TestCase):
    def load(self, group):
        sid = "Z01_group_check"
        doc = {"id": sid, "title": "t", "kind": "attack", "technique": "T1105", "threat_model": "m", "phase": "after_loader",
               "marker": "EVT_EVAL_Z01", "expected": [{"detection": "download_chmod_exec", "min_count": 1}], "acceptable": [],
               "timeout_seconds": 10, "known_gap": None, "notes": "n", "group": group}
        with tempfile.TemporaryDirectory() as root:
            folder = os.path.join(root, sid)
            os.makedirs(folder)
            with open(os.path.join(folder, "scenario.json"), "w", encoding="utf-8") as f:
                json.dump(doc, f)
            with open(os.path.join(folder, "action.sh"), "w", encoding="utf-8") as f:
                f.write(":\n")
            return scenario_lib.load_scenarios(root)[1]

    def test_independent_is_accepted(self):
        self.assertEqual(self.load("independent"), [])

    def test_existing_groups_are_still_accepted(self):
        self.assertEqual(self.load("ordinary"), [])
        self.assertEqual(self.load("gap"), [])

    def test_other_groups_are_still_refused(self):
        problems = self.load("other")
        self.assertEqual(len(problems), 1)
        self.assertIn("group of an attack", problems[0])


class IndependentGroupScoring(unittest.TestCase):
    def scored(self, scenarios, alerts):
        data = data_for(scenarios, alerts)
        scores = evaluate.score(data)
        return scores, evaluate.render_report("folder", scores, data)

    def test_independent_has_its_own_row(self):
        scenarios = [attack("Z01_a", "EVT_EVAL_Z01", "ordinary"), attack("Z02_b", "EVT_EVAL_Z02", "gap"),
                     attack("Z03_c", "EVT_EVAL_Z03", "independent")]
        scores, _ = self.scored(scenarios, [alert_for("EVT_EVAL_Z03", 4500)])
        groups = scores["groups"]
        self.assertEqual(groups["independent"]["scenarios"], 1)
        self.assertEqual(groups["independent"]["detected"], 1)

    def test_independent_is_not_added_into_ordinary_or_gap(self):
        scenarios = [attack("Z01_a", "EVT_EVAL_Z01", "ordinary"), attack("Z02_b", "EVT_EVAL_Z02", "gap"),
                     attack("Z03_c", "EVT_EVAL_Z03", "independent")]
        scores, _ = self.scored(scenarios, [alert_for("EVT_EVAL_Z03", 4500)])
        for name in ("ordinary", "gap"):
            self.assertEqual(scores["groups"][name]["scenarios"], 1)
            self.assertEqual(scores["groups"][name]["detected"], 0)
        by_group = scores["per_technique"]["T1105"]["by_group"]
        self.assertEqual(by_group["ordinary"]["num"], 0)
        self.assertEqual(by_group["ordinary"]["den"], 1)
        self.assertEqual(by_group["gap"]["num"], 0)
        self.assertEqual(by_group["independent"]["num"], 1)
        self.assertEqual(by_group["independent"]["den"], 1)

    def test_independent_appears_in_the_report(self):
        scenarios = [attack("Z03_c", "EVT_EVAL_Z03", "independent")]
        scores, report = self.scored(scenarios, [alert_for("EVT_EVAL_Z03", 500)])
        self.assertIn("| independent |", report)
        self.assertIn("is not added into the ordinary or gap rows", report)

    def test_nothing_independent_appears_without_such_a_scenario(self):
        scenarios = [attack("Z01_a", "EVT_EVAL_Z01", "ordinary"), attack("Z02_b", "EVT_EVAL_Z02", "gap")]
        scores, report = self.scored(scenarios, [alert_for("EVT_EVAL_Z01", 500)])
        self.assertEqual(sorted(scores["groups"]), ["gap", "ordinary"])
        self.assertEqual(sorted(scores["per_technique"]["T1105"]["by_group"]), ["gap", "ordinary"])
        self.assertNotIn("independent", report)
        self.assertNotIn("independent", json.dumps(scores))


if __name__ == "__main__":
    unittest.main()
