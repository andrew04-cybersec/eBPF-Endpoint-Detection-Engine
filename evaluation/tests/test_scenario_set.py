"""tests for 29 scenarios under evaluation/scenarios and for evaluation/predictions.json; the scenarios and the predictions are read as they are; nothing here is a result of a run"""
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL_DIR = os.path.dirname(HERE)
ROOT = os.path.dirname(EVAL_DIR)
sys.path.insert(0, EVAL_DIR)
sys.path.insert(0, os.path.join(ROOT, "detections"))

import attack_map  #noqa: E402
import outbound_after_exec  #noqa: E402
import rapid_spawn  #noqa: E402
import scenario_lib as lib  #noqa: E402

SCENARIOS, PROBLEMS = lib.load_scenarios(os.path.join(EVAL_DIR, "scenarios"))
BY = {s["id"][:3]: s for s in SCENARIOS}
with open(os.path.join(EVAL_DIR, "predictions.json"), encoding="utf-8") as f:
    PREDICTIONS = json.load(f)


def action_text(key):
    return lib.read_text(BY[key]["_scripts"]["action"])


def number(text, name):
    m = re.search(r"^%s=([0-9.]+)$" % name, text, re.M)
    assert m, name
    return float(m.group(1))


class TheSet(unittest.TestCase):

    def test_all_29_validate(self):
        self.assertEqual(PROBLEMS, [])
        self.assertEqual(len(SCENARIOS), 29)
        self.assertEqual(sorted(BY), ["S%02d" % i for i in range(1, 30)])

    def test_the_counts_of_the_groups(self):
        attacks = [s for s in SCENARIOS if s["kind"] == "attack"]
        self.assertEqual(len(attacks), 28)
        self.assertEqual(len([s for s in attacks if s["group"] == "ordinary"]), 18)
        self.assertEqual(len([s for s in attacks if s["group"] == "gap"]), 10)
        self.assertEqual(BY["S05"]["kind"], "benign")
        self.assertIsNone(BY["S05"]["group"])

    def test_the_groups_of_the_smoke_scenarios(self):
        self.assertEqual([BY[k]["group"] for k in ("S01", "S02", "S03", "S04", "S05")], ["ordinary", "gap", "ordinary", "gap", None])
        gap = ["S02", "S04", "S09", "S10", "S16", "S22", "S23", "S25", "S27", "S29"]
        self.assertEqual(sorted(k for k, s in BY.items() if s["group"] == "gap"), gap)

    def test_markers_are_two_digit_unique_and_not_substrings(self):
        markers = [s["marker"] for s in SCENARIOS]
        self.assertEqual(markers, ["EVT_EVAL_S%02d" % i for i in range(1, 30)])
        for a in markers:
            for b in markers:
                self.assertTrue(a == b or a not in b)

    def test_techniques_expected_and_acceptable_are_valid(self):
        for s in SCENARIOS:
            if s["kind"] == "attack":
                self.assertIn(s["technique"], attack_map.TECHNIQUES, s["id"])
                self.assertTrue(s["expected"], s["id"])
            for e in s["expected"]:
                self.assertIn(e["detection"], lib.DETECTION_NAMES)
            for a in s["acceptable"]:
                self.assertIn(a, lib.DETECTION_NAMES)

    def test_every_gap_scenario_states_its_gap_and_no_ordinary_one_does(self):
        for s in SCENARIOS:
            if s["group"] == "gap":
                self.assertTrue(s["known_gap"], s["id"])
            elif s["group"] == "ordinary":
                self.assertIsNone(s["known_gap"], s["id"])

    def test_the_expected_lists_follow_the_table(self):
        expect = {"S06": ["unusual_ancestry"], "S07": ["shell_from_service", "unusual_ancestry"], "S08": ["interpreter_chain"],
                  "S09": ["interpreter_chain"], "S10": ["download_chmod_exec"], "S11": ["download_chmod_exec"], "S12": ["exec_from_tmp"],
                  "S13": ["download_chmod_exec", "exec_from_tmp"], "S14": ["sensitive_file_access"], "S15": ["sensitive_file_access"],
                  "S16": ["sensitive_file_access"], "S17": ["sensitive_file_access"], "S18": ["persistence_write"], "S19": ["persistence_write"],
                  "S20": ["persistence_write"], "S21": ["persistence_write"], "S22": ["persistence_write"], "S23": ["persistence_write"],
                  "S24": ["privilege_escalation"], "S25": ["privilege_escalation"], "S26": ["outbound_after_exec"], "S27": ["outbound_after_exec"],
                  "S28": ["rapid_spawn"], "S29": ["rapid_spawn"]}
        for key, names in expect.items():
            self.assertEqual([e["detection"] for e in BY[key]["expected"]], names, key)
        techniques = {"S06": "T1059", "S07": "T1059.004", "S08": "T1059", "S09": "T1059", "S10": "T1105", "S11": "T1105", "S12": "T1059", "S13": "T1105",
                      "S14": "T1003.008", "S15": "T1552.004", "S16": "T1003.008", "S17": "T1003.008", "S18": "T1053.003", "S19": "T1546.004",
                      "S20": "T1098.004", "S21": "T1543.002", "S22": "T1053.003", "S23": "T1053.003", "S24": "T1068", "S25": "T1068",
                      "S26": "T1095", "S27": "T1095", "S28": "T1059", "S29": "T1059"}
        for key, tech in techniques.items():
            self.assertEqual(BY[key]["technique"], tech, key)

    def test_needs_locations_and_requirements(self):
        self.assertEqual([k for k, s in BY.items() if s.get("needs")], ["S26", "S27"])
        self.assertEqual(BY["S26"]["needs"], ["non_loopback_ipv4"])
        locations = {k: s["locations"] for k, s in BY.items() if s.get("locations")}
        self.assertEqual(locations, {"S12": ["shm"], "S13": ["tmp"], "S15": ["home"], "S18": ["cron"], "S19": ["home"], "S20": ["home"],
                                     "S21": ["systemd"], "S22": ["cron"], "S23": ["cron"]})

    def test_scripts_have_no_comments(self):
        for s in SCENARIOS:
            for path in s["_scripts"].values():
                if path:
                    self.assertFalse([l for l in lib.read_text(path).splitlines() if l.strip().startswith("#")], path)

    def test_servers_use_distinct_fixed_ports(self):
        ports = {}
        for key, s in BY.items():
            setup = s["_scripts"]["setup"]
            if setup:
                for p in set(re.findall(r"http\.server (\d+)", lib.read_text(setup))):
                    ports.setdefault(p, []).append(key)
        self.assertEqual(ports, {"18741": ["S03"], "18742": ["S10"], "18743": ["S11"], "18744": ["S13"]})

    def test_listeners_do_not_use_a_fixed_port(self):
        for key in ("S26", "S27"):
            setup = lib.read_text(BY[key]["_scripts"]["setup"])
            self.assertIn("s.bind((sys.argv[1], 0))", setup)
            self.assertIn("-s \"$EVT_EVAL_WORK/port\"", setup)

    def test_the_two_privilege_scenarios_make_the_work_directory_readable(self):
        for key in ("S24", "S25"):
            self.assertIn('chmod 755 "$EVT_EVAL_WORK"', lib.read_text(BY[key]["_scripts"]["setup"]))
            self.assertIn('cd "$EVT_EVAL_WORK"', action_text(key))
        self.assertIn('ln -s /usr/bin/python3 "$EVT_EVAL_WORK/sudo"', lib.read_text(BY["S25"]["_scripts"]["setup"]))


class TiedToTheDetections(unittest.TestCase):

    def test_s27_sleeps_longer_than_the_connect_window_plus_a_margin(self):
        window = outbound_after_exec.CONNECT_WINDOW_NS / 1e9
        sleep = number(action_text("S27"), "SLEEP_SECONDS")
        self.assertGreater(sleep, window + 5)
        self.assertGreaterEqual(BY["S27"]["timeout_seconds"], sleep + 20)

    def test_s26_connects_without_waiting(self):
        self.assertNotIn("sleep", action_text("S26"))

    def test_s28_spawns_at_least_twice_the_threshold(self):
        self.assertGreaterEqual(number(action_text("S28"), "COUNT"), 2 * rapid_spawn.SPAWN_THRESHOLD)
        self.assertNotIn("sleep", action_text("S28"))

    def test_s29_spacing_cannot_put_the_threshold_of_spawns_in_one_window(self):
        text = action_text("S29")
        count, spacing = number(text, "COUNT"), number(text, "SPACING")
        body = text.split("do\n", 1)[1].split("done", 1)[0]
        children = len([l for l in body.splitlines() if l.strip().startswith(("/bin/true", "sleep"))])
        self.assertEqual(children, 2)
        window = rapid_spawn.WINDOW_NS / 1e9
        in_one_window = (int(window / spacing) + 1) * children
        self.assertLess(in_one_window, rapid_spawn.SPAWN_THRESHOLD)
        self.assertGreaterEqual(count * children, rapid_spawn.SPAWN_THRESHOLD)
        self.assertGreaterEqual(count * spacing, 20)
        self.assertGreaterEqual(BY["S29"]["timeout_seconds"], count * spacing + 20)


class KernelLimits(unittest.TestCase):

    def test_fake_home_names_fit_the_kernel_filter_with_a_margin(self):
        header = lib.read_text(os.path.join(ROOT, "telemetry", "src", "common.h"))
        scan = int(re.search(r"#define HOME_USER_SCAN (\d+)", header).group(1))
        limit = scan - 1
        for s in SCENARIOS:
            if "home" in (s.get("locations") or []):
                name = lib.scenario_env(s["id"])["EVT_EVAL_HOME"].split("/home/", 1)[1]
                self.assertNotIn("/", name)
                self.assertLessEqual(len(name), limit - 8, s["id"])


class Predictions(unittest.TestCase):

    def test_every_scenario_has_a_prediction_that_cites_a_rule_or_a_gap(self):
        self.assertEqual(sorted(PREDICTIONS["predictions"]), sorted(s["id"] for s in SCENARIOS))
        for sid, p in PREDICTIONS["predictions"].items():
            self.assertIn(p["predicted_outcome"], ("detected", "missed", "no alerts"), sid)
            self.assertIsInstance(p["predicted_other_alerts"], list)
            self.assertIsInstance(p["assumptions"], list)
            self.assertRegex(p["basis"], r"(?i)section \d+", sid)
            for name in p["predicted_other_alerts"]:
                self.assertIn(name, lib.DETECTION_NAMES)

    def test_the_gap_scenarios_are_predicted_missed_and_the_ordinary_ones_detected(self):
        for s in SCENARIOS:
            p = PREDICTIONS["predictions"][s["id"]]["predicted_outcome"]
            self.assertEqual(p, {"ordinary": "detected", "gap": "missed", None: "no alerts"}[s["group"]], s["id"])
            if s["group"] == "gap":
                self.assertTrue(PREDICTIONS["predictions"][s["id"]]["basis"].startswith("GAP"), s["id"])

    def test_the_smoke_predictions_are_the_original_ones(self):
        got = {k[:3]: v["predicted_outcome"] for k, v in PREDICTIONS["predictions"].items() if k[:3] in ("S01", "S02", "S03", "S04", "S05")}
        self.assertEqual(got, {"S01": "detected", "S02": "missed", "S03": "detected", "S04": "missed", "S05": "no alerts"})

    def test_the_header_and_the_label_set_it_was_written_against(self):
        self.assertEqual(PREDICTIONS["written_before_any_run_of"], "S06 to S29")
        self.assertIn("before any run of S06 to S29", PREDICTIONS["note"])
        self.assertEqual(PREDICTIONS["label_set_sha256"], lib.label_hashes(SCENARIOS)["set"])

    def test_predictions_md_lists_every_scenario(self):
        text = lib.read_text(os.path.join(EVAL_DIR, "PREDICTIONS.md"))
        for s in SCENARIOS:
            self.assertIn(s["id"], text)
        self.assertIn(lib.label_hashes(SCENARIOS)["set"], text)
        self.assertIn("written before any run of S06 to S29", text)

    def test_the_predictions_file_has_sorted_keys(self):
        raw = lib.read_text(os.path.join(EVAL_DIR, "predictions.json"))
        self.assertEqual(list(json.loads(raw)), sorted(json.loads(raw)))
        self.assertEqual(list(PREDICTIONS["predictions"]), sorted(PREDICTIONS["predictions"]))
        for p in PREDICTIONS["predictions"].values():
            self.assertEqual(list(p), sorted(p))


if __name__ == "__main__":
    unittest.main()
