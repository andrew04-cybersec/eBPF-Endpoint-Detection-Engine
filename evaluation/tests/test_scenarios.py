"""
tests for scenario_lib.py: scenario validation, the script lint and the label hashes
every scenario and script written here is a !!constructed fixture!!; the smoke set under evaluation/scenarios is read as is
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL_DIR = os.path.dirname(HERE)
sys.path.insert(0, EVAL_DIR)

import scenario_lib as lib  # noqa: E402

GOOD = {"id": "T1", "title": "t", "kind": "attack", "group": "ordinary", "technique": "T1059", "threat_model": "x", "phase": "after_loader",
        "marker": "EVT_EVAL_T1", "expected": [{"detection": "exec_from_tmp", "min_count": 1}], "acceptable": [],
        "timeout_seconds": 10, "known_gap": None, "notes": "x"}


class Directory:
    def __init__(self):
        self.root = tempfile.mkdtemp()

    def add(self, sid, over=None, action="echo $1\n", setup=None, teardown=None, drop=()):
        sc = dict(GOOD, id=sid, marker="EVT_EVAL_" + sid.upper())
        sc.update(over or {})
        for k in drop:
            sc.pop(k)
        folder = os.path.join(self.root, sid)
        os.makedirs(folder)
        with open(os.path.join(folder, "scenario.json"), "w") as f:
            json.dump(sc, f)
        for name, text in (("action", action), ("setup", setup), ("teardown", teardown)):
            if text is not None:
                with open(os.path.join(folder, name + ".sh"), "w") as f:
                    f.write(text)

    def problems(self):
        return lib.load_scenarios(self.root)[1]

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def directory(test):
    d = Directory()
    test.addCleanup(d.cleanup)
    return d


class SmokeSet(unittest.TestCase):

    def test_the_five_smoke_scenarios_validate(self):
        scenarios, problems = lib.load_scenarios(os.path.join(EVAL_DIR, "scenarios"))
        self.assertEqual(problems, [])
        self.assertEqual([s["id"] for s in scenarios][:5], ["S01_shell_from_service_after_loader", "S02_shell_from_service_before_loader",
                                                             "S03_download_chmod_exec", "S04_exec_from_tmp_via_interpreter", "S05_benign_smoke"])
        self.assertEqual([s["kind"] for s in scenarios][:5], ["attack"] * 4 + ["benign"])
        self.assertEqual(len({s["marker"] for s in scenarios}), len(scenarios))

    def test_the_labels_of_the_smoke_set(self):
        by = {s["id"][:3]: s for s in lib.load_scenarios(os.path.join(EVAL_DIR, "scenarios"))[0]}
        for key, det in (("S01", "shell_from_service"), ("S02", "shell_from_service"), ("S03", "download_chmod_exec"), ("S04", "exec_from_tmp")):
            self.assertEqual(by[key]["expected"], [{"detection": det, "min_count": 1}])
        self.assertEqual(by["S05"]["expected"], [])
        self.assertEqual((by["S02"]["phase"], by["S01"]["phase"]), ("before_loader", "after_loader"))
        self.assertTrue(by["S04"]["known_gap"] and by["S02"]["known_gap"])
        self.assertTrue(by["S04"]["tmp_staging"])

    def test_every_smoke_script_passes_the_lint(self):
        for sc in lib.load_scenarios(os.path.join(EVAL_DIR, "scenarios"))[0]:
            created = set().union(*[lib.created_copies(lib.read_text(p)) for p in sc["_scripts"].values() if p])
            for path in sc["_scripts"].values():
                if path:
                    self.assertEqual(lib.lint_script(lib.read_text(path), allow_tmp=bool(sc.get("tmp_staging")), locations=sc.get("locations", []),
                                                     created=created), [], path)


class Rejections(unittest.TestCase):

    def test_a_good_scenario_has_no_problems(self):
        d = directory(self)
        d.add("T1")
        self.assertEqual(d.problems(), [])

    def test_duplicate_ids_and_markers(self):
        d = directory(self)
        d.add("T1")
        d.add("T2", {"marker": "EVT_EVAL_T1"})
        self.assertTrue(any("marker EVT_EVAL_T1 is also used" in p for p in d.problems()))
        d2 = directory(self)
        d2.add("T1")
        d2.add("T2", {"id": "T1"})
        self.assertTrue(any("duplicate id" in p for p in d2.problems()))

    def test_a_marker_inside_another_marker(self):
        d = directory(self)
        d.add("T1")
        d.add("T10", {"marker": "EVT_EVAL_T10"})
        self.assertTrue(any("contained in marker" in p for p in d.problems()))

    def test_unknown_detection_names(self):
        d = directory(self)
        d.add("T1", {"expected": [{"detection": "no_such", "min_count": 1}]})
        d.add("T2", {"acceptable": ["also_no_such"]})
        text = " ".join(d.problems())
        self.assertIn("unknown detection name 'no_such' in expected", text)
        self.assertIn("unknown detection name 'also_no_such' in acceptable", text)

    def test_a_technique_that_is_not_in_the_attack_map(self):
        d = directory(self)
        d.add("T1", {"technique": "T9999"})
        d.add("T2", {"technique": None})
        text = " ".join(d.problems())
        self.assertIn("T1: technique 'T9999' is not in the attack map", text)
        self.assertIn("T2: technique None is not in the attack map", text)

    def test_benign_rules(self):
        d = directory(self)
        d.add("T1", {"kind": "benign", "technique": None})
        self.assertTrue(any("benign scenario has an empty expected list" in p for p in d.problems()))
        d2 = directory(self)
        d2.add("T1", {"kind": "benign", "technique": "T1059", "expected": []})
        self.assertTrue(any("benign scenario has technique null" in p for p in d2.problems()))

    def test_an_attack_needs_an_action_and_an_expected_entry(self):
        d = directory(self)
        d.add("T1", action=None)
        d.add("T2", {"expected": []})
        text = " ".join(d.problems())
        self.assertIn("T1: action.sh is missing", text)
        self.assertIn("T2: an attack scenario needs at least one expected entry", text)

    def test_a_before_loader_scenario_needs_a_setup(self):
        d = directory(self)
        d.add("T1", {"phase": "before_loader"})
        self.assertTrue(any("needs setup.sh" in p for p in d.problems()))

    def test_unsafe_scripts_are_rejected_with_the_file_and_line(self):
        d = directory(self)
        d.add("T1", action="echo ok\nsudo ls\n")
        d.add("T2", setup="touch /etc/x\n")
        d.add("T3", teardown="rm -rf /opt/other\n")
        text = " ".join(d.problems())
        self.assertIn("T1: unsafe script action.sh line 2: command sudo is not allowed", text)
        self.assertIn("T2: unsafe script setup.sh line 1: write to /etc/x is not allowed", text)
        self.assertIn("T3: unsafe script teardown.sh line 1: rm -r of /opt/other is outside the work directory variable", text)

    def test_missing_and_unknown_fields_and_bad_values(self):
        d = directory(self)
        d.add("T1", drop=("marker",))
        d.add("T2", {"colour": "red"})
        d.add("T3", {"expected": [{"detection": "exec_from_tmp", "min_count": 0}], "timeout_seconds": 0, "kind": "other"})
        d.add("T4", {"marker": "lowercase"})
        text = " ".join(d.problems())
        self.assertIn("T1: missing fields ['marker']", text)
        self.assertIn("T2: unknown fields ['colour']", text)
        self.assertIn("min_count of exec_from_tmp must be an integer of at least 1", text)
        self.assertIn("T3: timeout_seconds must be a positive integer", text)
        self.assertIn("T3: kind must be attack or benign", text)
        self.assertIn("T4: marker must look like EVT_EVAL_NAME", text)

    def test_the_id_must_match_the_directory_and_a_bad_file_is_reported(self):
        d = directory(self)
        d.add("T1", {"id": "OTHER"})
        os.makedirs(os.path.join(d.root, "T2"))
        os.makedirs(os.path.join(d.root, "T3"))
        with open(os.path.join(d.root, "T3", "scenario.json"), "w") as f:
            f.write("{not json")
        text = " ".join(d.problems())
        self.assertIn("id does not match its directory name", text)
        self.assertIn("T2: scenario.json is missing", text)
        self.assertIn("T3: scenario.json cannot be read", text)

    def test_a_tmp_script_needs_tmp_staging(self):
        d = directory(self)
        d.add("T1", setup='mkdir -p "$EVT_EVAL_TMP"\n')
        d.add("T2", {"tmp_staging": True}, setup='mkdir -p "$EVT_EVAL_TMP"\n')
        text = " ".join(d.problems())
        self.assertIn("T1: unsafe script setup.sh", text)
        self.assertNotIn("T2:", text)


class Lint(unittest.TestCase):

    DENIED = ["sudo ls", "su root", "pkexec id", "doas id", "echo a; sudo id", "rm -rf /opt/x", "rm -rf $HOME", "rm -rf /tmp/foo",
              "rm -r \"$OTHER\"", "echo x > /etc/passwd", "echo x >> /usr/x", "cp a /usr/bin/b", "touch /root/x", "mkdir /home/bob",
              "mv a /lib/x", "echo x 2> /bin/y", "tee /etc/f", "systemctl enable x", "crontab -e", "crontab file", "mkfs.ext4 /dev/x",
              "mkfs /dev/x", "dd if=/dev/zero of=/dev/sda", "shutdown now", "reboot", "poweroff", "halt", "iptables -L", "nft list ruleset",
              "echo x > /etc/ld.so.preload", "cat /etc/ld.so.preload", "cat /tmp/x", "ls /tmp", "chmod 777 /etc/shadow", "ln -s a /etc/b"]
    ALLOWED = ["echo hello", "cat /etc/hostname", "ls /usr/bin | wc -l", "cp /bin/bash \"$EVT_EVAL_WORK/nginx\"",
               "rm -rf \"$EVT_EVAL_WORK\"", "rm -rf \"$EVT_EVAL_WORK/serve\"", "rm -f \"$EVT_EVAL_WORK/x\"", "rm -rf ${EVT_EVAL_WORK}",
               "cp /bin/true \"$EVT_EVAL_WORK/crontab\"\n\"$EVT_EVAL_WORK/crontab\" -l", "ln -s /bin/true \"$EVT_EVAL_WORK/systemctl\"\n\"$EVT_EVAL_WORK/systemctl\" status",
               "# sudo is only a word in this comment", "echo done # reboot later", "python3 -c 'print(1)'", "mkfifo \"$EVT_EVAL_WORK/f\"",
               "echo x > /dev/null", "echo x 2> /dev/null", "sleep 1", "kill \"$pid\" 2> /dev/null || true", "[ -f \"$EVT_EVAL_WORK/p\" ] && echo yes"]

    def test_every_denied_pattern_is_rejected(self):
        for text in self.DENIED:
            self.assertTrue(lib.lint_script(text), text)

    def test_safe_scripts_are_accepted(self):
        for text in self.ALLOWED:
            self.assertEqual(lib.lint_script(text), [], text)

    def test_tmp_is_allowed_only_under_the_evt_eval_prefix_and_only_with_the_flag(self):
        self.assertEqual(lib.lint_script("ls /tmp/evt_eval_x/y", allow_tmp=True), [])
        self.assertEqual(lib.lint_script("rm -rf \"$EVT_EVAL_TMP\"", allow_tmp=True), [])
        self.assertTrue(lib.lint_script("ls /tmp/other", allow_tmp=True))
        self.assertTrue(lib.lint_script("ls /tmp", allow_tmp=True))
        self.assertTrue(lib.lint_script("ls /tmp/evt_eval_x/y", allow_tmp=False))
        self.assertTrue(lib.lint_script("rm -rf \"$EVT_EVAL_TMP\"", allow_tmp=False))

    def test_the_problems_carry_the_line_number(self):
        self.assertEqual([n for n, _ in lib.lint_script("echo a\n\nsudo b\necho c\nreboot\n")], [3, 5])


class Hashes(unittest.TestCase):

    def test_hashes_are_stable_and_change_with_a_file(self):
        d = directory(self)
        d.add("T1")
        d.add("T2")
        first = lib.label_hashes(lib.load_scenarios(d.root)[0])
        again = lib.label_hashes(lib.load_scenarios(d.root)[0])
        self.assertEqual(first, again)
        with open(os.path.join(d.root, "T2", "scenario.json"), "a") as f:
            f.write("\n")
        changed = lib.label_hashes(lib.load_scenarios(d.root)[0])
        self.assertEqual(first["scenarios"]["T1"], changed["scenarios"]["T1"])
        self.assertNotEqual(first["scenarios"]["T2"], changed["scenarios"]["T2"])
        self.assertNotEqual(first["set"], changed["set"])

    def test_the_environment_of_a_scenario(self):
        env = lib.scenario_env("S01_Abc")
        self.assertEqual({k: env[k] for k in ("EVT_EVAL_ID", "EVT_EVAL_WORK", "EVT_EVAL_TMP")},
                         {"EVT_EVAL_ID": "S01_Abc", "EVT_EVAL_WORK": "/opt/evt_eval_s01_abc", "EVT_EVAL_TMP": "/tmp/evt_eval_s01_abc"})


if __name__ == "__main__":
    unittest.main()
