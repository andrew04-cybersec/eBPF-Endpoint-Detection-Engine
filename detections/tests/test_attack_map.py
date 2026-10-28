"""
tests for attack_map.py
every event here is a !!constructed fixture, not captured output!!
the category lists of sensitive_file_access and persistence are imported from those modules and the two command names (crontab, systemctl) are read from the test because persistence.py keeps them inline
"""
import io
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DET_DIR = os.path.dirname(HERE)
sys.path.insert(0, DET_DIR)

import attack_map as am  #noqa: E402
import exec_from_tmp  #noqa: E402
import download_chmod_exec  #noqa: E402
import interpreter_chain  #noqa: E402
import outbound_after_exec  #noqa: E402
import persistence as pers  #noqa: E402
import privilege_escalation  #noqa: E402
import rapid_spawn  #noqa: E402
import runner  #noqa: E402
import sensitive_file_access as sfa  #noqa: E402
import shell_from_service  #noqa: E402
import unusual_ancestry  #noqa: E402

ID_PATTERN = re.compile(r"T\d{4}(\.\d{3})?")
PLAIN = (shell_from_service, exec_from_tmp, download_chmod_exec, unusual_ancestry, rapid_spawn,
         outbound_after_exec, privilege_escalation, interpreter_chain)

PERSIST_PATHS = {"ld_preload": "/etc/ld.so.preload", "ld_conf": "/etc/ld.so.conf.d/x.conf", "cron": "/etc/cron.d/x",
                 "systemd": "/etc/systemd/system/x.service", "init": "/etc/rc.local", "shell_startup": "/root/.bashrc",
                 "pam": "/etc/pam.d/x", "motd": "/etc/update-motd.d/x", "user_autostart": "/root/.config/autostart/x.desktop",
                 "ssh_keys": "/root/.ssh/authorized_keys", "accounts": "/etc/passwd"}
SENSITIVE_PATHS = {"shadow": ["/etc/shadow", "/etc/gshadow"], "passwd": ["/etc/passwd"],
                   "sudoers": ["/etc/sudoers", "/etc/sudoers.d/x"], "ssh_private_key": ["/root/.ssh/id_rsa", "/home/bob/.ssh/id_ed25519"]}


def event(pid, typ, ppid=1, comm="bash", **fields):
    e = {"schema_version": 1, "type": typ, "ts_ns": pid, "pid": pid, "tid": pid, "comm": comm, "ppid": ppid,
         "uid": 0, "gid": 0, "start_time_ns": pid * 10, "process_key": "%d:%d" % (pid, pid * 10)}
    e.update(fields)
    return e


def run_alerts(events, detect):
    lines = [(json.dumps(e) + "\n").encode() for e in events]
    out = io.StringIO()
    runner.run(lines, runner.alert.AlertSink(out, None), detections=[detect])
    return [json.loads(l) for l in out.getvalue().splitlines()]


def all_entries():
    tables = [am.DETECTIONS] + list(am.CATEGORY_TABLES.values())
    return [e for t in tables for e in t.values()]


class Table(unittest.TestCase):

    def test_every_id_looks_like_an_id_and_every_used_id_is_in_the_table(self):
        for tid in am.TECHNIQUES:
            self.assertRegex(tid, ID_PATTERN)
            self.assertTrue(ID_PATTERN.fullmatch(tid), tid)
        for tid, conf in all_entries():
            self.assertIn(tid, am.TECHNIQUES)
            self.assertTrue(ID_PATTERN.fullmatch(tid), tid)
        for ids in am.RELATED.values():
            for tid in ids:
                self.assertIn(tid, am.TECHNIQUES)

    def test_every_record_is_complete(self):
        for tid, rec in am.TECHNIQUES.items():
            self.assertTrue(rec["name"], tid)
            self.assertTrue(rec["tactics"] and all(t for t in rec["tactics"]), tid)
            self.assertTrue(rec["platforms"], tid)
            self.assertIsInstance(rec["verified"], bool)

    def test_confidence_values(self):
        self.assertEqual(am.CONFIDENCES, ("direct", "partial", "weak"))
        for tid, conf in all_entries():
            self.assertIn(conf, am.CONFIDENCES)

    def test_version_and_date_are_set(self):
        for value in (am.ATTACK_VERSION, am.VERIFIED_DATE):
            self.assertIsInstance(value, str)
            self.assertTrue(value.strip())

    def test_the_mapping_asked_for(self):
        expect = {"shell_from_service": "T1059.004", "unusual_ancestry": "T1059", "exec_from_tmp": "T1059",
                  "download_chmod_exec": "T1105", "outbound_after_exec": "T1095", "privilege_escalation": "T1068",
                  "interpreter_chain": "T1059", "rapid_spawn": "T1059"}
        for name, tid in expect.items():
            self.assertEqual(am.technique_for(name), tid, name)
        self.assertEqual(am.technique_for("persistence_command", "crontab"), "T1053.003")
        self.assertEqual(am.technique_for("persistence_command", "systemctl"), "T1543.002")
        self.assertEqual(am.confidence_for("exec_from_tmp"), "weak")
        self.assertEqual(am.confidence_for("sensitive_file_access", "sudoers"), "weak")
        self.assertEqual(am.confidence_for("persistence_write", "accounts"), "partial")


class Lookup(unittest.TestCase):

    def test_every_detection_name_is_mapped(self):
        for module in PLAIN:
            self.assertIsNotNone(am.technique_for(module.DETECTION_NAME), module.DETECTION_NAME)
        self.assertEqual(sfa.DETECTION_NAME, "sensitive_file_access")
        self.assertIn(sfa.DETECTION_NAME, am.CATEGORY_TABLES)
        self.assertIn(pers.FILE_DETECTION, am.CATEGORY_TABLES)
        self.assertIn(pers.COMMAND_DETECTION, am.CATEGORY_TABLES)

    def test_none_only_for_an_unknown_key(self):
        for name, table in am.CATEGORY_TABLES.items():
            for category in table:
                self.assertIsNotNone(am.technique_for(name, category))
                self.assertIsNotNone(am.confidence_for(name, category))
            self.assertIsNone(am.technique_for(name, "no-such-category"))
            self.assertIsNone(am.technique_for(name))
        for name in am.DETECTIONS:
            self.assertIsNone(am.technique_for(name, "category"))
        self.assertIsNone(am.technique_for("no_such_detection"))
        self.assertIsNone(am.confidence_for("no_such_detection"))

    def test_every_persistence_category_is_covered_and_nothing_extra(self):
        produced = set(pers.EXACT.values()) | {n for _, n in pers.PREFIX} | set(pers.HOME_EXACT.values()) \
            | {n for _, n in pers.HOME_PREFIX}
        self.assertEqual(produced, set(am.PERSISTENCE_FILE))
        self.assertEqual(set(PERSIST_PATHS), set(am.PERSISTENCE_FILE))
        for category, path in PERSIST_PATHS.items():
            self.assertEqual(pers.category_of(path), category, path)

    def test_every_sensitive_path_has_a_category(self):
        paths = list(sfa.TIER1_EXACT) + [p + "x" for p in sfa.TIER1_PREFIX] + list(sfa.TIER2_EXACT)
        paths += ["/root/.ssh/id_rsa", "/home/bob/.ssh/id_ed25519", "/home/bob/.ssh/anything"]
        for path in paths:
            self.assertIsNotNone(sfa.tier_of(path), path)
            category = am.sensitive_category(path)
            self.assertIn(category, am.SENSITIVE_FILE, path)
        for category, group in SENSITIVE_PATHS.items():
            for path in group:
                self.assertEqual(am.sensitive_category(path), category, path)
        self.assertEqual(set(SENSITIVE_PATHS), set(am.SENSITIVE_FILE))
        self.assertIsNone(am.sensitive_category("/etc/hosts"))


class OnAlerts(unittest.TestCase):

    def test_persistence_write_alerts_carry_the_technique_of_their_category(self):
        paths = sorted(PERSIST_PATHS.items())
        events = [event(100 + i, "file_open", path=path, flags=1, ret=3) for i, (_, path) in enumerate(paths)]
        alerts = run_alerts(events, pers.detect)
        self.assertEqual(len(alerts), len(paths))
        for a, (category, _) in zip(alerts, paths):
            self.assertEqual(a["detection"], "persistence_write")
            self.assertEqual(a["technique"], am.PERSISTENCE_FILE[category][0], category)

    def test_persistence_command_alerts_carry_the_technique_of_the_command(self):
        events = [event(100, "exec_success", exe="/usr/bin/crontab", argv=["crontab", "x"], cmdline="crontab x"),
                  event(101, "exec_success", exe="/usr/bin/systemctl", argv=["systemctl", "enable", "x"], cmdline="systemctl enable x")]
        alerts = run_alerts(events, pers.detect)
        self.assertEqual([(a["detection"], a["technique"]) for a in alerts],
                         [("persistence_command", "T1053.003"), ("persistence_command", "T1543.002")])

    def test_sensitive_file_access_alerts_carry_the_technique_of_the_path(self):
        pairs = [(c, p) for c, group in sorted(SENSITIVE_PATHS.items()) for p in group if c != "passwd"]
        events = [event(100 + i, "file_open", comm="cat", path=p, ret=3) for i, (_, p) in enumerate(pairs)]
        alerts = run_alerts(events, sfa.detect)
        self.assertEqual(len(alerts), len(pairs))
        for a, (category, path) in zip(alerts, pairs):
            self.assertEqual(a["technique"], am.SENSITIVE_FILE[category][0], path)

    def test_a_passwd_open_below_a_service_carries_its_technique(self):
        events = [event(50, "exec_success", comm="nginx", exe="/usr/sbin/nginx", argv=["nginx"], cmdline="nginx"),
                  event(60, "file_open", ppid=50, comm="cat", path="/etc/passwd", ret=3)]
        alerts = run_alerts(events, sfa.detect)
        self.assertEqual([a["technique"] for a in alerts], ["T1003.008"])


class Consistency(unittest.TestCase):
    """attack_map.sensitive_category repeats the path tiers of sensitive_file_access so both have to agree on every path (including any near misses)"""

    def sensitive_paths(self):
        paths = list(sfa.TIER1_EXACT) + list(sfa.TIER2_EXACT)
        paths += [p + "x" for p in sfa.TIER1_PREFIX] + [p + "sub/x" for p in sfa.TIER1_PREFIX]
        for base in ("/root", "/home/bob"):
            paths += ["%s/.ssh/%s" % (base, n) for n in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "anything", "key.pem")]
        return paths

    def near_misses(self):
        paths = list(sfa.TIER1_PREFIX) + [p.rstrip("/") for p in sfa.TIER1_PREFIX]
        paths += [p + s for p in list(sfa.TIER1_EXACT) + list(sfa.TIER2_EXACT) for s in ("-", ".bak", "x")]
        paths += ["/etc/hosts", "/etc/passwd.d/x", "/etc/sudoers.dx/y"]
        for base in ("/root", "/home/bob"):
            paths += ["%s/.ssh/%s" % (base, n) for n in ["id_rsa.pub"] + list(sfa.SSH_NOT_PRIVATE)]
            paths += ["%s/.ssh" % base, "%s/.ssh/" % base, "%s/.ssh/sub/id_rsa" % base, "%s/x/.ssh/id_rsa" % base]
        paths += ["/homebob/.ssh/id_rsa", "/home/.ssh/id_rsa", "/home/bob/sub/.ssh/id_rsa", "/var/.ssh/id_rsa"]
        return paths

    def test_both_agree_on_whether_a_path_is_sensitive(self):
        for path in self.sensitive_paths() + self.near_misses():
            self.assertEqual(sfa.tier_of(path) is not None, am.sensitive_category(path) is not None, path)

    def test_every_sensitive_path_has_the_category_its_tier_implies(self):
        for path in self.sensitive_paths():
            category = am.sensitive_category(path)
            tier = sfa.tier_of(path)
            self.assertEqual(tier, 2 if category == "passwd" else 1, path)
            self.assertIn(category, am.SENSITIVE_FILE, path)
        for path in ("/etc/shadow", "/etc/gshadow"):
            self.assertEqual(am.sensitive_category(path), "shadow")
        self.assertEqual(am.sensitive_category("/etc/sudoers.d/x"), "sudoers")
        self.assertEqual(am.sensitive_category("/home/bob/.ssh/id_rsa"), "ssh_private_key")

    def test_every_tier_one_and_two_constant_is_classified(self):
        for path in list(sfa.TIER1_EXACT) + list(sfa.TIER2_EXACT):
            self.assertIsNotNone(am.sensitive_category(path), path)
        for prefix in sfa.TIER1_PREFIX:
            self.assertIsNotNone(am.sensitive_category(prefix + "x"), prefix)

    def test_every_path_category_of_persistence_can_return_is_mapped(self):
        paths = list(pers.EXACT) + [p + "x" for p, _ in pers.PREFIX]
        for base in ("/root", "/home/bob"):
            paths += ["%s/%s" % (base, n) for n in pers.HOME_EXACT] + ["%s/%sx" % (base, n) for n, _ in pers.HOME_PREFIX]
        for path in paths:
            category = pers.category_of(path)
            self.assertIn(category, am.PERSISTENCE_FILE, path)
            self.assertIsNotNone(am.technique_for("persistence_write", category), path)


if __name__ == "__main__":
    unittest.main()
