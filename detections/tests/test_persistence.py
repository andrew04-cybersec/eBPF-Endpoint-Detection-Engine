"""
tests for persistence.py
every event here is a !!constructed fixture, not captured output!!
"""
import copy
import io
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DET_DIR = os.path.dirname(HERE)
sys.path.insert(0, DET_DIR)

import runner  #noqa: E402
import persistence as pers  #noqa: E402

HEADER = os.path.join(os.path.dirname(DET_DIR), "telemetry", "src", "sensitive_paths.h")
REQUIRED = ("alert_schema_version", "alert_seq", "detection", "technique", "ts_ns", "process",
            "ancestry", "ancestry_stop", "evidence", "evidence_dropped", "data_quality")
NO = object()
WRITE = 0o1 | 0o100 | 0o1000


def opened(pid, path, flags=WRITE, ret=3, comm="bash", ts=None):
    event = {"schema_version": 1, "type": "file_open", "ts_ns": pid if ts is None else ts, "pid": pid, "tid": pid,
             "comm": comm, "path": path, "path_truncated": False, "ppid": 1, "uid": 0, "gid": 0,
             "start_time_ns": pid * 10, "user_read_failed": False}
    if flags is not NO:
        event["flags"] = flags
    if ret is not NO:
        event["ret"] = ret
    return event


def started(pid, exe, args, **extra):
    event = {"schema_version": 1, "type": "exec_success", "ts_ns": pid, "pid": pid, "tid": pid,
             "comm": os.path.basename(exe)[:15], "ppid": 1, "uid": 0, "gid": 0, "start_time_ns": pid * 10,
             "filename": exe, "exe": exe, "argv": [os.path.basename(exe)] + args,
             "cmdline": " ".join([os.path.basename(exe)] + args)}
    event.update(extra)
    return event


def run_events(events):
    lines = [(json.dumps(e) + "\n").encode() for e in events]
    out = io.StringIO()
    graph, ctx, stats = runner.run(lines, runner.alert.AlertSink(out, None), detections=[pers.detect])
    return [json.loads(l) for l in out.getvalue().splitlines()], graph, ctx, stats


def persist_counts(ctx):
    return {k: v for k, v in ctx["counts"].items() if k.startswith("persist_")}


class FileCategories(unittest.TestCase):

    def test_one_path_per_category_alerts(self):
        paths = {"ld_preload": "/etc/ld.so.preload", "ld_conf": "/etc/ld.so.conf.d/evil.conf",
                 "cron": "/etc/cron.d/job", "systemd": "/etc/systemd/system/x.service",
                 "init": "/etc/rc.local", "shell_startup": "/etc/profile.d/x.sh", "pam": "/etc/pam.d/sudo",
                 "motd": "/etc/update-motd.d/99-x", "user_autostart": "/root/.config/autostart/x.desktop",
                 "ssh_keys": "/root/.ssh/authorized_keys", "accounts": "/etc/passwd"}
        for name, path in paths.items():
            self.assertEqual(pers.category_of(path), name, path)
            alerts, _, ctx, stats = run_events([opened(200, path)])
            self.assertEqual([a["detection"] for a in alerts], ["persistence_write"], path)
            self.assertEqual(alerts[0]["evidence"][0]["path"], path)
            self.assertEqual(persist_counts(ctx), {}, path)

    def test_every_listed_path_and_prefix_classifies(self):
        for path in list(pers.EXACT) + [p + "x" for p, _ in pers.PREFIX]:
            self.assertIsNotNone(pers.category_of(path), path)
        for name in pers.HOME_EXACT:
            for home in ("/root/", "/home/bob/"):
                self.assertIsNotNone(pers.category_of(home + name), home + name)
        for prefix, _ in pers.HOME_PREFIX:
            self.assertIsNotNone(pers.category_of("/home/bob/" + prefix + "x"))

    def test_home_forms_and_the_one_level_rule(self):
        for path in ("/root/.bashrc", "/home/bob/.bashrc", "/home/bob/.zshrc", "/home/bob/.ssh/authorized_keys2",
                     "/home/bob/.config/systemd/user/x.service"):
            self.assertIsNotNone(pers.category_of(path), path)
        for path in ("/home/bob/sub/.bashrc", "/home/bob/sub/.ssh/authorized_keys", "/root/sub/.profile",
                     "/home/.bashrc", "/home/bob/.config/other/x", "/home/bob/.ssh/id_rsa", "/etc/os-release",
                     "/etc/cron.d/", "/home/bob/.config/autostart/"):
            self.assertIsNone(pers.category_of(path), path)

    def test_credential_files_belong_to_sensitive_file_access(self):
        for path in ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d/90-x"):
            alerts, _, ctx, _ = run_events([opened(200, path)])
            self.assertEqual(alerts, [], path)
            self.assertEqual(persist_counts(ctx), {}, path)

    def test_path_is_cleaned_before_matching(self):
        alerts, _, _, _ = run_events([opened(200, "/etc/cron.d/../cron.d/x")])
        self.assertEqual(len(alerts), 1)
        alerts, _, _, _ = run_events([opened(200, "//etc//cron.d/x"), opened(201, "/etc/cron.d/../os-release")])
        self.assertEqual(len(alerts), 1)

    def test_missing_and_relative_paths_are_counted(self):
        alerts, _, ctx, _ = run_events([opened(200, ""), opened(201, None), opened(202, "etc/cron.d/x")])
        self.assertEqual(alerts, [])
        self.assertEqual(persist_counts(ctx), {"persist_no_path": 2, "persist_relative_path": 1})


class FileOutcome(unittest.TestCase):
    PATH = "/etc/cron.d/x"

    def test_each_write_flag_form_alerts(self):
        for flags in (0o1, 0o2, 0o100, 0o1000, 0o2000, 0o1101, 0o2102):
            alerts, _, _, _ = run_events([opened(200, self.PATH, flags=flags)])
            self.assertEqual(len(alerts), 1, oct(flags))

    def test_read_only_open_does_not_alert(self):
        alerts, _, ctx, _ = run_events([opened(200, self.PATH, flags=0), opened(201, self.PATH, flags=0o2000000)])
        self.assertEqual(alerts, [])
        self.assertEqual(persist_counts(ctx), {"persist_read_only": 2})

    def test_missing_or_bad_flags_and_ret_are_counted(self):
        events = [opened(200, self.PATH, flags=NO), opened(201, self.PATH, flags="1"), opened(202, self.PATH, ret=NO),
                  opened(203, self.PATH, ret=True), opened(204, self.PATH, ret=-2), opened(205, self.PATH, ret=-13)]
        alerts, _, ctx, _ = run_events(events)
        self.assertEqual(alerts, [])
        self.assertEqual(persist_counts(ctx), {"persist_no_flags": 2, "persist_no_return_value": 2,
                                               "persist_failed_open": 2})

    def test_every_expected_writer_is_suppressed_and_an_editor_is_not(self):
        for n, comm in enumerate(pers.EXPECTED_WRITERS):
            alerts, _, ctx, _ = run_events([opened(200 + n, self.PATH, comm=comm)])
            self.assertEqual(alerts, [], comm)
            self.assertEqual(persist_counts(ctx), {"persist_expected_writer": 1}, comm)
        for comm in ("vim", "nano", "bash", "sh", "python3"):
            alerts, _, _, _ = run_events([opened(200, self.PATH, comm=comm)])
            self.assertEqual(len(alerts), 1, comm)

    def test_dedup_per_process_and_path(self):
        events = [opened(200, self.PATH, ts=1), opened(200, self.PATH, ts=2), opened(200, "/etc/cron.d/y", ts=3),
                  opened(201, self.PATH, ts=4)]
        alerts, _, ctx, _ = run_events(events)
        self.assertEqual(len(alerts), 3)
        self.assertEqual(persist_counts(ctx), {"persist_duplicate_write": 1})

    def test_a_suppressed_write_is_not_remembered(self):
        alerts, _, _, _ = run_events([opened(200, self.PATH, ret=-2), opened(200, self.PATH)])
        self.assertEqual(len(alerts), 1)

    def test_dedup_memory_is_bounded_and_evicts_the_oldest(self):
        old = pers.MAX_SEEN_WRITES
        pers.MAX_SEEN_WRITES = 2
        try:
            events = [opened(200, "/etc/cron.d/a", ts=1), opened(200, "/etc/cron.d/b", ts=2),
                      opened(200, "/etc/cron.d/c", ts=3), opened(200, "/etc/cron.d/a", ts=4)]
            alerts, _, ctx, _ = run_events(events)
            self.assertEqual(len(alerts), 4)
            self.assertEqual(persist_counts(ctx), {})
        finally:
            pers.MAX_SEEN_WRITES = old


class Commands(unittest.TestCase):

    def cmd(self, exe, args, **extra):
        alerts, _, ctx, _ = run_events([started(300, exe, args, **extra)])
        return alerts, ctx

    def test_crontab_install_forms_alert(self):
        for args in (["mycron"], ["-"], ["-e"], ["-u", "root", "mycron"], ["-uroot", "mycron"], ["-i", "-e"],
                     ["-u", "bob", "-e"], ["--", "-odd"]):
            alerts, _ = self.cmd("/usr/bin/crontab", args)
            self.assertEqual([a["detection"] for a in alerts], ["persistence_command"], args)
            self.assertEqual(alerts[0]["evidence"][0]["argv"][1:], args)

    def test_crontab_other_forms_do_not_alert(self):
        for args in ([], ["-l"], ["-r"], ["-u", "root", "-l"], ["-u", "root"], ["-n", "mycron"], ["-l", "mycron"]):
            alerts, ctx = self.cmd("/usr/bin/crontab", args)
            self.assertEqual(alerts, [], args)
            self.assertEqual(persist_counts(ctx), {}, args)

    def test_crontab_unparsable_is_counted(self):
        for args in (["-u"], ["-z", "f"]):
            alerts, ctx = self.cmd("/usr/bin/crontab", args)
            self.assertEqual(alerts, [], args)
            self.assertEqual(persist_counts(ctx), {"persist_command_unparsed": 1}, args)
        alerts, ctx = self.cmd("/usr/bin/crontab", ["-l"], argv_truncated=True)
        self.assertEqual(persist_counts(ctx), {"persist_command_unparsed": 1})
        alerts, ctx = self.cmd("/usr/bin/crontab", [], argv=None)
        self.assertEqual(persist_counts(ctx), {"persist_command_unparsed": 1})

    def test_systemctl_install_verbs_alert(self):
        for args in (["enable", "x.service"], ["reenable", "x"], ["link", "/a/x.service"],
                     ["--user", "enable", "x"], ["--now", "enable", "x"], ["-H", "host", "enable", "x"],
                     ["--root", "/r", "enable", "x"], ["--root=/r", "enable", "x"], ["-ft", "service", "enable"],
                     ["-tservice", "enable"], ["--", "enable"]):
            alerts, _ = self.cmd("/usr/bin/systemctl", args)
            self.assertEqual([a["detection"] for a in alerts], ["persistence_command"], args)

    def test_systemctl_other_verbs_do_not_alert(self):
        for args in ([], ["status", "x"], ["start", "x"], ["daemon-reload"], ["--user", "status", "enable"],
                     ["-p", "enable", "show", "x"], ["--state", "enable", "list-units"], ["disable", "x"]):
            alerts, ctx = self.cmd("/usr/bin/systemctl", args)
            self.assertEqual(alerts, [], args)
            self.assertEqual(persist_counts(ctx), {}, args)

    def test_systemctl_unparsable_is_counted(self):
        alerts, ctx = self.cmd("/usr/bin/systemctl", ["--root"])
        self.assertEqual(persist_counts(ctx), {"persist_command_unparsed": 1})

    def test_judged_by_exe_not_comm_and_other_programs_ignored(self):
        alerts, _ = self.cmd("/work/crontab", ["f"], comm="something")
        self.assertEqual(len(alerts), 1)
        alerts, ctx = self.cmd("/usr/bin/ls", ["enable"], comm="crontab")
        self.assertEqual(alerts, [])
        self.assertEqual(persist_counts(ctx), {})

    def test_every_exec_is_its_own_alert(self):
        alerts, _, _, _ = run_events([started(300, "/usr/bin/crontab", ["f"]), started(300, "/usr/bin/crontab", ["f"], ts_ns=9)])
        self.assertEqual(len(alerts), 2)


class General(unittest.TestCase):

    def events(self):
        return [started(300, "/usr/bin/systemctl", ["enable", "x"]), opened(200, "/etc/cron.d/x"),
                opened(200, "/etc/cron.d/x", ts=5), opened(201, "/etc/pam.d/sudo", flags=0),
                started(301, "/usr/bin/crontab", ["-l"]), {"schema_version": 1, "type": "net_connect"}]

    def test_alerts_have_every_required_field(self):
        alerts, _, _, _ = run_events(self.events())
        self.assertEqual(len(alerts), 2)
        for a in alerts:
            self.assertTrue(all(f in a for f in REQUIRED))
            self.assertIsNone(a["technique"])

    def test_no_mutation_of_graph_or_events(self):
        events = self.events()
        before = copy.deepcopy(events)
        lines = [(json.dumps(e) + "\n").encode() for e in events]
        graph = runner.process_graph.ProcessGraph()
        for l in lines:
            graph.ingest_line(l)
        snap = repr(sorted(graph.nodes.items(), key=lambda kv: kv[0]))
        ctx = {"counts": {}, "attempts": runner.OrderedDict()}
        for e in events:
            pers.detect(graph, e, ctx)
        self.assertEqual(events, before)
        self.assertEqual(repr(sorted(graph.nodes.items(), key=lambda kv: kv[0])), snap)

    def test_two_runs_give_identical_output(self):
        first = run_events(self.events())
        second = run_events(self.events())
        self.assertEqual(first[0], second[0])
        self.assertEqual(first[2]["counts"], second[2]["counts"])

    def test_odd_events_never_crash(self):
        odd = [None, 5, "x", [], {}, {"type": "file_open"}, {"type": "exec_success"},
               {"type": "exec_success", "exe": 5}, {"type": "exec_success", "exe": "/usr/bin/crontab", "argv": [1]},
               {"type": "file_open", "path": "/etc/cron.d/x", "flags": 1.5}]
        ctx = {"counts": {}, "attempts": runner.OrderedDict()}
        graph = runner.process_graph.ProcessGraph()
        for e in odd:
            pers.detect(graph, e, ctx)


class HeaderConsistency(unittest.TestCase):

    def entries(self, macro, text):
        m = re.search(r"#define %s\(X\)((?:[^\n]*\\\n)*[^\n]*)" % macro, text)
        return re.findall(r'X\("([^"]+)"\)', m.group(1)) if m else []

    def test_every_write_intent_entry_has_a_category(self):
        try:
            with open(HEADER) as f:
                text = f.read()
        except OSError as e:
            self.skipTest("cannot read %s: %s" % (HEADER, e))
        exact = self.entries("WRITE_INTENT_EXACT", text)
        prefix = self.entries("WRITE_INTENT_PREFIX", text)
        home_exact = self.entries("WRITE_INTENT_HOME_EXACT", text)
        home_prefix = self.entries("WRITE_INTENT_HOME_PREFIX", text)
        if not (exact and prefix and home_exact and home_prefix):
            self.skipTest("could not parse the WRITE_INTENT lists in %s" % HEADER)
        for path in exact:
            self.assertIsNotNone(pers.category_of(path), path)
        for p in prefix + home_prefix:
            self.assertIsNotNone(pers.category_of(p + "x") if p.startswith("/") else pers.category_of("/home/u/" + p + "x"), p)
        for name in home_exact:
            self.assertIsNotNone(pers.category_of("/root/" + name), name)
            self.assertIsNotNone(pers.category_of("/home/u/" + name), name)


if __name__ == "__main__":
    unittest.main()
