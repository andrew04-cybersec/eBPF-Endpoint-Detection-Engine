"""
tests for download_chmod_exec.py
every event here is a !!constructed fixture, not captured output!!
"""
import copy
import io
import json
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
DET_DIR = os.path.dirname(HERE)
sys.path.insert(0, DET_DIR)

import download_chmod_exec as dce  # noqa: E402
import runner  # noqa: E402

REQUIRED = ("alert_schema_version", "alert_seq", "detection", "technique", "ts_ns", "process",
            "ancestry", "ancestry_stop", "evidence", "evidence_dropped", "data_quality")
SEC = 1000000000
URL = "http://127.0.0.1:8000/files/app"


def ex(pid, ts, ppid, exe, argv, start=None, comm="x", **extra):
    start = pid * 10 if start is None else start
    event = {"schema_version": 1, "type": "exec_success", "ts_ns": ts, "pid": pid, "tid": pid,
             "comm": comm, "ppid": ppid, "uid": 0, "gid": 0, "start_time_ns": start,
             "process_key": "%d:%d" % (pid, start), "filename": exe, "exe": exe,
             "filename_truncated": False, "user_read_failed": False,
             "argv": list(argv), "cmdline": " ".join(argv), "attempt_joined": True}
    event.update(extra)
    return event


def parent_shell(pid=100):
    return ex(pid, 1, 1, "/bin/bash", ["bash"], comm="bash")


def curl(pid, ts, argv, ppid=100):
    return ex(pid, ts, ppid, "/usr/bin/curl", ["curl"] + argv)


def wget(pid, ts, argv, ppid=100):
    return ex(pid, ts, ppid, "/usr/bin/wget", ["wget"] + argv)


def chmod(pid, ts, argv, ppid=100):
    return ex(pid, ts, ppid, "/bin/chmod", ["chmod"] + argv)


def run_events(events, detections=None):
    lines = [(json.dumps(e) + "\n").encode() for e in events]
    out = io.StringIO()
    graph, ctx, stats = runner.run(lines, runner.alert.AlertSink(out, None), detections=detections)
    alerts = [json.loads(l) for l in out.getvalue().splitlines()]
    return alerts, graph, ctx, stats


def only_chain(events):
    return run_events(events, detections=[dce.detect])


def chain(download, mode, target, final, gap=SEC, ppid=100):
    return [parent_shell(ppid)] + download + [chmod(300, 20 * SEC, [mode, target], ppid)] + [final]


def absolute_chain(path="/opt/work/app", mode="+x", final_ts=30 * SEC, download_ts=10 * SEC):
    return [parent_shell(), curl(200, download_ts, ["-o", path, URL]),
            chmod(300, 20 * SEC, [mode, path]), ex(400, final_ts, 100, path, [path])]


#three steps by absolute path and also how each download tool names its output
class Chain(unittest.TestCase):

    def test_full_chain_by_absolute_path_alerts_once(self):
        alerts, _, _, stats = only_chain(absolute_chain())
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        for field in REQUIRED:
            self.assertIn(field, a)
        self.assertEqual(a["detection"], "download_chmod_exec")
        self.assertIsNone(a["technique"])
        self.assertEqual(a["process"]["pid"], 400)
        self.assertEqual([e["argv"][0] for e in a["evidence"]], ["curl", "chmod", "/opt/work/app"])
        self.assertEqual(a["ts_ns"], 30 * SEC)
        self.assertEqual(stats["alerts"], {"download_chmod_exec": 1})

    def test_curl_output_forms(self):
        for argv in (["-o", "/opt/a", URL], ["-o/opt/a", URL], ["--output", "/opt/a", URL],
                     ["--output=/opt/a", URL], ["-sSLo", "/opt/a", URL], ["-fsSLo/opt/a", URL]):
            alerts, _, _, _ = only_chain(absolute_chain("/opt/a")[:1] + [curl(200, 10 * SEC, argv)]
                                         + absolute_chain("/opt/a")[2:])
            self.assertEqual(len(alerts), 1, argv)

    def test_curl_remote_name_saves_in_the_current_directory(self):
        events = [parent_shell(), curl(200, 10 * SEC, ["-sSLO", URL]), chmod(300, 20 * SEC, ["+x", "app"]),
                  ex(400, 30 * SEC, 100, "./app", ["./app"])]
        alerts, _, _, _ = only_chain(events)
        self.assertEqual(len(alerts), 1)
        events[1] = curl(200, 10 * SEC, ["--remote-name", URL + "?x=1#frag"])
        self.assertEqual(len(only_chain(events)[0]), 1)

    def test_wget_forms(self):
        for argv, target in ((["-O", "/opt/a", URL], "/opt/a"), (["-O/opt/a", URL], "/opt/a"),
                             (["--output-document=/opt/a", URL], "/opt/a"),
                             (["--output-document", "/opt/a", URL], "/opt/a"),
                             (["-qO", "/opt/a", URL], "/opt/a"),
                             (["-P", "/opt/dl", URL], "/opt/dl/app"),
                             (["--directory-prefix=/opt/dl", URL], "/opt/dl/app")):
            events = [parent_shell(), wget(200, 10 * SEC, argv), chmod(300, 20 * SEC, ["a+x", target]),
                      ex(400, 30 * SEC, 100, target, [target])]
            self.assertEqual(len(only_chain(events)[0]), 1, argv)

    def test_wget_default_name_in_the_current_directory(self):
        events = [parent_shell(), wget(200, 10 * SEC, [URL]), chmod(300, 20 * SEC, ["755", "app"]),
                  ex(400, 30 * SEC, 100, "app", ["app"])]
        self.assertEqual(len(only_chain(events)[0]), 1)
        events[1] = wget(200, 10 * SEC, ["http://127.0.0.1:8000/dir/"])
        events[2] = chmod(300, 20 * SEC, ["755", "index.html"])
        events[3] = ex(400, 30 * SEC, 100, "./index.html", ["./index.html"])
        self.assertEqual(len(only_chain(events)[0]), 1)

    def test_parsers_directly(self):
        self.assertEqual(dce.parse_curl(["-o", "-", URL]), ([], 1, False))
        self.assertEqual(dce.parse_curl([URL]), ([], 1, False))
        self.assertEqual(dce.parse_curl(["-O"]), ([], 0, True))
        self.assertEqual(dce.parse_curl(["-H", "Accept: x", "-Afoo", "-o", "f", URL]), (["f"], 0, False))
        self.assertEqual(dce.parse_wget(["-O-", URL]), ([], 1, False))
        self.assertEqual(dce.parse_wget(["-q"]), ([], 0, True))
        self.assertEqual(dce.parse_wget(["-P", "/d", "-O", "x", URL]), (["x"], 0, False))
        self.assertEqual(dce.url_name("http://h/a/b.sh?x=1#y"), "b.sh")
        self.assertEqual(dce.parse_chmod(["-R", "+x", "a", "b"]), (True, ["a", "b"]))
        self.assertEqual(dce.parse_chmod(["--", "+x", "a"]), (True, ["a"]))
        self.assertEqual(dce.parse_chmod(["+x"]), (False, []))

    def test_chmod_modes(self):
        for mode in ("+x", "a+x", "u+x", "ug+x", "=rwx", "a=rx", "755", "700", "0755", "4755", "711", "a+rx,u-x", "u+rw,g+x"):
            self.assertTrue(dce.is_exec_mode(mode), mode)
        for mode in ("644", "600", "0644", "u-x", "a-x", "+r", "u=rw", "g+w", "1644", "x", "+X", "99", "", "=u", "a+rw,g-x"):
            self.assertFalse(dce.is_exec_mode(mode), mode)

    def test_chmod_with_each_octal_mode_completes_the_chain(self):
        for mode in ("755", "700", "0755", "4755"):
            alerts, _, _, _ = only_chain(absolute_chain(mode=mode))
            self.assertEqual(len(alerts), 1, mode)

    def test_path_is_cleaned_before_matching(self):
        events = absolute_chain("/opt/work/app")
        events[2] = chmod(300, 20 * SEC, ["+x", "/opt//work/./x/../app"])
        events[3] = ex(400, 30 * SEC, 100, "/opt/work/../work/app", ["app"])
        self.assertEqual(len(only_chain(events)[0]), 1)


#sequences that must not alert
class NoAlert(unittest.TestCase):

    def test_missing_steps(self):
        events = absolute_chain()
        self.assertEqual(only_chain(events[:2] + events[3:])[0], [])
        self.assertEqual(only_chain([events[0]] + events[2:])[0], [])
        self.assertEqual(only_chain(events[:3])[0], [])

    def test_chmod_without_an_execute_bit(self):
        for mode in ("644", "u-x", "a+rw", "1644"):
            self.assertEqual(only_chain(absolute_chain(mode=mode))[0], [], mode)

    def test_wrong_order(self):
        events = absolute_chain()
        swapped = [events[0], events[2], events[1], events[3]]
        swapped[1] = chmod(300, 5 * SEC, ["+x", "/opt/work/app"])
        self.assertEqual(only_chain(swapped)[0], [])
        early_exec = [events[0], events[1], ex(400, 15 * SEC, 100, "/opt/work/app", ["x"]), events[2]]
        self.assertEqual(only_chain(early_exec)[0], [])

    def test_window(self):
        late = absolute_chain(final_ts=10 * SEC + dce.CHAIN_WINDOW_NS + 1)
        self.assertEqual(only_chain(late)[0], [])
        edge = absolute_chain(final_ts=10 * SEC + dce.CHAIN_WINDOW_NS)
        self.assertEqual(len(only_chain(edge)[0]), 1)

    def test_a_different_path(self):
        events = absolute_chain()
        events[3] = ex(400, 30 * SEC, 100, "/opt/work/other", ["other"])
        self.assertEqual(only_chain(events)[0], [])
        events = absolute_chain()
        events[2] = chmod(300, 20 * SEC, ["+x", "/opt/work/other"])
        self.assertEqual(only_chain(events)[0], [])

    def test_stdout_and_unparsable_downloads_are_counted_not_tracked(self):
        events = [parent_shell(), curl(200, 10 * SEC, ["-o", "-", URL]), wget(201, 11 * SEC, ["-O-", URL]),
                  curl(202, 12 * SEC, ["-O"]), chmod(300, 20 * SEC, ["+x", "-"]),
                  ex(400, 30 * SEC, 100, "-", ["-"])]
        alerts, _, ctx, _ = only_chain(events)
        self.assertEqual(alerts, [])
        self.assertEqual(ctx["counts"]["download_to_stdout"], 2)
        self.assertEqual(ctx["counts"]["unevaluable_download_unparsed"], 1)

    def test_other_events_and_odd_events_are_ignored(self):
        events = [{"schema_version": 1, "type": "exec_success"}, {"schema_version": 1, "type": "exec_success", "argv": 5,
                  "exe": "/usr/bin/curl", "ts_ns": 1}, {"schema_version": 1, "type": "exec_success", "exe": "/bin/chmod",
                  "argv": ["chmod", 5, None], "ts_ns": 2}, {"schema_version": 1, "type": "file_open", "path": "/etc/passwd"},
                  ex(5, "x", 1, "/usr/bin/curl", ["curl", "-o", "f", URL])]
        alerts, _, ctx, stats = only_chain(events)
        self.assertEqual(alerts, [])
        self.assertEqual(stats["detection_errors"], 0)

    def test_truncated_or_unreadable_final_filename(self):
        for flag in ({"filename_truncated": True}, {"user_read_failed": True}):
            events = absolute_chain()
            events[3] = ex(400, 30 * SEC, 100, "/opt/work/app", ["app"], **flag)
            self.assertEqual(only_chain(events)[0], [], flag)


#relative names count only inside one parent
class Relative(unittest.TestCase):

    def steps(self, parents=(100, 100, 100)):
        return [parent_shell(100), ex(101, 2, 1, "/bin/bash", ["bash"], comm="bash"),
                curl(200, 10 * SEC, ["-O", URL], ppid=parents[0]),
                chmod(300, 20 * SEC, ["+x", "app"], ppid=parents[1]),
                ex(400, 30 * SEC, parents[2], "./app", ["./app"])]

    def test_same_parent_alerts(self):
        alerts, _, _, _ = only_chain(self.steps())
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["process"]["exe"], "./app")

    def test_different_parents_do_not_alert(self):
        for parents in ((101, 100, 100), (100, 101, 100), (100, 100, 101)):
            alerts, _, ctx, _ = only_chain(self.steps(parents))
            self.assertEqual(alerts, [], parents)
            self.assertEqual(ctx["counts"].get("unevaluable", 0), 0, parents)

    def test_placeholder_parent_is_unevaluable(self):
        events = [curl(200, 10 * SEC, ["-O", URL], ppid=999), chmod(300, 20 * SEC, ["+x", "app"], ppid=999),
                  ex(400, 30 * SEC, 999, "./app", ["./app"])]
        alerts, graph, ctx, _ = only_chain(events)
        self.assertEqual(alerts, [])
        self.assertTrue(graph.nodes["999:unknown"].placeholder)
        self.assertEqual(ctx["counts"]["unevaluable_relative_unknown_parent"], 1)

    def test_final_exec_with_an_unknown_parent_is_unevaluable_only_for_a_tracked_name(self):
        events = self.steps()[:4] + [ex(400, 30 * SEC, 999, "./app", ["./app"]),
                                     ex(401, 31 * SEC, 999, "./other", ["./other"])]
        alerts, _, ctx, _ = only_chain(events)
        self.assertEqual(alerts, [])
        self.assertEqual(ctx["counts"]["unevaluable_relative_unknown_parent"], 1)

    def test_absolute_paths_match_across_parents(self):
        events = [parent_shell(100), ex(101, 2, 1, "/bin/bash", ["bash"], comm="bash"),
                  curl(200, 10 * SEC, ["-o", "/opt/a", URL], ppid=100), chmod(300, 20 * SEC, ["+x", "/opt/a"], ppid=101),
                  ex(400, 30 * SEC, 999, "/opt/a", ["a"])]
        self.assertEqual(len(only_chain(events)[0]), 1)


#counts, limits, purity, and the other detections next to it
class Together(unittest.TestCase):

    def test_second_exec_of_the_same_path_alerts_again(self):
        events = absolute_chain() + [ex(401, 40 * SEC, 100, "/opt/work/app", ["app"])]
        alerts, _, _, _ = only_chain(events)
        self.assertEqual([a["process"]["pid"] for a in alerts], [400, 401])
        self.assertEqual([a["alert_seq"] for a in alerts], [1, 2])

    def test_a_new_download_of_the_path_starts_a_new_chain(self):
        events = absolute_chain()[:3] + [curl(210, 25 * SEC, ["-o", "/opt/work/app", URL]),
                                         ex(400, 30 * SEC, 100, "/opt/work/app", ["app"])]
        self.assertEqual(only_chain(events)[0], [])

    def test_oldest_tracked_path_is_evicted(self):
        events = [parent_shell()]
        for i, name in enumerate(("a", "b", "c")):
            events.append(curl(200 + i, (10 + i) * SEC, ["-o", "/opt/" + name, URL]))
        for i, name in enumerate(("a", "b", "c")):
            events.append(chmod(300 + i, (20 + i) * SEC, ["+x", "/opt/" + name]))
        for i, name in enumerate(("a", "b", "c")):
            events.append(ex(400 + i, (30 + i) * SEC, 100, "/opt/" + name, [name]))
        with mock.patch.object(dce, "MAX_TRACKED_PATHS", 2):
            alerts, _, _, _ = only_chain(events)
        self.assertEqual(sorted(a["process"]["exe"] for a in alerts), ["/opt/b", "/opt/c"])

    def test_stored_argv_text_is_cut_and_the_input_is_not(self):
        events = absolute_chain()
        before = copy.deepcopy(events)
        with mock.patch.object(dce, "MAX_STORED_ARGV_CHARS", 12):
            alerts, _, _, _ = only_chain(events)
        self.assertEqual(events, before)
        first = alerts[0]["evidence"][0]
        self.assertTrue(first["stored_text_cut_by_detection"])
        self.assertLessEqual(len(first["cmdline"]), 12)

    def test_inputs_are_not_changed_and_output_is_repeatable(self):
        events = absolute_chain()
        before = copy.deepcopy(events)
        first = run_events(events)
        self.assertEqual(events, before)
        graph_before = json.dumps(first[1].to_dict(), sort_keys=True)
        dce.detect(first[1], events[3], {"counts": {}, "attempts": {}})
        self.assertEqual(json.dumps(first[1].to_dict(), sort_keys=True), graph_before)
        self.assertEqual(events, before)
        self.assertEqual(first[0], run_events(copy.deepcopy(events))[0])

    def test_state_is_kept_per_detection_in_ctx(self):
        _, _, ctx, _ = run_events(absolute_chain())
        self.assertIn("download_chmod_exec", ctx["state"])
        self.assertEqual(dce.detect(None, {"type": "file_open"}, {}), None)

    def test_registered_in_the_runner(self):
        self.assertEqual([d.__module__ for d in runner.DETECTIONS],
                         ["shell_from_service", "exec_from_tmp", "download_chmod_exec"])

    def test_chain_completed_from_tmp_gives_both_alerts(self):
        alerts, _, _, stats = run_events(absolute_chain("/tmp/work/app"))
        self.assertEqual(sorted(a["detection"] for a in alerts), ["download_chmod_exec", "exec_from_tmp"])
        for a in alerts:
            for field in REQUIRED:
                self.assertIn(field, a)
        self.assertEqual(stats["alerts"], {"download_chmod_exec": 1, "exec_from_tmp": 1})

    def test_other_detections_still_alert(self):
        service = ex(50, 1, 1, "/usr/sbin/nginx", ["nginx"], comm="nginx")
        shell = ex(51, 2, 50, "/bin/sh", ["sh", "-c", "x"], comm="sh")
        alerts, _, _, _ = run_events([service, shell])
        self.assertEqual([a["detection"] for a in alerts], ["shell_from_service"])


if __name__ == "__main__":
    unittest.main()
