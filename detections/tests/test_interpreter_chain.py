"""
tests for interpreter_chain.py
every event here is a !!constructed fixture, not captured output!!
"""
import copy
import io
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DET_DIR = os.path.dirname(HERE)
sys.path.insert(0, DET_DIR)

import interpreter_chain as ic  # noqa: E402
import runner  # noqa: E402
import shell_from_service as sfs  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(DET_DIR), "graph"))
import process_graph  # noqa: E402

REQUIRED = ("alert_schema_version", "alert_seq", "detection", "technique", "ts_ns", "process",
            "ancestry", "ancestry_stop", "evidence", "evidence_dropped", "data_quality")


def ex(pid, ppid, exe, args=(), comm=None, ts=None, typ="exec_success"):
    argv = [os.path.basename(exe)] + list(args)
    comm = os.path.basename(exe)[:15] if comm is None else comm
    ts = pid if ts is None else ts
    return {"schema_version": 1, "type": typ, "ts_ns": ts, "pid": pid, "tid": pid, "comm": comm,
            "ppid": ppid, "uid": 0, "gid": 0, "start_time_ns": pid * 10, "process_key": "%d:%d" % (pid, pid * 10),
            "filename": exe, "exe": exe, "filename_truncated": False, "user_read_failed": False,
            "argv": argv, "cmdline": " ".join(argv), "attempt_joined": True}


def line(specs, root_ppid=1):
    """a straight chain of exe & args from the root down with the pids 100, 200, 300, etc."""
    events = []
    for i, (exe, args) in enumerate(specs):
        events.append(ex(100 * (i + 1), root_ppid if i == 0 else 100 * i, exe, args))
    return events


def run_events(events, detections=None, graph=None):
    lines = [(json.dumps(e) + "\n").encode() for e in events]
    out = io.StringIO()
    graph, ctx, stats = runner.run(lines, runner.alert.AlertSink(out, None), detections=detections, graph=graph)
    alerts = [json.loads(l) for l in out.getvalue().splitlines()]
    return alerts, graph, ctx, stats


def only_chain(events, graph=None):
    return run_events(events, detections=[ic.detect], graph=graph)


def pids(alerts):
    return [a["process"]["pid"] for a in alerts]


def chain_counts(ctx):
    return {k: v for k, v in ctx["counts"].items() if k.startswith("chain_")}


BASH_C = ("/bin/bash", ["-c", "x"])
PY_C = ("/usr/bin/python3", ["-c", "y"])
SH_C = ("/bin/sh", ["-c", "z"])


class Rule(unittest.TestCase):

    def test_bash_python_sh_alerts_at_the_sh(self):
        events = line([BASH_C, PY_C, SH_C])
        alerts, graph, ctx, stats = only_chain(events)
        self.assertEqual(pids(alerts), [300])
        a = alerts[0]
        for field in REQUIRED:
            self.assertIn(field, a)
        self.assertEqual(a["detection"], "interpreter_chain")
        self.assertIsNone(a["technique"])
        self.assertEqual([c["comm"] for c in a["ancestry"]], ["sh", "python3", "bash"])
        self.assertEqual(a["ancestry_stop"], "root")
        self.assertEqual([e["type"] for e in a["evidence"]], ["exec_success"])
        self.assertEqual(stats["alerts"], {"interpreter_chain": 1})
        self.assertEqual(chain_counts(ctx), {})
        members, end = ic.chain_for(graph, "300:3000", events[2])
        self.assertEqual([(m["exe"], m["family"], m["inline"]) for m in members],
                         [("sh", "shell", True), ("python3", "python", True), ("bash", "shell", True)])
        self.assertEqual(end, "root")

    def test_a_chain_of_four_alerts_at_the_last_member_too(self):
        events = line([BASH_C, PY_C, SH_C, ("/usr/bin/perl", ["-e", "w"])])
        alerts, graph, _, _ = only_chain(events)
        self.assertEqual(pids(alerts), [300, 400])
        members, _ = ic.chain_for(graph, "400:4000", events[3])
        self.assertEqual([m["exe"] for m in members], ["perl", "sh", "python3", "bash"])

    def test_a_chain_of_two_does_not_alert_and_is_not_counted(self):
        alerts, _, ctx, _ = only_chain(line([BASH_C, PY_C]))
        self.assertEqual(alerts, [])
        self.assertEqual(chain_counts(ctx), {})

    def test_three_nested_shells_are_one_family(self):
        alerts, _, ctx, _ = only_chain(line([BASH_C, BASH_C, BASH_C]))
        self.assertEqual(alerts, [])
        self.assertEqual(chain_counts(ctx), {})

    def test_two_families_with_no_inline_option_do_not_alert(self):
        alerts, _, _, _ = only_chain(line([("/bin/bash", ["a.sh"]), ("/usr/bin/python3", ["b.py"]), ("/bin/sh", ["c.sh"])]))
        self.assertEqual(alerts, [])

    def test_an_inline_option_only_on_the_middle_member_alerts(self):
        alerts, _, _, _ = only_chain(line([("/bin/bash", ["a.sh"]), PY_C, ("/bin/sh", ["c.sh"])]))
        self.assertEqual(pids(alerts), [300])

    def test_inline_option_forms_of_each_family(self):
        forms = [("/usr/bin/python3", ["-c", "x"], True), ("/usr/bin/python3.12", ["-c", "x"], True),
                 ("/usr/bin/perl", ["-e", "x"], True), ("/usr/bin/perl", ["-E", "x"], True),
                 ("/usr/bin/ruby", ["-e", "x"], True), ("/usr/bin/php", ["-r", "x"], True),
                 ("/usr/bin/node", ["-e", "x"], True), ("/usr/bin/node", ["--eval", "x"], True),
                 ("/usr/bin/node", ["-p", "x"], True), ("/usr/bin/node", ["--print", "x"], True),
                 ("/bin/bash", ["-c", "x"], True), ("/bin/bash", ["-lc", "x"], True), ("/bin/zsh", ["-ic", "x"], True),
                 ("/usr/bin/python3", ["-lc", "x"], False), ("/usr/bin/perl", ["-le", "x"], False),
                 ("/usr/bin/ruby", ["-E", "UTF-8"], False), ("/usr/bin/php", ["-c", "x"], False),
                 ("/bin/bash", ["--rcfile", "x"], False), ("/bin/bash", ["-x", "x.sh"], False)]
        for exe, args, inline in forms:
            as_trigger = line([("/bin/sh", ["a.sh"]), ("/usr/bin/python3", ["b.py"]), (exe, args)])
            self.assertEqual(len(only_chain(as_trigger)[0]), 1 if inline else 0, ("trigger", exe, args))
            as_ancestor = line([("/bin/sh", ["a.sh"]), (exe, args), ("/usr/bin/python3", ["b.py"])])
            self.assertEqual(len(only_chain(as_ancestor)[0]), 1 if inline else 0, ("ancestor", exe, args))

    def test_the_trigger_uses_argv_and_falls_back_to_cmdline(self):
        events = line([("/bin/bash", ["a.sh"]), ("/usr/bin/python3", ["b.py"]), ("/bin/sh", ["c.sh"])])
        events[2]["argv"] = []
        events[2]["cmdline"] = "sh -c z"
        self.assertEqual(pids(only_chain(events)[0]), [300])
        events[2]["argv"] = ["sh", "c.sh"]
        self.assertEqual(only_chain(events)[0], [])


class Breaks(unittest.TestCase):

    def test_a_program_that_is_not_watched_ends_the_run(self):
        events = line([BASH_C, PY_C, ("/bin/ls", []), SH_C])
        alerts, graph, ctx, _ = only_chain(events)
        self.assertEqual(alerts, [])
        self.assertEqual(ic.chain_for(graph, "400:4000", events[3])[1], "not_watched")
        self.assertEqual(len(ic.chain_for(graph, "400:4000", events[3])[0]), 1)
        self.assertEqual(chain_counts(ctx), {})

    def test_a_short_run_ending_at_a_placeholder_is_counted(self):
        alerts, graph, ctx, _ = only_chain(line([BASH_C], root_ppid=999))
        self.assertEqual(alerts, [])
        self.assertTrue(graph.nodes["999:unknown"].placeholder)
        self.assertEqual(chain_counts(ctx), {"chain_incomplete": 1})
        _, _, ctx, _ = only_chain(line([PY_C, SH_C], root_ppid=999))
        self.assertEqual(chain_counts(ctx), {"chain_incomplete": 2})

    def test_a_run_long_enough_is_not_counted_when_it_ends_at_a_placeholder(self):
        alerts, _, ctx, _ = only_chain(line([BASH_C, PY_C, SH_C], root_ppid=999))
        self.assertEqual(pids(alerts), [300])
        self.assertEqual(chain_counts(ctx), {"chain_incomplete": 2})

    def test_a_short_run_ending_at_a_node_with_no_exec_history_is_counted(self):
        exited = {"schema_version": 1, "type": "exit", "ts_ns": 5, "pid": 100, "comm": "bash", "ppid": 1, "uid": 0,
                  "gid": 0, "start_time_ns": 1000, "process_key": "100:1000"}
        alerts, graph, ctx, _ = only_chain([exited, ex(200, 100, "/usr/bin/python3", ["-c", "y"])])
        self.assertEqual(alerts, [])
        self.assertEqual(graph.nodes["100:1000"].execs, [])
        self.assertEqual(chain_counts(ctx), {"chain_incomplete": 1})

    def test_a_node_with_only_a_failed_exec_has_no_exec_history(self):
        events = [ex(100, 1, "/bin/bash", typ="exec_failed"), ex(200, 100, "/usr/bin/python3", ["-c", "y"])]
        _, graph, ctx, _ = only_chain(events)
        self.assertEqual(len(graph.nodes["100:1000"].execs), 1)
        self.assertEqual(chain_counts(ctx), {"chain_incomplete": 1})

    def test_a_trigger_with_no_node_is_counted(self):
        events = line([BASH_C, PY_C])
        odd = ex(300, 200, "/bin/sh", ["-c", "z"])
        del odd["start_time_ns"]
        alerts, _, ctx, _ = only_chain(events + [odd])
        self.assertEqual(alerts, [])
        self.assertEqual(chain_counts(ctx), {"chain_not_in_graph": 1})

    def test_a_chain_cut_by_the_depth_cap_is_counted_when_short(self):
        events = line([BASH_C, PY_C, SH_C])
        alerts, graph, ctx, _ = only_chain(events, graph=process_graph.ProcessGraph(max_depth=2))
        self.assertEqual(alerts, [])
        self.assertEqual(graph.ancestry("300:3000")["stop"], "depth_cap")
        self.assertEqual(chain_counts(ctx), {"chain_incomplete": 1})


class Members(unittest.TestCase):

    def test_an_in_place_exec_counts_the_node_once_by_its_latest_exe(self):
        events = [ex(100, 1, "/bin/bash", ["-c", "x"]), ex(200, 100, "/bin/bash", ["a.sh"]),
                  ex(200, 100, "/usr/bin/python3", ["-c", "y"], ts=250), ex(300, 200, "/bin/sh", ["-c", "z"])]
        alerts, graph, _, _ = only_chain(events)
        self.assertEqual(len(graph.nodes["200:2000"].execs), 2)
        self.assertEqual(pids(alerts), [300])
        members, _ = ic.chain_for(graph, "300:3000", events[3])
        self.assertEqual([m["exe"] for m in members], ["sh", "python3", "bash"])

    def test_a_renamed_interpreter_is_not_a_member(self):
        alerts, graph, ctx, _ = only_chain(line([BASH_C, ("/usr/local/bin/py3", ["-c", "y"]), SH_C]))
        self.assertEqual(alerts, [])
        self.assertEqual(chain_counts(ctx), {})
        alerts, _, _, _ = only_chain(line([BASH_C, PY_C, ("/tmp/renamed", ["-c", "z"])]))
        self.assertEqual(alerts, [])

    def test_network_tools_are_not_members(self):
        events = line([BASH_C, ("/usr/bin/nc", ["-l"]), PY_C, SH_C])
        alerts, graph, ctx, _ = only_chain(events)
        self.assertEqual(alerts, [])
        self.assertEqual([m["exe"] for m in ic.chain_for(graph, "400:4000", events[3])[0]], ["sh", "python3"])
        self.assertEqual(chain_counts(ctx), {})

    def test_comm_does_not_decide_membership(self):
        events = line([BASH_C, PY_C, SH_C])
        events[1]["comm"] = "something-else"
        self.assertEqual(pids(only_chain(events)[0]), [300])


class Together(unittest.TestCase):

    def test_the_same_event_can_alert_as_shell_from_service_and_interpreter_chain(self):
        events = line([BASH_C, PY_C, SH_C])
        events[1]["comm"] = "nginx"
        alerts, _, _, stats = run_events(events, detections=[sfs.detect, ic.detect])
        self.assertEqual(sorted(a["detection"] for a in alerts), ["interpreter_chain", "shell_from_service"])
        self.assertEqual(pids(alerts), [300, 300])
        self.assertEqual(stats["alerts"], {"interpreter_chain": 1, "shell_from_service": 1})

    def test_evidence_has_the_attempt_and_the_success(self):
        events = line([BASH_C, PY_C, SH_C])
        events.insert(2, ex(300, 200, "/bin/sh", ["-c", "z"], typ="exec_attempt"))
        alerts, _, _, _ = only_chain(events)
        self.assertEqual([e["type"] for e in alerts[0]["evidence"]], ["exec_attempt", "exec_success"])

    def test_one_alert_per_exec_with_no_dedup(self):
        events = line([BASH_C, PY_C, SH_C]) + [ex(300, 200, "/usr/bin/perl", ["-e", "w"], ts=350)]
        alerts, _, _, _ = only_chain(events)
        self.assertEqual([(a["alert_seq"], a["process"]["pid"]) for a in alerts], [(1, 300), (2, 300)])

    def test_inputs_are_not_changed_and_output_is_repeatable(self):
        events = line([BASH_C, PY_C, SH_C, ("/usr/bin/perl", ["-e", "w"])])
        before = copy.deepcopy(events)
        first = run_events(events, detections=[ic.detect])
        self.assertEqual(events, before)
        graph_before = json.dumps(first[1].to_dict(), sort_keys=True)
        ic.detect(first[1], events[2], {"counts": {}, "attempts": {}})
        self.assertEqual(json.dumps(first[1].to_dict(), sort_keys=True), graph_before)
        self.assertEqual(events, before)
        self.assertEqual(first[0], run_events(copy.deepcopy(events), detections=[ic.detect])[0])

    def test_registered_in_the_runner(self):
        self.assertEqual(len(runner.DETECTIONS), 10)
        self.assertEqual(runner.DETECTIONS[-1].__module__, "interpreter_chain")

    def test_odd_events_do_not_crash(self):
        odd = [{"schema_version": 1, "type": "exec_success"}, {"schema_version": 1, "type": "exec_success", "exe": 5},
               {"schema_version": 1, "type": "exec_success", "exe": "/bin/sh", "pid": "x"},
               dict(ex(500, 1, "/bin/sh"), argv=[1, None], cmdline=7),
               dict(ex(600, 500, "/bin/sh"), argv="sh -c", cmdline=None)]
        alerts, _, ctx, stats = run_events(odd + line([BASH_C, PY_C, SH_C]), detections=[ic.detect])
        self.assertEqual(stats["detection_errors"], 0)
        self.assertEqual(pids(alerts), [300])
        self.assertEqual(chain_counts(ctx).get("chain_not_in_graph"), 1)


if __name__ == "__main__":
    unittest.main()
