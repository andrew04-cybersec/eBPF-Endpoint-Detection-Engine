"""these are tests for process_graph.py. every event here is a constructed fixture and not some captured output."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GRAPH_DIR = os.path.dirname(HERE)
sys.path.insert(0, GRAPH_DIR)

import process_graph as pg  #noqa: E402


def ev(typ, pid, start, ts, ppid=1, **extra):
    event = {"schema_version": 1, "type": typ, "ts_ns": ts, "pid": pid, "tid": pid,
             "comm": "x", "ppid": ppid, "uid": 0, "gid": 0, "start_time_ns": start,
             "process_key": "%d:%d" % (pid, start)}
    event.update(extra)
    return event


def success(pid, start, ts, ppid, exe, cmdline=""):
    return ev("exec_success", pid, start, ts, ppid, exe=exe, filename=exe, cmdline=cmdline)


def exit_ev(pid, start, ts, ppid=1, status=0):
    return ev("exit", pid, start, ts, ppid, exit_code=status << 8, exit_status=status, exit_signal=0)


def build(events, **limits):
    graph = pg.ProcessGraph(**limits)
    for e in events:
        graph.ingest(e)
    return graph


#bash (100) runs sh (200); which runs ls (300)
class Chain(unittest.TestCase):

    def setUp(self):
        self.graph = build([
            success(100, 10, 11, 1, "/usr/bin/bash"),
            success(200, 20, 21, 100, "/usr/bin/sh"),
            success(300, 30, 31, 200, "/usr/bin/ls"),
        ])

    def test_ancestry_reaches_root(self):
        result = self.graph.ancestry("300:30")
        self.assertEqual(result["chain"], ["300:30", "200:20", "100:10"])
        self.assertEqual(result["stop"], "root")

    def test_children_and_counts(self):
        self.assertEqual(self.graph.children("100:10"), ["200:20"])
        summary = self.graph.summary()
        self.assertEqual((summary["nodes"], summary["edges"], summary["placeholders"]), (3, 2, 0))
        self.assertEqual(summary["edges_by_link"]["observed"], 2)

    def test_exec_in_place_is_one_node(self):
        graph = build([
            ev("exec_attempt", 200, 20, 21, 100, filename="/usr/bin/sh"),
            success(200, 20, 22, 100, "/usr/bin/sh", "sh -c ls"),
            ev("exec_attempt", 200, 20, 23, 100, filename="/usr/bin/ls"),
            success(200, 20, 24, 100, "/usr/bin/ls", "ls /"),
        ])
        self.assertEqual(len(graph.nodes) - len(graph.placeholders), 1)
        node = graph.nodes["200:20"]
        self.assertEqual([x["exe"] for x in node.execs], ["/usr/bin/sh", "/usr/bin/ls"])
        self.assertEqual(node.first_seen_ts, 21)
        self.assertEqual(node.last_seen_ts, 24)

    def test_failed_exec_is_flagged_in_history(self):
        graph = build([
            ev("exec_failed", 400, 40, 41, 100, exe="/nonexistent", cmdline="/nonexistent x", reason="exit"),
            exit_ev(400, 40, 42, 100, 127),
        ])
        entry = graph.nodes["400:40"].execs[0]
        self.assertTrue(entry["failed"])
        self.assertEqual(entry["reason"], "exit")
        self.assertEqual(graph.nodes["400:40"].exit["exit_status"], 127)


#parents that werent seen or arent real parents
class Parents(unittest.TestCase):

    def test_unknown_parent_gets_a_placeholder(self):
        graph = build([success(200, 20, 21, 999, "/usr/bin/sh"),
                       success(201, 22, 23, 999, "/usr/bin/ls")])
        self.assertEqual(graph.nodes["200:20"].link, "placeholder")
        self.assertTrue(graph.nodes["999:unknown"].placeholder)
        self.assertEqual(graph.summary()["placeholders"], 1)
        result = graph.ancestry("200:20")
        self.assertEqual(result["chain"], ["200:20", "999:unknown"])
        self.assertEqual(result["stop"], "placeholder")

    def test_real_parent_replaces_placeholder_for_later_children_only(self):
        graph = build([success(200, 60, 61, 999, "/usr/bin/sh"),
                       success(201, 10, 62, 999, "/usr/bin/ls"),
                       success(999, 50, 70, 1, "/usr/bin/bash")])
        self.assertEqual(graph.nodes["200:60"].parent_key, "999:50")
        self.assertEqual(graph.nodes["200:60"].link, "late")
        self.assertEqual(graph.nodes["201:10"].parent_key, "999:unknown")
        self.assertEqual(graph.summary()["placeholders_adopted"], 1)

    def test_ppid_0_and_1_need_no_placeholder(self):
        graph = build([success(10, 1, 2, 0, "/sbin/init"), success(11, 3, 4, 1, "/usr/sbin/d")])
        self.assertEqual(graph.summary()["placeholders"], 0)
        self.assertEqual(graph.ancestry("10:1")["stop"], "root")
        self.assertEqual(graph.ancestry("11:3")["stop"], "root")

    def test_pid_reuse_resolves_to_the_right_process(self):
        graph = build([
            success(50, 100, 101, 1, "/usr/bin/a"),
            success(60, 300, 301, 50, "/usr/bin/c"),
            exit_ev(50, 100, 400),
            success(50, 500, 501, 1, "/usr/bin/b"),
            success(61, 600, 601, 50, "/usr/bin/d"),
        ])
        self.assertEqual(graph.nodes["60:300"].parent_key, "50:100")
        self.assertEqual(graph.nodes["61:600"].parent_key, "50:500")

    def test_child_started_after_parent_exit_is_not_linked_to_it(self):
        graph = build([success(50, 100, 101, 1, "/usr/bin/a"), exit_ev(50, 100, 200),
                       success(70, 250, 251, 50, "/usr/bin/e")])
        self.assertEqual(graph.nodes["70:250"].link, "placeholder")

    def test_late_child_events_after_parent_exit(self):
        graph = build([
            success(50, 100, 101, 1, "/usr/bin/a"),
            exit_ev(50, 100, 200),
            ev("file_open", 50, 100, 210, 1, path="/etc/passwd", flags=0),
            success(70, 150, 300, 50, "/usr/bin/e"),
        ])
        self.assertEqual(graph.nodes["70:150"].link, "observed")
        self.assertEqual(graph.nodes["70:150"].parent_key, "50:100")
        self.assertEqual(graph.summary()["events_after_exit"], 1)
        self.assertEqual(len(graph.nodes["50:100"].files), 1)

    def test_changed_ppid_is_a_note_not_an_edge(self):
        graph = build([success(200, 20, 21, 100, "/usr/bin/sh"),
                       ev("file_open", 200, 20, 30, 1, path="/etc/passwd", flags=0)])
        node = graph.nodes["200:20"]
        self.assertEqual(node.ppid, 100)
        self.assertEqual(node.ppid_changes, [{"ts_ns": 30, "ppid": 1}])
        self.assertEqual(graph.summary()["edges"], 1)


#structures that cant make query loop or hide in a live process
class Limits(unittest.TestCase):

    def test_cycle_is_detected(self):
        #equal start times let each process resolve the other as its parent
        graph = build([success(10, 5, 6, 20, "/a"), success(20, 5, 7, 10, "/b")])
        result = graph.ancestry("10:5")
        self.assertEqual(result["stop"], "cycle")
        self.assertEqual(sorted(result["chain"]), ["10:5", "20:5"])

    def test_depth_cap(self):
        events = [success(1000 + i, 10 + i, 10 + i, 999 + i if i else 1, "/x") for i in range(6)]
        graph = build(events, max_depth=3)
        result = graph.ancestry("1005:15")
        self.assertEqual(result["stop"], "depth_cap")
        self.assertEqual(len(result["chain"]), 3)
        self.assertEqual(pg.ProcessGraph().ancestry("1005:15")["stop"], "unknown_key")

    def test_eviction_takes_the_oldest_exited_node_only(self):
        graph = build([
            success(1, 10, 11, 0, "/a"), success(2, 20, 21, 0, "/b"),
            success(3, 30, 31, 2, "/c"), exit_ev(2, 20, 35),
            success(4, 40, 41, 0, "/d"),
        ], max_nodes=3)
        self.assertNotIn("2:20", graph.nodes)
        self.assertEqual(sorted(graph.nodes), ["1:10", "3:30", "4:40"])
        self.assertEqual(graph.summary()["evicted"], 1)
        self.assertEqual(graph.ancestry("3:30")["stop"], "parent_missing")

    def test_live_nodes_are_never_evicted(self):
        graph = build([success(i, 10 + i, 20 + i, 0, "/x") for i in range(1, 6)], max_nodes=2)
        self.assertEqual(len(graph.nodes), 5)
        self.assertEqual(graph.summary()["evicted"], 0)
        self.assertGreater(graph.summary()["over_limit_while_live"], 0)

    def test_list_caps_keep_the_first_and_count_drops(self):
        events = [ev("file_open", 7, 70, 100 + i, 1, path="/f%d" % i, flags=0) for i in range(5)]
        graph = build(events, max_list=3)
        node = graph.nodes["7:70"]
        self.assertEqual([f["path"] for f in node.files], ["/f0", "/f1", "/f2"])
        self.assertEqual(node.dropped["files"], 2)
        self.assertEqual(graph.summary()["dropped_by_list"]["files"], 2)


#events attached to nodes, lookups, and input that is wrong in some way
class Events(unittest.TestCase):

    def test_file_net_priv_events_attach_to_the_node(self):
        graph = build([
            ev("file_open", 7, 70, 1, path="/etc/shadow", flags=0, ret=3),
            ev("net_connect", 7, 70, 2, family=2, remote_addr="127.0.0.1", remote_port=80),
            ev("priv_change", 7, 70, 3, syscall="setuid", ids=[0]),
        ])
        node = graph.nodes["7:70"]
        self.assertEqual((len(node.files), len(node.nets), len(node.privs)), (1, 1, 1))
        self.assertEqual(node.nets[0]["remote_port"], 80)
        self.assertEqual(node.privs[0]["ids"], [0])

    def test_find_by_pid_at_a_time(self):
        graph = build([success(50, 100, 101, 1, "/a"), exit_ev(50, 100, 200),
                       success(50, 500, 501, 1, "/b")])
        self.assertEqual(graph.find_by_pid(50, 150), "50:100")
        self.assertIsNone(graph.find_by_pid(50, 300))
        self.assertEqual(graph.find_by_pid(50, 600), "50:500")
        self.assertIsNone(graph.find_by_pid(50, 50))
        self.assertIsNone(graph.find_by_pid(51, 150))
        self.assertEqual(graph.keys_for_pid(50), ["50:100", "50:500"])

    def test_repeat_exit_keeps_the_first(self):
        graph = build([exit_ev(8, 80, 5, 1, 0), exit_ev(8, 80, 6, 1, 3)])
        self.assertEqual(graph.nodes["8:80"].exit["ts_ns"], 5)
        self.assertEqual(graph.summary()["repeat_exits"], 1)

    def test_lost_is_counted_and_not_attached(self):
        graph = build([{"schema_version": 1, "type": "lost", "ts_ns": 1, "pid": 9, "tid": 9,
                        "comm": "loader", "dropped": 12, "process_key": None}])
        summary = graph.summary()
        self.assertEqual((summary["lost_events"], summary["lost_records_dropped"], summary["nodes"]), (1, 12, 0))

    def test_bad_input_is_counted_and_never_fatal(self):
        graph = pg.ProcessGraph()
        good = json.dumps(success(5, 50, 1, 1, "/a"))
        for line in [b"{not json\n", b"[1, 2]\n", b"\n", good.encode(), b'{"x": NaN}\n',
                     b'{"schema_version":2,"type":"exit"}\n',
                     b'{"schema_version":1,"type":"mystery","pid":1}\n',
                     b'{"schema_version":1,"type":"exit","pid":"x"}\n',
                     b'{"schema_version":1,"type":"exec_success","pid":6,"start_time_ns":60,"exe":5,"cmdline":[1],"ppid":"a"}\n',
                     b'{"schema_version":1,"type":"exit","pid":6,"start_time_ns":60,"process_key":"6:61"}\n',
                     b"\xff\xfe\n"]:
            graph.ingest_line(line)
        a = graph.summary()["anomalies"]
        self.assertEqual(a["bad_json_lines"], 3)
        self.assertEqual(a["invalid_utf8_lines"], 1)
        self.assertEqual(a["not_an_object"], 1)
        self.assertEqual(a["unsupported_schema_version"], 1)
        self.assertEqual(a["unknown_event_type"], 1)
        self.assertEqual(a["missing_identity"], 1)
        self.assertEqual(a["malformed_field"], 1)
        self.assertEqual(a["ppid_missing"], 1)
        self.assertEqual(a["key_mismatch"], 1)
        self.assertEqual(sorted(graph.nodes), ["5:50", "6:60"])


#small normalized file ran through the command line
class CommandLine(unittest.TestCase):

    def setUp(self):
        events = [success(100, 10, 11, 1, "/usr/bin/bash"), success(200, 20, 21, 100, "/usr/bin/sh"),
                  success(300, 30, 31, 200, "/usr/bin/ls")]
        self.data = "".join(json.dumps(e) + "\n" for e in events)
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "in.jsonl")
        with open(self.path, "w") as f:
            f.write(self.data)

    def tearDown(self):
        self.dir.cleanup()

    def run_cli(self, *args, stdin=None):
        return subprocess.run([sys.executable, os.path.join(GRAPH_DIR, "process_graph.py")] + list(args),
                              input=stdin, capture_output=True, text=True)

    def test_summary_from_file(self):
        done = self.run_cli("-i", self.path, "summary")
        self.assertEqual(done.returncode, 0)
        self.assertIn("nodes: 3, edges: 2", done.stdout)

    def test_ancestry_from_stdin(self):
        done = self.run_cli("ancestry", "--pid", "300", stdin=self.data)
        self.assertEqual(done.returncode, 0)
        self.assertIn("stop reason: root", done.stdout)
        self.assertIn("300:30", done.stdout)

    def test_ancestry_with_no_match(self):
        done = self.run_cli("-i", self.path, "ancestry", "--pid", "12345")
        self.assertEqual(done.returncode, 1)

    def test_dump_is_valid_json(self):
        done = self.run_cli("-i", self.path, "dump")
        self.assertEqual(done.returncode, 0)
        dumped = json.loads(done.stdout)
        self.assertEqual(len(dumped["nodes"]), 3)
        self.assertEqual(len(dumped["edges"]), 2)

    def test_missing_input_file(self):
        done = self.run_cli("-i", os.path.join(self.dir.name, "nope"), "summary")
        self.assertEqual(done.returncode, 2)


if __name__ == "__main__":
    unittest.main()
