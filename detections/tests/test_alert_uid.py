"""
tests for the uid and gid of the process entry that alerts/alert.py builds
every event here is a !!constructed fixture, not captured output!!
"""
import copy
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DET_DIR = os.path.dirname(HERE)
sys.path.insert(0, DET_DIR)
sys.path.insert(0, os.path.join(os.path.dirname(DET_DIR), "alerts"))
sys.path.insert(0, os.path.join(os.path.dirname(DET_DIR), "graph"))

import alert  # noqa: E402
import process_graph  # noqa: E402


def ev(pid, ppid, uid, gid, ts, typ="exec_success", **fields):
    e = {"schema_version": 1, "type": typ, "ts_ns": ts, "pid": pid, "tid": pid, "comm": "sh", "ppid": ppid, "uid": uid,
         "gid": gid, "start_time_ns": pid * 10, "process_key": "%d:%d" % (pid, pid * 10), "exe": "/bin/sh",
         "cmdline": "sh", "argv": ["sh"]}
    e.update(fields)
    return e


def graph_of(events):
    graph = process_graph.ProcessGraph()
    for e in events:
        graph.ingest(copy.deepcopy(e))
    return graph


class ProcessIds(unittest.TestCase):

    def test_the_ids_of_the_triggering_event_are_used(self):
        first = ev(200, 1, 0, 0, 1)
        later = ev(200, 1, 61234, 61234, 5, typ="priv_change", syscall="setuid", ids=[0])
        a = alert.build_alert(graph_of([first, later]), "x", later, [later])
        self.assertEqual((a["process"]["uid"], a["process"]["gid"]), (61234, 61234))
        self.assertEqual(a["process"]["pid"], 200)

    def test_without_ids_on_the_event_the_node_is_used(self):
        first = ev(200, 1, 7, 8, 1)
        bare = ev(200, 1, 61234, 61234, 5)
        del bare["uid"]
        del bare["gid"]
        a = alert.build_alert(graph_of([first, bare]), "x", bare, [bare])
        self.assertEqual((a["process"]["uid"], a["process"]["gid"]), (7, 8))

    def test_ids_that_are_not_integers_fall_back_to_the_node(self):
        first = ev(200, 1, 7, 8, 1)
        for bad in (True, False, "5", 1.5, None, [1]):
            odd = ev(200, 1, bad, bad, 5)
            a = alert.build_alert(graph_of([first]), "x", odd, [odd])
            self.assertEqual((a["process"]["uid"], a["process"]["gid"]), (7, 8), repr(bad))

    def test_each_id_is_taken_on_its_own(self):
        first = ev(200, 1, 7, 8, 1)
        odd = ev(200, 1, 61234, None, 5)
        a = alert.build_alert(graph_of([first]), "x", odd, [odd])
        self.assertEqual((a["process"]["uid"], a["process"]["gid"]), (61234, 8))

    def test_ancestors_keep_the_ids_first_seen_for_them(self):
        parent_first = ev(100, 1, 5, 5, 1)
        parent_later = ev(100, 1, 6, 6, 2, typ="priv_change", syscall="setuid", ids=[6])
        child = ev(200, 100, 9, 9, 3)
        trigger = ev(200, 100, 61234, 61234, 4)
        a = alert.build_alert(graph_of([parent_first, parent_later, child]), "x", trigger, [trigger])
        self.assertEqual([(e["pid"], e["uid"], e["gid"]) for e in a["ancestry"]], [(200, 9, 9), (100, 5, 5)])
        self.assertEqual((a["process"]["uid"], a["process"]["gid"]), (61234, 61234))

    def test_a_process_not_in_the_graph_still_uses_the_event(self):
        trigger = ev(200, 1, 61234, 61234, 4)
        a = alert.build_alert(graph_of([]), "x", trigger, [trigger])
        self.assertEqual((a["process"]["uid"], a["process"]["gid"]), (61234, 61234))
        self.assertFalse(a["data_quality"]["process_in_graph"])

    def test_nothing_else_changes_and_inputs_are_not_mutated(self):
        first = ev(200, 1, 0, 0, 1)
        later = ev(200, 1, 61234, 61234, 5)
        events = [first, later]
        before = copy.deepcopy(events)
        graph = graph_of(events)
        graph_before = json.dumps(graph.to_dict(), sort_keys=True)
        a = alert.build_alert(graph, "x", later, [later])
        self.assertEqual(events, before)
        self.assertEqual(json.dumps(graph.to_dict(), sort_keys=True), graph_before)
        self.assertEqual(graph.nodes["200:2000"].uid, 0)
        node_alert = alert.build_alert(graph, "x", first, [first])
        for field in ("process_key", "pid", "ppid", "comm", "exe", "cmdline", "placeholder"):
            self.assertEqual(a["process"][field], node_alert["process"][field], field)
        self.assertEqual(a["ancestry"], node_alert["ancestry"])


if __name__ == "__main__":
    unittest.main()
