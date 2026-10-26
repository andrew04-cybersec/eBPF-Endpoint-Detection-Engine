"""
tests for alert.py
every event and graph in here is a !!constructed fixture, not captured output!!
"""
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ALERTS_DIR = os.path.dirname(HERE)
sys.path.insert(0, ALERTS_DIR)
sys.path.insert(0, os.path.join(os.path.dirname(ALERTS_DIR), "graph"))

import alert  # noqa: E402
import process_graph as pg  # noqa: E402

REQUIRED = ("alert_schema_version", "alert_seq", "detection", "technique", "ts_ns", "process",
            "ancestry", "ancestry_stop", "evidence", "evidence_dropped", "data_quality")


def ev(typ, pid, start, ts, ppid=1, **extra):
    event = {"schema_version": 1, "type": typ, "ts_ns": ts, "pid": pid, "tid": pid,
             "comm": "x", "ppid": ppid, "uid": 0, "gid": 0, "start_time_ns": start,
             "process_key": "%d:%d" % (pid, start)}
    event.update(extra)
    return event


def success(pid, start, ts, ppid, exe, cmdline="", comm="x"):
    return ev("exec_success", pid, start, ts, ppid, exe=exe, filename=exe, cmdline=cmdline, comm=comm)


def make_graph(events):
    graph = pg.ProcessGraph()
    for e in events:
        graph.ingest(e)
    return graph


def chain_events():
    return [success(100, 10, 11, 1, "/usr/bin/bash", "bash", "bash"),
            success(200, 20, 21, 100, "/usr/bin/sh", "sh -c ls", "sh"),
            success(300, 30, 31, 200, "/usr/bin/ls", "ls /", "ls")]


#test-only trigger: stands in for detection and fires on any event its given
def fire_test_only_trigger(graph, event, evidence=None, **kwargs):
    return alert.build_alert(graph, "test_only_trigger", event, [event] if evidence is None else evidence, **kwargs)


#alerts built from small graphs
class Build(unittest.TestCase):

    def test_full_chain(self):
        events = chain_events()
        built = fire_test_only_trigger(make_graph(events), events[2])
        for field in REQUIRED:
            self.assertIn(field, built)
        self.assertEqual(built["alert_schema_version"], 1)
        self.assertIsNone(built["technique"])
        self.assertEqual(built["ts_ns"], 31)
        self.assertEqual(built["process"]["process_key"], "300:30")
        self.assertEqual(built["process"]["exe"], "/usr/bin/ls")
        self.assertEqual(built["process"]["cmdline"], "ls /")
        self.assertEqual([c["pid"] for c in built["ancestry"]], [300, 200, 100])
        for entry in built["ancestry"]:
            for field in ("process_key", "pid", "comm", "exe"):
                self.assertIn(field, entry)
        self.assertEqual(built["ancestry_stop"], "root")
        self.assertTrue(built["data_quality"]["ancestry_complete"])
        self.assertTrue(built["data_quality"]["process_in_graph"])
        self.assertEqual(built["data_quality"]["lost_events_seen"], 0)
        json.loads(alert.encode_alert(built))

    def test_ancestry_stops_at_a_placeholder(self):
        events = [success(200, 20, 21, 999, "/usr/bin/sh", "sh", "sh")]
        built = fire_test_only_trigger(make_graph(events), events[0])
        self.assertEqual(built["ancestry_stop"], "placeholder")
        self.assertFalse(built["data_quality"]["ancestry_complete"])
        self.assertTrue(built["ancestry"][-1]["placeholder"])
        lines = alert.render_alert(built)
        self.assertTrue(any(l.startswith("  WARNING: ancestry is incomplete") for l in lines))

    def test_process_missing_from_graph(self):
        trigger = success(200, 20, 21, 100, "/usr/bin/sh", "sh -c x", "sh")
        built = fire_test_only_trigger(pg.ProcessGraph(), trigger)
        self.assertFalse(built["data_quality"]["process_in_graph"])
        self.assertFalse(built["data_quality"]["ancestry_complete"])
        self.assertEqual((built["ancestry"], built["ancestry_stop"]), ([], "unknown_key"))
        self.assertEqual(built["process"]["pid"], 200)
        self.assertEqual(built["process"]["cmdline"], "sh -c x")
        lines = alert.render_alert(built)
        self.assertTrue(any("not in the graph" in l for l in lines))

    def test_odd_input_does_not_crash(self):
        for graph in (None, object(), pg.ProcessGraph()):
            for trigger in (None, {}, {"pid": "x", "ts_ns": "y"}, "text"):
                built = alert.build_alert(graph, "d", trigger, [None, 5, {"type": "exit"}], technique=7)
                self.assertIsNone(built["technique"])
                self.assertIsNone(built["ts_ns"])
                self.assertEqual(len(built["evidence"]), 1)
                alert.render_alert(built)
                alert.encode_alert(built)

    def test_evidence_over_the_cap(self):
        trigger = success(200, 20, 21, 1, "/a")
        extra = [ev("file_open", 200, 20, 100 + i, path="/f%d" % i, flags=0) for i in range(alert.MAX_EVIDENCE_EVENTS + 5)]
        built = fire_test_only_trigger(make_graph([trigger]), trigger, evidence=extra)
        self.assertEqual(len(built["evidence"]), alert.MAX_EVIDENCE_EVENTS)
        self.assertEqual(built["evidence_dropped"], 5)
        self.assertEqual(built["evidence"][0]["path"], "/f0")

    def test_ancestry_over_the_cap(self):
        events = chain_events()
        with mock.patch.object(alert, "MAX_ANCESTRY_ENTRIES", 2):
            built = fire_test_only_trigger(make_graph(events), events[2])
        self.assertEqual(len(built["ancestry"]), 2)
        self.assertEqual(built["ancestry_stop"], "root")
        self.assertTrue(built["data_quality"]["ancestry_truncated"])
        self.assertFalse(built["data_quality"]["ancestry_complete"])

    def test_lost_events_seen(self):
        events = chain_events()
        graph = make_graph(events + [{"schema_version": 1, "type": "lost", "ts_ns": 40, "pid": 9, "tid": 9,
                                      "comm": "loader", "dropped": 3, "process_key": None}])
        built = fire_test_only_trigger(graph, events[2])
        self.assertEqual(built["data_quality"]["lost_events_seen"], 1)
        lines = alert.render_alert(built)
        self.assertTrue(any("1 lost events were seen" in l for l in lines))

    def test_build_does_not_change_its_inputs(self):
        events = chain_events()
        graph = make_graph(events)
        before_graph = json.dumps(graph.to_dict(), sort_keys=True)
        before_events = copy.deepcopy(events)
        built = fire_test_only_trigger(graph, events[2], evidence=events)
        self.assertEqual(json.dumps(graph.to_dict(), sort_keys=True), before_graph)
        self.assertEqual(events, before_events)
        built["evidence"][0]["comm"] = "changed"
        built["ancestry"][0]["comm"] = "changed"
        self.assertEqual(events, before_events)
        self.assertEqual(json.dumps(graph.to_dict(), sort_keys=True), before_graph)

    def test_same_input_gives_same_output(self):
        events = chain_events()
        outputs = []
        for _ in range(2):
            out, err = io.StringIO(), io.StringIO()
            sink = alert.AlertSink(out, err)
            sink.emit(fire_test_only_trigger(make_graph(events), events[2]))
            outputs.append((out.getvalue(), err.getvalue()))
        self.assertEqual(outputs[0], outputs[1])


#the sink; the readable form; and the viewer
class Output(unittest.TestCase):

    def setUp(self):
        self.events = chain_events()
        self.built = fire_test_only_trigger(make_graph(self.events), self.events[2])

    def test_json_lines_round_trip(self):
        out = io.StringIO()
        sink = alert.AlertSink(out, None)
        sent = [sink.emit(self.built), sink.emit(self.built)]
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual([json.loads(l) for l in lines], sent)
        self.assertEqual([a["alert_seq"] for a in sent], [1, 2])
        self.assertIsNone(self.built["alert_seq"])
        self.assertTrue(lines[0].isascii())
        self.assertEqual(lines[0], alert.encode_alert(sent[0]))

    def test_readable_form_order_and_content(self):
        lines = alert.render_alert(dict(self.built, alert_seq=1))
        self.assertEqual(lines[0], "ALERT 1  test_only_trigger  [technique unassigned]")
        self.assertIn("31", lines[1])
        self.assertIn("pid=300", lines[2])
        self.assertEqual(lines[3], "  command: ls /")
        self.assertEqual(lines[4], "  ancestry: ls(300) <- sh(200) <- bash(100) [stop: root]")
        self.assertTrue(lines[5].startswith("  evidence (1 shown, 0 dropped)"))
        self.assertIn("exec_success", lines[6])
        self.assertFalse(any("WARNING" in l for l in lines))
        labeled = alert.render_alert(dict(self.built, technique="test-label"))
        self.assertIn("[test-label]", labeled[0])

    def test_control_characters_are_escaped(self):
        hostile = dict(self.built, process=dict(self.built["process"], cmdline="a\x1b[2Jb\ncé"))
        text = "\n".join(alert.render_alert(hostile))
        self.assertNotIn("\x1b", text)
        self.assertIn("a\\u001b[2Jb\\nc\\u00e9", text)

    def test_sink_streams_can_be_disabled(self):
        out, err = io.StringIO(), io.StringIO()
        alert.AlertSink(out, None).emit(self.built)
        alert.AlertSink(None, err).emit(self.built)
        alert.AlertSink(None, None).emit(self.built)
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        self.assertTrue(err.getvalue().startswith("ALERT 1"))

    def test_unencodable_alert_is_counted_not_fatal(self):
        out = io.StringIO()
        sink = alert.AlertSink(out, None)
        sink.emit(dict(self.built, evidence=[{"bad": float("nan")}]))
        sink.emit(self.built)
        self.assertEqual(sink.failed, 1)
        self.assertEqual(len(out.getvalue().splitlines()), 1)


#saved alert lines run through the viewer command line
class Viewer(unittest.TestCase):

    def setUp(self):
        events = chain_events()
        out = io.StringIO()
        alert.AlertSink(out, None).emit(fire_test_only_trigger(make_graph(events), events[2]))
        self.data = out.getvalue() + "not json\n"
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "alerts.jsonl")
        with open(self.path, "w") as f:
            f.write(self.data)

    def tearDown(self):
        self.dir.cleanup()

    def run_cli(self, *args, stdin=None):
        return subprocess.run([sys.executable, os.path.join(ALERTS_DIR, "alert.py")] + list(args),
                              input=stdin, capture_output=True, text=True)

    def test_from_file(self):
        done = self.run_cli(self.path)
        self.assertEqual(done.returncode, 0)
        self.assertIn("ALERT 1  test_only_trigger  [technique unassigned]", done.stdout)
        self.assertIn("alerts shown: 1, lines skipped: 1", done.stderr)

    def test_from_stdin(self):
        done = self.run_cli(stdin=self.data)
        self.assertEqual(done.returncode, 0)
        self.assertIn("ancestry: ls(300) <- sh(200) <- bash(100) [stop: root]", done.stdout)

    def test_missing_file(self):
        done = self.run_cli(os.path.join(self.dir.name, "nope"))
        self.assertEqual(done.returncode, 2)


if __name__ == "__main__":
    unittest.main()
