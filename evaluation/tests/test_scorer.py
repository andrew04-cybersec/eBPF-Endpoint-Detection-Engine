"""
tests for evaluate.py, the offline scorer, and report generator
every scenario, alert, window and results folder here is a !!constructed fixture, not captured output!!
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL_DIR = os.path.dirname(HERE)
sys.path.insert(0, EVAL_DIR)

import evaluate  # noqa: E402
import scenario_lib  # noqa: E402

SEC = 1000000000
SHELL = {"detection": "shell_from_service", "min_count": 1}


def scenario(sid, kind="attack", expected=None, acceptable=None, technique="T1059.004"):
    if expected is None:
        expected = [SHELL] if kind == "attack" else []
    return {"id": sid, "title": sid, "kind": kind, "technique": technique if kind == "attack" else None, "threat_model": "x",
            "phase": "after_loader", "marker": "EVT_EVAL_" + sid, "expected": expected, "acceptable": acceptable or [],
            "timeout_seconds": 30, "known_gap": None, "notes": "x"}


def alert(detection, ts, cmdline="", seq=1, ancestry_cmdline=None):
    return {"alert_schema_version": 1, "alert_seq": seq, "detection": detection, "technique": None, "ts_ns": ts,
            "process": {"pid": 5, "exe": "/bin/sh", "cmdline": cmdline}, "ancestry": [{"cmdline": ancestry_cmdline}],
            "evidence": [{"type": "exec_success", "cmdline": "", "argv": ["sh"]}], "evidence_dropped": 0}


def read_bytes(folder, name):
    with open(os.path.join(folder, name), "rb") as f:
        return f.read()


def window(start, end, timed_out=False):
    return {"start_ns": start, "end_ns": end, "timed_out": timed_out, "exit_status": 0}


class Folder:
    """constructed results folder in a temporary directory with a matching live scenario directory"""

    def __init__(self, scenarios, windows, alerts, latency_ns=5000000, env=None, extra=None):
        self.tmp = tempfile.mkdtemp()
        self.results = os.path.join(self.tmp, "20000101-000000-eval")
        self.live = os.path.join(self.tmp, "scenarios")
        os.makedirs(os.path.join(self.results, "scenarios_snapshot"))
        hashes = {}
        for sc in scenarios:
            for base in (os.path.join(self.results, "scenarios_snapshot", sc["id"] + ".json"),
                         os.path.join(self.live, sc["id"], "scenario.json")):
                os.makedirs(os.path.dirname(base), exist_ok=True)
                with open(base, "w") as f:
                    json.dump(sc, f, sort_keys=True)
            hashes[sc["id"]] = scenario_lib.sha256_file(os.path.join(self.live, sc["id"], "scenario.json"))
        self.write("label_hashes.json", json.dumps({"scenarios": hashes, "set": scenario_lib.set_hash(hashes)}))
        self.write("scenario_windows.json", json.dumps({"scenarios": windows, "clock_check": {"passed": True, "max_skew_ns": 0}}))
        lines = []
        for a in alerts:
            lines.append("%d\t%s" % (a["ts_ns"] + latency_ns if type(a.get("ts_ns")) is int else 0, json.dumps(a)))
        self.write("alerts.stamped.tsv", "\n".join(lines) + ("\n" if lines else ""))
        self.write("env.txt", "mode: buffered\nclk_tck: 100\n" if env is None else env)
        for name, text in (extra or {}).items():
            self.write(name, text)

    def write(self, name, text):
        with open(os.path.join(self.results, name), "w") as f:
            f.write(text)

    def score(self):
        return evaluate.score_folder(self.results, self.live)

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class Percentiles(unittest.TestCase):

    def test_empty_is_none_and_one_value_is_itself(self):
        self.assertIsNone(evaluate.percentile([], 50))
        self.assertIsNone(evaluate.percentile([], 95))
        self.assertEqual(evaluate.percentile([7], 50), 7)
        self.assertEqual(evaluate.percentile([7], 95), 7)

    def test_nearest_rank_on_known_lists(self):
        values = list(range(20, 0, -1))
        self.assertEqual(evaluate.percentile(values, 50), 10)
        self.assertEqual(evaluate.percentile(values, 95), 19)
        self.assertEqual(evaluate.percentile(values, 100), 20)
        self.assertEqual(evaluate.percentile([1, 2, 3, 4], 50), 2)
        self.assertEqual(evaluate.percentile([1, 2, 3, 4], 95), 4)

    def test_ties(self):
        self.assertEqual(evaluate.percentile([1, 1, 1, 2], 50), 1)
        self.assertEqual(evaluate.percentile([1, 1, 1, 2], 95), 2)
        self.assertEqual(evaluate.percentile([3, 3, 3], 95), 3)

    def test_ratio_is_none_not_zero_or_one_for_an_empty_denominator(self):
        self.assertEqual(evaluate.ratio(0, 0), {"num": 0, "den": 0, "value": None})
        self.assertEqual(evaluate.ratio(2, 4)["value"], 0.5)
        self.assertEqual(evaluate.ratio(0, 3)["value"], 0.0)


class Attribution(unittest.TestCase):

    def check(self, alerts, windows=None):
        f = Folder([scenario("S1")], windows or {"S1": window(1000, 2000)}, alerts)
        self.addCleanup(f.cleanup)
        return f.score()[0]

    def test_inside_the_window_with_the_marker_is_scored(self):
        s = self.check([alert("shell_from_service", 1500, "sh -c EVT_EVAL_S1")])
        self.assertEqual(s["scenarios"]["S1"]["tp"], {"shell_from_service": 1})
        self.assertEqual((s["unattributed_in_window"], s["unattributed_outside_windows"]), ([], []))

    def test_inside_the_window_without_the_marker_is_listed_and_not_scored(self):
        s = self.check([alert("shell_from_service", 1500, "sh -c something")])
        self.assertEqual(s["scenarios"]["S1"]["alerts_attributed"], 0)
        self.assertEqual([(a["detection"], a["window"]) for a in s["unattributed_in_window"]], [("shell_from_service", "S1")])
        self.assertEqual(s["scenarios"]["S1"]["outcome"], "missed")

    def test_outside_every_window_is_listed_and_not_scored(self):
        s = self.check([alert("shell_from_service", 999, "EVT_EVAL_S1"), alert("shell_from_service", 2001, "EVT_EVAL_S1")])
        self.assertEqual(len(s["unattributed_outside_windows"]), 2)
        self.assertEqual(s["scenarios"]["S1"]["alerts_attributed"], 0)

    def test_the_window_edges_are_inside(self):
        s = self.check([alert("shell_from_service", 1000, "EVT_EVAL_S1"), alert("shell_from_service", 2000, "EVT_EVAL_S1")])
        self.assertEqual(s["scenarios"]["S1"]["tp"], {"shell_from_service": 2})

    def test_the_marker_can_be_in_an_ancestry_entry_an_evidence_cmdline_or_an_evidence_argv(self):
        a1 = alert("shell_from_service", 1100, "", ancestry_cmdline="bash -c x EVT_EVAL_S1")
        a2 = alert("shell_from_service", 1200, "")
        a2["evidence"] = [{"type": "exec_success", "cmdline": "sh EVT_EVAL_S1"}]
        a3 = alert("shell_from_service", 1300, "")
        a3["evidence"] = [{"type": "exec_success", "argv": ["sh", "-c", "EVT_EVAL_S1"]}]
        s = self.check([a1, a2, a3])
        self.assertEqual(s["scenarios"]["S1"]["tp"], {"shell_from_service": 3})

    def test_the_marker_of_another_scenario_does_not_count(self):
        f = Folder([scenario("S1"), scenario("S2")], {"S1": window(1000, 2000), "S2": window(3000, 4000)},
                   [alert("shell_from_service", 1500, "EVT_EVAL_S2")])
        self.addCleanup(f.cleanup)
        s = f.score()[0]
        self.assertEqual(len(s["unattributed_in_window"]), 1)

    def test_a_scenario_that_did_not_run_is_listed_and_not_counted(self):
        f = Folder([scenario("S1"), scenario("S2")], {"S1": window(1000, 2000)}, [])
        self.addCleanup(f.cleanup)
        s = f.score()[0]
        self.assertEqual(s["not_run"], ["S2"])
        self.assertEqual(s["pooled"]["recall"], {"num": 0, "den": 1, "value": 0.0})

    def test_alerts_without_a_usable_timestamp_are_outside_the_windows(self):
        bad = alert("shell_from_service", 1500, "EVT_EVAL_S1")
        bad["ts_ns"] = "x"
        s = self.check([bad])
        self.assertEqual(len(s["unattributed_outside_windows"]), 1)


class Classification(unittest.TestCase):

    def test_true_positive_acceptable_and_false_positive(self):
        f = Folder([scenario("S1", acceptable=["unusual_ancestry"])], {"S1": window(1000, 5000)},
                   [alert("shell_from_service", 1100, "EVT_EVAL_S1"), alert("unusual_ancestry", 1200, "EVT_EVAL_S1"),
                    alert("exec_from_tmp", 1300, "EVT_EVAL_S1"), alert("exec_from_tmp", 1400, "EVT_EVAL_S1")])
        self.addCleanup(f.cleanup)
        r = f.score()[0]["scenarios"]["S1"]
        self.assertEqual((r["tp"], r["acceptable"], r["fp"]), ({"shell_from_service": 1}, {"unusual_ancestry": 1}, {"exec_from_tmp": 2}))
        self.assertEqual(r["outcome"], "detected")

    def test_every_alert_of_a_benign_scenario_is_a_false_positive(self):
        f = Folder([scenario("B1", kind="benign", acceptable=["unusual_ancestry"])], {"B1": window(0, 10 * SEC)},
                   [alert("unusual_ancestry", SEC, "EVT_EVAL_B1"), alert("shell_from_service", 2 * SEC, "EVT_EVAL_B1")])
        self.addCleanup(f.cleanup)
        r = f.score()[0]["scenarios"]["B1"]
        self.assertEqual(r["fp"], {"shell_from_service": 1, "unusual_ancestry": 1})
        self.assertEqual(r["outcome"], "false alerts")

    def test_min_count_and_the_unmet_entries(self):
        two = [{"detection": "shell_from_service", "min_count": 2}, {"detection": "exec_from_tmp", "min_count": 1}]
        f = Folder([scenario("S1", expected=two), scenario("S2", expected=two)],
                   {"S1": window(1000, 2000), "S2": window(3000, 4000)},
                   [alert("shell_from_service", 1100, "EVT_EVAL_S1"), alert("shell_from_service", 1200, "EVT_EVAL_S1"),
                    alert("shell_from_service", 3100, "EVT_EVAL_S2"), alert("exec_from_tmp", 3200, "EVT_EVAL_S2")])
        self.addCleanup(f.cleanup)
        s = f.score()[0]["scenarios"]
        self.assertEqual((s["S1"]["outcome"], s["S1"]["unmet"]), ("missed", [{"detection": "exec_from_tmp", "min_count": 1, "got": 0}]))
        self.assertEqual((s["S2"]["outcome"], s["S2"]["unmet"]), ("missed", [{"detection": "shell_from_service", "min_count": 2, "got": 1}]))

    def test_all_entries_met_is_detected(self):
        two = [{"detection": "shell_from_service", "min_count": 2}]
        f = Folder([scenario("S1", expected=two)], {"S1": window(1000, 2000)},
                   [alert("shell_from_service", 1100, "EVT_EVAL_S1"), alert("shell_from_service", 1200, "EVT_EVAL_S1")])
        self.addCleanup(f.cleanup)
        self.assertEqual(f.score()[0]["scenarios"]["S1"]["outcome"], "detected")


class Aggregates(unittest.TestCase):

    def folder(self):
        scenarios = [scenario("S1"), scenario("S2"), scenario("S3", technique="T1059", expected=[{"detection": "exec_from_tmp", "min_count": 1}]),
                     scenario("B1", kind="benign")]
        windows = {"S1": window(1000, 2000), "S2": window(3000, 4000), "S3": window(5000, 6000), "B1": window(10 * SEC, 30 * SEC)}
        alerts = [alert("shell_from_service", 1100, "EVT_EVAL_S1"),
                  alert("unusual_ancestry", 1200, "EVT_EVAL_S1"), alert("exec_from_tmp", 5100, "EVT_EVAL_S3"),
                  alert("shell_from_service", 11 * SEC, "EVT_EVAL_B1"), alert("rapid_spawn", 12 * SEC, "EVT_EVAL_B1")]
        scenarios[0]["acceptable"] = ["unusual_ancestry"]
        f = Folder(scenarios, windows, alerts)
        self.addCleanup(f.cleanup)
        return f

    def test_per_technique(self):
        s = self.folder().score()[0]
        self.assertEqual({k: v for k, v in s["per_technique"]["T1059.004"].items() if k != "by_group"},
                         {"attacks": 2, "detected": 1, "missed": 1, "recall": {"num": 1, "den": 2, "value": 0.5}})
        self.assertEqual(s["per_technique"]["T1059"]["recall"], {"num": 1, "den": 1, "value": 1.0})

    def test_per_detection_and_strict_against_lenient_precision(self):
        s = self.folder().score()[0]["per_detection"]
        shell = s["shell_from_service"]
        self.assertEqual((shell["expected"], shell["detected"], shell["tp"], shell["fp"]), (2, 1, 1, 1))
        self.assertEqual(shell["recall"], {"num": 1, "den": 2, "value": 0.5})
        self.assertEqual(shell["precision_lenient"], {"num": 1, "den": 2, "value": 0.5})
        ua = s["unusual_ancestry"]
        self.assertEqual((ua["tp"], ua["fp"], ua["acceptable"]), (0, 0, 1))
        self.assertEqual(ua["precision_lenient"], {"num": 0, "den": 0, "value": None})
        self.assertEqual(ua["precision_strict"], {"num": 0, "den": 1, "value": 0.0})
        self.assertEqual(ua["recall"], {"num": 0, "den": 0, "value": None})

    def test_strict_differs_from_lenient_when_an_acceptable_alert_exists(self):
        both = Folder([scenario("S1", acceptable=["exec_from_tmp"])], {"S1": window(1000, 5000)},
                      [alert("shell_from_service", 1100, "EVT_EVAL_S1"), alert("exec_from_tmp", 1200, "EVT_EVAL_S1")])
        self.addCleanup(both.cleanup)
        p = both.score()[0]["pooled"]
        self.assertEqual((p["precision_lenient"], p["precision_strict"]),
                         ({"num": 1, "den": 1, "value": 1.0}, {"num": 1, "den": 2, "value": 0.5}))

    def test_pooled_numbers(self):
        p = self.folder().score()[0]["pooled"]
        self.assertEqual(p["recall"], {"num": 2, "den": 3, "value": round(2 / 3, 6)})
        self.assertEqual((p["tp"], p["fp"], p["acceptable"]), (2, 2, 1))
        self.assertEqual(p["precision_lenient"], {"num": 2, "den": 4, "value": 0.5})
        self.assertEqual(p["precision_strict"], {"num": 2, "den": 5, "value": 0.4})

    def test_benign_false_positives_per_hour_and_the_denominator(self):
        b = self.folder().score()[0]["benign"]
        self.assertEqual(b, {"alerts": 2, "seconds": 20.0, "fp_per_hour": 360.0})

    def test_without_a_benign_scenario_the_rate_is_none(self):
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [])
        self.addCleanup(f.cleanup)
        self.assertEqual(f.score()[0]["benign"], {"alerts": 0, "seconds": 0.0, "fp_per_hour": None})

    def test_technique_recall_is_not_listed_for_a_technique_with_no_attack(self):
        f = Folder([scenario("B1", kind="benign")], {"B1": window(0, SEC)}, [])
        self.addCleanup(f.cleanup)
        s = f.score()[0]
        self.assertEqual(s["per_technique"], {})
        self.assertEqual(s["pooled"]["recall"], {"num": 0, "den": 0, "value": None})


class Latency(unittest.TestCase):

    def test_latency_comes_from_the_stamped_file(self):
        a1, a2 = alert("shell_from_service", 1100, "EVT_EVAL_S1"), alert("exec_from_tmp", 1200, "EVT_EVAL_S1")
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [a1, a2], latency_ns=2500000)
        self.addCleanup(f.cleanup)
        lat = f.score()[0]["latency"]
        self.assertEqual(lat["all"], {"n": 2, "p50_ms": 2.5, "p95_ms": 2.5, "max_ms": 2.5})
        self.assertEqual(lat["true_positive"]["n"], 1)
        self.assertEqual(lat["mode"], "buffered")

    def test_arrival_before_the_event_is_counted_as_negative(self):
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [alert("shell_from_service", 1100, "EVT_EVAL_S1")], latency_ns=-1000000)
        self.addCleanup(f.cleanup)
        lat = f.score()[0]["latency"]
        self.assertEqual((lat["negative"], lat["all"]["p50_ms"]), (1, -1.0))

    def test_no_alerts_gives_none(self):
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [])
        self.addCleanup(f.cleanup)
        self.assertEqual(f.score()[0]["latency"]["all"], {"n": 0, "p50_ms": None, "p95_ms": None, "max_ms": None})

    def test_unreadable_lines_are_counted(self):
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [], extra={"alerts.stamped.tsv": "not a stamped line\n12\t{broken\n12\t[1]\n"})
        self.addCleanup(f.cleanup)
        self.assertEqual(f.score()[0]["bad_alert_lines"], 3)


class Snapshot(unittest.TestCase):

    def test_no_warning_when_the_live_files_match(self):
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [])
        self.addCleanup(f.cleanup)
        self.assertEqual(f.score()[0]["warnings"], [])

    def test_a_changed_live_file_warns_and_the_snapshot_is_used(self):
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [alert("shell_from_service", 1100, "EVT_EVAL_S1")])
        self.addCleanup(f.cleanup)
        live = os.path.join(f.live, "S1", "scenario.json")
        changed = scenario("S1")
        changed["expected"] = [{"detection": "exec_from_tmp", "min_count": 1}]
        with open(live, "w") as fh:
            json.dump(changed, fh)
        scores, report = f.score()
        self.assertEqual(len(scores["warnings"]), 1)
        self.assertIn("S1 was changed after the run", scores["warnings"][0])
        self.assertEqual(scores["scenarios"]["S1"]["outcome"], "detected")
        self.assertTrue(report.startswith("# Evaluation report: 20000101-000000-eval\n\nWARNING"))

    def test_a_missing_and_an_extra_live_scenario_warn(self):
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [])
        self.addCleanup(f.cleanup)
        shutil.rmtree(os.path.join(f.live, "S1"))
        os.makedirs(os.path.join(f.live, "S9"))
        text = " ".join(f.score()[0]["warnings"])
        self.assertIn("for S1 is gone", text)
        self.assertIn("live scenario S9 was not part of this run", text)

    def test_a_snapshot_that_does_not_match_its_recorded_hash_warns(self):
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [])
        self.addCleanup(f.cleanup)
        with open(os.path.join(f.results, "scenarios_snapshot", "S1.json"), "a") as fh:
            fh.write(" ")
        self.assertIn("snapshot of S1 does not match", " ".join(f.score()[0]["warnings"]))


class Resources(unittest.TestCase):

    def test_cpu_memory_events_and_drops(self):
        csv_text = ("elapsed_ns,role,pid,utime_ticks,stime_ticks,vmrss_kb,vmhwm_kb\n"
                    "0,loader,10,0,0,1000,1100\n1000000000,loader,10,40,10,1200,1300\n2000000000,loader,10,90,60,1100,1400\n"
                    "0,runner,12,0,0,5000,5000\n")
        events = "".join(json.dumps(e) + "\n" for e in (
            {"type": "exec_attempt", "ts_ns": 10 * SEC}, {"type": "exec_success", "ts_ns": 10 * SEC + SEC // 2},
            {"type": "lost", "ts_ns": 11 * SEC, "dropped": 7}, {"type": "exit", "ts_ns": 12 * SEC + 9 * SEC // 10}))
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [],
                   extra={"resources.csv": csv_text, "events.jsonl": events, "loader.stderr": "loader: attached\nloader: file_stats mode=exit x=1\n"})
        self.addCleanup(f.cleanup)
        r = f.score()[0]["resources"]
        loader = r["processes"]["loader"]
        self.assertEqual((loader["samples"], loader["cpu_percent_mean"], loader["cpu_percent_p95"]), (3, 75.0, 100.0))
        self.assertEqual((loader["max_rss_kb"], loader["peak_vmhwm_kb"]), (1200, 1400))
        self.assertIsNone(r["processes"]["runner"]["cpu_percent_mean"])
        self.assertEqual(r["events"], {"n": 4, "seconds": 3, "mean_per_s": 1.333, "p95_per_s": 2, "peak_per_s": 2})
        self.assertEqual((r["drops"]["lost_events"], r["drops"]["dropped_records"]), (1, 7))
        self.assertEqual(r["drops"]["loader_lines"], ["loader: file_stats mode=exit x=1"])

    def test_bpf_stats_mean_per_run(self):
        raw = {"available": True, "reason": None, "programs": [{"name": "b", "run_cnt": 4, "run_time_ns": 1000}, {"name": "a", "run_cnt": 0, "run_time_ns": 0}]}
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [], extra={"bpf_stats.json": json.dumps(raw)})
        self.addCleanup(f.cleanup)
        programs = f.score()[0]["bpf_stats"]["programs"]
        self.assertEqual([(p["name"], p["mean_ns_per_run"]) for p in programs], [("a", None), ("b", 250.0)])

    def bpf_folder(self, extra=None):
        """constructed folder and not a captured output with a bpf_stats.json in the new format; raw events and loader stats line"""
        raw = {"available": True, "reason": None, "mode": "exit", "selected_by": "names",
               "programs": [{"name": "handle_exec_attempt", "kernel_name": "handle_exec_att", "run_cnt": 5, "run_time_ns": 500, "status": "counts"},
                            {"name": "handle_exit", "kernel_name": "handle_exit", "run_cnt": 4, "run_time_ns": 400, "status": "counts"},
                            {"name": "handle_openat_save", "kernel_name": "handle_openat_sav", "run_cnt": 90, "run_time_ns": 900, "status": "counts"},
                            {"name": "handle_setuid", "kernel_name": "handle_setuid", "run_cnt": None, "run_time_ns": None, "status": "no data from bpftool"}],
               "not_found": ["handle_setresuid", "handle_exec_success"],
               "ambiguous": [{"kernel_name": "handle_aaaaaaaa", "candidates": ["handle_aaaaaaaa_x", "handle_aaaaaaaa_y"], "reason": "a prefix shared by several expected programs"}],
               "raw_names_selected": ["handle_exec_att", "handle_exit"], "raw_names_listed": ["handle_exec_att", "sd_devices"]}
        events = "".join(json.dumps({"type": t, "ts_ns": 10 + i}) + "\n" for i, t in enumerate(
            ["exec_attempt", "exec_attempt", "exec_success", "exit", "file_open"]))
        files = {"bpf_stats.json": json.dumps(raw), "events.jsonl": events,
                 "loader.stderr": "loader: attached\nloader: file_stats mode=exit openat_seen=88 openat_blank=0 file_open_emitted=1\n"}
        files.update(extra or {})
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [], extra=files)
        self.addCleanup(f.cleanup)
        return f

    def test_the_table_has_the_raw_name_the_status_and_the_own_data_count(self):
        scores, report = self.bpf_folder().score()
        by = {p["name"]: p for p in scores["bpf_stats"]["programs"]}
        self.assertEqual(by["handle_exec_attempt"]["own_data"], {"what": "exec_attempt events", "count": 2})
        self.assertEqual(by["handle_openat_save"]["own_data"], {"what": "openat_seen", "count": 88})
        self.assertIsNone(by["handle_exit"]["own_data"])
        self.assertEqual(by["handle_setuid"]["status"], "no data from bpftool")
        self.assertEqual(by["handle_exec_attempt"]["kernel_name"], "handle_exec_att")
        self.assertIn("| handle_exec_attempt | handle_exec_att | 5 | 500 | 100.0 | exec_attempt events 2 | counts |", report)
        self.assertIn("| handle_openat_save | handle_openat_sav | 90 | 900 | 10.0 | openat_seen 88 | counts |", report)
        self.assertIn("| handle_exit | handle_exit | 4 | 400 | 100.0 | - | counts |", report)
        self.assertIn("| handle_setuid | handle_setuid | n/a | n/a | n/a | - | no data from bpftool |", report)

    def test_the_report_lists_what_was_not_found_and_what_is_ambiguous(self):
        scores, report = self.bpf_folder().score()
        self.assertEqual(scores["bpf_stats"]["not_found"], ["handle_exec_success", "handle_setresuid"])
        self.assertIn("not found in the bpftool output: handle_exec_success, handle_setresuid.", report)
        self.assertIn("bpftool name handle_aaaaaaaa could be handle_aaaaaaaa_x or handle_aaaaaaaa_y (a prefix shared by several expected programs)", report)
        self.assertIn("not an error", report)
        self.assertIn("slightly after the loader attached", report)
        self.assertIn("exceed the events by design", report)
        self.assertIn("is not read as zero runs", report)

    def test_the_old_format_still_scores_and_says_the_not_found_list_was_not_recorded(self):
        raw = {"available": True, "reason": None, "programs": [{"name": "handle_exit", "run_cnt": 4, "run_time_ns": 400}]}
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [], extra={"bpf_stats.json": json.dumps(raw)})
        self.addCleanup(f.cleanup)
        scores, report = f.score()
        self.assertIsNone(scores["bpf_stats"]["not_found"])
        self.assertIn("not found in the bpftool output: not recorded in this folder.", report)
        self.assertEqual(scores["bpf_stats"]["programs"][0]["status"], "counts")

    def test_no_programs_and_no_data_are_stated(self):
        raw = {"available": False, "reason": "none of the expected programs was found in the bpftool output", "programs": [],
               "not_found": ["handle_exit"], "ambiguous": []}
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [], extra={"bpf_stats.json": json.dumps(raw)})
        self.addCleanup(f.cleanup)
        report = f.score()[1]
        self.assertIn("Not available: none of the expected programs was found", report)
        self.assertIn("not found in the bpftool output: handle_exit.", report)

    def test_rescoring_with_the_new_columns_is_byte_identical(self):
        f = self.bpf_folder()
        f.score()
        first = [read_bytes(f.results, n) for n in ("scores.json", "report.md")]
        f.score()
        self.assertEqual(first, [read_bytes(f.results, n) for n in ("scores.json", "report.md")])

    def test_missing_files_do_not_stop_the_scoring(self):
        f = Folder([scenario("S1")], {"S1": window(1000, 2000)}, [])
        self.addCleanup(f.cleanup)
        s = f.score()[0]
        self.assertEqual((s["resources"]["processes"], s["resources"]["events"]), ({}, None))
        self.assertFalse(s["bpf_stats"]["available"])


class Outputs(unittest.TestCase):

    def folder(self):
        f = Folder([scenario("S1", acceptable=["unusual_ancestry"]), scenario("B1", kind="benign")],
                   {"S1": window(1000, 2000), "B1": window(5 * SEC, 25 * SEC)},
                   [alert("shell_from_service", 1100, "EVT_EVAL_S1"), alert("exec_from_tmp", 7 * SEC, "EVT_EVAL_B1"),
                    alert("rapid_spawn", 3000, "no marker")])
        self.addCleanup(f.cleanup)
        return f

    def test_rescoring_is_byte_identical(self):
        f = self.folder()
        f.score()
        first = [read_bytes(f.results, n) for n in ("scores.json", "report.md")]
        f.score()
        again = [read_bytes(f.results, n) for n in ("scores.json", "report.md")]
        self.assertEqual(first, again)
        self.assertEqual(json.loads(first[0])["scenarios"]["S1"]["outcome"], "detected")

    def test_scores_json_has_sorted_keys_and_no_clock_values(self):
        f = self.folder()
        f.score()
        raw = read_bytes(f.results, "scores.json").decode()
        self.assertEqual(raw, json.dumps(json.loads(raw), sort_keys=True, indent=1) + "\n")
        self.assertNotIn("wall", raw)

    def test_the_report_has_every_section_and_denominators(self):
        report = self.folder().score()[1]
        for heading in ("## Scenario outcomes", "## Per technique", "## Per detection", "## Benign runs", "## Latency", "## Resources",
                        "## bpf_stats", "## Unattributed alerts", "## What these numbers do not mean"):
            self.assertIn(heading, report)
        self.assertIn("1/1 (1.000)", report)
        self.assertIn("0/0 (n/a)", report)
        self.assertIn("false positives per hour: 180.0", report)
        self.assertIn("Inside a scenario window without that scenario's marker: 0.", report)
        self.assertIn("Outside every scenario window: 1.", report)

    def test_main_prints_the_warnings_and_writes_both_files(self):
        f = self.folder()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(evaluate.main([f.results, "--scenarios-dir", f.live]), 0)
            self.assertEqual(evaluate.main([os.path.join(f.tmp, "nowhere")]), 2)
        self.assertTrue(os.path.isfile(os.path.join(f.results, "scores.json")))
        self.assertTrue(os.path.isfile(os.path.join(f.results, "report.md")))


if __name__ == "__main__":
    unittest.main()
