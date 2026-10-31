import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "stress"))
import run_stress  #noqa: E402
import stress  #noqa: E402


class FakeClock:
    def __init__(self):
        self.now = 0

    def clock(self):
        return self.now

    def wait(self, seconds):
        self.now += int(round(seconds * 1e9))
        return False


class PacingArithmetic(unittest.TestCase):
    def test_slots_are_evenly_spaced(self):
        self.assertEqual([stress.slot_ns(1000, 4, i) for i in range(3)], [1000, 250001000, 500001000])
        self.assertEqual(stress.slot_ns(0, 3, 1), 333333333)
        self.assertEqual(stress.slot_ns(0, 3, 3), 1000000000)

    def test_planned_and_achieved(self):
        self.assertEqual(stress.planned_execs(250, 30), 7500)
        self.assertEqual(stress.achieved_rate(300, 0, 3000000000), 100.0)
        self.assertEqual(stress.achieved_rate(300, 5, 5), 0.0)

    def test_lateness_limit_is_exclusive(self):
        self.assertFalse(stress.is_late(0, stress.LATE_LIMIT_NS))
        self.assertTrue(stress.is_late(0, stress.LATE_LIMIT_NS + 1))

    def test_on_time_step_attempts_every_slot(self):
        fake = FakeClock()
        result = stress.run_step(10, 1, 1, lambda: True, fake.clock, fake.wait, lambda: False)
        self.assertEqual((result["attempted"], result["completed"], result["late_skipped"], result["partial"]), (10, 10, 0, False))

    def test_slow_spawns_skip_late_slots_and_never_burst(self):
        fake = FakeClock()

        def slow():
            fake.now += 300000000
            return True

        result = stress.run_step(10, 1, 1, slow, fake.clock, fake.wait, lambda: False)
        self.assertEqual((result["attempted"], result["completed"], result["late_skipped"]), (4, 4, 6))
        self.assertEqual(result["end_ns"], 1200000000)

    def test_failed_spawns_are_attempted_but_not_completed(self):
        fake = FakeClock()
        result = stress.run_step(10, 1, 1, lambda: False, fake.clock, fake.wait, lambda: False)
        self.assertEqual((result["attempted"], result["completed"]), (10, 0))

    def test_stop_request_ends_the_step_as_partial(self):
        fake = FakeClock()
        calls = {"n": 0}

        def spawn():
            calls["n"] += 1
            return True

        result = stress.run_step(10, 1, 1, spawn, fake.clock, fake.wait, lambda: calls["n"] >= 1)
        self.assertEqual(result["attempted"], 1)
        self.assertTrue(result["partial"])


class Arguments(unittest.TestCase):
    def test_defaults_are_valid(self):
        self.assertEqual(stress.validate(list(stress.DEFAULT_RATES), stress.DEFAULT_STEP_SECONDS, stress.DEFAULT_GAP_SECONDS, stress.DEFAULT_WORKERS), [])

    def test_limits_are_enforced(self):
        self.assertEqual(len(stress.validate([0], 30, 10, 32)), 1)
        self.assertEqual(len(stress.validate([stress.MAX_RATE + 1], 30, 10, 32)), 1)
        self.assertEqual(len(stress.validate([100], 0, 10, 32)), 1)
        self.assertEqual(len(stress.validate([100], 30, 10, stress.MAX_WORKERS + 1)), 1)
        self.assertEqual(len(stress.validate([], 30, 10, 32)), 1)

    def test_step_line_round_trip(self):
        result = {"start_ns": 0, "end_ns": 30000000000, "attempted": 3000, "completed": 3000, "late_skipped": 0, "partial": False}
        line = stress.format_step_line(1, 100, result)
        self.assertEqual(line, "step=1 target=100 start_ns=0 end_ns=30000000000 attempted=3000 completed=3000 achieved=100.0 late_skipped=0 partial=0")
        parsed = stress.parse_step_line(line)
        self.assertEqual((parsed["step"], parsed["target"], parsed["attempted"], parsed["achieved"], parsed["partial"]), (1, 100, 3000, 100.0, 0))

    def test_unreadable_lines_are_ignored(self):
        self.assertIsNone(stress.parse_step_line("stress pid 4"))
        self.assertIsNone(stress.parse_step_line("step=1 target=100"))


class SamplerWindows(unittest.TestCase):
    def rows(self):
        ticks = [0, 10, 30, 60, 100]
        rss = [100, 200, 150, 120, 110]
        return [{"elapsed_ns": i * 1000000000, "role": "runner", "ticks": ticks[i], "rss": rss[i], "hwm": rss[i]} for i in range(5)]

    def test_slice_keeps_rows_inside_the_window_in_order(self):
        rows = list(reversed(self.rows()))
        inside = run_stress.slice_rows(rows, 1000000000, 3000000000)
        self.assertEqual([r["elapsed_ns"] for r in inside], [1000000000, 2000000000, 3000000000])

    def test_cpu_percent_per_interval(self):
        inside = run_stress.slice_rows(self.rows(), 1000000000, 4000000000)
        got = run_stress.cpu_percents(inside, 100)
        self.assertEqual(len(got), 3)
        for want, have in zip([20.0, 30.0, 40.0], got):
            self.assertAlmostEqual(want, have)

    def test_window_stats(self):
        stats = run_stress.window_stats(self.rows(), 1000000000, 4000000000, 100)
        self.assertEqual(stats["samples"], 4)
        self.assertAlmostEqual(stats["cpu_mean"], 30.0)
        self.assertAlmostEqual(stats["cpu_p95"], 40.0)
        self.assertEqual(stats["max_rss_kb"], 200)

    def test_window_with_one_row_has_no_cpu(self):
        stats = run_stress.window_stats(self.rows(), 1500000000, 2500000000, 100)
        self.assertEqual(stats["samples"], 1)
        self.assertIsNone(stats["cpu_mean"])
        self.assertEqual(stats["max_rss_kb"], 150)

    def test_empty_window(self):
        stats = run_stress.window_stats(self.rows(), 9000000000, 10000000000, 100)
        self.assertEqual(stats, {"samples": 0, "cpu_mean": None, "cpu_p95": None, "max_rss_kb": None})


class EventWindows(unittest.TestCase):
    def test_events_and_lost_records_are_binned_by_timestamp(self):
        lines = [{"type": "exec_success", "ts_ns": 1500000000}, {"type": "exec_success", "ts_ns": 1600000000},
                 {"type": "exec_success", "ts_ns": 2500000000}, {"type": "lost", "ts_ns": 1700000000, "dropped": 5},
                 {"type": "lost", "dropped": 3}, {"type": "exec_success", "ts_ns": 5000000000}]
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "events.jsonl")
            with open(path, "w", encoding="utf-8") as f:
                for ev in lines[:5]:
                    f.write(json.dumps(ev) + "\n")
                f.write("not json\n")
                f.write(json.dumps(lines[5]) + "\n")
            per, totals = run_stress.bin_events(path, [(1, 1000000000, 2000000000), (2, 5000000000, 6000000000)])
        self.assertEqual((per[1]["events"], per[1]["lost_events"], per[1]["dropped_records"]), (2, 1, 5))
        self.assertEqual(max(per[1]["seconds"].values()), 2)
        self.assertEqual(per[2]["events"], 1)
        self.assertEqual(totals, {"events": 4, "lost_events": 2, "dropped_records": 8, "unplaced_lost_events": 1, "unplaced_dropped_records": 3})

    def test_missing_file_gives_zeros(self):
        per, totals = run_stress.bin_events("/nonexistent/events.jsonl", [(1, 0, 10)])
        self.assertEqual(per[1]["events"], 0)
        self.assertEqual(totals["events"], 0)


class Guards(unittest.TestCase):
    def test_guard_reasons(self):
        self.assertIn("disk", run_stress.guard_reason(10, 1000, 100, 100))
        self.assertIn("memory", run_stress.guard_reason(1000, 10, 100, 100))
        self.assertIsNone(run_stress.guard_reason(1000, 1000, 100, 100))
        self.assertIsNone(run_stress.guard_reason(None, None, 100, 100))

    def test_results_folder_must_be_outside_the_repository(self):
        with tempfile.TemporaryDirectory() as base:
            repo = os.path.join(base, "repo")
            self.assertTrue(run_stress.inside_repo(os.path.join(repo, "out"), repo))
            self.assertTrue(run_stress.inside_repo(repo, repo))
            self.assertFalse(run_stress.inside_repo(os.path.join(base, "repo_other"), repo))
            self.assertFalse(run_stress.inside_repo(os.path.join(base, "out"), repo))

    def test_estimates_and_time_limit(self):
        self.assertEqual(run_stress.estimate_bytes([100, 200], 10), 3000 * run_stress.EST_BYTES_PER_EXEC)
        self.assertEqual(run_stress.stress_timeout_seconds(6, 30, 10), 6 * 35 + 5 * 10 + 5)

    def test_mem_available_is_read_from_meminfo(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "meminfo")
            with open(path, "w", encoding="ascii") as f:
                f.write("MemTotal:       100 kB\nMemAvailable:   2048 kB\n")
            self.assertEqual(run_stress.mem_available_kb(path), 2048)
        self.assertIsNone(run_stress.mem_available_kb("/nonexistent/meminfo"))


class Report(unittest.TestCase):
    def doc(self):
        ran = {"index": 1, "target": 100, "status": "ok", "reason": None, "start_ns": 0, "end_ns": 30000000000, "window_seconds": 30.0,
               "attempted": 3000, "completed": 2990, "late_skipped": 0, "achieved": 99.7, "events": 9000, "events_per_s": 300.0,
               "peak_events_per_s": 410, "lost_events": 2, "dropped_records": 17,
               "cpu": {"loader": {"cpu_mean": 5.0, "cpu_p95": 8.0, "max_rss_kb": 100}, "normalizer": {"cpu_mean": 20.5, "cpu_p95": 31.0, "max_rss_kb": 100},
                       "runner": {"cpu_mean": None, "cpu_p95": None, "max_rss_kb": 5000}},
               "runner_max_rss_kb": 5000, "alerts": 3, "alerts_by_detection": {"rapid_spawn": 3}}
        skipped = {"index": 2, "target": 250, "status": "not run", "reason": "free disk space is below the floor"}
        totals = {"events": 9000, "lost_events": 2, "dropped_records": 17, "unplaced_lost_events": 0, "unplaced_dropped_records": 0,
                  "alerts": 3, "alerts_in_steps": 3, "alerts_outside_steps": 0, "bad_alert_lines": 0}
        return {"folder": "20250101-000000-stress", "kernel": "6.6.0", "rates": [100, 250], "step_seconds": 30, "gap_seconds": 10, "workers": 32,
                "spawn_parent_pid": 4242, "spawn_parent_count": 1, "clock_check": {"passed": True}, "aborted": None,
                "guard": "free disk space is below the floor", "bpf_available": True, "loader_lines": ["lost 2"], "totals": totals,
                "steps": [ran, skipped]}

    def test_pair_format(self):
        self.assertEqual(run_stress.fmt_pair(12.5, 20.0), "12.5 / 20.0")
        self.assertEqual(run_stress.fmt_pair(None, None), "n/a")

    def test_one_row_per_step_including_steps_not_run(self):
        report = run_stress.render_report(self.doc())
        rows = [l for l in report.splitlines() if l.startswith("| 1 |") or l.startswith("| 2 |")]
        self.assertEqual(len(rows), 2)
        self.assertIn("2990", rows[0])
        self.assertIn("2 (17 dropped)", rows[0])
        self.assertIn("5.0 / 8.0", rows[0])
        self.assertIn("not run: free disk space is below the floor", rows[1])

    def test_report_states_the_rules(self):
        report = run_stress.render_report(self.doc())
        for phrase in ("separate from detection accuracy", "not pooled", "not scored", "Only measured rates are claimed",
                       "Nothing is extrapolated beyond the highest rate measured: 99.7 execs per second",
                       "1 distinct parent process", "pid 4242"):
            self.assertIn(phrase, report)

    def test_report_without_a_measured_step_claims_no_rate(self):
        doc = self.doc()
        doc["steps"] = [doc["steps"][1]]
        self.assertIn("no step ran, so no rate was measured", run_stress.render_report(doc))

    def test_report_has_no_long_dashes(self):
        report = run_stress.render_report(self.doc())
        self.assertNotIn("—", report)
        self.assertNotIn("–", report)

    def test_build_steps_lists_missing_steps_with_the_reason(self):
        lines = [stress.parse_step_line(stress.format_step_line(1, 100, {"start_ns": 0, "end_ns": 30000000000, "attempted": 5, "completed": 5,
                                                                         "late_skipped": 0, "partial": True}))]
        steps = run_stress.build_steps([100, 250, 500], lines, "stopped by the guard")
        self.assertEqual([s["status"] for s in steps], ["partial", "not run", "not run"])
        self.assertEqual(steps[2]["reason"], "stopped by the guard")


if __name__ == "__main__":
    unittest.main()
