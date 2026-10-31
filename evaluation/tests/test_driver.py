"""
tests for parts of the harness that need no root which is the stamper, the sampler's parsing, the clock check, the plan, the dry run and the small helpers of run_eval.py
every file, event, and /proc text here is a !!constructed fixture, not captured output!!; the one test that starts processes only runs bash and sleep
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL_DIR = os.path.dirname(HERE)
sys.path.insert(0, EVAL_DIR)

import run_eval  #noqa: E402
import sampler  #noqa: E402
import scenario_lib  #noqa: E402
import stamp_lines  #noqa: E402

SCENARIOS = os.path.join(EVAL_DIR, "scenarios")

STAT = "1234 (my (odd) name) S 1 1234 1234 0 -1 4194304 100 0 0 0 40 10 0 0 20 0 1 0 5000 1000000 100 18446744073709551615"
STATUS = "Name:\tloader\nVmPeak:\t   5000 kB\nVmHWM:\t    2048 kB\nVmRSS:\t    1024 kB\nThreads:\t1\n"


class Stamper(unittest.TestCase):

    def run_stamp(self, chunks):
        ticks = iter(range(100, 1000, 100))
        pending = list(chunks) + [b""]
        out = io.BytesIO()
        count = stamp_lines.stamp(lambda: pending.pop(0), out, clock=lambda: next(ticks))
        return count, out.getvalue().decode().splitlines()

    def test_each_line_gets_the_time_of_the_read_that_completed_it(self):
        count, lines = self.run_stamp([b'{"a":1}\n', b'{"b"', b':2}\n{"c":3}\n'])
        self.assertEqual(count, 3)
        self.assertEqual(lines, ['100\t{"a":1}', '300\t{"b":2}', '300\t{"c":3}'])

    def test_a_last_line_without_a_newline_is_kept(self):
        count, lines = self.run_stamp([b"one\ntwo"])
        self.assertEqual((count, lines), (2, ["100\tone", "200\ttwo"]))

    def test_no_input_writes_nothing(self):
        self.assertEqual(self.run_stamp([]), (0, []))

    def test_main_needs_exactly_one_argument(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(stamp_lines.main([]), 2)


class SamplerParsing(unittest.TestCase):

    def test_stat_with_spaces_and_brackets_in_the_command_name(self):
        self.assertEqual(sampler.parse_stat(STAT), (40, 10))

    def test_stat_that_cannot_be_read(self):
        self.assertIsNone(sampler.parse_stat(""))
        self.assertIsNone(sampler.parse_stat("1 (x) S 1 2"))
        self.assertIsNone(sampler.parse_stat("1 (x) S" + " a" * 20))

    def test_status(self):
        self.assertEqual(sampler.parse_status(STATUS), {"VmRSS": 1024, "VmHWM": 2048})
        self.assertEqual(sampler.parse_status("Name:\tx\n"), {})

    def test_one_sample_of_a_fake_proc_tree(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        os.makedirs(os.path.join(root, "1234"))
        with open(os.path.join(root, "1234", "stat"), "w") as f:
            f.write(STAT)
        with open(os.path.join(root, "1234", "status"), "w") as f:
            f.write(STATUS)
        out = os.path.join(root, "out.csv")
        s = sampler.Sampler({"loader": 1234, "gone": 999}, out, clock=iter([1000, 2500000000]).__next__, proc_root=root)
        s.sample_once()
        s.out.close()
        with open(out) as f:
            lines = f.read().splitlines()
        self.assertEqual(lines, [sampler.CSV_HEADER, "2499999000,loader,1234,40,10,1024,2048"])
        self.assertEqual(s.rows, 1)


class ClockCheck(unittest.TestCase):

    def events(self, items):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "events.jsonl")
        with open(path, "w") as f:
            for typ, ts, argv in items:
                f.write(json.dumps({"type": typ, "ts_ns": ts, "argv": argv}) + "\n")
        return path

    def test_inside_the_bracket_passes(self):
        path = self.events([("exec_attempt", 150, ["/bin/true", "M1"]), ("exec_attempt", 250, ["/bin/true", "M2"])])
        result = run_eval.check_clock(path, [("M1", 100, 200), ("M2", 200, 300)])
        self.assertEqual((result["passed"], result["max_skew_ns"]), (True, 0))

    def test_outside_the_bracket_fails_and_the_skew_is_the_distance_to_the_nearest_edge(self):
        path = self.events([("exec_attempt", 90, ["/bin/true", "M1"]), ("exec_attempt", 340, ["/bin/true", "M2"])])
        result = run_eval.check_clock(path, [("M1", 100, 200), ("M2", 200, 300)])
        self.assertEqual((result["passed"], result["max_skew_ns"]), (False, 40))
        self.assertEqual([c["skew_ns"] for c in result["checks"]], [10, 40])

    def test_a_marker_that_never_shows_up_fails(self):
        path = self.events([("exec_success", 150, ["/bin/true", "M1"])])
        result = run_eval.check_clock(path, [("M1", 100, 200)])
        self.assertEqual((result["passed"], result["checks"][0]["found"]), (False, False))

    def test_a_missing_file_fails_without_an_exception(self):
        self.assertFalse(run_eval.check_clock("/nonexistent/events.jsonl", [("M1", 1, 2)])["passed"])


class Plan(unittest.TestCase):

    def scenarios(self):
        scenarios, problems = scenario_lib.load_scenarios(SCENARIOS)
        self.assertEqual(problems, [])
        return scenarios

    def test_the_plan_lists_every_scenario_and_the_exact_pipeline(self):
        text = "\n".join(run_eval.plan_lines(self.scenarios(), found=[]))
        for sc in self.scenarios():
            self.assertIn(sc["id"], text)
            self.assertIn("marker " + sc["marker"], text)
            self.assertIn("evt_eval_action " + sc["marker"], text)
        for stage in ("loader", "tee_events", "normalizer", "tee_normalized", "runner", "stamper"):
            self.assertIn(stage, text)
        self.assertIn("--stats-json", text)
        self.assertIn("2 s settle pause", text)
        self.assertIn("every exit path", text)
        self.assertIn("nothing is started", text)

    def test_leftovers_are_shown_in_the_plan(self):
        text = "\n".join(run_eval.plan_lines(self.scenarios(), found=["/opt/evt_eval_s01_x"]))
        self.assertIn("/opt/evt_eval_s01_x", text)

    def test_dry_run_prints_the_plan_and_starts_nothing(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = run_eval.main(["--dry-run", "--results-root", "/nonexistent/should/not/be/made"])
        self.assertEqual(status, 0)
        self.assertIn("S05_benign_smoke", out.getvalue())
        self.assertFalse(os.path.exists("/nonexistent"))

    def test_a_bad_scenario_directory_stops_the_run_before_anything_starts(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(os.path.join(d, "X"))
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(run_eval.main(["--dry-run", "--scenarios-dir", d]), 2)
        self.assertIn("X: scenario.json is missing", err.getvalue())

    def test_the_pipeline_commands(self):
        cmds = run_eval.pipeline_commands("/r")
        self.assertEqual([n for n, _ in cmds], list(run_eval.PIPELINE_STAGES))
        by = dict(cmds)
        self.assertEqual(by["loader"], [run_eval.LOADER])
        self.assertEqual(by["tee_events"], ["tee", "/r/events.jsonl"])
        self.assertEqual(by["tee_normalized"], ["tee", "/r/normalized.jsonl"])
        self.assertEqual(by["runner"][1:], [run_eval.RUNNER, "--stats-json", "/r/stats.json"])
        self.assertEqual(by["stamper"][1:], [run_eval.STAMPER, "/r/alerts.stamped.tsv"])

    def test_the_action_is_its_own_bash_c_with_the_marker_last(self):
        for sc in self.scenarios():
            argv = run_eval.action_argv(sc)
            self.assertEqual(argv[:2], ["bash", "-c"])
            self.assertEqual(argv[-1], sc["marker"])
            self.assertEqual(argv[2], scenario_lib.read_text(sc["_scripts"]["action"]))


class Helpers(unittest.TestCase):

    def test_loader_program_names_are_the_full_names_of_the_programs_the_mode_loads(self):
        names = run_eval.loader_program_names()
        self.assertEqual(len(names), 11)
        self.assertIn("handle_exec_attempt", names)
        self.assertIn("handle_openat_save", names)
        self.assertNotIn("handle_openat_entry", names)
        self.assertEqual(sorted(n for n in names if len(n) > 15), ["handle_exec_attempt", "handle_exec_success", "handle_openat_exit",
                                                                    "handle_openat_save", "handle_setresgid", "handle_setresuid"])
        entry = run_eval.loader_program_names(mode="entry")
        self.assertIn("handle_openat_entry", entry)
        self.assertNotIn("handle_openat_save", entry)
        self.assertNotIn("handle_openat_exit", entry)
        self.assertEqual(run_eval.loader_program_names("/nonexistent/exec_exit.bpf.c"), [])


def listing(names, counts=True, extra=()):
    """`bpftool -j prog show` text as a constructed fixture and not a captured output; one entry per name... with counts or without them"""
    entries = []
    for i, name in enumerate(names):
        entry = {"id": i + 1, "type": "tracepoint", "name": name}
        if counts:
            entry.update({"run_time_ns": 1000 * (i + 1), "run_cnt": 10 * (i + 1)})
        entries.append(entry)
    return json.dumps(entries + list(extra))


class BpfMatching(unittest.TestCase):

    def setUp(self):
        self.expected = run_eval.loader_program_names()

    def test_names_cut_to_fifteen_characters_are_reported_under_their_full_names(self):
        raw = [n[:15] for n in self.expected]
        got = run_eval.parse_bpf_programs(listing(raw), 1, self.expected)
        self.assertEqual([p["name"] for p in got["programs"]], sorted(self.expected))
        by = {p["name"]: p for p in got["programs"]}
        self.assertEqual(by["handle_exec_attempt"]["kernel_name"], "handle_exec_att")
        self.assertEqual(by["handle_exit"]["kernel_name"], "handle_exit")
        self.assertEqual((got["not_found"], got["ambiguous"], got["unmatched_names"]), ([], [], []))
        self.assertEqual(got["selected_by"], "names")

    def test_full_names_match_too(self):
        got = run_eval.parse_bpf_programs(listing(self.expected), 1, self.expected)
        self.assertEqual([p["name"] for p in got["programs"]], sorted(self.expected))
        self.assertEqual(got["not_found"], [])

    def test_a_prefix_shared_by_two_expected_names_is_ambiguous_and_not_guessed(self):
        expected = ["handle_aaaaaaaa_x", "handle_aaaaaaaa_y", "handle_other"]
        got = run_eval.parse_bpf_programs(listing(["handle_aaaaaaaa", "handle_other"]), 1, expected)
        self.assertEqual([p["name"] for p in got["programs"]], ["handle_other"])
        self.assertEqual(len(got["ambiguous"]), 1)
        self.assertEqual((got["ambiguous"][0]["kernel_name"], got["ambiguous"][0]["candidates"]), ("handle_aaaaaaaa", ["handle_aaaaaaaa_x", "handle_aaaaaaaa_y"]))
        self.assertEqual(got["not_found"], [])
        single = run_eval.parse_bpf_programs(listing(["handle_aaaaaaaa_x", "handle_aaaaaaaa_y"]), 1, expected)
        self.assertEqual([p["name"] for p in single["programs"]], ["handle_aaaaaaaa_x", "handle_aaaaaaaa_y"])

    def test_an_expected_program_that_is_not_listed_is_not_found(self):
        raw = [n[:15] for n in self.expected if n != "handle_setresuid"]
        got = run_eval.parse_bpf_programs(listing(raw), 1, self.expected)
        self.assertEqual(got["not_found"], ["handle_setresuid"])
        self.assertEqual(len(got["programs"]), 10)

    def test_a_program_with_no_counts_is_not_read_as_zero_runs(self):
        some = run_eval.parse_bpf_programs(listing(["handle_exit"], counts=False), 1, ["handle_exit"])
        p = some["programs"][0]
        self.assertEqual((p["run_cnt"], p["run_time_ns"], p["status"]), (None, None, "no data from bpftool"))
        zero = json.dumps([{"name": "handle_exit", "run_cnt": 0, "run_time_ns": 0}])
        self.assertEqual(run_eval.parse_bpf_programs(zero, 1, ["handle_exit"])["programs"][0]["status"], "counts")

    def test_a_program_with_counts(self):
        p = run_eval.parse_bpf_programs(listing(["handle_exit"]), 1, ["handle_exit"])["programs"][0]
        self.assertEqual((p["run_cnt"], p["run_time_ns"], p["status"]), (10, 1000, "counts"))

    def test_programs_are_taken_by_pid_when_bpftool_lists_pids(self):
        text = listing(["handle_exit"], extra=[{"name": "other", "pids": [{"pid": 77}], "run_cnt": 1, "run_time_ns": 2}])
        entries = json.loads(text)
        entries[0]["pids"] = [{"pid": 77, "comm": "loader"}]
        got = run_eval.parse_bpf_programs(json.dumps(entries), 77, ["handle_exit", "handle_connect"])
        self.assertEqual(got["selected_by"], "pids")
        self.assertEqual([p["name"] for p in got["programs"]], ["handle_exit"])
        self.assertEqual(got["unmatched_names"], ["other"])
        self.assertEqual(got["not_found"], ["handle_connect"])

    def test_unrelated_programs_are_ignored_by_name_and_the_raw_names_are_recorded(self):
        text = listing(["handle_exit", "sd_devices", "handle_exec_att"])
        got = run_eval.parse_bpf_programs(text, 1, ["handle_exit", "handle_exec_attempt"])
        self.assertEqual(got["raw_names_selected"], ["handle_exec_att", "handle_exit"])
        self.assertEqual(got["raw_names_listed"], ["handle_exec_att", "handle_exit", "sd_devices"])

    def test_a_program_listed_twice_is_ambiguous(self):
        got = run_eval.parse_bpf_programs(listing(["handle_exit", "handle_exit"]), 1, ["handle_exit"])
        self.assertEqual(got["programs"], [])
        self.assertEqual(got["ambiguous"][0]["reason"], "listed 2 times")
        self.assertEqual(got["not_found"], [])

    def test_text_that_is_not_a_json_list(self):
        self.assertIsNone(run_eval.parse_bpf_programs("not json", 1, []))
        self.assertIsNone(run_eval.parse_bpf_programs("{}", 1, []))


class BpfRead(unittest.TestCase):

    def fake(self, text, status=0):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, "out.json"), "w") as f:
            f.write(text)
        script = os.path.join(d, "fake_bpftool")
        with open(script, "w") as f:
            f.write("#!/bin/sh\ncat '%s/out.json'\nexit %d\n" % (d, status))
        os.chmod(script, 0o755)
        return script

    def test_counts_found_and_not_found_are_in_the_document(self):
        expected = ["handle_exit", "handle_connect"]
        doc = run_eval.read_bpf_stats(1, self.fake(listing(["handle_exit"])), expected)
        self.assertTrue(doc["available"])
        self.assertEqual((doc["not_found"], doc["expected"], doc["mode"]), (["handle_connect"], expected, "exit"))
        self.assertEqual(doc["raw_names_listed"], ["handle_exit"])

    def test_listed_without_counts_is_not_available_and_says_why(self):
        doc = run_eval.read_bpf_stats(1, self.fake(listing(["handle_exit"], counts=False)), ["handle_exit"])
        self.assertFalse(doc["available"])
        self.assertIn("no run_cnt", doc["reason"])
        self.assertEqual(doc["programs"][0]["status"], "no data from bpftool")

    def test_none_found_and_failures(self):
        doc = run_eval.read_bpf_stats(1, self.fake(listing(["sd_devices"])), ["handle_exit"])
        self.assertEqual((doc["available"], doc["not_found"], doc["raw_names_listed"]), (False, ["handle_exit"], ["sd_devices"]))
        self.assertIn("none of the expected programs", doc["reason"])
        self.assertIn("exited 3", run_eval.read_bpf_stats(1, self.fake("", status=3), ["handle_exit"])["reason"])
        self.assertIn("not a JSON list", run_eval.read_bpf_stats(1, self.fake("oops"), ["handle_exit"])["reason"])
        missing = run_eval.read_bpf_stats(1, "/nonexistent/bpftool", ["handle_exit"])
        self.assertEqual((missing["available"], missing["not_found"]), (False, ["handle_exit"]))
        self.assertIn("could not be run", missing["reason"])


class Helpers2(unittest.TestCase):

    def test_sysctl_read_write_and_missing(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "bpf_stats_enabled")
        self.assertEqual(run_eval.read_sysctl(path), "unavailable")
        run_eval.write_sysctl("1", path)
        self.assertEqual(run_eval.read_sysctl(path), "1")

    def test_required_commands(self):
        scenarios = scenario_lib.load_scenarios(SCENARIOS)[0]
        self.assertEqual(run_eval.missing_requirements(scenarios, which=lambda c: "/bin/" + c), [])
        self.assertEqual(run_eval.missing_requirements(scenarios, which=lambda c: None if c == "curl" else "/bin/x"),
                         ["S03_download_chmod_exec needs curl", "S11_download_relative_path needs curl", "S13_download_to_tmp_and_run needs curl"])

    def test_code_hashes_cover_the_code_directories(self):
        hashes = run_eval.code_hashes()
        for path in ("detections/runner.py", "alerts/alert.py", "graph/process_graph.py", "normalizer/normalize.py", "telemetry/src/loader.c"):
            self.assertIn(path.replace("/", os.sep), hashes)
        self.assertTrue(all(len(h) == 64 for h in hashes.values()))

    def test_env_file_has_the_hashes_and_no_timestamps(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        run_eval.write_env(d, {"kernel": "k", "mode": "m"}, {"b.py": "2", "a.py": "1"})
        with open(os.path.join(d, "env.txt")) as f:
            self.assertEqual(f.read().splitlines(), ["kernel: k", "mode: m", "sha256 a.py: 1", "sha256 b.py: 2"])

    def test_derive_alerts_strips_the_stamps(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, "alerts.stamped.tsv"), "w") as f:
            f.write('11\t{"a":1}\n22\t{"b":2}\n')
        run_eval.derive_alerts(d)
        with open(os.path.join(d, "alerts.jsonl")) as f:
            self.assertEqual(f.read(), '{"a":1}\n{"b":2}\n')

    def test_leftovers_finds_matching_paths_only(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(os.path.join(d, "evt_eval_a"))
        os.makedirs(os.path.join(d, "other"))
        self.assertEqual(run_eval.leftovers([os.path.join(d, "evt_eval_*")]), [os.path.join(d, "evt_eval_a")])
        self.assertEqual(run_eval.leftovers([os.path.join(d, "nothing_*")]), [])

    def test_a_script_that_runs_too_long_is_killed_with_its_children(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        start = time.monotonic()
        s, e, status, timed_out = run_eval.run_script(["bash", "-c", "sleep 30 & wait"], dict(os.environ), os.path.join(d, "log"), 1)
        self.assertTrue(timed_out)
        self.assertLess(time.monotonic() - start, 10)
        self.assertGreaterEqual(e - s, 1000000000)

    def test_a_script_that_finishes_reports_its_status_and_writes_its_log(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        s, e, status, timed_out = run_eval.run_script(["bash", "-c", "echo hello; exit 3"], dict(os.environ), os.path.join(d, "log"), 10)
        self.assertEqual((status, timed_out), (3, False))
        self.assertLessEqual(s, e)
        with open(os.path.join(d, "log")) as f:
            self.assertEqual(f.read(), "hello\n")


class Needs(unittest.TestCase):
    """the need checks, the new refuse-to-start patterns and the plan of the 29 scenarios; the address lookup is injected so no root and no network is needed"""

    def scenarios(self):
        scenarios, problems = scenario_lib.load_scenarios(SCENARIOS)
        self.assertEqual(problems, [])
        return scenarios

    class Done:
        def __init__(self, text):
            self.stdout = text

    def test_the_address_is_the_first_global_ipv4_of_ip_addr(self):
        text = ("2: eth0    inet 10.255.255.254/32 brd 10.255.255.254 scope global eth0\n"
                "3: eth1    inet 192.168.1.5/24 brd 192.168.1.255 scope global eth1\n")
        self.assertEqual(run_eval.first_global_ipv4(run=lambda *a, **k: self.Done(text)), "10.255.255.254")
        self.assertIsNone(run_eval.first_global_ipv4(run=lambda *a, **k: self.Done("")))
        self.assertIsNone(run_eval.first_global_ipv4(run=lambda *a, **k: self.Done("2: eth0    inet6 fe80::1/64 scope link\n")))

    def test_the_command_used_is_the_one_of_the_d7_live_test(self):
        seen = []
        run_eval.first_global_ipv4(run=lambda argv, **k: seen.append(argv) or self.Done(""))
        self.assertEqual(seen, [["ip", "-4", "-o", "addr", "show", "scope", "global"]])

    def test_a_missing_ip_command_means_no_address(self):
        def missing(*a, **k):
            raise OSError("no ip")
        self.assertIsNone(run_eval.first_global_ipv4(run=missing))

    def test_a_scenario_whose_need_is_not_met_is_skipped_with_a_reason(self):
        skipped, address = run_eval.evaluate_needs(self.scenarios(), lookup=lambda: None)
        self.assertEqual(sorted(k[:3] for k in skipped), ["S26", "S27"])
        self.assertIn("non-loopback IPv4", " ".join(skipped.values()))
        self.assertIsNone(address)

    def test_when_the_need_is_met_nothing_is_skipped_and_the_address_is_returned(self):
        self.assertEqual(run_eval.evaluate_needs(self.scenarios(), lookup=lambda: "10.0.0.7"), ({}, "10.0.0.7"))

    def test_the_lookup_is_not_made_when_no_scenario_needs_it(self):
        calls = []
        plain = [s for s in self.scenarios() if not s.get("needs")]
        self.assertEqual(run_eval.evaluate_needs(plain, lookup=lambda: calls.append(1)), ({}, None))
        self.assertEqual(calls, [])

    def test_the_lookup_is_made_once(self):
        calls = []
        run_eval.evaluate_needs(self.scenarios(), lookup=lambda: calls.append(1) or "10.0.0.7")
        self.assertEqual(calls, [1])

    def test_the_script_environment_carries_the_address_only_when_there_is_one(self):
        sc = [s for s in self.scenarios() if s["id"].startswith("S26")][0]
        self.assertEqual(run_eval.script_env(sc, "10.0.0.7")["EVT_EVAL_NONLOOPBACK_IPV4"], "10.0.0.7")
        self.assertNotIn("EVT_EVAL_NONLOOPBACK_IPV4", run_eval.script_env(sc))
        self.assertEqual(run_eval.script_env(sc, bases={"cron": "/scratch"})["EVT_EVAL_CRON_FILE"], "/scratch/evt_eval_" + sc["id"].lower())
        self.assertEqual(run_eval.script_env(sc)["EVT_EVAL_MARKER"], sc["marker"])

    def test_the_plan_marks_a_scenario_that_would_not_run(self):
        text = "\n".join(run_eval.plan_lines(self.scenarios(), found=[], lookup=lambda: None))
        self.assertIn("non-loopback IPv4 address: none; not run for that reason: S26_reverse_shell_style_connect, S27_delayed_connect", text)
        self.assertIn("S26_reverse_shell_style_connect  A shell opens a TCP connection to another address   [NOT RUN:", text)
        self.assertIn("group gap", text)
        self.assertIn("locations ['cron']", text)

    def test_the_plan_lists_all_29_with_their_markers(self):
        text = "\n".join(run_eval.plan_lines(self.scenarios(), found=[], lookup=lambda: "10.0.0.7"))
        for i in range(1, 30):
            self.assertIn("marker EVT_EVAL_S%02d" % i, text)
        self.assertIn("non-loopback IPv4 address: 10.0.0.7", text)
        self.assertNotIn("[NOT RUN", text)

    def test_the_refuse_to_start_patterns_cover_the_new_locations(self):
        self.assertEqual(sorted(run_eval.LEFTOVER_PATTERNS), sorted(["/opt/evt_eval_*", "/tmp/evt_eval_*", "/dev/shm/evt_eval_*", "/etc/cron.d/evt_eval_*",
                                                                       "/etc/systemd/system/evt_eval_*", "/home/evt_eval_*"]))

    def test_the_driver_removes_only_the_exact_names_it_may_have_created(self):
        ok = ["/opt/evt_eval_s01_x", "/tmp/evt_eval_s04_y", "/dev/shm/evt_eval_s12_z", "/home/evt_eval_s15_a", "/etc/cron.d/evt_eval_s18_b",
              "/etc/systemd/system/evt_eval_s21_c.service"]
        for path in ok:
            self.assertTrue(run_eval.SAFE_LEFTOVER.fullmatch(path), path)
        for path in ["/etc/cron.d/other", "/etc/cron.d/evt_eval_x/../passwd", "/etc/cron.daily/evt_eval_x", "/etc/systemd/system/evt_eval_x",
                     "/etc/systemd/system/other.service", "/home/bob", "/home/evt_eval_X", "/etc/passwd", "/opt/other", "/opt/evt_eval_s01/sub",
                     "/etc/cron.d/evt_eval_x.bak"]:
            self.assertFalse(run_eval.SAFE_LEFTOVER.fullmatch(path), path)

    def test_every_path_a_scenario_may_create_is_one_the_driver_may_remove(self):
        for sc in self.scenarios():
            for path in scenario_lib.scenario_paths(sc["id"]):
                self.assertTrue(run_eval.SAFE_LEFTOVER.fullmatch(path), path)

    def test_the_dry_run_lists_all_29_and_validates_them(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(run_eval.main(["--dry-run"]), 0)
        self.assertIn("scenarios: 29", out.getvalue())
        self.assertIn("S29_slow_spawn_loop", out.getvalue())


if __name__ == "__main__":
    unittest.main()
