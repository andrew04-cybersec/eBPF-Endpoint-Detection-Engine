#!/usr/bin/env python3
"""
evaluation driver: starts the pipeline (loader, normalizer, runner) and runs the scenarios one at a time and stops at everything and scores the run
Usage: sudo python3 evaluation/run_eval.py [--dry-run] [--scenarios-dir DIR] [--results-root DIR] --dry-run validates the scenarios and prints the plan and the exact commands without starting anything and doesnt need root

do not run anything else on the machine during a run!!! the pipeline records every process it sees.
"""
import argparse
import glob
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(EVAL_DIR)
sys.path.insert(0, EVAL_DIR)
import evaluate  # noqa: E402
import sampler  # noqa: E402
import scenario_lib  # noqa: E402

LOADER = os.path.join(ROOT, "telemetry", "build", "exec_exit_loader")
LOADER_SOURCE = os.path.join(ROOT, "telemetry", "src", "exec_exit.bpf.c")
NORMALIZER = os.path.join(ROOT, "normalizer", "normalize.py")
RUNNER = os.path.join(ROOT, "detections", "runner.py")
STAMPER = os.path.join(EVAL_DIR, "stamp_lines.py")
BPF_SYSCTL = "/proc/sys/kernel/bpf_stats_enabled"
KERNEL_NAME_CHARS = 15
LOADER_MODE = "exit"
OPENAT_PROGRAMS = {"exit": ("handle_openat_save", "handle_openat_exit"), "entry": ("handle_openat_entry",)}

SETTLE_SECONDS = 2
ATTACH_TIMEOUT_SECONDS = 10
DRAIN_TIMEOUT_SECONDS = 30
SCRIPT_TIMEOUT_SECONDS = 60
CLOCK_CHECK_WAIT_SECONDS = 5
KILL_GRACE_SECONDS = 3
LEFTOVER_PATTERNS = ("/opt/evt_eval_*", "/tmp/evt_eval_*", "/dev/shm/evt_eval_*", "/etc/cron.d/evt_eval_*",
                     "/etc/systemd/system/evt_eval_*", "/home/evt_eval_*")
SAFE_LEFTOVER = re.compile(r"/(opt|tmp|dev/shm|home)/evt_eval_[a-z0-9_]+|/etc/cron\.d/evt_eval_[a-z0-9_]+|/etc/systemd/system/evt_eval_[a-z0-9_]+\.service")
PREDICTIONS = os.path.join(EVAL_DIR, "predictions.json")
CODE_DIRS = ("detections", "alerts", "graph", "normalizer")
PIPELINE_STAGES = ("loader", "tee_events", "normalizer", "tee_normalized", "runner", "stamper")


class HarnessError(Exception):
    pass


def leftovers(patterns=LEFTOVER_PATTERNS):
    return sorted(p for pattern in patterns for p in glob.glob(pattern))


def missing_requirements(scenarios, which=shutil.which):
    return sorted({"%s needs %s" % (sc["id"], cmd) for sc in scenarios for cmd in sc.get("requires", []) if which(cmd) is None})


def first_global_ipv4(run=subprocess.run):
    """first global IPv4 address the way the d7 live test finds it (ip -4 -o addr show scope global); or None"""
    try:
        done = run(["ip", "-4", "-o", "addr", "show", "scope", "global"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in (done.stdout or "").splitlines():
        m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)/", line)
        if m:
            return m.group(1)
    return None


def evaluate_needs(scenarios, lookup=first_global_ipv4):
    """returns ({scenario id: reason} for scenarios in which the needs are not met as the address or None); the lookup is made once and only if a scenario needs it"""
    wants = [sc for sc in scenarios if "non_loopback_ipv4" in sc.get("needs", [])]
    address = lookup() if wants else None
    skipped = {}
    if wants and address is None:
        for sc in wants:
            skipped[sc["id"]] = "needs a non-loopback IPv4 address and the machine has none"
    return skipped, address


def find_bpftool():
    """the way telemetry/Makefile finds it is the last of the sorted /usr/lib/linux-tools/*/bpftool or else bpftool from the path"""
    found = sorted(glob.glob("/usr/lib/linux-tools/*/bpftool"))
    return found[-1] if found else (shutil.which("bpftool") or "bpftool")


def loader_program_names(source=LOADER_SOURCE, mode=LOADER_MODE):
    """full function names of programs the loader loads in this mode and read from the eBPF source; the loader loads only the openat programs of its file mode"""
    try:
        with open(source, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return []
    names = set(re.findall(r"^int (handle_\w+)\(", text, re.M))
    skipped = {n for group in OPENAT_PROGRAMS.values() for n in group} - set(OPENAT_PROGRAMS[mode])
    return sorted(names - skipped)


def parse_bpf_programs(text, loader_pid, expected):
    """
    match the programs in `bpftool -j prog show` to the expected full names and report each under its full name (or None if text is not a JSON list)
    the kernel keeps 15 characters of a name so a listed name is matched as the full name or as its first 15 characters; a 15 character prefix shared by two expected names is reported as ambiguous and not assigned
    """
    try:
        listed = json.loads(text)
    except ValueError:
        return None
    if not isinstance(listed, list):
        return None
    entries = [p for p in listed if isinstance(p, dict)]
    by_prefix = {}
    for full in expected:
        by_prefix.setdefault(full[:KERNEL_NAME_CHARS], []).append(full)
    shared = {k: sorted(v) for k, v in by_prefix.items() if len(v) > 1}
    by_pid = [p for p in entries if any(isinstance(x, dict) and x.get("pid") == loader_pid for x in p.get("pids") or [])]
    candidates = by_pid or [p for p in entries if p.get("name") in expected or p.get("name") in by_prefix]
    found, ambiguous, unmatched = {}, [], []
    for p in candidates:
        raw = p.get("name")
        if raw in shared:
            ambiguous.append({"kernel_name": raw, "candidates": shared[raw], "reason": "a prefix shared by several expected programs",
                              "run_cnt": p.get("run_cnt"), "run_time_ns": p.get("run_time_ns")})
        elif raw in expected:
            found.setdefault(raw, []).append(p)
        elif raw in by_prefix:
            found.setdefault(by_prefix[raw][0], []).append(p)
        else:
            unmatched.append(raw)
    programs = []
    for full in sorted(found):
        if len(found[full]) > 1:
            ambiguous.append({"kernel_name": found[full][0].get("name"), "candidates": [full], "reason": "listed %d times" % len(found[full]),
                              "run_cnt": None, "run_time_ns": None})
            continue
        p = found[full][0]
        has = type(p.get("run_cnt")) is int
        programs.append({"name": full, "kernel_name": p.get("name"), "run_cnt": p.get("run_cnt"), "run_time_ns": p.get("run_time_ns"),
                         "status": "counts" if has else "no data from bpftool"})
    placed = {p["name"] for p in programs} | {c for a in ambiguous for c in a["candidates"]}
    return {"selected_by": "pids" if by_pid else "names", "programs": programs, "ambiguous": ambiguous,
            "not_found": sorted(set(expected) - placed), "unmatched_names": sorted(set(str(n) for n in unmatched)),
            "raw_names_selected": sorted(str(p.get("name")) for p in candidates),
            "raw_names_listed": sorted(set(str(p.get("name")) for p in entries))}


def read_bpf_stats(loader_pid, bpftool=None, expected=None):
    """what bpf_stats.json holds as the matched programs with the raw names bpftool returned and the expected programs that were not found and also the ambiguous ones"""
    bpftool = bpftool or find_bpftool()
    expected = loader_program_names() if expected is None else expected
    base = {"available": False, "reason": None, "mode": LOADER_MODE, "expected": expected, "programs": [], "not_found": expected,
            "ambiguous": [], "selected_by": None, "raw_names_selected": [], "raw_names_listed": []}
    try:
        done = subprocess.run([bpftool, "-j", "prog", "show"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return dict(base, reason="bpftool could not be run: %s" % e)
    if done.returncode != 0:
        return dict(base, reason="bpftool exited %d: %s" % (done.returncode, done.stderr.strip()[:200]))
    parsed = parse_bpf_programs(done.stdout, loader_pid, expected)
    if parsed is None:
        return dict(base, reason="the bpftool output is not a JSON list")
    doc = dict(base, **parsed)
    counted = [p for p in doc["programs"] if p["status"] == "counts"]
    if not doc["programs"]:
        doc["reason"] = "none of the expected programs was found in the bpftool output"
    elif not counted:
        doc["reason"] = "bpftool gave no run_cnt for any program (bpf_stats_enabled may have been off, or the programs did not run)"
    doc["available"] = bool(counted)
    return doc


def read_sysctl(path=BPF_SYSCTL):
    try:
        with open(path, encoding="ascii") as f:
            return f.read().strip()
    except OSError:
        return "unavailable"


def write_sysctl(value, path=BPF_SYSCTL):
    with open(path, "w", encoding="ascii") as f:
        f.write(value)


def check_clock(events_path, brackets):
    """compare loader's ts_ns for each marked /bin/true run with harness clock read just before and after it; brackets is a list of (marker, before_ns, after_ns) and the check only passes if every marker has exec_attempt event inside its bracket"""
    seen = {}
    try:
        with open(events_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                argv = ev.get("argv") if isinstance(ev, dict) else None
                if ev.get("type") == "exec_attempt" and isinstance(argv, list) and argv and type(ev.get("ts_ns")) is int:
                    seen[argv[-1]] = ev["ts_ns"]
    except OSError:
        pass
    checks, worst = [], 0
    for marker, before, after in brackets:
        ts = seen.get(marker)
        if ts is None:
            checks.append({"marker": marker, "found": False, "before_ns": before, "after_ns": after})
            continue
        skew = 0 if before <= ts <= after else (before - ts if ts < before else ts - after)
        worst = max(worst, skew)
        checks.append({"marker": marker, "found": True, "ts_ns": ts, "before_ns": before, "after_ns": after, "inside": skew == 0, "skew_ns": skew})
    return {"passed": all(c["found"] and c["inside"] for c in checks), "max_skew_ns": worst, "checks": checks}


def code_hashes(root=ROOT):
    hashes = {}
    for d in CODE_DIRS:
        for base, dirs, files in os.walk(os.path.join(root, d)):
            dirs[:] = sorted(x for x in dirs if x not in ("__pycache__", "out"))
            for name in sorted(files):
                if name.endswith(".py"):
                    path = os.path.join(base, name)
                    hashes[os.path.relpath(path, root)] = scenario_lib.sha256_file(path)
    src = os.path.join(root, "telemetry", "src")
    if os.path.isdir(src):
        for name in sorted(os.listdir(src)):
            hashes[os.path.join("telemetry", "src", name)] = scenario_lib.sha256_file(os.path.join(src, name))
    return hashes


def pipeline_commands(results):
    """commands of stages in pipeline order which is the same as the live tests except the runner writes alerts to standard output for the stamper"""
    py = sys.executable or "python3"
    return [("loader", [LOADER]),
            ("tee_events", ["tee", os.path.join(results, "events.jsonl")]),
            ("normalizer", [py, NORMALIZER]),
            ("tee_normalized", ["tee", os.path.join(results, "normalized.jsonl")]),
            ("runner", [py, RUNNER, "--stats-json", os.path.join(results, "stats.json")]),
            ("stamper", [py, STAMPER, os.path.join(results, "alerts.stamped.tsv")])]


def action_argv(sc):
    """the action runs as its own bash -c with the marker as the last argument so the marker is in the command line of the process the loader sees"""
    return ["bash", "-c", scenario_lib.read_text(sc["_scripts"]["action"]), "evt_eval_action", sc["marker"]]


def plan_lines(scenarios, results_name="<timestamp>-eval", found=None, lookup=first_global_ipv4):
    found = leftovers() if found is None else found
    skipped, address = evaluate_needs(scenarios, lookup)
    lines = ["dry run: nothing is started and nothing is written",
             "scenarios: %d (%s)" % (len(scenarios), ", ".join(s["id"] for s in scenarios)),
             "label set sha256: %s" % scenario_lib.label_hashes(scenarios)["set"],
             "", "refuse-to-start checks:",
             "  root: %s" % ("yes" if hasattr(os, "geteuid") and os.geteuid() == 0 else "no (required for a real run)"),
             "  loader built: %s (%s)" % ("yes" if os.access(LOADER, os.X_OK) else "no", LOADER),
             "  leftover work directories (%s): %s" % (" ".join(LEFTOVER_PATTERNS), ", ".join(found) if found else "none"),
             "  commands the scenarios need: %s" % (", ".join(missing_requirements(scenarios)) or "all found"),
             "  non-loopback IPv4 address: %s" % (address or "none") + ("; not run for that reason: " + ", ".join(sorted(skipped)) if skipped else ""),
             "", "order of a run:",
             "  1. run every setup.sh in id order, before the pipeline, so nothing they start is recorded",
             "  2. read %s and set it to 1 unless NO_BPF_STATS=1 is set" % BPF_SYSCTL,
             "  3. start the pipeline (each stage in its own session, so Ctrl-C reaches only this program), wait for 'attached' in loader.stderr:"]
    for name, argv in pipeline_commands("evaluation/results/" + results_name):
        lines.append("       %-15s %s" % (name, " ".join(argv)))
    lines += ["       (the loader's standard error goes to loader.stderr, the normalizer's to normalizer.stderr, the runner's to runner.stderr)",
              "  4. start the resource sampler (every %g s) for the loader, normalizer and runner" % sampler.SAMPLE_INTERVAL_SECONDS,
              "  5. clock check: run /bin/true twice with markers, each bracketed by time.monotonic_ns(), and require the loader's ts_ns inside the bracket",
              "  6. run the scenarios in id order, %d s settle pause after each:" % SETTLE_SECONDS]
    for sc in scenarios:
        env = scenario_lib.scenario_env(sc["id"], address=address)
        lines += ["", "     %s  %s%s" % (sc["id"], sc["title"], "   [NOT RUN: %s]" % skipped[sc["id"]] if sc["id"] in skipped else ""),
                  "       kind %s, group %s, technique %s, phase %s, timeout %d s, tmp_staging %s, locations %s, needs %s" % (
                      sc["kind"], sc["group"], sc["technique"], sc["phase"], sc["timeout_seconds"], bool(sc.get("tmp_staging")),
                      sc.get("locations", []), sc.get("needs", [])),
                  "       marker %s" % sc["marker"],
                  "       expected %s, acceptable %s" % (json.dumps(sc["expected"]), json.dumps(sc["acceptable"])),
                  "       known_gap: %s" % sc["known_gap"],
                  "       env EVT_EVAL_WORK=%s EVT_EVAL_TMP=%s EVT_EVAL_ID=%s EVT_EVAL_MARKER=%s" % (env["EVT_EVAL_WORK"], env["EVT_EVAL_TMP"], env["EVT_EVAL_ID"], sc["marker"]),
                  "       setup:    %s" % (("bash " + sc["_scripts"]["setup"]) if sc["_scripts"]["setup"] else "none"),
                  "       action:   bash -c <%d characters of %s> evt_eval_action %s" % (len(scenario_lib.read_text(sc["_scripts"]["action"])), sc["_scripts"]["action"], sc["marker"]),
                  "       teardown: %s" % (("bash " + sc["_scripts"]["teardown"]) if sc["_scripts"]["teardown"] else "none")]
    lines += ["", "  7. read bpf_stats with %s -j prog show while the loader is still running" % find_bpftool(),
              "  8. stop: SIGINT to the loader, wait for the drain, wait for the other stages, stop the sampler",
              "  9. run every teardown.sh, restore bpf_stats_enabled, remove only the scenario directories that are left",
              " 10. write env.txt, scenario_windows.json, bpf_stats.json, alerts.jsonl, then score the folder with evaluate.py",
              "every exit path (an error, Ctrl-C, SIGTERM, a timeout) runs steps 8 and 9.",
              "", "results folder: evaluation/results/%s" % results_name]
    return lines


def run_script(argv, env, log_path, timeout, clock=time.monotonic_ns, record=None):
    """run one script in its own process group with a timeout and write its output to log_path and finally return (start_ns, end_ns, exit status, and timed_out)"""
    timed_out = False
    with open(log_path, "ab") as log:
        start = clock()
        proc = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        #when caller passes a list... the pid and the clock readings around the start are kept; the kernel start time of the new process lies between the two readings
        if record is not None:
            record.append({"pid": proc.pid, "before_ns": start, "after_ns": clock()})
        try:
            status = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(proc.pid, sig)
                except ProcessLookupError:
                    break
                try:
                    proc.wait(timeout=KILL_GRACE_SECONDS)
                    break
                except subprocess.TimeoutExpired:
                    continue
            status = proc.poll()
        end = clock()
    return start, end, status, timed_out


def script_env(sc, address=None, bases=None, seed=None):
    env = dict(os.environ)
    env.update(scenario_lib.scenario_env(sc["id"], bases=bases, address=address))
    env["EVT_EVAL_MARKER"] = sc["marker"]
    #seed inherited from the calling shell is dropped so the only way to set one is --seed option which is recorded in env.txt
    env.pop("EVT_EVAL_SEED", None)
    if seed is not None:
        env["EVT_EVAL_SEED"] = str(seed)
    return env


def resolve_predictions(option, scenarios_dir):
    """
    path of predictions file for a run (or None for no predictions) where the option is the --predictions value or None for the default; default is predictions.json next to the folder that holds the scenarios directory which for standard scenarios directory is evaluation/predictions.json
    """
    if option is not None:
        return None if option == "none" else os.path.abspath(option)
    beside = os.path.join(os.path.dirname(os.path.abspath(scenarios_dir)), "predictions.json")
    return beside if os.path.isfile(beside) else None


def wait_for_text(path, text, timeout, alive=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                if text in f.read():
                    return True
        except OSError:
            pass
        if alive is not None and not alive():
            return False
        time.sleep(0.1)
    return False


class Pipeline:
    """the six stages connected by pipes and every stage runs in its own session so that a Ctrl-C at terminal reaches only the driver"""

    def __init__(self, results):
        self.results = results
        self.procs = {}
        self.files = []
        #pid and clock readings around each start are kept for harness process list in scenario_windows.json
        self.launched = {}

    def start(self):
        previous = None
        for name, argv in pipeline_commands(self.results):
            stderr = None
            if name in ("loader", "normalizer", "runner"):
                stderr = open(os.path.join(self.results, name + ".stderr"), "wb")
                self.files.append(stderr)
            last = name == "stamper"
            before = time.monotonic_ns()
            proc = subprocess.Popen(argv, stdin=previous.stdout if previous else subprocess.DEVNULL,
                                    stdout=None if last else subprocess.PIPE, stderr=stderr, start_new_session=True)
            self.launched[name] = {"pid": proc.pid, "before_ns": before, "after_ns": time.monotonic_ns()}
            if previous is not None:
                previous.stdout.close()
            self.procs[name] = proc
            previous = proc

    def attached(self):
        return wait_for_text(os.path.join(self.results, "loader.stderr"), "attached", ATTACH_TIMEOUT_SECONDS,
                             alive=lambda: self.procs["loader"].poll() is None)

    def pids(self):
        return {name: self.procs[name].pid for name in ("loader", "normalizer", "runner")}

    def stop(self):
        """SIGINT to the loader as live tests do and then wait for the stages in order which ends them as the pipes close; a stage that doesnt end is therefore killed and reported"""
        codes = {}
        loader = self.procs.get("loader")
        if loader is not None and loader.poll() is None:
            try:
                os.kill(loader.pid, signal.SIGINT)
            except ProcessLookupError:
                pass
        for name in PIPELINE_STAGES:
            proc = self.procs.get(name)
            if proc is None:
                continue
            try:
                codes[name] = proc.wait(timeout=DRAIN_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                codes[name] = "killed after %d s" % DRAIN_TIMEOUT_SECONDS
        for f in self.files:
            f.close()
        return codes


def harness_processes(stages, scripts, helpers, driver_pid):
    """
    processes run_eval.py started itself as a list of dicts for the scorer; stages maps a role to {pid, before_ns, after_ns} and scripts is a list of (role, that dict)
    process is matched by pid and by kernel start time inside [start_ns_min, start_ns_max] where the clock of the start time in the process key so a reused pid doesnt match; the driver predates the run and is matched by pid alone
    helpers are (role, from_ns, to_ns) commands that give no pid before they end and ran outside every scenario window so they are kept as intervals for the record only
    """
    rows = [{"role": "driver", "pid": driver_pid, "start_ns_min": None, "start_ns_max": None}]
    for role, p in sorted(stages.items()) + list(scripts):
        rows.append({"role": role, "pid": p["pid"], "start_ns_min": p["before_ns"], "start_ns_max": p["after_ns"]})
    for role, start, end in helpers:
        rows.append({"role": role, "pid": None, "ran_from_ns": start, "ran_to_ns": end})
    return rows


def write_env(results, info, hashes):
    lines = ["%s: %s" % (k, v) for k, v in info.items()]
    lines += ["sha256 %s: %s" % (path, digest) for path, digest in sorted(hashes.items())]
    with open(os.path.join(results, "env.txt"), "w", encoding="ascii", errors="replace") as f:
        f.write("\n".join(lines) + "\n")


def write_json(path, obj):
    with open(path, "w", encoding="ascii") as f:
        f.write(json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=True) + "\n")


def derive_alerts(results):
    src, dst = os.path.join(results, "alerts.stamped.tsv"), os.path.join(results, "alerts.jsonl")
    with open(dst, "w", encoding="utf-8") as out:
        try:
            with open(src, encoding="utf-8", errors="replace") as f:
                for line in f:
                    out.write(line.partition("\t")[2])
        except OSError:
            pass


def give_to_owner(results):
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not (uid and gid and uid.isdigit() and gid.isdigit()):
        return
    for base, dirs, files in os.walk(results):
        for name in dirs + files + [""]:
            try:
                os.chown(os.path.join(base, name), int(uid), int(gid))
            except OSError:
                pass


def raise_interrupt(signum, frame):
    raise KeyboardInterrupt()


def execute(scenarios, scenarios_dir, results_root, predictions=None, seed=None):
    """the order of steps is in plan_lines and every exit path goes through the finally block"""
    results = os.path.join(results_root, time.strftime("%Y%m%d-%H%M%S") + "-eval")
    os.makedirs(results)
    os.makedirs(os.path.join(results, "scenarios_snapshot"))
    os.makedirs(os.path.join(results, "logs"))
    for sc in scenarios:
        shutil.copyfile(os.path.join(sc["_dir"], "scenario.json"), os.path.join(results, "scenarios_snapshot", sc["id"] + ".json"))
    hashes = scenario_lib.label_hashes(scenarios)
    hashes["predictions_sha256"] = None
    predictions_path = resolve_predictions(predictions, scenarios_dir)
    if predictions_path is not None and os.path.isfile(predictions_path):
        shutil.copyfile(predictions_path, os.path.join(results, "predictions.json"))
        hashes["predictions_sha256"] = scenario_lib.sha256_file(predictions_path)
    else:
        predictions_path = None
    #scorer reads these two paths back so a folder from another set is compared with its own scenarios and predictions
    hashes["scenarios_dir"] = os.path.abspath(scenarios_dir)
    hashes["predictions_path"] = predictions_path
    write_json(os.path.join(results, "label_hashes.json"), hashes)
    helpers, setup_runs, teardown_runs = [], [], []
    ip_start = time.monotonic_ns()
    skipped, address = evaluate_needs(scenarios)
    helpers.append(("ip", ip_start, time.monotonic_ns()))
    for sid, reason in sorted(skipped.items()):
        print("not run: %s: %s" % (sid, reason), file=sys.stderr)
    todo = [sc for sc in scenarios if sc["id"] not in skipped]

    state = {"windows": {}, "order": [], "aborted": None, "clock_check": None, "teardown": {}, "exit_codes": {}, "setup": {}}
    pipeline, samp, sysctl_before, sysctl_changed = Pipeline(results), None, read_sysctl(), False
    bpf = {"available": False, "reason": "not read", "programs": []}
    setups = []
    previous_term = signal.signal(signal.SIGTERM, raise_interrupt)
    try:
        for sc in todo:
            if sc["_scripts"]["setup"]:
                setups.append(sc["id"])
                log = os.path.join(results, "logs", sc["id"] + ".setup.log")
                started = []
                _, _, status, timed_out = run_script(["bash", sc["_scripts"]["setup"]], script_env(sc, address, seed=seed), log, SCRIPT_TIMEOUT_SECONDS, record=started)
                setup_runs += [("setup " + sc["id"], p) for p in started]
                state["setup"][sc["id"]] = status
                if status != 0 or timed_out:
                    raise HarnessError("setup of %s failed (status %s, timed out %s); see logs/%s.setup.log" % (sc["id"], status, timed_out, sc["id"]))
        if sysctl_before != "unavailable" and os.environ.get("NO_BPF_STATS") != "1":
            write_sysctl("1")
            sysctl_changed = True
        pipeline.start()
        if not pipeline.attached():
            raise HarnessError("the loader did not attach; see loader.stderr")
        samp = sampler.Sampler(pipeline.pids(), os.path.join(results, "resources.csv"))
        samp.start()
        brackets = []
        for i in (1, 2):
            marker = "EVT_EVAL_CLOCK_%d" % i
            before = time.monotonic_ns()
            subprocess.run(["/bin/true", marker], check=False)
            after = time.monotonic_ns()
            brackets.append((marker, before, after))
            helpers.append(("clock check true " + str(i), before, after))
        wait_for_text(os.path.join(results, "events.jsonl"), brackets[-1][0], CLOCK_CHECK_WAIT_SECONDS)
        state["clock_check"] = check_clock(os.path.join(results, "events.jsonl"), brackets)
        if not state["clock_check"]["passed"]:
            raise HarnessError("clock check failed: %s" % json.dumps(state["clock_check"], sort_keys=True))
        for sc in todo:
            state["order"].append(sc["id"])
            log = os.path.join(results, "logs", sc["id"] + ".action.log")
            start, end, status, timed_out = run_script(action_argv(sc), script_env(sc, address, seed=seed), log, sc["timeout_seconds"])
            state["windows"][sc["id"]] = {"start_ns": start, "end_ns": end, "exit_status": status, "timed_out": timed_out}
            time.sleep(SETTLE_SECONDS)
        bpf_start = time.monotonic_ns()
        bpf = read_bpf_stats(pipeline.procs["loader"].pid)
        helpers.append(("bpftool", bpf_start, time.monotonic_ns()))
    except (KeyboardInterrupt, HarnessError) as e:
        state["aborted"] = "interrupted" if isinstance(e, KeyboardInterrupt) else str(e)
        print("run stopped: %s" % state["aborted"], file=sys.stderr)
    except Exception as e:
        state["aborted"] = "unexpected error: %r" % (e,)
        print("run stopped: %s" % state["aborted"], file=sys.stderr)
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if samp is not None:
            try:
                samp.stop()
            except Exception as e:
                print("sampler: %r" % (e,), file=sys.stderr)
        try:
            state["exit_codes"] = pipeline.stop()
        except Exception as e:
            print("stopping the pipeline: %r" % (e,), file=sys.stderr)
        touched = set(setups) | set(state["order"])
        for sc in todo:
            if sc["id"] in touched and sc["_scripts"]["teardown"]:
                log = os.path.join(results, "logs", sc["id"] + ".teardown.log")
                try:
                    started = []
                    state["teardown"][sc["id"]] = run_script(["bash", sc["_scripts"]["teardown"]], script_env(sc, address, seed=seed), log, SCRIPT_TIMEOUT_SECONDS, record=started)[2]
                    teardown_runs += [("teardown " + sc["id"], p) for p in started]
                except Exception as e:
                    state["teardown"][sc["id"]] = repr(e)
        left = []
        for sc in todo:
            for path in scenario_lib.scenario_paths(sc["id"]):
                if sc["id"] in touched and os.path.lexists(path) and SAFE_LEFTOVER.fullmatch(path) and not os.path.islink(path):
                    left.append(path)
                    if os.path.isdir(path):
                        shutil.rmtree(path, ignore_errors=True)
                    else:
                        try:
                            os.remove(path)
                        except OSError:
                            pass
        state["leftovers_removed_by_driver"] = left
        sysctl_after = sysctl_before
        if sysctl_changed:
            try:
                write_sysctl(sysctl_before)
            except OSError as e:
                print("could not restore %s: %s" % (BPF_SYSCTL, e), file=sys.stderr)
            sysctl_after = read_sysctl()
        signal.signal(signal.SIGTERM, previous_term)
        info = {"kernel": platform.release(), "python": platform.python_version(),
                "mode": "buffered: the stages run as in the live tests, with no python3 -u and no stdbuf",
                "bpf_stats_enabled_before": sysctl_before, "bpf_stats_enabled_after": sysctl_after,
                "bpf_stats_requested": "no (NO_BPF_STATS=1)" if os.environ.get("NO_BPF_STATS") == "1" else "yes",
                "clk_tck": os.sysconf("SC_CLK_TCK"), "bpftool": find_bpftool(), "settle_seconds": SETTLE_SECONDS,
                "sample_interval_seconds": sampler.SAMPLE_INTERVAL_SECONDS,
                "loader_sha256": scenario_lib.sha256_file(LOADER) if os.path.isfile(LOADER) else "missing"}
        if seed is not None:
            info["seed"] = seed
        for name, argv in pipeline_commands(results):
            info["pipeline " + name] = " ".join(argv)
        write_env(results, info, code_hashes())
        write_json(os.path.join(results, "bpf_stats.json"), bpf)
        write_json(os.path.join(results, "scenario_windows.json"), {
            "scenarios": state["windows"], "order": state["order"], "skipped": skipped, "clock_check": state["clock_check"], "aborted": state["aborted"],
            "pipeline_exit_codes": state["exit_codes"], "setup_status": state["setup"], "teardown_status": state["teardown"],
            "leftovers_removed_by_driver": state["leftovers_removed_by_driver"],
            "harness_processes": harness_processes(pipeline.launched, setup_runs + teardown_runs, helpers, os.getpid())})
        derive_alerts(results)
    scores, _ = evaluate.score_folder(results, scenarios_dir)
    give_to_owner(results)
    print("results: %s" % results)
    print("report: %s" % os.path.join(results, "report.md"))
    for w in scores["warnings"]:
        print(w, file=sys.stderr)
    return 1 if state["aborted"] or state["leftovers_removed_by_driver"] else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the evaluation scenarios against the live pipeline (root required).")
    ap.add_argument("--dry-run", action="store_true", help="validate the scenarios and print the plan and the commands; start nothing")
    ap.add_argument("--scenarios-dir", default=os.path.join(EVAL_DIR, "scenarios"))
    ap.add_argument("--results-root", default=os.path.join(EVAL_DIR, "results"))
    ap.add_argument("--predictions", default=None, metavar="PATH|none",
                    help="predictions file to copy into the results folder, or none; the default is the predictions.json next to the folder that holds the scenarios directory")
    ap.add_argument("--seed", type=int, default=None, help="non-negative integer given to every script as EVT_EVAL_SEED and written to env.txt")
    args = ap.parse_args(argv)

    scenarios, problems = scenario_lib.load_scenarios(args.scenarios_dir)
    if problems or not scenarios:
        for p in problems or ["no scenarios found in " + args.scenarios_dir]:
            print("scenario problem: " + p, file=sys.stderr)
        return 2
    if args.seed is not None and args.seed < 0:
        print("--seed must not be negative", file=sys.stderr)
        return 2
    chosen = resolve_predictions(args.predictions, args.scenarios_dir)
    if args.predictions not in (None, "none") and not os.path.isfile(chosen):
        print("--predictions file %s does not exist" % args.predictions, file=sys.stderr)
        return 2
    if args.dry_run:
        print("\n".join(plan_lines(scenarios)))
        print("predictions: %s" % (chosen if chosen and os.path.isfile(chosen) else "none"))
        print("seed: %s" % ("none" if args.seed is None else args.seed))
        return 0
    if os.geteuid() != 0:
        print("run this with sudo", file=sys.stderr)
        return 2
    if not os.access(LOADER, os.X_OK):
        print("build the loader first: make -C telemetry", file=sys.stderr)
        return 2
    if missing_requirements(scenarios):
        print("missing commands: " + ", ".join(missing_requirements(scenarios)), file=sys.stderr)
        return 2
    found = leftovers()
    if found:
        print("refusing to start, leftovers of an earlier run exist (remove them yourself after looking at them):", file=sys.stderr)
        for p in found:
            print("  " + p, file=sys.stderr)
        return 2
    return execute(scenarios, args.scenarios_dir, args.results_root, predictions=args.predictions, seed=args.seed)


if __name__ == "__main__":
    sys.exit(main())
