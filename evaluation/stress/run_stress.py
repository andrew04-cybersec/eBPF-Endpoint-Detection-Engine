#!/usr/bin/env python3
"""
stepped exec rate stress driver starts the same pipeline as run_eval.py, runs stress.py as its only child and writes steps.json and stress_report.md
Usage: sudo python3 evaluation/stress/run_stress.py --results-root DIR [--dry-run] [--step-seconds N] [--gap-seconds N] [--workers N] [RATE ...]
the results folder must be outside the repository and stress results are separate from detection accuracy and are never pooled with any scenario result
"""
import argparse
import bisect
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time

STRESS_DIR = os.path.dirname(os.path.abspath(__file__))
EVAL_DIR = os.path.dirname(STRESS_DIR)
REPO_ROOT = os.path.dirname(EVAL_DIR)
sys.path.insert(0, EVAL_DIR)
sys.path.insert(0, STRESS_DIR)
import evaluate  #noqa: E402
import run_eval  #noqa: E402
import sampler  #noqa: E402
import scenario_lib  #noqa: E402
import stress  #noqa: E402

STRESS = os.path.join(STRESS_DIR, "stress.py")
ROLES = ("loader", "normalizer", "runner")
STEP_MARGIN_SECONDS = 5
GUARD_INTERVAL_SECONDS = 1.0
MIN_FREE_DISK_BYTES = 2 * 1024 ** 3
MIN_MEM_AVAILABLE_KB = 512 * 1024
EST_BYTES_PER_EXEC = 2500


def inside_repo(path, root=REPO_ROOT):
    real, base = os.path.realpath(path), os.path.realpath(root)
    return real == base or real.startswith(base + os.sep)


def estimate_bytes(rates, step_seconds):
    return sum(rates) * step_seconds * EST_BYTES_PER_EXEC


def stress_timeout_seconds(count, step_seconds, gap_seconds):
    return count * (step_seconds + STEP_MARGIN_SECONDS) + max(count - 1, 0) * gap_seconds + STEP_MARGIN_SECONDS


def mem_available_kb(path="/proc/meminfo"):
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    parts = line.split()
                    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    except OSError:
        pass
    return None


def free_bytes(path):
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return None


def guard_reason(free, mem_kb, min_free, min_mem_kb):
    """run must stop early (or None); reading that is not available (None) is not held against the run"""
    if free is not None and free < min_free:
        return "free disk space %d bytes is below the floor of %d bytes" % (free, min_free)
    if mem_kb is not None and mem_kb < min_mem_kb:
        return "available memory %d kB is below the floor of %d kB" % (mem_kb, min_mem_kb)
    return None


def guard_loop(stop, record, path, state, interval=GUARD_INTERVAL_SECONDS):
    while not stop.wait(interval):
        reason = guard_reason(free_bytes(path), mem_available_kb(), MIN_FREE_DISK_BYTES, MIN_MEM_AVAILABLE_KB)
        if reason:
            state["guard"] = reason
            if record:
                try:
                    os.killpg(record[0]["pid"], signal.SIGTERM)
                except OSError:
                    pass
            return


def by_role(rows):
    out = {}
    for row in rows:
        out.setdefault(row["role"], []).append(row)
    return out


def slice_rows(rows, low, high):
    """sampler rows for elapsed_ns in which it lies in [low, high] which is in time order"""
    return sorted((r for r in rows if low <= r["elapsed_ns"] <= high), key=lambda r: r["elapsed_ns"])


def cpu_percents(rows, clk):
    """CPU percent of one core over each interval between consecutive rows"""
    out = []
    for a, b in zip(rows, rows[1:]):
        dt = (b["elapsed_ns"] - a["elapsed_ns"]) / 1e9
        if clk and dt > 0:
            out.append(((b["ticks"] - a["ticks"]) / clk) / dt * 100.0)
    return out


def window_stats(rows, low, high, clk):
    inside = slice_rows(rows, low, high)
    cpu = cpu_percents(inside, clk)
    rss = [r["rss"] for r in inside if r["rss"] is not None]
    return {"samples": len(inside), "cpu_mean": evaluate.rounded(sum(cpu) / len(cpu)) if cpu else None,
            "cpu_p95": evaluate.rounded(evaluate.percentile(cpu, 95)), "max_rss_kb": max(rss) if rss else None}


def bin_events(path, windows):
    """
    events per step window from the raw events file by the event's own ts_ns; windows is a sorted list of (index, start_ns, end_ns)
    lost records are counted apart from events and a lost record with no ts_ns or outside every window is counted as unplaced
    """
    starts = [w[1] for w in windows]
    per = {w[0]: {"events": 0, "lost_events": 0, "dropped_records": 0, "seconds": {}} for w in windows}
    totals = {"events": 0, "lost_events": 0, "dropped_records": 0, "unplaced_lost_events": 0, "unplaced_dropped_records": 0}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(ev, dict):
                    continue
                lost = ev.get("type") == "lost"
                dropped = ev["dropped"] if type(ev.get("dropped")) is int else 0
                ts = ev.get("ts_ns")
                slot = None
                if type(ts) is int and starts:
                    i = bisect.bisect_right(starts, ts) - 1
                    if i >= 0 and ts <= windows[i][2]:
                        slot = i
                if lost:
                    totals["lost_events"] += 1
                    totals["dropped_records"] += dropped
                else:
                    totals["events"] += 1
                if slot is None:
                    if lost:
                        totals["unplaced_lost_events"] += 1
                        totals["unplaced_dropped_records"] += dropped
                    continue
                row = per[windows[slot][0]]
                if lost:
                    row["lost_events"] += 1
                    row["dropped_records"] += dropped
                else:
                    row["events"] += 1
                    second = (ts - windows[slot][1]) // 1000000000
                    row["seconds"][second] = row["seconds"].get(second, 0) + 1
    except OSError:
        pass
    return per, totals


def loader_lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return [l.rstrip("\n") for l in f if "file_stats" in l or "lost" in l or "drop" in l]
    except OSError:
        return []


def build_steps(rates, lines, reason):
    """one entry per planned step and a step with no result line is listed as not run with the reason"""
    by_index = {l["step"]: l for l in lines}
    steps = []
    for index, rate in enumerate(rates, 1):
        line = by_index.get(index)
        if line is None or line["target"] != rate:
            steps.append({"index": index, "target": rate, "status": "not run", "reason": reason})
            continue
        window = (line["end_ns"] - line["start_ns"]) / 1e9
        steps.append({"index": index, "target": rate, "status": "partial" if line["partial"] else "ok", "reason": None,
                      "start_ns": line["start_ns"], "end_ns": line["end_ns"], "window_seconds": evaluate.rounded(window),
                      "attempted": line["attempted"], "completed": line["completed"], "late_skipped": line["late_skipped"],
                      "achieved": line["achieved"]})
    return steps


def analyze(results, steps, sampler_start_ns, clk):
    """fills the pipeline side of every step that ran and returns the run totals"""
    ran = [s for s in steps if s["status"] != "not run"]
    per, totals = bin_events(os.path.join(results, "events.jsonl"), [(s["index"], s["start_ns"], s["end_ns"]) for s in ran])
    alerts, bad = evaluate.load_stamped(os.path.join(results, "alerts.stamped.tsv"))
    rows = by_role(evaluate.load_resources(os.path.join(results, "resources.csv")))
    in_steps = 0
    for s in ran:
        e = per[s["index"]]
        seconds = (s["end_ns"] - s["start_ns"]) / 1e9
        s["events"] = e["events"]
        s["events_per_s"] = evaluate.rounded(e["events"] / seconds) if seconds > 0 else None
        s["peak_events_per_s"] = max(e["seconds"].values()) if e["seconds"] else 0
        s["lost_events"] = e["lost_events"]
        s["dropped_records"] = e["dropped_records"]
        low, high = s["start_ns"] - sampler_start_ns, s["end_ns"] - sampler_start_ns
        s["cpu"] = {role: window_stats(rows.get(role, []), low, high, clk) for role in ROLES}
        s["runner_max_rss_kb"] = s["cpu"]["runner"]["max_rss_kb"]
        mine = [a for a in alerts if type(a.get("ts_ns")) is int and s["start_ns"] <= a["ts_ns"] <= s["end_ns"]]
        s["alerts"] = len(mine)
        by_detection = {}
        for a in mine:
            by_detection[str(a.get("detection"))] = by_detection.get(str(a.get("detection")), 0) + 1
        s["alerts_by_detection"] = by_detection
        in_steps += len(mine)
    totals.update({"alerts": len(alerts), "alerts_in_steps": in_steps, "alerts_outside_steps": len(alerts) - in_steps, "bad_alert_lines": bad})
    return totals


def fmt_pair(mean, p95):
    return "n/a" if mean is None else "%s / %s" % (mean, evaluate.fmt(p95))


def step_row(s):
    if s["status"] == "not run":
        return [s["index"], s["target"]] + ["n/a"] * 12 + ["not run: %s" % s["reason"]]
    cpu = s["cpu"]
    return [s["index"], s["target"], evaluate.fmt(s["window_seconds"]), s["attempted"], s["completed"], "%.1f" % s["achieved"],
            evaluate.fmt(s["events_per_s"]), s["peak_events_per_s"], "%d (%d dropped)" % (s["lost_events"], s["dropped_records"]),
            fmt_pair(cpu["loader"]["cpu_mean"], cpu["loader"]["cpu_p95"]), fmt_pair(cpu["normalizer"]["cpu_mean"], cpu["normalizer"]["cpu_p95"]),
            fmt_pair(cpu["runner"]["cpu_mean"], cpu["runner"]["cpu_p95"]), evaluate.fmt(s["runner_max_rss_kb"]), s["alerts"],
            s["status"] + (" (%d late slots skipped)" % s["late_skipped"] if s["late_skipped"] else "")]


def render_report(doc):
    steps = doc["steps"]
    ran = [s for s in steps if s["status"] != "not run"]
    lines = ["# Stress report: " + doc["folder"], "",
             "Stepped exec rate test of the pipeline. Kernel %s. Steps of %d s with %d s idle gaps, %d worker threads, targets %s execs per second." % (
                 doc["kernel"], doc["step_seconds"], doc["gap_seconds"], doc["workers"], " ".join(str(r) for r in doc["rates"])), ""]
    if doc["aborted"]:
        lines += ["Run stopped early: %s." % doc["aborted"], ""]
    cc = doc["clock_check"]
    lines += ["Clock check: %s." % ("not recorded" if not cc else ("passed" if cc.get("passed") else "FAILED")), ""]
    lines += ["## Steps", ""]
    lines += evaluate.table(["step", "target/s", "window s", "attempted", "completed", "achieved/s", "events/s", "peak events/s", "lost events",
                             "loader CPU % mean / p95", "normalizer CPU % mean / p95", "runner CPU % mean / p95", "runner max RSS kB", "alerts", "status"],
                            [step_row(s) for s in steps]) + [""]
    lines += ["CPU is percent of one core, taken from sampler rows that lie inside the step window. Events per second counts events by their own timestamp inside the window, lost records excluded. A lost event is a loader record saying that events were dropped, and the dropped count is the number of records it reports.", ""]
    t = doc["totals"]
    lines += ["Whole run: %d events, %d lost events (%d dropped records), of which %d lost events (%d dropped records) could not be placed in a step window. Alerts: %d in total, %d inside step windows, %d outside." % (
        t["events"], t["lost_events"], t["dropped_records"], t["unplaced_lost_events"], t["unplaced_dropped_records"], t["alerts"], t["alerts_in_steps"], t["alerts_outside_steps"]), ""]
    overall = {}
    for s in ran:
        for name, n in s["alerts_by_detection"].items():
            overall[name] = overall.get(name, 0) + n
    lines += ["Alerts inside step windows by detection (not scored): %s." % (", ".join("%s %d" % kv for kv in sorted(overall.items())) or "none"), ""]
    if doc["loader_lines"]:
        lines += ["Loader lines about lost events and drops: " + " / ".join(doc["loader_lines"]), ""]
    best = max(ran, key=lambda s: s["achieved"]) if ran else None
    lines += ["## Reading these results", "",
              "- Stress results are separate from detection accuracy. No scenario is run, no label is used, and no recall or precision is computed. They are not pooled with any scenario result.",
              "- Alerts raised during a step (rapid_spawn is the expected example) are side effects of the load. They are counted and listed for the record and are not scored.",
              "- Only measured rates are claimed. A step's achieved rate is the completed spawns divided by the step window. The target rate is a setting and not a result.",
              "- Nothing is extrapolated beyond the highest rate measured: " + (
                  "%.1f execs per second achieved in the step with target %d. Nothing is stated about higher rates." % (best["achieved"], best["target"]) if best
                  else "no step ran, so no rate was measured."),
              "- Every planned step is listed above, including steps with lost events, partial steps and steps that were not run, each with its reason.", "",
              "## Where the spawns come from", "",
              "All spawns come from %d distinct parent process: the stress.py process (pid %s), which the driver starts as its only child for the stress run. The worker threads belong to that process and add no parents. Each spawn is a direct child of it running /bin/true from an argument list, with no shell." % (
                  1, doc["spawn_parent_pid"]), "",
              "## Caps applied", "",
              "Target rate at most %d per second, step at most %d s, at most %d worker threads. A slot more than %d ms behind its time is skipped and counted, never run in a catch-up burst. The run is told to stop when free disk space on the results folder falls below %d bytes or available memory falls below %d kB%s." % (
                  stress.MAX_RATE, stress.MAX_STEP_SECONDS, stress.MAX_WORKERS, stress.LATE_LIMIT_NS // 1000000, MIN_FREE_DISK_BYTES, MIN_MEM_AVAILABLE_KB,
                  ("; this run was stopped for: " + doc["guard"]) if doc["guard"] else "; neither floor was reached in this run"), "",
              "bpf_stats were read once at the end of the run and are in bpf_stats.json (available: %s). The run is one machine, so the numbers are approximate." % doc["bpf_available"], ""]
    return "\n".join(lines)


def stress_argv(rates, step_seconds, gap_seconds, workers):
    return [sys.executable or "python3", STRESS, "--step-seconds", str(step_seconds), "--gap-seconds", str(gap_seconds),
            "--workers", str(workers)] + [str(r) for r in rates]


def plan_lines(rates, step_seconds, gap_seconds, workers, results_root):
    free = free_bytes(results_root)
    need = estimate_bytes(rates, step_seconds)
    return ["dry run: nothing is started and nothing is written",
            "targets: %s execs per second, %d s per step, %d s gap, %d workers" % (" ".join(str(r) for r in rates), step_seconds, gap_seconds, workers),
            "planned spawns: %d" % sum(stress.planned_execs(r, step_seconds) for r in rates),
            "estimated disk use (assumes %d bytes per spawn, not measured): %d bytes; free in %s: %s; floor %d bytes" % (
                EST_BYTES_PER_EXEC, need, results_root, "unknown" if free is None else free, MIN_FREE_DISK_BYTES),
            "stress command: " + " ".join(stress_argv(rates, step_seconds, gap_seconds, workers)),
            "stress run time limit: %d s" % stress_timeout_seconds(len(rates), step_seconds, gap_seconds)]


def execute(rates, step_seconds, gap_seconds, workers, results_root):
    results = os.path.join(results_root, time.strftime("%Y%m%d-%H%M%S") + "-stress")
    os.makedirs(results)
    os.makedirs(os.path.join(results, "logs"))
    state = {"aborted": None, "guard": None, "clock_check": None, "exit_codes": {}, "stress_status": None, "stress_timed_out": False}
    pipeline, samp = run_eval.Pipeline(results), None
    sysctl_before, sysctl_changed = run_eval.read_sysctl(), False
    bpf = {"available": False, "reason": "not read", "programs": []}
    record = []
    guard_stop = threading.Event()
    previous_term = signal.signal(signal.SIGTERM, run_eval.raise_interrupt)
    try:
        if sysctl_before != "unavailable" and os.environ.get("NO_BPF_STATS") != "1":
            run_eval.write_sysctl("1")
            sysctl_changed = True
        pipeline.start()
        if not pipeline.attached():
            raise run_eval.HarnessError("the loader did not attach; see loader.stderr")
        samp = sampler.Sampler(pipeline.pids(), os.path.join(results, "resources.csv"))
        samp.start()
        brackets = []
        for i in (1, 2):
            marker = "EVT_EVAL_CLOCK_%d" % i
            before = time.monotonic_ns()
            subprocess.run(["/bin/true", marker], check=False)
            brackets.append((marker, before, time.monotonic_ns()))
        run_eval.wait_for_text(os.path.join(results, "events.jsonl"), brackets[-1][0], run_eval.CLOCK_CHECK_WAIT_SECONDS)
        state["clock_check"] = run_eval.check_clock(os.path.join(results, "events.jsonl"), brackets)
        if not state["clock_check"]["passed"]:
            raise run_eval.HarnessError("clock check failed: %s" % json.dumps(state["clock_check"], sort_keys=True))
        threading.Thread(target=guard_loop, args=(guard_stop, record, results, state), daemon=True).start()
        _, _, status, timed_out = run_eval.run_script(stress_argv(rates, step_seconds, gap_seconds, workers), dict(os.environ),
                                                      os.path.join(results, "logs", "stress.log"),
                                                      stress_timeout_seconds(len(rates), step_seconds, gap_seconds), record=record)
        state["stress_status"], state["stress_timed_out"] = status, timed_out
        guard_stop.set()
        time.sleep(run_eval.SETTLE_SECONDS)
        bpf = run_eval.read_bpf_stats(pipeline.procs["loader"].pid)
    except (KeyboardInterrupt, run_eval.HarnessError) as e:
        state["aborted"] = "interrupted" if isinstance(e, KeyboardInterrupt) else str(e)
        print("run stopped: %s" % state["aborted"], file=sys.stderr)
    except Exception as e:
        state["aborted"] = "unexpected error: %r" % (e,)
        print("run stopped: %s" % state["aborted"], file=sys.stderr)
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        guard_stop.set()
        if record and state["stress_status"] is None:
            try:
                os.killpg(record[0]["pid"], signal.SIGTERM)
            except OSError:
                pass
        if samp is not None:
            try:
                samp.stop()
            except Exception as e:
                print("sampler: %r" % (e,), file=sys.stderr)
        try:
            state["exit_codes"] = pipeline.stop()
        except Exception as e:
            print("stopping the pipeline: %r" % (e,), file=sys.stderr)
        sysctl_after = sysctl_before
        if sysctl_changed:
            try:
                run_eval.write_sysctl(sysctl_before)
            except OSError as e:
                print("could not restore %s: %s" % (run_eval.BPF_SYSCTL, e), file=sys.stderr)
            sysctl_after = run_eval.read_sysctl()
        signal.signal(signal.SIGTERM, previous_term)
        info = {"kernel": platform.release(), "python": platform.python_version(), "bpf_stats_enabled_before": sysctl_before,
                "bpf_stats_enabled_after": sysctl_after, "clk_tck": os.sysconf("SC_CLK_TCK"), "settle_seconds": run_eval.SETTLE_SECONDS,
                "sample_interval_seconds": sampler.SAMPLE_INTERVAL_SECONDS, "rates": " ".join(str(r) for r in rates),
                "step_seconds": step_seconds, "gap_seconds": gap_seconds, "workers": workers,
                "loader_sha256": scenario_lib.sha256_file(run_eval.LOADER) if os.path.isfile(run_eval.LOADER) else "missing"}
        for name, argv in run_eval.pipeline_commands(results):
            info["pipeline " + name] = " ".join(argv)
        hashes = run_eval.code_hashes()
        for path in (STRESS, os.path.join(STRESS_DIR, "run_stress.py")):
            hashes[os.path.relpath(path, REPO_ROOT)] = scenario_lib.sha256_file(path)
        run_eval.write_env(results, info, hashes)
        run_eval.write_json(os.path.join(results, "bpf_stats.json"), bpf)
        run_eval.derive_alerts(results)
        try:
            with open(os.path.join(results, "logs", "stress.log"), encoding="utf-8", errors="replace") as f:
                parsed = [p for p in (stress.parse_step_line(l) for l in f) if p is not None]
        except OSError:
            parsed = []
        reason = (state["guard"] or state["aborted"] or ("stress.py timed out" if state["stress_timed_out"] else None)
                  or "stress.py ended with status %s before this step" % state["stress_status"])
        steps = build_steps(rates, parsed, reason)
        totals = analyze(results, steps, samp.start_ns if samp is not None else 0, os.sysconf("SC_CLK_TCK"))
        doc = {"folder": os.path.basename(results), "kernel": platform.release(), "rates": list(rates), "step_seconds": step_seconds,
               "gap_seconds": gap_seconds, "workers": workers, "spawn_parent_pid": record[0]["pid"] if record else None,
               "spawn_parent_count": 1, "clock_check": state["clock_check"], "aborted": state["aborted"], "guard": state["guard"],
               "stress_status": state["stress_status"], "stress_timed_out": state["stress_timed_out"], "pipeline_exit_codes": state["exit_codes"],
               "bpf_available": bool(bpf.get("available")), "loader_lines": loader_lines(os.path.join(results, "loader.stderr")),
               "totals": totals, "steps": steps}
        run_eval.write_json(os.path.join(results, "steps.json"), doc)
        with open(os.path.join(results, "stress_report.md"), "w", encoding="ascii", errors="replace") as f:
            f.write(render_report(doc))
    run_eval.give_to_owner(results)
    print("results: %s" % results)
    print("report: %s" % os.path.join(results, "stress_report.md"))
    return 1 if state["aborted"] or state["guard"] else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the stepped exec rate stress test against the live pipeline (root required).")
    ap.add_argument("rates", nargs="*", type=int, help="target execs per second, one step each (default %s)" % " ".join(str(r) for r in stress.DEFAULT_RATES))
    ap.add_argument("--results-root", required=True, help="folder for the results; must be outside the repository")
    ap.add_argument("--step-seconds", type=int, default=stress.DEFAULT_STEP_SECONDS)
    ap.add_argument("--gap-seconds", type=int, default=stress.DEFAULT_GAP_SECONDS)
    ap.add_argument("--workers", type=int, default=stress.DEFAULT_WORKERS)
    ap.add_argument("--dry-run", action="store_true", help="print the plan and the limits; start nothing")
    args = ap.parse_args(argv)
    rates = args.rates or list(stress.DEFAULT_RATES)
    problems = stress.validate(rates, args.step_seconds, args.gap_seconds, args.workers)
    if inside_repo(args.results_root):
        problems.append("--results-root must be outside the repository")
    if problems:
        for p in problems:
            print("stress: " + p, file=sys.stderr)
        return 2
    if args.dry_run:
        print("\n".join(plan_lines(rates, args.step_seconds, args.gap_seconds, args.workers, args.results_root)))
        return 0
    if os.geteuid() != 0:
        print("run this with sudo", file=sys.stderr)
        return 2
    if not os.access(run_eval.LOADER, os.X_OK):
        print("build the loader first: make -C telemetry", file=sys.stderr)
        return 2
    os.makedirs(args.results_root, exist_ok=True)
    free = free_bytes(args.results_root)
    need = estimate_bytes(rates, args.step_seconds)
    if free is not None and free < need + MIN_FREE_DISK_BYTES:
        print("refusing to start: free disk space %d bytes is below the estimate %d bytes plus the floor %d bytes" % (free, need, MIN_FREE_DISK_BYTES), file=sys.stderr)
        return 2
    reason = guard_reason(None, mem_available_kb(), MIN_FREE_DISK_BYTES, MIN_MEM_AVAILABLE_KB)
    if reason:
        print("refusing to start: " + reason, file=sys.stderr)
        return 2
    return execute(rates, args.step_seconds, args.gap_seconds, args.workers, args.results_root)


if __name__ == "__main__":
    sys.exit(main())
