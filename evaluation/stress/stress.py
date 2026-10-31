#!/usr/bin/env python3
"""
stepped exec rate generator: runs /bin/true at each target rate for a fixed step and prints one line per step on standard output
Usage: stress.py [--step-seconds N] [--gap-seconds N] [--workers N] [RATE ...]  (every spawn is a direct child of this one process)
"""
import argparse
import os
import signal
import subprocess
import sys
import threading
import time

DEFAULT_RATES = (100, 250, 500, 1000, 2000, 4000)
DEFAULT_STEP_SECONDS = 30
DEFAULT_GAP_SECONDS = 10
DEFAULT_WORKERS = 32
MAX_RATE = 5000
MAX_STEP_SECONDS = 120
MAX_GAP_SECONDS = 300
MAX_WORKERS = 64
LATE_LIMIT_NS = 50000000
SPAWN_ARGV = ["/bin/true"]
LINE_FIELDS = (("step", int), ("target", int), ("start_ns", int), ("end_ns", int), ("attempted", int), ("completed", int),
               ("achieved", float), ("late_skipped", int), ("partial", int))

STOP = threading.Event()


def slot_ns(start_ns, rate, index):
    """time at which spawn number index of a step is due, also slots are evenly spaced from the step start"""
    return start_ns + index * 1000000000 // rate


def planned_execs(rate, seconds):
    return rate * seconds


def achieved_rate(completed, start_ns, end_ns):
    span = end_ns - start_ns
    return completed * 1e9 / span if span > 0 else 0.0


def is_late(due_ns, now_ns, limit_ns=LATE_LIMIT_NS):
    return now_ns - due_ns > limit_ns


def validate(rates, step_seconds, gap_seconds, workers):
    problems = []
    if not rates:
        problems.append("no rates given")
    for rate in rates:
        if type(rate) is not int or not 1 <= rate <= MAX_RATE:
            problems.append("rate %r must be an integer from 1 to %d" % (rate, MAX_RATE))
    if type(step_seconds) is not int or not 1 <= step_seconds <= MAX_STEP_SECONDS:
        problems.append("step seconds must be an integer from 1 to %d" % MAX_STEP_SECONDS)
    if type(gap_seconds) is not int or not 0 <= gap_seconds <= MAX_GAP_SECONDS:
        problems.append("gap seconds must be an integer from 0 to %d" % MAX_GAP_SECONDS)
    if type(workers) is not int or not 1 <= workers <= MAX_WORKERS:
        problems.append("workers must be an integer from 1 to %d" % MAX_WORKERS)
    return problems


def format_step_line(index, rate, result):
    return "step=%d target=%d start_ns=%d end_ns=%d attempted=%d completed=%d achieved=%.1f late_skipped=%d partial=%d" % (
        index, rate, result["start_ns"], result["end_ns"], result["attempted"], result["completed"],
        achieved_rate(result["completed"], result["start_ns"], result["end_ns"]), result["late_skipped"], 1 if result["partial"] else 0)


def parse_step_line(line):
    found = {}
    for part in line.split():
        key, sep, value = part.partition("=")
        if sep:
            found[key] = value
    try:
        return {name: kind(found[name]) for name, kind in LINE_FIELDS}
    except (KeyError, ValueError):
        return None


def spawn_true():
    try:
        return subprocess.run(SPAWN_ARGV, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              check=False).returncode == 0
    except OSError:
        return False


def run_step(rate, seconds, workers, spawn, clock, wait, stopped):
    """
    workers take numbered slots in order and each waits for its slot time; wait(seconds) returns True when a stop was requested
    a slot more than LATE_LIMIT_NS behind its time is skipped and counted so a slow worker never fires a catch-up burst
    """
    start = clock()
    deadline = start + seconds * 1000000000
    lock = threading.Lock()
    state = {"next": 0, "attempted": 0, "completed": 0, "late": 0}

    def work():
        while not stopped():
            with lock:
                index = state["next"]
                state["next"] += 1
            due = slot_ns(start, rate, index)
            if due >= deadline:
                return
            now = clock()
            if due > now and wait((due - now) / 1e9):
                return
            if is_late(due, clock()):
                with lock:
                    state["late"] += 1
                continue
            with lock:
                state["attempted"] += 1
            if spawn():
                with lock:
                    state["completed"] += 1

    threads = [threading.Thread(target=work) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return {"start_ns": start, "end_ns": clock(), "attempted": state["attempted"], "completed": state["completed"],
            "late_skipped": state["late"], "partial": bool(stopped())}


def on_signal(signum, frame):
    STOP.set()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run /bin/true at stepped target rates and print one line per step.")
    ap.add_argument("rates", nargs="*", type=int, help="target execs per second, one step each (default %s)" % " ".join(str(r) for r in DEFAULT_RATES))
    ap.add_argument("--step-seconds", type=int, default=DEFAULT_STEP_SECONDS)
    ap.add_argument("--gap-seconds", type=int, default=DEFAULT_GAP_SECONDS)
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    args = ap.parse_args(argv)
    rates = args.rates or list(DEFAULT_RATES)
    problems = validate(rates, args.step_seconds, args.gap_seconds, args.workers)
    if problems:
        for p in problems:
            print("stress: " + p, file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    print("stress pid %d" % os.getpid(), file=sys.stderr)
    sys.stderr.flush()
    for index, rate in enumerate(rates, 1):
        if STOP.is_set():
            break
        result = run_step(rate, args.step_seconds, args.workers, spawn_true, time.monotonic_ns, STOP.wait, STOP.is_set)
        print(format_step_line(index, rate, result))
        sys.stdout.flush()
        if result["partial"]:
            break
        if index < len(rates) and STOP.wait(args.gap_seconds):
            break
    return 3 if STOP.is_set() else 0


if __name__ == "__main__":
    sys.exit(main())
