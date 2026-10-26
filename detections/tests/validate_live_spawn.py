#!/usr/bin/env python3
"""
check saved output of live_test_spawn.sh: normalized events, alerts, and the runner's standard error
Usage: validate_live_spawn.py --events normalized.jsonl --alerts alerts.jsonl --cases cases.json [--runner-stderr FILE]
"""
import argparse
import json
import sys

import validate_live as v

NAME = "rapid_spawn"


def peak(times, window_ns):
    """highest number of timestamps inside any window (of window_ns, ends included) which is the count that the rule sees at its worst moment"""
    best, left = 0, 0
    for right, t in enumerate(times):
        while times[left] < t - window_ns:
            left += 1
        best = max(best, right - left + 1)
    return best


def find_parent(events, marker):
    found = [e for e in events if e.get("type") == "exec_success" and v.basename(e.get("exe")) == "bash"
             and marker in str(e.get("cmdline"))]
    v.check("%s: the bash -c ran once" % marker, len(found) == 1, "%d exec_success" % len(found))
    return found[0] if len(found) == 1 else None


def children_of(events, parent):
    seen = {}
    for e in events:
        if e.get("type") == "exec_success" and e.get("ppid") == parent.get("pid") and e.get("pid") != parent.get("pid"):
            seen.setdefault(e.get("process_key"), e)
    return sorted(seen.values(), key=lambda e: e.get("ts_ns"))


def alerts_for(alerts, parent):
    return [a for a in alerts if a.get("detection") == NAME and isinstance(a.get("process"), dict)
            and a["process"].get("ppid") == parent.get("pid")]


def show(alert, label):
    names = [c.get("comm") for c in alert["ancestry"] if isinstance(c, dict)]
    v.info("%s: alert ancestry %s, ancestry_stop %s, evidence %d, evidence_dropped %s"
           % (label, names, alert.get("ancestry_stop"), len(alert["evidence"]), alert.get("evidence_dropped")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", required=True)
    ap.add_argument("--alerts", required=True)
    ap.add_argument("--cases", required=True)
    ap.add_argument("--runner-stderr")
    args = ap.parse_args()
    check, info = v.check, v.info

    with open(args.cases) as f:
        cases = json.load(f)
    threshold, window_ns, below = cases["threshold"], cases["window_ns"], cases["below"]
    events, bad_events = v.load_lines(args.events)
    alerts, bad_alerts = v.load_lines(args.alerts)
    check("normalized events present", len(events) > 0, "%d events, %d bad lines" % (len(events), bad_events))
    check("every alert line is a JSON object", bad_alerts == 0, "%d alerts, %d bad lines" % (len(alerts), bad_alerts))
    missing = [a.get("alert_seq") for a in alerts if any(f not in a for f in v.REQUIRED)]
    check("every alert has every required field", not missing, "alerts missing a field: %s" % missing)
    check("every alert has technique null", all(a.get("technique") is None for a in alerts))
    seqs = [a.get("alert_seq") for a in alerts]
    check("alert_seq counts 1..N in order", seqs == list(range(1, len(alerts) + 1)), "%s" % seqs[:10])
    by_detection = {}
    for a in alerts:
        by_detection[a.get("detection")] = by_detection.get(a.get("detection"), 0) + 1
    info("total alerts in the run: %s (the machine may produce alerts of its own)" % by_detection)
    info("threshold %d, window %d ns" % (threshold, window_ns))
    info("lost events in the normalized stream: %d" % sum(1 for e in events if e.get("type") == "lost"))

    plan = (("EVT_D6_A", "case a (60 fast children)", 1, 60), ("EVT_D6_B", "case b (threshold minus one)", 0, below),
            ("EVT_D6_C", "case c (slow loop)", 0, 100), ("EVT_D6_D", "case d (two bursts and a sleep)", 2, 121))
    for marker, label, expected, total in plan:
        parent = find_parent(events, marker)
        if parent is None:
            continue
        kids = children_of(events, parent)
        check("%s: the parent started %d distinct children" % (label, total), len(kids) == total, "%d children" % len(kids))
        info("%s: highest in-window child count %d" % (label, peak([k["ts_ns"] for k in kids], window_ns)))
        mine = alerts_for(alerts, parent)
        check("%s: %d %s alert" % (label, expected, NAME), len(mine) == expected, "%d alerts" % len(mine))
        for a in mine:
            show(a, label)
            check("%s: evidence ends with the crossing exec" % label, a["evidence"][-1].get("pid") == a["process"].get("pid"))
        if marker == "EVT_D6_C":
            check("%s: the peak stayed below the threshold" % label, peak([k["ts_ns"] for k in kids], window_ns) < threshold)
        if marker == "EVT_D6_B":
            check("%s: no child other than /bin/true was started" % label,
                  all(v.basename(k.get("exe")) == "true" for k in kids))

    if args.runner_stderr:
        with open(args.runner_stderr, encoding="utf-8", errors="replace") as f:
            text = f.read()
        check("runner printed its summary", "runner summary" in text and "events processed:" in text)
        for line in text.splitlines():
            if line.startswith("unevaluable:") or line.startswith("alerts emitted:"):
                info("runner: " + line)

    failed = [n for n, ok in v.results if not ok]
    print("\n%d checks, %d failed" % (len(v.results), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
