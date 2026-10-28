#!/usr/bin/env python3
"""
check the saved output of live_test_ancestry.sh for: normalized events, alerts, and the runner's standard error
Usage: validate_live_ancestry.py --events normalized.jsonl --alerts alerts.jsonl --cases cases.json [--runner-stderr FILE]
"""
import argparse
import json
import sys

import validate_live as v


def runs(events, base_prefix, marker):
    """exec_success events of program whose basename starts with base_prefix and also whether the command line has the marker or not"""
    return [e for e in events if e.get("type") == "exec_success" and v.basename(e.get("exe")).startswith(base_prefix)
            and marker in str(e.get("cmdline"))]


def alerts_of(alerts, detection, pid):
    return [a for a in alerts if a.get("detection") == detection and isinstance(a.get("process"), dict)
            and a["process"].get("pid") == pid]


def mentions(alerts, marker):
    return [a for a in alerts if a.get("detection") in ("unusual_ancestry", "shell_from_service") and marker in json.dumps(a)]


def show(alert):
    names = [c.get("comm") for c in alert["ancestry"] if isinstance(c, dict)]
    v.info("%s alert for pid %s: ancestry %s, ancestry_stop %s" % (alert["detection"], alert["process"].get("pid"), names, alert.get("ancestry_stop")))


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
    events, bad_events = v.load_lines(args.events)
    alerts, bad_alerts = v.load_lines(args.alerts)
    check("normalized events present", len(events) > 0, "%d events, %d bad lines" % (len(events), bad_events))
    check("every alert line is a JSON object", bad_alerts == 0, "%d alerts, %d bad lines" % (len(alerts), bad_alerts))
    missing = [a.get("alert_seq") for a in alerts if any(f not in a for f in v.REQUIRED)]
    check("every alert has every required field", not missing, "alerts missing a field: %s" % missing)
    check("every alert has the technique the mapping gives it", all(v.technique_ok(a) for a in alerts))
    seqs = [a.get("alert_seq") for a in alerts]
    check("alert_seq counts 1..N in order", seqs == list(range(1, len(alerts) + 1)), "%s" % seqs[:10])
    by_detection = {}
    for a in alerts:
        by_detection[a.get("detection")] = by_detection.get(a.get("detection"), 0) + 1
    info("total alerts in the run: %s (the machine may produce alerts of its own)" % by_detection)
    info("lost events in the normalized stream: %d" % sum(1 for e in events if e.get("type") == "lost"))
    info("alerts of other detections (not judged here): %s" % dict(sorted((k, n) for k, n in by_detection.items() if k not in ("unusual_ancestry", "shell_from_service"))))

    parent = [e for e in events if e.get("type") == "exec_success" and e.get("exe") == cases["service"]
              and "EVT_D4_DIRECT" in str(e.get("cmdline"))]
    check("case a: nginx copy ran", len(parent) == 1, "%d exec_success" % len(parent))
    direct = runs(events, "python3", "EVT_D4_DIRECT")
    check("case a: python3 ran as a distinct child of the nginx copy",
          len(direct) == 1 and len(parent) == 1 and direct[0].get("ppid") == parent[0].get("pid") != direct[0].get("pid"))
    if len(direct) == 1:
        mine = alerts_of(alerts, "unusual_ancestry", direct[0].get("pid"))
        check("case a: exactly one unusual_ancestry alert for python3", len(mine) == 1, "%d alerts" % len(mine))
        for a in mine:
            show(a)
        check("case a: no shell_from_service alert", len(mentions([a for a in alerts if a.get("detection") == "shell_from_service"], "EVT_D4_DIRECT")) == 0)

    parent = [e for e in events if e.get("type") == "exec_success" and e.get("exe") == cases["service"]
              and "EVT_D4_GRAND" in str(e.get("cmdline"))]
    check("case b: nginx copy ran", len(parent) == 1, "%d exec_success" % len(parent))
    sh = runs(events, "sh", "EVT_D4_GRAND")
    sh = [e for e in sh if v.basename(e.get("exe")) == "sh"]
    check("case b: sh ran as a distinct child of the nginx copy",
          len(sh) == 1 and len(parent) == 1 and sh[0].get("ppid") == parent[0].get("pid") != sh[0].get("pid"))
    grand = runs(events, "python3", "EVT_D4_GRAND")
    check("case b: python3 ran as a distinct child of the sh",
          len(grand) == 1 and len(sh) == 1 and grand[0].get("ppid") == sh[0].get("pid") != grand[0].get("pid"))
    if len(sh) == 1 and len(grand) == 1:
        mine = alerts_of(alerts, "unusual_ancestry", grand[0].get("pid"))
        check("case b: exactly one unusual_ancestry alert for python3", len(mine) == 1, "%d alerts" % len(mine))
        for a in mine:
            show(a)
        check("case b: no unusual_ancestry alert for the sh", len(alerts_of(alerts, "unusual_ancestry", sh[0].get("pid"))) == 0)
        owned = alerts_of(alerts, "shell_from_service", sh[0].get("pid"))
        check("case b: exactly one shell_from_service alert for the sh", len(owned) == 1, "%d alerts" % len(owned))
        for a in owned:
            show(a)

    for marker, label in (("EVT_D4_CTL_DIRECT", "control a"), ("EVT_D4_CTL_GRAND", "control b")):
        ran = runs(events, "python3", marker)
        check("%s: python3 ran below the unlisted copy" % label, len(ran) == 1, "%d exec_success" % len(ran))
        check("%s: no unusual_ancestry or shell_from_service alert" % label, len(mentions(alerts, marker)) == 0, "%d alerts" % len(mentions(alerts, marker)))
    true_runs = runs(events, "true", "EVT_D4_TRUE")
    check("control c: /bin/true ran below the nginx copy", len(true_runs) == 1, "%d exec_success" % len(true_runs))
    check("control c: no alert for /bin/true", len(mentions(alerts, "EVT_D4_TRUE")) == 0)
    plain = runs(events, "python3", "EVT_D4_PLAIN")
    check("control d: plain python3 ran", len(plain) == 1, "%d exec_success" % len(plain))
    check("control d: no alert for the plain python3", len(mentions(alerts, "EVT_D4_PLAIN")) == 0)

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
