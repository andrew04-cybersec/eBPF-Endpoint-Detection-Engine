#!/usr/bin/env python3
"""
checks saved output of live_test_tmp.sh: normalized events, alerts, and the runner's standard error
Usage: validate_live_tmp.py --events normalized.jsonl --alerts alerts.jsonl --cases cases.json [--runner-stderr FILE]
"""
import argparse
import json
import re
import sys

import validate_live as v


def exec_events(events, typ, path):
    return [e for e in events if e.get("type") == typ and e.get("filename") == path]


def alerts_for(alerts, path, detection="exec_from_tmp"):
    return [a for a in alerts if isinstance(a.get("process"), dict) and a["process"].get("exe") == path
            and a.get("detection") == detection]


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

    for case in cases["suspect"]:
        path = case["path"]
        ran = exec_events(events, "exec_success", path)
        check("%s copy ran by absolute path" % case["label"], len(ran) == 1, "%d exec_success" % len(ran))
        mine = alerts_for(alerts, path)
        check("%s copy: exactly one exec_from_tmp alert" % case["label"], len(mine) == 1, "%d alerts" % len(mine))
        if len(mine) == 1:
            a = mine[0]
            check("%s alert evidence has the exec_success" % case["label"],
                  any(isinstance(e, dict) and e.get("type") == "exec_success" for e in a["evidence"]))
            check("%s alert process is the copy" % case["label"],
                  case["marker"] in str(a["process"].get("cmdline")) and a["ancestry"][0].get("pid") == a["process"].get("pid"))

    control = cases["control"]
    ran = exec_events(events, "exec_success", control["path"])
    check("control copy ran by absolute path", len(ran) == 1, "%d exec_success" % len(ran))
    inside = [a for a in alerts if a.get("detection") == "exec_from_tmp" and isinstance(a.get("process"), dict)
              and str(a["process"].get("exe")).startswith(control["dir"] + "/")]
    check("no exec_from_tmp alert for the control directory", len(inside) == 0, "%d alerts" % len(inside))

    failed = cases["failed"]
    attempts = exec_events(events, "exec_attempt", failed["path"])
    check("failed exec attempt was recorded", len(attempts) == 1, "%d exec_attempt" % len(attempts))
    check("failed exec has no exec_success", len(exec_events(events, "exec_success", failed["path"])) == 0)
    info("derived exec_failed events for it: %d" % len(exec_events(events, "exec_failed", failed["path"])))
    bad = [a for a in alerts if a.get("detection") == "exec_from_tmp" and isinstance(a.get("process"), dict)
           and failed["marker"] in str(a["process"].get("cmdline"))]
    check("no exec_from_tmp alert for the failed exec", len(bad) == 0, "%d alerts" % len(bad))

    rel = cases["relative"]
    ran = [e for e in events if e.get("type") == "exec_success" and rel["marker"] in str(e.get("cmdline"))]
    check("relative-path copy ran", len(ran) == 1, "%d exec_success" % len(ran))
    if len(ran) == 1:
        recorded = ran[0].get("filename")
        info("filename recorded by the loader for the relative run: %r" % recorded)
        hit = [a for a in alerts if isinstance(a.get("process"), dict) and rel["marker"] in str(a["process"].get("cmdline"))
               and a.get("detection") == "exec_from_tmp"]
        info("exec_from_tmp alerts for the relative run: %d" % len(hit))
        if isinstance(recorded, str) and not recorded.startswith("/"):
            check("relative filename did not alert", len(hit) == 0)
            if args.runner_stderr:
                with open(args.runner_stderr, encoding="utf-8", errors="replace") as f:
                    text = f.read()
                m = re.search(r"relative_path (\d+)", text)
                check("runner counted relative_path as unevaluable", bool(m) and int(m.group(1)) >= 1,
                      "relative_path %s" % (m.group(1) if m else "not in summary"))
        else:
            check("absolute filename recorded for the relative run alerted once", len(hit) == 1, "%d alerts" % len(hit))

    if args.runner_stderr:
        with open(args.runner_stderr, encoding="utf-8", errors="replace") as f:
            text = f.read()
        check("runner printed its summary", "runner summary" in text and "events processed:" in text)

    failed_checks = [n for n, ok in v.results if not ok]
    print("\n%d checks, %d failed" % (len(v.results), len(failed_checks)))
    return 1 if failed_checks else 0


if __name__ == "__main__":
    sys.exit(main())
