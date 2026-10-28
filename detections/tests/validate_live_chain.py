#!/usr/bin/env python3
"""
check that the saved output of live_test_chain.sh is: normalized events, alerts, and the runner's standard error
Usage: validate_live_chain.py --events normalized.jsonl --alerts alerts.jsonl --cases cases.json [--runner-stderr FILE]
"""
import argparse
import json
import sys

import validate_live as v

NAME = "download_chmod_exec"


def exec_success(events, filename):
    return [e for e in events if e.get("type") == "exec_success" and e.get("filename") == filename]


def tool_runs(events, tool, text):
    return [e for e in events if e.get("type") == "exec_success" and v.basename(e.get("exe")) == tool
            and text in str(e.get("cmdline"))]


def chain_alerts(alerts, pid):
    return [a for a in alerts if a.get("detection") == NAME and isinstance(a.get("process"), dict)
            and a["process"].get("pid") == pid]


def mentions(alerts, text):
    return [a for a in alerts if a.get("detection") == NAME and text in json.dumps(a)]


def evidence_tools(alert):
    return [v.basename(str(e.get("argv", [""])[0])) if isinstance(e.get("argv"), list) and e.get("argv") else None
            for e in alert["evidence"]]


def full_chain(events, alerts, label, tool, text, final):
    check = v.check
    check("%s: %s ran" % (label, tool), len(tool_runs(events, tool, text)) >= 1)
    check("%s: chmod ran" % label, len(tool_runs(events, "chmod", text)) >= 1)
    ran = exec_success(events, final)
    check("%s: downloaded file was executed" % label, len(ran) == 1, "%d exec_success with filename %s" % (len(ran), final))
    if len(ran) != 1:
        return
    mine = chain_alerts(alerts, ran[0].get("pid"))
    check("%s: exactly one %s alert" % (label, NAME), len(mine) == 1, "%d alerts" % len(mine))
    if len(mine) == 1:
        tools = evidence_tools(mine[0])
        check("%s: evidence is %s, chmod, final exec" % (label, tool), tools[:2] == [tool, "chmod"] and len(tools) == 3, "%s" % tools)
        stamps = [e.get("ts_ns") for e in mine[0]["evidence"]]
        check("%s: evidence is in time order" % label, stamps == sorted(set(stamps)), "%s" % stamps)


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

    full_chain(events, alerts, "case a (curl, absolute)", "curl", cases["a"]["download"], cases["a"]["final"])
    if cases["wget"]:
        full_chain(events, alerts, "case b (wget, absolute)", "wget", cases["b"]["download"], cases["b"]["final"])
    else:
        info("case b skipped: wget is not installed")

    c = cases["c"]
    info("filename recorded by the loader for the relative exec: %s"
         % [e.get("filename") for e in exec_success(events, c["final"])])
    full_chain(events, alerts, "case c (curl, relative)", "curl", c["name"], c["final"])

    d1, d2, d3 = cases["d1"]["path"], cases["d2"]["path"], cases["d3"]["path"]
    attempts = [e for e in events if e.get("type") == "exec_attempt" and e.get("filename") == d1]
    check("control d1: the exec without chmod was attempted", len(attempts) == 1, "%d exec_attempt" % len(attempts))
    check("control d1: the exec without chmod failed", len(exec_success(events, d1)) == 0)
    check("control d1: no alert", len(mentions(alerts, d1)) == 0, "%d alerts" % len(mentions(alerts, d1)))
    check("control d2: chmod and exec of a local file ran", len(exec_success(events, d2)) == 1)
    check("control d2: no alert", len(mentions(alerts, d2)) == 0, "%d alerts" % len(mentions(alerts, d2)))
    check("control d3: download and chmod ran", len(tool_runs(events, "curl", d3)) >= 1 and len(tool_runs(events, "chmod", d3)) >= 1)
    check("control d3: file was not executed", len(exec_success(events, d3)) == 0)
    check("control d3: no alert", len(mentions(alerts, d3)) == 0, "%d alerts" % len(mentions(alerts, d3)))

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
