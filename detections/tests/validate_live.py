#!/usr/bin/env python3
"""
Check saved output of live_test.sh
Usage: validate_live.py --events normalized.jsonl --alerts alerts.jsonl --service-exe PATH --control-exe PATH [--runner-stderr FILE]
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import attack_map  # noqa: E402
import persistence  # noqa: E402
from exec_from_tmp import clean_path  # noqa: E402

REQUIRED = ("alert_schema_version", "alert_seq", "detection", "technique", "ts_ns", "process",
            "ancestry", "ancestry_stop", "evidence", "evidence_dropped", "data_quality")

results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print("%s  %s%s" % ("PASS" if ok else "FAIL", name, ("  " + detail) if detail else ""))


def info(text):
    print("info  " + text)


def load_lines(path):
    good, bad = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                bad += 1
                continue
            if isinstance(obj, dict):
                good.append(obj)
            else:
                bad += 1
    return good, bad


def basename(path):
    return path.rsplit("/", 1)[-1] if isinstance(path, str) else ""


def expected_technique(a):
    """technique the mapping gives an alert and read from the alert's detection name and its evidence (path or program for the detections that map by category), None if it cant be worked out"""
    name = a.get("detection")
    evidence = a.get("evidence")
    last = evidence[-1] if isinstance(evidence, list) and evidence and isinstance(evidence[-1], dict) else {}
    category = None
    if name == "sensitive_file_access" and isinstance(last.get("path"), str):
        category = attack_map.sensitive_category(clean_path(last["path"]))
    elif name == "persistence_write" and isinstance(last.get("path"), str):
        category = persistence.category_of(clean_path(last["path"]))
    elif name == "persistence_command":
        category = basename(last.get("exe"))
    return attack_map.technique_for(name, category)


def technique_ok(a):
    expected = expected_technique(a)
    return expected is not None and a.get("technique") == expected


def find_parent(events, exe, label):
    """find the process that exec'd exe and the shell exec_attempt that has it as parent; returns (pid, child pid) or None"""
    parents = [e for e in events if e.get("type") == "exec_success" and e.get("exe") == exe]
    pids = sorted({e.get("pid") for e in parents})
    check("%s parent exec seen once" % label, len(pids) == 1, "pids %s" % pids)
    if len(pids) != 1:
        return None
    pid = pids[0]
    children = [e for e in events if e.get("type") == "exec_attempt" and e.get("ppid") == pid
                and basename(e.get("exe")) == "sh" and e.get("pid") != pid]
    check("%s parent forked a distinct child shell" % label, len(children) == 1,
          "child pids %s" % [c.get("pid") for c in children])
    return (pid, children[0].get("pid")) if len(children) == 1 else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", required=True)
    ap.add_argument("--alerts", required=True)
    ap.add_argument("--service-exe", required=True)
    ap.add_argument("--control-exe", required=True)
    ap.add_argument("--runner-stderr")
    args = ap.parse_args()

    events, bad_events = load_lines(args.events)
    alerts, bad_alerts = load_lines(args.alerts)
    check("normalized events present", len(events) > 0, "%d events, %d bad lines" % (len(events), bad_events))
    check("every alert line is a JSON object", bad_alerts == 0, "%d alerts, %d bad lines" % (len(alerts), bad_alerts))
    missing = [a.get("alert_seq") for a in alerts if any(f not in a for f in REQUIRED)]
    check("every alert has every required field", not missing, "alerts missing a field: %s" % missing)
    check("every alert has the technique the mapping gives it", all(technique_ok(a) for a in alerts))
    check("every alert is named shell_from_service", all(a.get("detection") == "shell_from_service" for a in alerts))
    seqs = [a.get("alert_seq") for a in alerts]
    check("alert_seq counts 1..N in order", seqs == list(range(1, len(alerts) + 1)), "%s" % seqs[:10])
    info("total alerts in the run: %d (the machine may produce alerts of its own)" % len(alerts))
    info("lost events in the normalized stream: %d" % sum(1 for e in events if e.get("type") == "lost"))

    service = find_parent(events, args.service_exe, "nginx-named")
    control = find_parent(events, args.control_exe, "control")
    plain = [e for e in events if e.get("type") == "exec_success" and basename(e.get("exe")) == "sh"
             and "EVT_D1_PLAIN" in str(e.get("cmdline"))]
    check("plain shell control ran", len(plain) == 1, "%d matching exec_success" % len(plain))

    def by_parent(pid):
        return [a for a in alerts if isinstance(a.get("process"), dict) and a["process"].get("ppid") == pid]

    if service:
        pid, child = service
        mine = by_parent(pid)
        check("one alert for the nginx-named parent", len(mine) == 1, "%d alerts" % len(mine))
        if len(mine) == 1:
            a = mine[0]
            check("alert process is the child shell", a["process"].get("pid") == child
                  and "EVT_D1_SERVICE" in str(a["process"].get("cmdline")))
            names = [c.get("comm") for c in a["ancestry"] if isinstance(c, dict)]
            check("alert ancestry is shell then nginx", names[:2] == ["sh", "nginx"], "%s" % names)
            check("alert evidence has the exec_success",
                  any(isinstance(e, dict) and e.get("type") == "exec_success" for e in a["evidence"]))
            info("ancestry_stop: %s" % a["ancestry_stop"])
    if control:
        mine = by_parent(control[0])
        check("no alert for the control parent", len(mine) == 0, "%d alerts" % len(mine))
        marked = [a for a in alerts if "EVT_D1_CONTROL" in str(a.get("process", {}).get("cmdline"))]
        check("no alert for the control shell command", len(marked) == 0)
    if plain:
        marked = [a for a in alerts if "EVT_D1_PLAIN" in str(a.get("process", {}).get("cmdline"))]
        check("no alert for the plain shell command", len(marked) == 0)

    if args.runner_stderr:
        with open(args.runner_stderr, encoding="utf-8", errors="replace") as f:
            text = f.read()
        check("runner printed its summary", "runner summary" in text and "events processed:" in text)

    failed = [n for n, ok in results if not ok]
    print("\n%d checks, %d failed" % (len(results), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
