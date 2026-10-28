#!/usr/bin/env python3
"""
check saved output of live_test_files.sh: normalized events, alerts, and the runner's standard error
Usage: validate_live_files.py --events normalized.jsonl --alerts alerts.jsonl --cases cases.json [--runner-stderr FILE]
"""
import argparse
import json
import re
import sys

import validate_live as v

NAME = "sensitive_file_access"


def procs(events, exe, args, parent=None):
    """exec_success events of exe in which the command line is exactly exe followed by args; or optionally only those with the given parent pid"""
    want = (exe + " " + args).strip()
    return [e for e in events if e.get("type") == "exec_success" and e.get("exe") == exe and e.get("cmdline") == want
            and (parent is None or e.get("ppid") == parent)]


def opens(events, proc, path):
    return [e for e in events if e.get("type") == "file_open" and e.get("process_key") == proc.get("process_key")
            and e.get("path") == path]


def alerts_for(alerts, proc):
    return [a for a in alerts if a.get("detection") == NAME and isinstance(a.get("process"), dict)
            and a["process"].get("process_key") == proc.get("process_key")]


def show(alert, label):
    names = [c.get("comm") for c in alert["ancestry"] if isinstance(c, dict)]
    v.info("%s: alert ancestry %s, ancestry_stop %s" % (label, names, alert.get("ancestry_stop")))


def one(events, label, exe, args, parent=None):
    found = procs(events, exe, args, parent)
    v.check("%s: the reader ran once" % label, len(found) == 1, "%d exec_success" % len(found))
    return found[0] if len(found) == 1 else None


def counted(text, reason):
    m = re.search(r"%s (\d+)" % reason, text)
    return int(m.group(1)) if m else 0


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
    base, ssh = cases["base"], cases["home"] + "/.ssh"
    cat, sudo = base + "/cat", base + "/sudo"
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

    def expect_alerts(label, proc, path, count):
        if proc is None:
            return
        seen = opens(events, proc, path)
        check("%s: the open was recorded with ret >= 0" % label, len(seen) == 1 and isinstance(seen[0].get("ret"), int) and seen[0]["ret"] >= 0,
              "%d file_open events, ret %s" % (len(seen), [e.get("ret") for e in seen]))
        mine = alerts_for(alerts, proc)
        check("%s: %d %s alert" % (label, count, NAME), len(mine) == count, "%d alerts" % len(mine))
        for a in mine:
            show(a, label)

    p = one(events, "case a (cat reads /etc/shadow)", cat, "/etc/shadow")
    expect_alerts("case a", p, "/etc/shadow", 1)
    p = one(events, "case b (copy named sudo reads /etc/shadow)", sudo, "/etc/shadow")
    expect_alerts("case b", p, "/etc/shadow", 0)
    p = one(events, "case c (cat reads the private key)", cat, ssh + "/id_ed25519")
    expect_alerts("case c", p, ssh + "/id_ed25519", 1)
    p = one(events, "case d (cat reads the public key and known_hosts)", cat, ssh + "/id_ed25519.pub " + ssh + "/known_hosts")
    if p is not None:
        check("case d: both opens were recorded",
              len(opens(events, p, ssh + "/id_ed25519.pub")) == 1 and len(opens(events, p, ssh + "/known_hosts")) == 1)
        check("case d: no alert", len(alerts_for(alerts, p)) == 0)

    readers = procs(events, cat, "/etc/passwd")
    nginx = [e for e in events if e.get("type") == "exec_success" and e.get("exe") == base + "/nginx"]
    ctl = [e for e in events if e.get("type") == "exec_success" and e.get("exe") == base + "/evt_notaservice"]
    check("cases e to g: the nginx copy and the unlisted copy ran once", len(nginx) == 1 and len(ctl) == 1)
    if len(nginx) == 1 and len(ctl) == 1:
        by_parent = {"own shell": [r for r in readers if r.get("ppid") not in (nginx[0].get("pid"), ctl[0].get("pid"))],
                     "nginx copy": [r for r in readers if r.get("ppid") == nginx[0].get("pid")],
                     "unlisted copy": [r for r in readers if r.get("ppid") == ctl[0].get("pid")]}
        for label, found in by_parent.items():
            check("%s: cat /etc/passwd ran once as a distinct child" % label, len(found) == 1 and found[0].get("pid") != found[0].get("ppid"),
                  "%d exec_success" % len(found))
        expect_alerts("case e (own shell)", (by_parent["own shell"] or [None])[0], "/etc/passwd", 0)
        expect_alerts("case f (nginx copy)", (by_parent["nginx copy"] or [None])[0], "/etc/passwd", 1)
        expect_alerts("case g (unlisted copy)", (by_parent["unlisted copy"] or [None])[0], "/etc/passwd", 0)

    p = one(events, "case h (cat reads a missing key)", cat, "/home/evt_nouser/.ssh/id_rsa")
    if p is not None:
        seen = opens(events, p, "/home/evt_nouser/.ssh/id_rsa")
        check("case h: the open was recorded with ret < 0", len(seen) == 1 and isinstance(seen[0].get("ret"), int) and seen[0]["ret"] < 0,
              "ret %s" % [e.get("ret") for e in seen])
        check("case h: no alert", len(alerts_for(alerts, p)) == 0)

    if args.runner_stderr:
        with open(args.runner_stderr, encoding="utf-8", errors="replace") as f:
            text = f.read()
        check("runner printed its summary", "runner summary" in text and "events processed:" in text)
        check("runner counted expected_reader", counted(text, "expected_reader") >= 1, "expected_reader %d" % counted(text, "expected_reader"))
        check("runner counted failed_open", counted(text, "failed_open") >= 1, "failed_open %d" % counted(text, "failed_open"))
        for line in text.splitlines():
            if line.startswith("unevaluable:") or line.startswith("alerts emitted:"):
                info("runner: " + line)

    failed = [n for n, ok in v.results if not ok]
    print("\n%d checks, %d failed" % (len(v.results), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
