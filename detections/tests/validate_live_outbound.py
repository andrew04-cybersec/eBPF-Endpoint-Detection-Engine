#!/usr/bin/env python3
"""
check the saved output of live_test_outbound.sh: normalized events, alerts, and the runner's standard error
Usage: validate_live_outbound.py --events normalized.jsonl --alerts alerts.jsonl --cases cases.json [--runner-stderr FILE]
"""
import argparse
import json
import sys

import validate_live as v

NAME = "outbound_after_exec"


def process_of(events, base_prefix, marker):
    return [e for e in events if e.get("type") == "exec_success" and v.basename(e.get("exe")).startswith(base_prefix)
            and marker in str(e.get("cmdline"))]


def connects(events, pid, addr, port):
    return [e for e in events if e.get("type") == "net_connect" and e.get("pid") == pid
            and e.get("remote_addr") == addr and e.get("remote_port") == port]


def alerts_for(alerts, pid):
    return [a for a in alerts if a.get("detection") == NAME and isinstance(a.get("process"), dict)
            and a["process"].get("pid") == pid]


def show(alert, exe_ts):
    sent = alert["evidence"][-1]
    gap = (sent.get("ts_ns") - exe_ts) / 1e9 if isinstance(exe_ts, int) and isinstance(sent.get("ts_ns"), int) else None
    v.info("alert: destination %s:%s, process %s, exec to connect gap %s seconds"
           % (sent.get("remote_addr"), sent.get("remote_port"), v.basename(alert["process"].get("exe")),
              "%.3f" % gap if gap is not None else "unknown"))


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
    addr, port, window_ns = cases["addr"], cases["port"], cases["window_ns"]
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
    info("listener %s:%s, window %d ns; IPv6 is not exercised live" % (addr, port, window_ns))
    info("lost events in the normalized stream: %d" % sum(1 for e in events if e.get("type") == "lost"))

    def case(label, marker, prefix, dest, expected, connect_count=None):
        found = process_of(events, prefix, marker)
        check("%s: the process ran once" % label, len(found) == 1, "%d exec_success" % len(found))
        if len(found) != 1:
            return None
        proc = found[0]
        seen = connects(events, proc.get("pid"), dest, port)
        check("%s: a connect to %s:%s was recorded" % (label, dest, port),
              len(seen) >= 1 if connect_count is None else len(seen) == connect_count, "%d net_connect events" % len(seen))
        mine = alerts_for(alerts, proc.get("pid"))
        check("%s: %d %s alert" % (label, expected, NAME), len(mine) == expected, "%d alerts" % len(mine))
        for a in mine:
            show(a, proc.get("ts_ns"))
        return proc, seen

    case("case a (python3 to the non-loopback address)", "EVT_D7_A", "python3", addr, 1)
    case("case b (python3 to 127.0.0.1)", "EVT_D7_B", "python3", "127.0.0.1", 0)
    found = case("case c (bash /dev/tcp)", "EVT_D7_C", "bash", addr, 1)
    if found is not None:
        check("case c: bash itself made the connect", all(e.get("comm") == "bash" for e in found[1]) and len(found[1]) >= 1)
    case("case d (copy of curl in /dev/shm)", "EVT_D7_D", "evt_d7_fetch", addr, 1)
    case("case e (normal curl, control)", "EVT_D7_E", "curl", addr, 0)
    case("case f (python3 connecting five times)", "EVT_D7_F", "python3", addr, 1, connect_count=5)
    if cases["slow"]:
        found = case("case g (python3 connecting after the window)", "EVT_D7_G", "python3", addr, 0)
        if found is not None and len(found[1]) >= 1:
            gap = found[1][0]["ts_ns"] - found[0]["ts_ns"]
            info("case g: exec to connect gap %.3f seconds" % (gap / 1e9))
            check("case g: the recorded gap is outside the window", gap > window_ns, "gap %d ns, window %d ns" % (gap, window_ns))
    else:
        info("case g skipped: SKIP_SLOW=1")

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
