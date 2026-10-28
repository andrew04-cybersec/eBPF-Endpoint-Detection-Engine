#!/usr/bin/env python3
"""
check saved output of live_test_priv.sh: normalized events, alerts, and the runner's standard error
Usage: validate_live_priv.py --events normalized.jsonl --alerts alerts.jsonl --cases cases.json [--runner-stderr FILE]
"""
import argparse
import io
import json
import os
import sys

import validate_live as v

DET_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DET_DIR)
import privilege_escalation as priv  #noqa: E402
import runner  #noqa: E402

NAME = "privilege_escalation"
NO_CHANGE = 4294967295


def marked(events, marker):
    return [e for e in events if e.get("type") == "exec_success" and isinstance(e.get("argv"), list)
            and e["argv"][-1:] == [marker]]


def process_keys(events, marker):
    return sorted({e.get("process_key") for e in marked(events, marker)}, key=str)


def of_key(events, key):
    return [e for e in events if e.get("process_key") == key]


def requests(events, key, syscall, ids):
    return [e for e in of_key(events, key) if e.get("type") == "priv_change" and e.get("syscall") == syscall
            and e.get("ids") == ids]


def children_requests(events, parent_pid, ids):
    return [e for e in events if e.get("type") == "priv_change" and e.get("ppid") == parent_pid
            and e.get("syscall") == "setresuid" and e.get("ids") == ids]


def alerts_for(alerts, key):
    return [a for a in alerts if a.get("detection") == NAME and isinstance(a.get("process"), dict)
            and a["process"].get("process_key") == key]


def replay(events):
    """events through privilege_escalation.detect alone and to read its priv_ counters (runner does not print them)"""
    lines = [(json.dumps(e) + "\n").encode() for e in events]
    _, ctx, _ = runner.run(lines, runner.alert.AlertSink(io.StringIO(), None), detections=[priv.detect])
    return {k: n for k, n in ctx["counts"].items() if k.startswith("priv_")}


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
    uid = cases["uid"]
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
    info("sudo-named binary is a %s" % cases.get("sudo_kind"))
    info("priv_ counters from replaying the saved events: %s" % dict(sorted(replay(events).items())))

    def show(label, a):
        ev = a["evidence"]
        info("%s: alert %s, process %s, process uid %s (the uid of the triggering event), evidence %s" % (
             label, a.get("detection"), a["process"].get("comm"), a["process"].get("uid"), [(e.get("type"), e.get("syscall"), e.get("ids"), e.get("uid")) for e in ev]))

    def after(label, key, ts):
        return [e for e in of_key(events, key) if isinstance(e.get("ts_ns"), int) and e["ts_ns"] > ts]

    def blocked(names, reason):
        for n in names:
            check(n, False, "not run: " + reason)

    def ran_once(label, marker, what):
        """one process key so a program that execs in place (setpriv then python3) counts once and returns (key, last exec_success) or None"""
        found = marked(events, marker)
        keys = process_keys(events, marker)
        check("%s: %s ran once" % (label, what), len(keys) == 1,
              "%d exec_success, %d process keys, exe %s" % (len(found), len(keys), [e.get("exe") for e in found]))
        return (keys[0], [e for e in found if e.get("process_key") == keys[0]][-1]) if len(keys) == 1 else None

    def simulated(label, marker, expect_alert, parent_comm=None):
        parent_names = ["%s: the parent's own setresuid(%d, %d, 0) was recorded at uid 0" % (label, uid, uid),
                        "%s: no alert for the parent" % label,
                        "%s: the child's setresuid(0, 0, 0) was recorded at uid %d" % (label, uid)]
        child_names = ["%s: %d %s alert for the child" % (label, expect_alert, NAME),
                       "%s: the child's later exec events are at uid 0 (the request was granted)" % label]
        comm_name = ["case c: comm of the sudo-named script is sudo"] if parent_comm else []
        got = ran_once(label, marker, "the root script")
        if got is None:
            blocked(comm_name + parent_names + child_names, "the root script was not found as exactly one process")
            return None
        pkey, parent = got
        if parent_comm:
            check(comm_name[0], parent.get("comm") == parent_comm, "comm %s" % parent.get("comm"))
        own = requests(events, pkey, "setresuid", [uid, uid, 0])
        check(parent_names[0], len(own) == 1 and own[0].get("uid") == 0, "%d events" % len(own))
        check(parent_names[1], not alerts_for(alerts, pkey))
        kids = children_requests(events, parent["pid"], [0, 0, 0])
        check(parent_names[2], len(kids) == 1 and kids[0].get("uid") == uid,
              "%d events, uid %s" % (len(kids), [k.get("uid") for k in kids]))
        if len(kids) != 1:
            blocked(child_names, "the child's request was not found exactly once")
            return None
        child = kids[0]
        ckey = child["process_key"]
        mine = alerts_for(alerts, ckey)
        check(child_names[0], len(mine) == expect_alert, "%d alerts" % len(mine))
        for a in mine:
            show(label, a)
        roots = [e for e in after(label, ckey, child["ts_ns"]) if e.get("uid") == 0 and e.get("type") in ("exec_attempt", "exec_success")]
        check(child_names[1], len(roots) >= 1, "%d events" % len(roots))
        return child, ckey, mine

    a_names = ["case a: the alert is the request signal, evidence is the priv_change",
               "case a: the alert process is in the graph"]
    a_counter = "case a: priv_transition_after_alert counted for the child"
    got = simulated("case a (granted request)", "EVT_PRIV_A", 1)
    if got is None:
        blocked(a_names + [a_counter], "no child process to check")
    else:
        child, ckey, mine = got
        if mine:
            a = mine[0]
            first = a["evidence"][0] if a.get("evidence") else {}
            check(a_names[0], first.get("type") == "priv_change"
                  and first.get("syscall") == "setresuid" and 0 in first.get("ids", []) and first.get("uid") == uid)
            check(a_names[1], a["data_quality"].get("process_in_graph") is True)
        else:
            blocked(a_names, "the child has no alert")
        counts = replay(of_key(events, ckey))
        check(a_counter, counts.get("priv_transition_after_alert", 0) >= 1, "%s" % counts)

    b_names = ["case b: setuid(0) was recorded at uid %d" % uid, "case b: 1 %s alert" % NAME,
               "case b: the process never became uid 0 after the request (the request alone raised the alert, so a denied request cannot be told from a granted one)"]
    got = ran_once("case b (denied request)", "EVT_PRIV_B", "the process")
    if got is None:
        blocked(b_names, "the process was not found as exactly one process")
    else:
        key = got[0]
        asked = requests(events, key, "setuid", [0])
        check(b_names[0], len(asked) == 1 and asked[0].get("uid") == uid, "%d events" % len(asked))
        mine = alerts_for(alerts, key)
        check(b_names[1], len(mine) == 1, "%d alerts" % len(mine))
        for a in mine:
            show("case b", a)
        if asked:
            later = [e for e in after("case b", key, asked[0]["ts_ns"]) if e.get("uid") == 0]
            check(b_names[2], not later, "%d events at uid 0" % len(later))
        else:
            blocked(b_names[2:], "setuid(0) was not recorded")

    c_names = ["case c: the child's request came from comm sudo", "case c: priv_expected_escalator counted for the child"]
    got = simulated("case c (python3 named sudo, the renamed-binary weakness)", "EVT_PRIV_C", 0, parent_comm="sudo")
    if got is None:
        blocked(c_names, "no child process to check")
    else:
        child, ckey, mine = got
        check(c_names[0], child.get("comm") == "sudo", "comm %s" % child.get("comm"))
        counts = replay(of_key(events, ckey))
        check(c_names[1], counts.get("priv_expected_escalator", 0) >= 1, "%s" % counts)

    for label, marker, syscall, ids, caller in (
            ("case d1 (setuid to own uid)", "EVT_PRIV_D1", "setuid", [uid], uid),
            ("case d2 (setreuid(-1, uid))", "EVT_PRIV_D2", "setreuid", [NO_CHANGE, uid], uid),
            ("case d3 (root setuid(0))", "EVT_PRIV_D3", "setuid", [0], 0)):
        names = ["%s: the request was recorded at uid %d" % (label, caller), "%s: no alert" % label]
        if marker == "EVT_PRIV_D3":
            names.append("case d3: priv_already_root counted")
        got = ran_once(label, marker, "the process")
        if got is None:
            blocked(names, "the process was not found as exactly one process")
            continue
        key = got[0]
        asked = requests(events, key, syscall, ids)
        check(names[0], len(asked) == 1 and asked[0].get("uid") == caller, "%d events" % len(asked))
        check(names[1], not alerts_for(alerts, key))
        if marker == "EVT_PRIV_D3":
            counts = replay(of_key(events, key))
            check(names[2], counts.get("priv_already_root", 0) == 1, "%s" % counts)

    in_graph = [a for a in alerts if a.get("detection") == NAME]
    check("every %s alert has its process in the graph" % NAME, all(a["data_quality"].get("process_in_graph") for a in in_graph),
          "%d alerts" % len(in_graph))

    left = [p for p in (cases["base"],) if os.path.lexists(p)]
    check("no leftover files after cleanup", not left, "left: %s" % left)

    if args.runner_stderr:
        with open(args.runner_stderr, encoding="utf-8", errors="replace") as f:
            text = f.read()
        check("runner printed its summary", "runner summary" in text)

    failed = [n for n, ok in v.results if not ok]
    print("\n%d checks, %d failed" % (len(v.results), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
