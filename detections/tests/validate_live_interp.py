#!/usr/bin/env python3
"""
check saved output of live_test_interp.sh: normalized events, alerts, and the runner's standard error
Usage: validate_live_interp.py --events normalized.jsonl --alerts alerts.jsonl --cases cases.json [--runner-stderr FILE]
"""
import argparse
import io
import json
import os
import sys

import validate_live as v

DET_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DET_DIR)
import interpreter_chain as ic  # noqa: E402
import runner  # noqa: E402

NAME = "interpreter_chain"

#expected values worked out by hand; each watched process is a trigger in which the run is itself plus the watched processes above it and also UNJUDGED is a run that ends at the test script's shell which started before the loader
UNJUDGED = "unjudged"
CASES = [
    {"label": "case a (bash, python3, sh, python3, all inline)", "marker": "EVT_INTERP_A",
     "exes": ["bash", "python3", "sh", "python3"], "all_inline": True,
     "runs": {0: (1, UNJUDGED), 1: (2, UNJUDGED), 2: (3, UNJUDGED), 3: (4, UNJUDGED)},
     "alerts": {2: 3, 3: 4}, "incomplete": 2},
    {"label": "case b (two levels)", "marker": "EVT_INTERP_B", "exes": ["bash", "python3"],
     "runs": {0: (1, UNJUDGED), 1: (2, UNJUDGED)}, "alerts": {}, "incomplete": 2},
    {"label": "case c (one family)", "marker": "EVT_INTERP_C", "exes": ["bash", "bash", "bash"],
     "runs": {0: (1, UNJUDGED), 1: (2, UNJUDGED), 2: (3, UNJUDGED)}, "alerts": {}, "incomplete": 2},
    {"label": "case d (no inline option)", "marker": "EVT_INTERP_D", "exes": ["bash", "python3", "sh", "python3"],
     "no_inline": True,
     "runs": {0: (1, UNJUDGED), 1: (2, UNJUDGED), 2: (3, UNJUDGED), 3: (4, UNJUDGED)},
     "alerts": {}, "incomplete": 2},
    {"label": "case e1 (broken by true)", "marker": "EVT_INTERP_E1", "exes": ["bash", "python3", "true"],
     "runs": {0: (1, UNJUDGED), 1: (2, UNJUDGED)}, "alerts": {}, "incomplete": 2},
    {"label": "case e2 (broken by xargs)", "marker": "EVT_INTERP_E2", "exes": ["bash", "python3", "xargs", "sh", "python3"],
     "runs": {0: (1, UNJUDGED), 1: (2, UNJUDGED), 3: (1, "not_watched"), 4: (2, "not_watched")},
     "alerts": {}, "incomplete": 2},
]


def replay(events):
    """events through interpreter_chain.detect alone will return: (graph, chain_ counters, alerts) because the runner doesnt print the counters"""
    lines = [(json.dumps(e) + "\n").encode() for e in events]
    out = io.StringIO()
    graph, ctx, _ = runner.run(lines, runner.alert.AlertSink(out, None), detections=[ic.detect])
    counts = {k: n for k, n in ctx["counts"].items() if k.startswith("chain_")}
    return graph, counts, [json.loads(l) for l in out.getvalue().splitlines()]


def exe_of(node):
    entry = ic.latest_exec(node)
    return ic.basename(entry["exe"]) if entry and isinstance(entry.get("exe"), str) else None


def success_event(events, key, ts=None):
    found = [e for e in events if e.get("type") == "exec_success" and e.get("process_key") == key]
    if ts is not None:
        found = [e for e in found if e.get("ts_ns") == ts] or found
    return found[-1] if found else None


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
    info("total alerts in the run: %s (the machine may produce alerts of its own)" % dict(sorted(by_detection.items())))
    info("lost events in the normalized stream: %d" % sum(1 for e in events if e.get("type") == "lost"))

    graph, counters, replayed = replay([e for e in events if isinstance(e, dict)])
    info("chain_ counters from replaying all the saved events (the machine's own processes are included): %s" % dict(sorted(counters.items())))
    saved = sorted(a["process"]["process_key"] for a in alerts if a.get("detection") == NAME and isinstance(a.get("process"), dict))
    again = sorted(a["process"]["process_key"] for a in replayed)
    check("replaying the saved events through the detection alone gives the same %s alerts" % NAME, saved == again,
          "saved %d, replayed %d" % (len(saved), len(again)))

    case_keys = set()

    def check_case(spec):
        label, marker, exes = spec["label"], spec["marker"], spec["exes"]
        shape = ["%s: the case ran as one process tree (one root)" % label,
                 "%s: the processes form a straight chain %s" % (label, exes),
                 "%s: no command line of the case was cut by the argument cap" % label]
        later = ["%s: run length and end for each watched process" % label,
                 "%s: %d %s alerts, at the processes %s" % (label, len(spec["alerts"]), NAME, sorted(spec["alerts"]))]
        if spec.get("no_inline"):
            later.append("%s: no command line of the case has an inline-code option" % label)
        later.append("%s: chain_incomplete is %d when the case alone is replayed" % (label, spec["incomplete"]))

        def blocked(names, reason):
            for n in names:
                check(n, False, "not run: " + reason)

        marked = {k for k, n in graph.nodes.items() if not n.placeholder
                  and any(marker in str(x.get("cmdline")) for x in n.execs)}
        roots = sorted(k for k in marked if graph.nodes[k].parent_key not in marked)
        check(shape[0], len(roots) == 1, "%d process keys at the root, %d marked processes" % (len(roots), len(marked)))
        if len(roots) != 1:
            blocked(shape[1:] + later, "the case was not found as exactly one process tree")
            return
        parent = graph.nodes.get(graph.nodes[roots[0]].parent_key)
        if parent is not None and not parent.placeholder and exe_of(graph.nodes[roots[0]]) != exes[0] \
                and exe_of(parent) == exes[0] and (success_event(events, parent.key) or {}).get("argv_truncated"):
            roots = [parent.key]
        line = [roots[0]]
        while len(graph.children(line[-1])) == 1:
            line.append(graph.children(line[-1])[0])
        tree, todo = set(), [roots[0]]
        while todo:
            k = todo.pop()
            tree.add(k)
            todo.extend(graph.children(k))
        case_keys.update(tree)
        got = [exe_of(graph.nodes[k]) for k in line]
        check(shape[1], got == exes and len(tree) == len(line), "found %s, %d processes in the tree" % (got, len(tree)))
        cut = [exe_of(graph.nodes[k]) for k in line if (success_event(events, k) or {}).get("argv_truncated")]
        check(shape[2], not cut, "cut command lines of %s" % cut)
        if got != exes or len(tree) != len(line):
            blocked(later, "the processes do not form the expected chain")
            return

        runs, actual = spec["runs"], {}
        for i, k in enumerate(line):
            ev = success_event(events, k)
            if ev is not None and ic.family(ic.basename(ev.get("exe"))) is not None:
                members, end = ic.chain_for(graph, k, ev)
                actual[i] = (len(members), UNJUDGED if end in ("placeholder", "no_history") else end)
        check(later[0], actual == runs, "found %s" % actual)

        mine = [a for a in alerts if a.get("detection") == NAME and isinstance(a.get("process"), dict)
                and a["process"].get("process_key") in tree]
        got_at = {}
        for a in mine:
            i = line.index(a["process"]["process_key"])
            got_at[i] = got_at.get(i, 0) + 1
        check(later[1], sorted(got_at.items()) == [(i, 1) for i in sorted(spec["alerts"])],
              "alerts per process index %s" % got_at)
        for i, length in sorted(spec["alerts"].items()):
            key = line[i]
            tag = "%s: alert at the %s (member %d of the chain)" % (label, exes[i], i + 1)
            sub = ["%s: run of %d with two families and an inline option, the root bash -c included" % (tag, length),
                   "%s: ancestry names are %s" % (tag, [e[:15] for e in reversed(exes[:i + 1])]),
                   "%s: evidence is the exec_attempt then the exec_success of that process" % tag]
            one = [a for a in mine if a["process"].get("process_key") == key]
            if len(one) != 1:
                blocked(sub, "the alert was not found exactly once")
                continue
            a = one[0]
            ev = success_event(events, key, a.get("ts_ns"))
            members, end = ic.chain_for(graph, key, ev)
            fams = sorted({m["family"] for m in members})
            info("%s: members %s, families %s, end %s" % (tag, [(m["exe"], m["family"], "inline" if m["inline"] else "no inline") for m in members], fams, end))
            ok = (len(members) == length and [m["exe"] for m in members] == list(reversed(exes[:i + 1]))
                  and len(fams) >= 2 and any(m["inline"] for m in members)
                  and (all(m["inline"] for m in members) or not spec.get("all_inline")))
            check(sub[0], ok, "%d members, families %s" % (len(members), fams))
            names = [c.get("comm") for c in a.get("ancestry", []) if isinstance(c, dict)]
            check(sub[1], names[:i + 1] == [e[:15] for e in reversed(exes[:i + 1])], "ancestry %s" % names)
            evid = a.get("evidence")
            evid = evid if isinstance(evid, list) else []
            types = [e.get("type") for e in evid if isinstance(e, dict)]
            last = evid[-1] if evid and isinstance(evid[-1], dict) else {}
            check(sub[2], types in (["exec_attempt", "exec_success"], ["exec_success"]) and last.get("process_key") == key
                  and ic.basename(str(last.get("exe"))) == exes[i] and a.get("evidence_dropped") == 0, "evidence %s" % types)
        if spec.get("no_inline"):
            flags = []
            for k in line:
                ev = success_event(events, k)
                flags.append(ev is not None and ic.is_inline(ic.family(ic.basename(ev.get("exe"))), ic.trigger_tokens(ev)))
            check(later[2], not any(flags), "inline flags %s" % flags)
        counts = replay([e for e in events if e.get("process_key") in tree])[1]
        check(later[-1], counts.get("chain_incomplete", 0) == spec["incomplete"] and "chain_not_in_graph" not in counts,
              "%s" % counts)

    for spec in CASES:
        check_case(spec)

    outside = [a for a in alerts if a.get("detection") == NAME and isinstance(a.get("process"), dict)
               and a["process"].get("process_key") not in case_keys]
    info("%s alerts outside the cases (the machine's own processes): %d" % (NAME, len(outside)))
    others = {}
    for a in alerts:
        if a.get("detection") != NAME and isinstance(a.get("process"), dict) and a["process"].get("process_key") in case_keys:
            others[a["detection"]] = others.get(a["detection"], 0) + 1
    info("alerts of other detections on the case processes: %s" % dict(sorted(others.items())))
    ours = [a for a in alerts if a.get("detection") == NAME and a.get("process", {}).get("process_key") in case_keys]
    check("every %s alert of the cases has its process in the graph" % NAME,
          all(isinstance(a.get("data_quality"), dict) and a["data_quality"].get("process_in_graph") is True for a in ours),
          "%d alerts" % len(ours))

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
