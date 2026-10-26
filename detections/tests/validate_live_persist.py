#!/usr/bin/env python3
"""
check saved output of live_test_persist.sh: normalized events, alerts, and the runner's standard error
Usage: validate_live_persist.py --events normalized.jsonl --alerts alerts.jsonl --cases cases.json [--runner-stderr FILE]
"""
import argparse
import io
import json
import os
import sys

import validate_live as v

DET_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DET_DIR)
import persistence  # noqa: E402
import runner  # noqa: E402

FILE_NAME = "persistence_write"
COMMAND_NAME = "persistence_command"


def marked(events, marker):
    return [e for e in events if e.get("type") == "exec_success" and isinstance(e.get("argv"), list)
            and e["argv"][-1:] == [marker]]


def execs(events, exe, rest):
    return [e for e in events if e.get("type") == "exec_success" and e.get("exe") == exe
            and isinstance(e.get("argv"), list) and e["argv"][1:] == rest]


def opens(events, proc, path):
    return [e for e in events if e.get("type") == "file_open" and e.get("process_key") == proc.get("process_key")
            and e.get("path") == path]


def alerts_for(alerts, proc, name):
    return [a for a in alerts if a.get("detection") == name and isinstance(a.get("process"), dict)
            and a["process"].get("process_key") == proc.get("process_key")]


def write_flags(flags):
    return isinstance(flags, int) and persistence.wants_write(flags)


def replay(path):
    """the saved normalized events through persistence.detect alone; to read its persist_ counters (runner does not print them)"""
    with open(path, "rb") as f:
        out = io.StringIO()
        _, ctx, _ = runner.run(f, runner.alert.AlertSink(out, None), detections=[persistence.detect])
    return {k: n for k, n in ctx["counts"].items() if k.startswith("persist_")}


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
    base, home = cases["base"], cases["home"]
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
    info("lost events in the normalized stream: %d" % sum(1 for e in events if e.get("type") == "lost"))
    counters = replay(args.events)
    info("persist_ counters from replaying the saved events: %s" % dict(sorted(counters.items())))

    def show(label, proc, mine):
        for a in mine:
            ev = a["evidence"][0] if a.get("evidence") else {}
            target = ev.get("path") or ev.get("cmdline")
            info("%s: alert %s, process %s, target %s, category %s" % (
                label, a.get("detection"), proc.get("comm"), target,
                persistence.category_of(persistence.clean_path(ev["path"])) if ev.get("path") else "-"))

    def writer(label, marker, path, want_alerts, want_ret_ok=True):
        found = marked(events, marker)
        check("%s: the writer ran once" % label, len(found) == 1, "%d exec_success" % len(found))
        if len(found) != 1:
            return None
        proc = found[0]
        seen = opens(events, proc, path)
        ok = len(seen) >= 1 and all(write_flags(e.get("flags")) for e in seen) and (
            not want_ret_ok or all(isinstance(e.get("ret"), int) and e["ret"] >= 0 for e in seen))
        check("%s: the write open was recorded with write flags" % label, ok,
              "%d file_open events, flags %s, ret %s" % (len(seen), [e.get("flags") for e in seen], [e.get("ret") for e in seen]))
        mine = alerts_for(alerts, proc, FILE_NAME)
        check("%s: %d %s alert" % (label, want_alerts, FILE_NAME), len(mine) == want_alerts, "%d alerts" % len(mine))
        show(label, proc, mine)
        return proc

    writer("case a (bash redirect into /etc/cron.d)", "EVT_PA", cases["cron"], 1)
    writer("case b (bash redirect into /etc/systemd/system)", "EVT_PB", cases["unit"], 1)
    writer("case c1 (append to .bashrc)", "EVT_PC1", home + "/.bashrc", 1)
    writer("case c2 (write .profile)", "EVT_PC2", home + "/.profile", 1)
    writer("case c3 (write .ssh/authorized_keys)", "EVT_PC3", home + "/.ssh/authorized_keys", 1)
    writer("case c4 (write a user systemd unit)", "EVT_PC4", home + "/.config/systemd/user/evt_d8.service", 1)

    for name, path in (("cron file", cases["cron"]), ("unit file", cases["unit"]), (".bashrc", home + "/.bashrc"),
                       (".profile", home + "/.profile"), ("authorized_keys", home + "/.ssh/authorized_keys"),
                       ("user unit", home + "/.config/systemd/user/evt_d8.service")):
        found = [e for e in events if e.get("type") == "exec_success" and v.basename(e.get("exe")) == "cat"
                 and isinstance(e.get("argv"), list) and e["argv"][1:] == [path]]
        check("case d (cat of the %s): the reader ran once" % name, len(found) == 1, "%d exec_success" % len(found))
        if len(found) == 1:
            mine = [a for a in alerts if a.get("detection") in (FILE_NAME, COMMAND_NAME)
                    and a["process"].get("process_key") == found[0].get("process_key")]
            check("case d (cat of the %s): no persistence alert" % name, not mine, "%d alerts" % len(mine))
            info("case d (cat of the %s): %d file_open events from the reader" % (name, len(opens(events, found[0], path))))

    dpkg = writer("case e (copy of bash named dpkg)", "EVT_PE", cases["cron"], 0)
    if dpkg is not None:
        check("case e: comm is dpkg", dpkg.get("comm") == "dpkg", "comm %s" % dpkg.get("comm"))
        check("case e: persist_expected_writer counted", counters.get("persist_expected_writer", 0) >= 1,
              "%d" % counters.get("persist_expected_writer", 0))

    if cases.get("preload_absent") == 1:
        found = marked(events, "EVT_PF")
        check("case f (python opens /etc/ld.so.preload r+): ran once", len(found) == 1, "%d exec_success" % len(found))
        if len(found) == 1:
            seen = opens(events, found[0], "/etc/ld.so.preload")
            check("case f: one open with write flags and ret < 0", len(seen) == 1 and write_flags(seen[0].get("flags"))
                  and isinstance(seen[0].get("ret"), int) and seen[0]["ret"] < 0,
                  "ret %s flags %s" % ([e.get("ret") for e in seen], [e.get("flags") for e in seen]))
            check("case f: no persistence alert", not alerts_for(alerts, found[0], FILE_NAME))
        check("case f: persist_failed_open counted", counters.get("persist_failed_open", 0) >= 1,
              "%d" % counters.get("persist_failed_open", 0))
        check("case f: /etc/ld.so.preload was not created", not os.path.lexists("/etc/ld.so.preload"))
    else:
        info("case f skipped: /etc/ld.so.preload exists on this machine")

    proc = writer("case g (two appends to one file)", "EVT_PG", cases["cron"], 1)
    if proc is not None:
        check("case g: both opens recorded", len(opens(events, proc, cases["cron"])) == 2,
              "%d file_open events" % len(opens(events, proc, cases["cron"])))
        check("case g: persist_duplicate_write counted", counters.get("persist_duplicate_write", 0) == 1,
              "%d" % counters.get("persist_duplicate_write", 0))

    for label, exe, rest, want in (
            ("case h1 (crontab FILE)", base + "/crontab", [base + "/cronfile"], 1),
            ("case h2 (crontab -)", base + "/crontab", ["-"], 1),
            ("case h3 (crontab -l)", base + "/crontab", ["-l"], 0),
            ("case h4 (systemctl enable)", base + "/systemctl", ["enable", "evt_d8_unit.service"], 1),
            ("case h5 (systemctl status)", base + "/systemctl", ["status", "evt_d8_unit.service"], 0)):
        found = execs(events, exe, rest)
        check("%s: ran once" % label, len(found) == 1, "%d exec_success" % len(found))
        if len(found) == 1:
            mine = alerts_for(alerts, found[0], COMMAND_NAME)
            check("%s: %d %s alert" % (label, want, COMMAND_NAME), len(mine) == want, "%d alerts" % len(mine))
            show(label, found[0], mine)
            check("%s: no %s alert" % (label, FILE_NAME), not alerts_for(alerts, found[0], FILE_NAME))

    found = marked(events, "EVT_PI")
    check("case i (write to an ordinary file): the writer ran once", len(found) == 1, "%d exec_success" % len(found))
    if len(found) == 1:
        mine = [a for a in alerts if a.get("detection") in (FILE_NAME, COMMAND_NAME)
                and a["process"].get("process_key") == found[0].get("process_key")]
        check("case i: no persistence alert", not mine, "%d alerts" % len(mine))

    in_graph = [a for a in alerts if a.get("detection") in (FILE_NAME, COMMAND_NAME)]
    check("every persistence alert has its process in the graph", all(a["data_quality"].get("process_in_graph") for a in in_graph),
          "%d alerts" % len(in_graph))

    left = [p for p in (cases["cron"], cases["unit"], home, base) if os.path.lexists(p)]
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
