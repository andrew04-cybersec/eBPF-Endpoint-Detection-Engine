#!/usr/bin/env python3
"""Validate the loader output captured by run_test.sh.

Exit status is 0 if every check passed, 1 otherwise. BCC comparisons are
printed for information and never fail the run.
"""
import argparse
import json
import sys

ENVELOPE = {"schema_version": int, "type": str, "ts_ns": int, "pid": int,
            "tid": int, "comm": str}
IDENT = {"ppid": int, "uid": int, "gid": int, "start_time_ns": int}
FIELDS = {
    "exec_attempt": {"filename": str, "filename_truncated": bool, "argv": list,
                     "argv_truncated": bool, "user_read_failed": bool,
                     "lossy_encoding": bool, **IDENT},
    "exec_success": {"filename": str, "filename_truncated": bool, "old_pid": int,
                     "user_read_failed": bool, "lossy_encoding": bool, **IDENT},
    "exit": {"exit_code": int, "exit_status": int, "exit_signal": int,
             "lossy_encoding": bool, **IDENT},
    "lost": {"dropped": int},
    "file_open": {"path": str, "path_truncated": bool, "flags": int,
                  "user_read_failed": bool, "lossy_encoding": bool, **IDENT},
    "net_connect": {"family": int, "remote_addr": str, "remote_port": int,
                    "lossy_encoding": bool, **IDENT},
    "priv_change": {"syscall": str, "ids": list, "lossy_encoding": bool, **IDENT},
}

#the sensitive list from src/sensitive_paths.h and HOME_USER_SCAN from src/common.h
SENS_EXACT = {"/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/sudoers"}
SENS_PREFIX = ("/etc/sudoers.d/", "/root/.ssh/")
HOME_USER_SCAN = 32
PRIV_SYSCALLS = {"setuid", "setreuid", "setresuid", "setgid", "setresgid"}

results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print("%s  %s%s" % ("PASS" if ok else "FAIL", name, ("  " + detail) if detail else ""))
    return ok


def info(msg):
    print("INFO  " + msg)


def load(path):
    """Return (events, bad_lines). Strict JSON, strict UTF-8."""
    events, bad = [], []
    def no_const(c):
        raise ValueError("non-JSON constant " + c)
    with open(path, "rb") as f:
        for n, raw in enumerate(f, 1):
            try:
                text = raw.decode("utf-8")
                ev = json.loads(text, parse_constant=no_const)
                if not isinstance(ev, dict):
                    raise ValueError("not an object")
                events.append(ev)
            except Exception as e:
                bad.append((n, str(e)))
    return events, bad


def field_errors(ev):
    errs = []
    t = ev.get("type")
    if t not in FIELDS:
        return ["unknown type %r" % (t,)]
    for name, typ in list(ENVELOPE.items()) + list(FIELDS[t].items()):
        if name not in ev:
            errs.append("missing " + name)
        elif type(ev[name]) is not typ:
            errs.append("%s has type %s" % (name, type(ev[name]).__name__))
    if t == "exec_attempt" and isinstance(ev.get("argv"), list):
        if not all(isinstance(a, str) for a in ev["argv"]):
            errs.append("argv has a non-string element")
    if ev.get("schema_version") != 1:
        errs.append("schema_version is not 1")
    if "envp" in ev:
        errs.append("envp must not be captured")
    if t == "file_open" and "ret" in ev and type(ev["ret"]) is not int:
        errs.append("ret has type %s" % type(ev["ret"]).__name__)
    if t == "net_connect" and ev.get("family") not in (2, 10):
        errs.append("family is not 2 or 10")
    if t == "priv_change":
        ids = ev.get("ids")
        if ev.get("syscall") not in PRIV_SYSCALLS:
            errs.append("unknown syscall %r" % (ev.get("syscall"),))
        if not isinstance(ids, list) or not ids or not all(type(i) is int for i in ids):
            errs.append("ids is not a non-empty list of integers")
    return errs


def derive(events):
    """Pair attempts with successes. Return (unmatched_successes, failed_attempts)."""
    pending, bad_success, failed = {}, [], []
    for i, ev in enumerate(events):
        t, pid = ev["type"], ev["pid"]
        if t == "exec_attempt":
            if pid in pending:
                failed.append(pending[pid])
            pending[pid] = i
        elif t == "exec_success":
            if pid in pending:
                del pending[pid]
            else:
                bad_success.append(i)
        elif t == "exit" and pid in pending:
            failed.append(pending.pop(pid))
    failed.extend(pending.values())
    return bad_success, failed


def with_marker(events, kind, marker):
    return [e for e in events if e["type"] == kind and
            any(marker in a for a in e.get("argv", []))]


def exits_for(events, pid):
    return [e for e in events if e["type"] == "exit" and e["pid"] == pid]


def is_sensitive(path):
    if path in SENS_EXACT or path.startswith(SENS_PREFIX):
        return True
    return path.startswith("/home/") and any(
        path[k:k + 6] == "/.ssh/" for k in range(6, 6 + HOME_USER_SCAN))


def cat_pids(events, path):
    """Pids that ran /bin/cat on the given path."""
    return {e["pid"] for e in events if e["type"] == "exec_attempt" and
            e["argv"] == ["/bin/cat", path]}


def parse_bcc(path):
    rows = []
    try:
        with open(path, errors="replace") as f:
            for line in f.read().splitlines()[1:]:
                if line.split():
                    rows.append(line)
    except OSError:
        pass
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("events")
    ap.add_argument("--threads-all", help="events from a run with --all-thread-exits")
    ap.add_argument("--execsnoop")
    ap.add_argument("--exitsnoop")
    ap.add_argument("--max-args", type=int, required=True)
    ap.add_argument("--arg-cap", type=int, required=True)
    ap.add_argument("--burst", type=int, required=True)
    ap.add_argument("--sudo-uid", type=int, default=0)
    ap.add_argument("--sudo-gid", type=int, default=0)
    ap.add_argument("--net4-port", type=int, default=0)
    ap.add_argument("--net6-port", type=int, default=0)
    ap.add_argument("--file-exit", help="events from a paired run in the default (exit) mode")
    ap.add_argument("--file-entry", help="events from a paired run with --file-at-entry")
    a = ap.parse_args()

    events, bad = load(a.events)
    check("every line is valid JSON", not bad and events,
          "%d lines, %d bad %s" % (len(events) + len(bad), len(bad), bad[:3]))
    if bad or not events:
        return 1

    errs = [(i, field_errors(e)) for i, e in enumerate(events)]
    errs = [(i, e) for i, e in errs if e]
    check("envelope and per-type fields present with correct JSON types", not errs,
          "%d events with problems, first: %s" % (len(errs), errs[:2]))
    if errs:
        return 1

    counts = {}
    for e in events:
        counts[e["type"]] = counts.get(e["type"], 0) + 1
    info("event counts: %s" % counts)

    bad_success, failed = derive(events)
    check("every exec_success has a matching earlier exec_attempt", not bad_success,
          "%d unmatched" % len(bad_success))

    exec_pids = {e["pid"] for e in events if e["type"] in ("exec_attempt", "exec_success")}
    exit_pids = {e["pid"] for e in events if e["type"] == "exit"}
    missing = sorted(exec_pids - exit_pids)
    check("every pid that exec'd has an exit event", not missing,
          "%d without exit: %s" % (len(missing), missing[:10]))

    #failed exec
    fa = with_marker(events, "exec_attempt", "EVT_FAIL")
    ok = len(fa) == 1 and fa[0]["filename"] == "/nonexistent/evt_program"
    check("failed exec: one attempt for the nonexistent path", ok, "%d found" % len(fa))
    if ok:
        pid = fa[0]["pid"]
        idx = events.index(fa[0])
        check("failed exec: no exec_success for that attempt", idx in failed)
        ex = exits_for(events, pid)
        check("failed exec: exit status 127 follows", bool(ex) and ex[0]["exit_status"] == 127,
              "exit event: %s" % (ex[0] if ex else None))
    info("%d exec attempts have no success (includes PATH search misses)" % len(failed))

    #successful exec
    oa = with_marker(events, "exec_attempt", "EVT_OK")
    check("successful exec: attempt, success and exit for the marked command",
          len(oa) == 1 and any(e["type"] == "exec_success" and e["pid"] == oa[0]["pid"] for e in events)
          and bool(exits_for(events, oa[0]["pid"])), "%d attempts" % len(oa))

    #shell chain
    sh = with_marker(events, "exec_attempt", "EVT_CHAIN")
    if check("chain: one sh attempt", len(sh) == 1):
        spid = sh[0]["pid"]
        ls = [e for e in events if e["type"] == "exec_success" and e["filename"].endswith("/ls")
              and e["ppid"] == spid]
        cat = [e for e in events if e["type"] == "exec_success" and e["filename"].endswith("/cat")
               and (e["ppid"] == spid or e["pid"] == spid)]
        check("chain: ls is a child of the sh process", len(ls) == 1, "%d found" % len(ls))
        check("chain: cat ran under the sh process (child or in place)", len(cat) == 1,
              "%d found" % len(cat))

    #burst
    ba = with_marker(events, "exec_attempt", "EVT_BURST")
    bpids = {e["pid"] for e in ba}
    bs = [e for e in events if e["type"] == "exec_success" and e["pid"] in bpids]
    bx = [e for e in events if e["type"] == "exit" and e["pid"] in bpids]
    check("burst: attempts, successes and exits all match the burst size",
          len(ba) == len(bs) == len(bx) == len(bpids) == a.burst,
          "attempts %d, successes %d, exits %d, distinct pids %d, expected %d" %
          (len(ba), len(bs), len(bx), len(bpids), a.burst))

    #identity
    if a.sudo_uid:
        ua = [e for e in events if e["type"] == "exec_success" and e["filename"].endswith("/echo")
              and e["pid"] in {x["pid"] for x in with_marker(events, "exec_attempt", "EVT_UID")}]
        check("uid: exec_success after setpriv carries the dropped uid",
              len(ua) == 1 and ua[0]["uid"] == a.sudo_uid, "%s" % [(e["uid"]) for e in ua])
    else:
        info("uid check skipped: not run through sudo from a normal user")

    #exit code (one exit per process)
    for marker, want_status, want_sig in (("EVT_EXIT7", 7, 0), ("EVT_KILL9", 0, 9)):
        att = with_marker(events, "exec_attempt", marker)
        ex = exits_for(events, att[0]["pid"]) if att else []
        ok = len(ex) == 1
        if ok:
            info("%s: raw exit_code=%d (0x%x), exit_status=%d, exit_signal=%d" %
                 (marker, ex[0]["exit_code"], ex[0]["exit_code"] & 0xffffffff,
                  ex[0]["exit_status"], ex[0]["exit_signal"]))
        check("exit_code: %s gives one exit with status %d and signal %d" % (marker, want_status, want_sig),
              ok and ex[0]["exit_status"] == want_status and ex[0]["exit_signal"] == want_sig,
              "%d exit events" % len(ex))

    th = with_marker(events, "exec_attempt", "EVT_THREADS")
    ex = exits_for(events, th[0]["pid"]) if th else []
    check("threads: a multi-threaded process produces exactly one exit event",
          len(th) == 1 and len(ex) == 1, "%d exit events" % len(ex))

    #truncation & encoding
    ma = with_marker(events, "exec_attempt", "EVT_MANYARGS")
    check("truncation: too many arguments sets argv_truncated and keeps the cap",
          len(ma) == 1 and ma[0]["argv_truncated"] and len(ma[0]["argv"]) == a.max_args,
          "%s" % [(len(e["argv"]), e["argv_truncated"]) for e in ma])
    la = with_marker(events, "exec_attempt", "EVT_LONGARG")
    check("truncation: a long argument sets argv_truncated and is cut to the cap",
          len(la) == 1 and la[0]["argv_truncated"] and
          all(len(x.encode("utf-8")) < a.arg_cap for x in la[0]["argv"]),
          "%s" % [(e["argv_truncated"], [len(x) for x in e["argv"]]) for e in la])
    check("truncation: burst attempts are not marked truncated",
          all(not e["argv_truncated"] and not e["filename_truncated"] for e in ba))
    bu = with_marker(events, "exec_attempt", "EVT_BADUTF8")
    check("encoding: invalid UTF-8 becomes U+FFFD and sets lossy_encoding",
          len(bu) == 1 and bu[0]["lossy_encoding"] and any("�" in x for x in bu[0]["argv"]),
          "%s" % [e["argv"] for e in bu])

    #file_open
    fo = [e for e in events if e["type"] == "file_open"]
    stray = [e["path"] for e in fo if not is_sensitive(e["path"])]
    check("file_open: every reported path is on the sensitive list", not stray, "%s" % stray[:5])
    check("file_open: default (exit) mode records a return value", bool(fo) and all("ret" in e for e in fo))
    mk = [e for e in fo if e["path"] == "/root/.ssh/evt_missing_key"]
    check("file_open: a missing listed path has a negative return value",
          len(mk) == 1 and mk[0].get("ret", 0) < 0, "%s" % [e.get("ret") for e in mk])
    for path in ("/etc/shadow", "/etc/passwd"):
        pids = cat_pids(events, path)
        got = [e for e in fo if e["path"] == path and e["pid"] in pids]
        check("file_open: cat %s gives one file_open for that process, opened read-only" % path,
              len(pids) == 1 and len(got) == 1 and got[0]["flags"] & 3 == 0,
              "%d cat runs, %d events, flags %s" % (len(pids), len(got), [e["flags"] for e in got]))
    pids = cat_pids(events, "/etc/os-release")
    got = [e for e in fo if e["pid"] in pids]
    check("file_open: an ordinary file gives no file_open", len(pids) == 1 and not got,
          "%d cat runs, %d events" % (len(pids), len(got)))
    for path in ("/root/.ssh/evt_missing_key", "/home/evt_nouser/.ssh/id_rsa"):
        pids = cat_pids(events, path)
        got = [e for e in fo if e["path"] == path and e["pid"] in pids]
        check("file_open: a listed path that does not exist is still reported (%s)" % path,
              len(pids) == 1 and len(got) == 1, "%d cat runs, %d events" % (len(pids), len(got)))

    #net_connect
    nc = [e for e in events if e["type"] == "net_connect"]
    for label, marker, port, addr, fam in (("IPv4", "EVT_NET4", a.net4_port, "127.0.0.1", 2),
                                           ("IPv6", "EVT_NET6", a.net6_port, "::1", 10)):
        if not port:
            info("net_connect %s loopback untested: no listener could be bound" % label)
            continue
        pids = {e["pid"] for e in with_marker(events, "exec_attempt", marker)}
        got = [e for e in nc if e["remote_addr"] == addr and e["remote_port"] == port and
               e["family"] == fam and e["pid"] in pids]
        check("net_connect: %s loopback connect to port %d is reported once with address and port" %
              (label, port), len(pids) == 1 and len(got) == 1,
              "%d processes, %d events" % (len(pids), len(got)))

    #priv_change
    if a.sudo_uid:
        u, g = a.sudo_uid, a.sudo_gid
        sp = [e for e in events if e["type"] == "exec_attempt" and e["filename"].endswith("/setpriv")
              and any("EVT_UID" in x for x in e["argv"])]
        got = [e for e in events if e["type"] == "priv_change" and sp and e["pid"] == sp[0]["pid"]
               and e["syscall"] in ("setreuid", "setresuid") and u in e["ids"]]
        check("priv_change: setpriv --reuid reports the requested uid", len(sp) == 1 and len(got) >= 1,
              "%d setpriv runs, %s" % (len(sp), [(e["syscall"], e["ids"]) for e in got]))
        py = with_marker(events, "exec_attempt", "EVT_PRIV")
        seq = [(e["syscall"], e["ids"]) for e in events if e["type"] == "priv_change"
               and py and e["pid"] == py[0]["pid"]]
        want = [("setgid", [g]), ("setresgid", [g, g, g]), ("setreuid", [u, u]),
                ("setresuid", [u, u, u]), ("setuid", [u])]
        check("priv_change: setgid, setresgid, setreuid, setresuid and setuid are all reported in order",
              len(py) == 1 and seq == want, "got %s" % seq)
    else:
        info("priv_change checks skipped: not run through sudo from a normal user")

    lost = [e for e in events if e["type"] == "lost"]
    info("lost events: %d, total dropped %d" % (len(lost), sum(e["dropped"] for e in lost)))
    check("no records were dropped during the main run", not lost)
    rf = [e for e in events if e.get("user_read_failed")]
    info("events with user_read_failed: %d" % len(rf))

    #per-thread exit run
    if a.threads_all:
        ev2, bad2 = load(a.threads_all)
        t2 = with_marker(ev2, "exec_attempt", "EVT_THREADS") if not bad2 else []
        x2 = exits_for(ev2, t2[0]["pid"]) if t2 else []
        check("threads (all-thread mode): one exit per thread, so more than one for the process",
              len(t2) == 1 and len(x2) > 1,
              "%d exit events, tids %s" % (len(x2), sorted(e["tid"] for e in x2)))

    #file_open with the path read at exit
    if a.file_exit:
        ev3, bad3 = load(a.file_exit)
        errs3 = [field_errors(e) for e in ev3 if field_errors(e)]
        check("file_open (exit mode): every line is valid JSON with correct fields",
              not bad3 and not errs3 and bool(ev3), "%d bad lines, %d with field problems" %
              (len(bad3), len(errs3)))
        if not bad3 and not errs3:
            fo3 = [e for e in ev3 if e["type"] == "file_open"]
            sh = [e for e in fo3 if e["path"] == "/etc/shadow" and e["pid"] in cat_pids(ev3, "/etc/shadow")]
            check("file_open (exit mode): /etc/shadow is reported with a return value of zero or more",
                  len(sh) == 1 and "ret" in sh[0] and sh[0]["ret"] >= 0, "%s" % [e.get("ret") for e in sh])
            ms = [e for e in fo3 if e["path"] == "/root/.ssh/evt_missing_key"]
            check("file_open (exit mode): a missing listed path is reported with a negative return value",
                  len(ms) == 1 and "ret" in ms[0] and ms[0]["ret"] < 0, "%s" % [e.get("ret") for e in ms])
            check("file_open (exit mode): an ordinary file gives no file_open",
                  not [e for e in fo3 if e["pid"] in cat_pids(ev3, "/etc/os-release")])
            check("file_open (exit mode): no records were dropped",
                  not [e for e in ev3 if e["type"] == "lost"])

    #file_open with the path read at entry
    if a.file_entry:
        ev4, bad4 = load(a.file_entry)
        errs4 = [field_errors(e) for e in ev4 if field_errors(e)]
        check("file_open (entry mode): every line is valid JSON with correct fields",
              not bad4 and not errs4 and bool(ev4), "%d bad lines, %d with field problems" %
              (len(bad4), len(errs4)))
        if not bad4 and not errs4:
            fo4 = [e for e in ev4 if e["type"] == "file_open"]
            sh4 = [e for e in fo4 if e["path"] == "/etc/shadow" and e["pid"] in cat_pids(ev4, "/etc/shadow")]
            check("file_open (entry mode): /etc/shadow is reported once",
                  len(sh4) == 1, "%d events" % len(sh4))
            check("file_open (entry mode): no return value is recorded",
                  bool(fo4) and all("ret" not in e for e in fo4))
            check("file_open (entry mode): an ordinary file gives no file_open",
                  not [e for e in fo4 if e["pid"] in cat_pids(ev4, "/etc/os-release")])
            check("file_open (entry mode): no records were dropped",
                  not [e for e in ev4 if e["type"] == "lost"])

    #BCC comparison
    try:
        if a.execsnoop:
            rows = [r for r in parse_bcc(a.execsnoop) if "EVT_" in r]
            ok_rows = [r for r in rows if r.split()[3] == "0"]
            info("execsnoop-bpfcc: %d marked lines, %d with RET 0" % (len(rows), len(ok_rows)))
            ours = [e for e in events if e["type"] == "exec_attempt" and
                    any("EVT_" in x for x in e["argv"])]
            info("this loader: %d marked attempts, %d of them with a success" %
                 (len(ours), len([e for e in ours if events.index(e) not in failed])))
        if a.exitsnoop:
            rows = parse_bcc(a.exitsnoop)
            bpids = {int(r.split()[1]) for r in rows if len(r.split()) > 1 and r.split()[1].isdigit()}
            marked = {e["pid"] for e in events if e["type"] == "exec_attempt" and
                      any("EVT_" in x for x in e["argv"])}
            info("exitsnoop-bpfcc: %d lines; of %d marked pids it saw %d" %
                 (len(rows), len(marked), len(marked & bpids)))
    except Exception as e:
        info("BCC comparison skipped: %s" % e)

    failed_checks = [n for n, ok in results if not ok]
    print("\n%d checks, %d failed" % (len(results), len(failed_checks)))
    return 1 if failed_checks else 0


if __name__ == "__main__":
    sys.exit(main())
