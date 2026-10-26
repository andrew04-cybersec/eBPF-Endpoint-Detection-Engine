#!/usr/bin/env python3
"""
Normalizer: read the loader's JSON lines and write normalized JSON lines
Usage: normalize.py [input] [-o output]

With no input argument or "-"... it reads any standard input so it can sit behind the loader in a pipe.
Without -o or "-"... it writes standard output and a summary goes to standard error when the input ends.

All accepted input events are written back with all fields plus a process key.
"""
import argparse
import json
import os
import signal
import sys
from collections import OrderedDict

SUPPORTED_SCHEMA_VERSION = 1

#upper bound on how many processes are tracked all at once and tracking state only needed between process first exec event and exit
MAX_TRACKED_PROCESSES = 65536

#event types describe one process
PROCESS_TYPES = ("exec_attempt", "exec_success", "exit",
                 "file_open", "net_connect", "priv_change")
KNOWN_TYPES = PROCESS_TYPES + ("lost",)

#for the amount of distinct unknown type names the summary lists; list is capped to keep the summary short
MAX_UNKNOWN_NAMES = 10

ANOMALY_NAMES = (
    "bad_json_lines",
    "invalid_utf8_lines",
    "unsupported_schema_version",
    "unknown_event_type",
    "missing_identity",
    "malformed_field",
    "exec_success_without_attempt",
    "exit_without_exec",
    "state_evicted",
)


def is_int(value):
    return type(value) is int


def reject_constant(name):
    """json.loads hook for NaN"""
    raise ValueError("not valid JSON: " + name)


def process_key(ev):
    """build the process key "<pid>:<start_time_ns>" from an event since the kernel reuses pids so pid alone can name two different processes over a longer run."""
    pid = ev.get("pid")
    start = ev.get("start_time_ns")
    if is_int(pid) and is_int(start):
        return "%d:%d" % (pid, start)
    return None


def clean_argv(ev):
    """Return (argv as a list of strings, it is True if the field was well formed)."""
    argv = ev.get("argv")
    if not isinstance(argv, list):
        return [], False
    ok = True
    out = []
    for item in argv:
        if isinstance(item, str):
            out.append(item)
        else:
            out.append(str(item))
            ok = False
    return out, ok


class Normalizer:

    def __init__(self, max_tracked=MAX_TRACKED_PROCESSES):
        self.max_tracked = max_tracked
        #process key -> {"pending": normalized exec_attempt or None... "epoch": value of self.epoch when it was stored}
        #order: oldest use first (oldest entry is dropped when table is full)
        self.procs = OrderedDict()

        #keys of processes whcih exit was already seen.
        #second exit for the same key is expected in all-thread mode
        self.exited = OrderedDict()

        self.epoch = 0
        self.lines_read = 0
        self.blank_lines = 0
        self.lines_written = 0
        self.type_counts = {}
        self.unknown_names = []
        self.anomalies = dict.fromkeys(ANOMALY_NAMES, 0)
        self.exec_failed = 0
        self.repeat_exits = 0
        self.lost_events = 0
        self.lost_dropped = 0
        self.pending_at_end = 0

    def feed_line(self, line):
        if isinstance(line, bytes):
            try:
                line = line.decode("utf-8")
            except UnicodeDecodeError:
                line = line.decode("utf-8", "replace")
                self.anomalies["invalid_utf8_lines"] += 1
        text = line.strip()
        if not text:
            self.blank_lines += 1
            return []
        self.lines_read += 1
        try:
            ev = json.loads(text, parse_constant=reject_constant)
        except (ValueError, RecursionError):
            self.anomalies["bad_json_lines"] += 1
            return []
        if not isinstance(ev, dict):
            self.anomalies["bad_json_lines"] += 1
            return []
        out = self.feed_event(ev)
        self.lines_written += len(out)
        return out

    def feed_event(self, ev):
        version = ev.get("schema_version")
        if not is_int(version) or version != SUPPORTED_SCHEMA_VERSION:
            self.anomalies["unsupported_schema_version"] += 1
            return []

        out = dict(ev)
        typ = ev.get("type")
        if not isinstance(typ, str) or typ not in KNOWN_TYPES:
            self.anomalies["unknown_event_type"] += 1
            name = typ if isinstance(typ, str) else repr(typ)
            if name not in self.unknown_names and len(self.unknown_names) < MAX_UNKNOWN_NAMES:
                self.unknown_names.append(name)
            out["process_key"] = process_key(ev)
            return [out]

        self.type_counts[typ] = self.type_counts.get(typ, 0) + 1

        if typ == "lost":
            #lost event describes the loader (not a process) so its pid, tid and comm are the loader's and it has no start time so no process key build and the field is null
            out["process_key"] = None
            self.lost_events += 1
            dropped = ev.get("dropped")
            if is_int(dropped):
                self.lost_dropped += dropped
            else:
                self.anomalies["malformed_field"] += 1

            #records may be missing from here on, so any failure decision that spans this point is marked uncertain :/
            self.epoch += 1
            return [out]

        key = process_key(ev)
        out["process_key"] = key
        if key is None:
            self.anomalies["missing_identity"] += 1

        if typ == "exec_attempt":
            return self._on_exec_attempt(out, key)
        if typ == "exec_success":
            return self._on_exec_success(out, key)
        if typ == "exit":
            return self._on_exit(out, key)
        #file_open, net_connect, and priv_change are passed through with the process key and dont take part in any join
        return [out]

    def finish(self):
        """Call once when the input has ended"""
        self.pending_at_end = sum(1 for st in self.procs.values() if st["pending"] is not None)

    def _state(self, key):
        """return the tracking entry for key"""
        st = self.procs.get(key)
        if st is None:
            if len(self.procs) >= self.max_tracked:
                self.procs.popitem(last=False)
                self.anomalies["state_evicted"] += 1
            st = {"pending": None, "epoch": self.epoch}
            self.procs[key] = st
        else:
            self.procs.move_to_end(key)
        return st

    def _fail(self, st, reason):
        failed = dict(st["pending"])
        failed["type"] = "exec_failed"
        failed["reason"] = reason
        failed["gap_uncertain"] = st["epoch"] != self.epoch
        st["pending"] = None
        self.exec_failed += 1
        return failed

    def _on_exec_attempt(self, out, key):
        filename = out.get("filename")
        well_formed = isinstance(filename, str)
        if not well_formed:
            filename = ""
        argv, argv_ok = clean_argv(out)
        out["argv"] = argv
        out["exe"] = filename
        out["cmdline"] = " ".join(argv)
        if not (well_formed and argv_ok):
            self.anomalies["malformed_field"] += 1
        if key is None:
            return [out]

        result = []
        st = self._state(key)
        if st["pending"] is not None:
            result.append(self._fail(st, "next_attempt"))
        st["pending"] = out
        st["epoch"] = self.epoch
        result.append(out)
        return result

    def _on_exec_success(self, out, key):
        """Handle an exec_success (argument data comes from pending attempt of the same process)"""
        filename = out.get("filename")
        if not isinstance(filename, str):
            filename = ""
            self.anomalies["malformed_field"] += 1
        out["exe"] = filename
        pending = None
        if key is not None:
            st = self._state(key)
            pending = st["pending"]
            st["pending"] = None
        if pending is not None:
            out["argv"] = list(pending["argv"])
            out["argv_truncated"] = pending.get("argv_truncated")
            out["cmdline"] = pending["cmdline"]
            out["attempt_joined"] = True
        else:
            out["argv"] = []
            out["cmdline"] = ""
            out["attempt_joined"] = False
            if key is not None:
                self.anomalies["exec_success_without_attempt"] += 1
        return [out]

    def _on_exit(self, out, key):
        """Handles exit"""
        code = out.get("exit_code")
        if is_int(code):
            if not is_int(out.get("exit_status")):
                out["exit_status"] = (code >> 8) & 0xFF
            if not is_int(out.get("exit_signal")):
                out["exit_signal"] = code & 0x7F
        else:
            self.anomalies["malformed_field"] += 1
        if key is None:
            return [out]

        result = []
        st = self.procs.pop(key, None)
        if st is not None and st["pending"] is not None:
            result.append(self._fail(st, "exit"))
        if st is None:
            if key in self.exited:
                self.repeat_exits += 1
            else:
                self.anomalies["exit_without_exec"] += 1
        self.exited[key] = True
        self.exited.move_to_end(key)
        if len(self.exited) > self.max_tracked:
            self.exited.popitem(last=False)
        result.append(out)
        return result

    def summary_lines(self):
        """Return summary as list of text lines"""
        lines = ["normalizer summary",
                 "lines read: %d (blank lines skipped: %d)" % (self.lines_read, self.blank_lines),
                 "events written: %d" % self.lines_written,
                 "input events by type:"]
        for typ in KNOWN_TYPES:
            lines.append("  %s: %d" % (typ, self.type_counts.get(typ, 0)))
        lines.append("derived exec_failed: %d" % self.exec_failed)
        lines.append("lost events: %d, records dropped: %d" % (self.lost_events, self.lost_dropped))
        lines.append("exec attempts still pending at end of input: %d" % self.pending_at_end)
        lines.append("repeat exit events (not anomalies): %d" % self.repeat_exits)
        lines.append("anomalies:")
        for name in ANOMALY_NAMES:
            lines.append("  %s: %d" % (name, self.anomalies[name]))
        if self.unknown_names:
            lines.append("unknown type names (first %d): %s" % (MAX_UNKNOWN_NAMES, ", ".join(self.unknown_names)))
        return lines


def encode_event(ev):
    text = json.dumps(ev, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return (text + "\n").encode("ascii")


def run(normalizer, inp, out, flush_each=False):
    for line in inp:
        for ev in normalizer.feed_line(line):
            out.write(encode_event(ev))
        if flush_each:
            out.flush()
    out.flush()
    normalizer.finish()


def main(argv=None):
    """command line entry point; returns process exit status (0 means input was read to its end)"""
    ap = argparse.ArgumentParser(description="Normalize loader JSON lines.")
    ap.add_argument("input", nargs="?", default="-", help="input file, or - for standard input")
    ap.add_argument("-o", "--output", default="-", help="output file, or - for standard output")
    args = ap.parse_args(argv)

    opened = []
    try:
        if args.input == "-":
            inp = sys.stdin.buffer
        else:
            inp = open(args.input, "rb")
            opened.append(inp)
        if args.output == "-":
            out = sys.stdout.buffer
        else:
            out = open(args.output, "wb")
            opened.append(out)
    except OSError as e:
        print("normalize: %s" % e, file=sys.stderr)
        for f in opened:
            f.close()
        return 2

    live = args.input == "-"
    if live:
        #loader drains its ring buffer and exits which closes the pipe
        #if this program stopped on the signal too, the lines still in the pipe would be lost so it ignores the signal and end on the end of input
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    n = Normalizer()
    try:
        run(n, inp, out, flush_each=live)
    except BrokenPipeError:
        #the reader of output went away; point standard output at the null device so the interpreter does not print a second error while shutting down, then report what was processed so far.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        n.finish()
    finally:
        for f in opened:
            f.close()
    print("\n".join(n.summary_lines()), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
