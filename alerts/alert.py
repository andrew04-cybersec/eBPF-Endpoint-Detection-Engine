#!/usr/bin/env python3
"""
Alert output layer: build alert dicts and write them as JSON lines (made sure to render them as readable lines)
Usage: alert.py [input] (reads alert JSON lines from a file or standard input and prints the readable form)
"""
import argparse
import copy
import json
import sys

ALERT_SCHEMA_VERSION = 1

#first guess: evidence events kept per alert and ancestry entries kept per alert
MAX_EVIDENCE_EVENTS = 10
MAX_ANCESTRY_ENTRIES = 32


def is_int(value):
    return type(value) is int


def int_or_none(value):
    return value if is_int(value) else None


def str_or_none(value):
    return value if isinstance(value, str) else None


def process_entry(node):
    """copy the fields of a graph node that an alert needs"""
    execs = getattr(node, "execs", None) or []
    last = execs[-1] if execs and isinstance(execs[-1], dict) else {}
    return {
        "process_key": getattr(node, "key", None),
        "pid": getattr(node, "pid", None),
        "ppid": getattr(node, "ppid", None),
        "comm": getattr(node, "comm", None),
        "exe": last.get("exe"),
        "cmdline": last.get("cmdline"),
        "uid": getattr(node, "uid", None),
        "gid": getattr(node, "gid", None),
        "placeholder": bool(getattr(node, "placeholder", False)),
    }


def entry_from_event(ev, key):
    """fill what an event alone can tell about its process (for a process that is not in the graph)"""
    return {
        "process_key": key,
        "pid": int_or_none(ev.get("pid")),
        "ppid": int_or_none(ev.get("ppid")),
        "comm": str_or_none(ev.get("comm")),
        "exe": str_or_none(ev.get("exe", ev.get("filename"))),
        "cmdline": str_or_none(ev.get("cmdline")),
        "uid": int_or_none(ev.get("uid")),
        "gid": int_or_none(ev.get("gid")),
        "placeholder": False,
    }


def trigger_key(ev):
    pid, start = ev.get("pid"), ev.get("start_time_ns")
    if is_int(pid) and is_int(start):
        return "%d:%d" % (pid, start)
    return str_or_none(ev.get("process_key"))


def build_alert(graph, detection, trigger_event, evidence_events, technique=None, alert_seq=None):
    """return a plain dict for one alert; the graph and the events are only read and every event kept as evidence is a deep copy so if the triggering process is not in the graph then the alert is still built from the trigger event and shows in data_quality."""
    trigger = trigger_event if isinstance(trigger_event, dict) else {}
    nodes = getattr(graph, "nodes", None)
    if not isinstance(nodes, dict):
        nodes = {}
    key = trigger_key(trigger)

    in_graph = key in nodes
    if in_graph:
        process = process_entry(nodes[key])
        #node keeps ids of first event of the process so the ids of the triggering event are used when it has integers (ancestry entries keep the node's ids)
        for field in ("uid", "gid"):
            if is_int(trigger.get(field)):
                process[field] = trigger[field]
        result = graph.ancestry(key)
        chain = result.get("chain") or []
        stop = result.get("stop")
        entries = [process_entry(nodes[k]) for k in chain if k in nodes]
        truncated = len(entries) > MAX_ANCESTRY_ENTRIES
        entries = entries[:MAX_ANCESTRY_ENTRIES]
    else:
        process = entry_from_event(trigger, key)
        entries, stop, truncated = [], "unknown_key", False

    evidence = [e for e in (evidence_events or []) if isinstance(e, dict)]
    kept = copy.deepcopy(evidence[:MAX_EVIDENCE_EVENTS])

    lost = getattr(graph, "lost_events", 0)
    return {
        "alert_schema_version": ALERT_SCHEMA_VERSION,
        "alert_seq": alert_seq,
        "detection": detection if isinstance(detection, str) else str(detection),
        "technique": str_or_none(technique),
        "ts_ns": int_or_none(trigger.get("ts_ns")),
        "process": process,
        "ancestry": entries,
        "ancestry_stop": stop,
        "evidence": kept,
        "evidence_dropped": len(evidence) - len(kept),
        "data_quality": {
            #lost count is for the entire run and not for this process because a lost event doesnt name any specific process
            "lost_events_seen": lost if is_int(lost) else 0,
            "ancestry_complete": stop == "root" and not truncated,
            "ancestry_truncated": truncated,
            "process_in_graph": in_graph,
        },
    }


def clean(value):
    """text for the terminal; hostile command line cant move the cursor or hide text"""
    if value is None:
        return "-"
    return json.dumps(str(value), ensure_ascii=True)[1:-1]


def evidence_line(ev):
    typ = ev.get("type")
    if typ in ("exec_attempt", "exec_success", "exec_failed"):
        detail = "exe=%s" % clean(ev.get("exe", ev.get("filename")))
    elif typ == "file_open":
        detail = "path=%s ret=%s" % (clean(ev.get("path")), clean(ev.get("ret")))
    elif typ == "net_connect":
        detail = "to=%s:%s" % (clean(ev.get("remote_addr")), clean(ev.get("remote_port")))
    elif typ == "priv_change":
        detail = "%s ids=%s" % (clean(ev.get("syscall")), clean(ev.get("ids")))
    else:
        detail = ""
    return ("%s ts_ns=%s %s" % (clean(typ), clean(ev.get("ts_ns")), detail)).rstrip()


def render_alert(alert):
    """returns the readable form of one alert as a list of lines meaning every field is read with a default just in case there is a damaged or older alert so it can still render"""
    process = alert.get("process")
    process = process if isinstance(process, dict) else {}
    quality = alert.get("data_quality")
    quality = quality if isinstance(quality, dict) else {}
    technique = alert.get("technique")

    lines = ["ALERT %s  %s  [%s]" % (
        clean(alert.get("alert_seq")), clean(alert.get("detection")),
        clean(technique) if technique else "technique unassigned")]
    lines.append("  ts_ns: %s (kernel monotonic clock, not wall-clock time)" % clean(alert.get("ts_ns")))
    lines.append("  process: %s pid=%s ppid=%s uid=%s gid=%s key=%s" % (
        clean(process.get("comm")), clean(process.get("pid")), clean(process.get("ppid")),
        clean(process.get("uid")), clean(process.get("gid")), clean(process.get("process_key"))))
    lines.append("  command: %s" % clean(process.get("cmdline")))

    chain = alert.get("ancestry")
    chain = [c for c in chain if isinstance(c, dict)] if isinstance(chain, list) else []
    names = ["%s(%s)" % (clean(c.get("comm")) if c.get("comm") else "unknown", clean(c.get("pid"))) for c in chain]
    lines.append("  ancestry: %s [stop: %s]" % (" <- ".join(names) if names else "none", clean(alert.get("ancestry_stop"))))

    evidence = alert.get("evidence")
    evidence = [e for e in evidence if isinstance(e, dict)] if isinstance(evidence, list) else []
    lines.append("  evidence (%d shown, %s dropped):" % (len(evidence), clean(alert.get("evidence_dropped"))))
    for ev in evidence:
        lines.append("    " + evidence_line(ev))

    if quality.get("process_in_graph") is False:
        lines.append("  WARNING: the process is not in the graph, fields come from the triggering event only")
    if quality.get("ancestry_complete") is not True:
        lines.append("  WARNING: ancestry is incomplete (stop: %s)" % clean(alert.get("ancestry_stop")))
    lost = quality.get("lost_events_seen")
    if is_int(lost) and lost > 0:
        lines.append("  WARNING: %d lost events were seen in this run, evidence may be incomplete" % lost)
    return lines


def encode_alert(alert):
    return json.dumps(alert, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


class AlertSink:
    """write each alert as one JSON line to json_stream and as readable lines to cli_stream (passing None for a stream disables that output)"""

    def __init__(self, json_stream=sys.stdout, cli_stream=sys.stderr):
        self.json_stream = json_stream
        self.cli_stream = cli_stream
        self.seq = 0
        self.failed = 0

    def emit(self, alert):
        """number the alert if it has no number and write it so that it can return the numbered copy without changing the input dict"""
        alert = dict(alert)
        self.seq += 1
        if alert.get("alert_seq") is None:
            alert["alert_seq"] = self.seq
        try:
            line = encode_alert(alert)
        except (TypeError, ValueError):
            #alert that cant be encoded as strict JSON (counted and skipped so any bad value cant stop the run)
            self.failed += 1
            return alert
        if self.json_stream is not None:
            self.json_stream.write(line + "\n")
            self.json_stream.flush()
        if self.cli_stream is not None:
            self.cli_stream.write("\n".join(render_alert(alert)) + "\n")
            self.cli_stream.flush()
        return alert


def view(inp, out, err):
    """render every alert line of input to output and returns: (alerts shown, lines that were not alerts)"""
    shown = bad = 0
    for raw in inp:
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        text = text.strip()
        if not text:
            continue
        try:
            alert = json.loads(text)
        except (ValueError, RecursionError):
            alert = None
        if not isinstance(alert, dict):
            bad += 1
            err.write("alert: line is not an alert JSON object, skipped\n")
            continue
        out.write("\n".join(render_alert(alert)) + "\n")
        shown += 1
    return shown, bad


def main(argv=None):
    ap = argparse.ArgumentParser(description="Show saved alert JSON lines in readable form.")
    ap.add_argument("input", nargs="?", default="-", help="alert JSON lines file, or - for standard input")
    args = ap.parse_args(argv)
    try:
        if args.input == "-":
            shown, bad = view(sys.stdin.buffer, sys.stdout, sys.stderr)
        else:
            with open(args.input, "rb") as inp:
                shown, bad = view(inp, sys.stdout, sys.stderr)
    except OSError as e:
        print("alert: %s" % e, file=sys.stderr)
        return 2
    print("alerts shown: %d, lines skipped: %d" % (shown, bad), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
