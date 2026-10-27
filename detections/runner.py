#!/usr/bin/env python3
"""
Runner: read normalized JSON lines and keep the process graph; also will run the detections and emit their alerts
Usage: runner.py [input] [-o alerts.jsonl] [--no-json] [--no-cli]

sits at the end of the pipe: loader | normalizer | runner and alerts go to standard output (or -o) as JSON lines and to standard error in readable form.
"""
import argparse
import json
import os
import signal
import sys
from collections import OrderedDict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "graph"))
sys.path.insert(0, os.path.join(ROOT, "alerts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import alert  # noqa: E402
import process_graph  # noqa: E402
import shell_from_service  # noqa: E402
import exec_from_tmp  # noqa: E402
import download_chmod_exec  # noqa: E402
import unusual_ancestry  # noqa: E402
import sensitive_file_access  # noqa: E402
import rapid_spawn  # noqa: E402
import outbound_after_exec  # noqa: E402
import persistence  # noqa: E402
import privilege_escalation  # noqa: E402

DETECTIONS = [shell_from_service.detect, exec_from_tmp.detect, download_chmod_exec.detect, unusual_ancestry.detect, sensitive_file_access.detect, rapid_spawn.detect, outbound_after_exec.detect, persistence.detect, privilege_escalation.detect]

#first guess: exec_attempt events kept for the evidence of a later exec_success
MAX_PENDING_ATTEMPTS = 4096


def reject_constant(name):
    raise ValueError("not valid JSON: " + name)


def parse_event(line):
    if isinstance(line, bytes):
        line = line.decode("utf-8", "replace")
    try:
        ev = json.loads(line, parse_constant=reject_constant)
    except (ValueError, RecursionError):
        return None
    return ev if isinstance(ev, dict) else None


def track_attempts(ctx, ev):
    typ = ev.get("type")
    key = alert.trigger_key(ev)
    if key is None:
        return
    attempts = ctx["attempts"]
    if typ == "exec_attempt":
        attempts[key] = ev
        attempts.move_to_end(key)
        if len(attempts) > MAX_PENDING_ATTEMPTS:
            attempts.popitem(last=False)
    elif typ in ("exec_success", "exec_failed", "exit"):
        attempts.pop(key, None)


def run(inp, sink, detections=None, graph=None):
    """feed every line to the graph first and then to each detection so then it can emit what they return; will return with: (graph, ctx, stats)"""
    detections = DETECTIONS if detections is None else detections
    graph = process_graph.ProcessGraph() if graph is None else graph
    ctx = {"counts": {}, "attempts": OrderedDict()}
    stats = {"events": 0, "alerts": {}, "detection_errors": 0}
    for line in inp:
        #the graph parses the line too which keeps its line and anomaly counters complete at the cost of parsing twice in this case
        graph.ingest_line(line)
        ev = parse_event(line)
        if ev is None or type(ev.get("schema_version")) is not int or ev["schema_version"] != 1:
            continue
        stats["events"] += 1
        for detect in detections:
            try:
                found = detect(graph, ev, ctx)
            except Exception:
                #one detection failing on an odd event shouldn't stop the stream so it is counted and reported instead
                stats["detection_errors"] += 1
                continue
            if found is not None:
                sent = sink.emit(found)
                name = sent.get("detection")
                stats["alerts"][name] = stats["alerts"].get(name, 0) + 1
        track_attempts(ctx, ev)
    return graph, ctx, stats


def summary_lines(graph, ctx, stats):
    counts = ctx["counts"]
    g = graph.summary()
    alerts = stats["alerts"]
    lines = ["runner summary",
             "events processed: %d" % stats["events"],
             "alerts emitted: %d%s" % (sum(alerts.values()), "".join(
                 ", %s %d" % kv for kv in sorted(alerts.items()))),
             "unevaluable: %d%s" % (counts.get("unevaluable", 0), "".join(
                 ", %s %d" % (k[len("unevaluable_"):], v) for k, v in sorted(counts.items())
                 if k.startswith("unevaluable_"))),
             "detection errors: %d" % stats["detection_errors"],
             "graph: nodes %d, edges %d, placeholders %d" % (g["nodes"], g["edges"], g["placeholders"]),
             "lost events: %d" % g["lost_events"]]
    return lines


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run detections over normalized JSON lines.")
    ap.add_argument("input", nargs="?", default="-", help="normalized JSON lines file, or - for standard input")
    ap.add_argument("-o", "--output", default="-", help="alert JSON lines file, or - for standard output")
    ap.add_argument("--no-json", action="store_true", help="do not write alert JSON lines")
    ap.add_argument("--no-cli", action="store_true", help="do not write the readable form to standard error")
    args = ap.parse_args(argv)

    opened = []
    try:
        if args.input == "-":
            inp = sys.stdin.buffer
        else:
            inp = open(args.input, "rb")
            opened.append(inp)
        if args.no_json:
            json_stream = None
        elif args.output == "-":
            json_stream = sys.stdout
        else:
            json_stream = open(args.output, "w", encoding="ascii")
            opened.append(json_stream)
    except OSError as e:
        print("runner: %s" % e, file=sys.stderr)
        for f in opened:
            f.close()
        return 2

    if args.input == "-":
        #loader stops on the same signal and closes the pipe so for this... the process ignores it and ends at the end of input instead of losing lines still in the pipe
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    sink = alert.AlertSink(json_stream, None if args.no_cli else sys.stderr)
    try:
        graph, ctx, stats = run(inp, sink)
    finally:
        for f in opened:
            f.close()
    print("\n".join(summary_lines(graph, ctx, stats)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
