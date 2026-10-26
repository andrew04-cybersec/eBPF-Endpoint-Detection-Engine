#!/usr/bin/env python3
"""
Process graph: read the normalizer's JSON lines and keep a graph of processes
Usage: process_graph.py [-i input] summary | ancestry (--pid N | --key K) [--ts T] | dump [-o output]
"""
import argparse
import bisect
import json
import sys
from collections import OrderedDict

SUPPORTED_SCHEMA_VERSION = 1

#first guess is that none of them measured because the node limit applies to exited nodes only and the list limit applies to each list of each node
MAX_NODES = 100000
MAX_EVENTS_PER_LIST = 200
MAX_ANCESTRY_DEPTH = 64
MAX_UNKNOWN_NAMES = 10

ROOT_PPIDS = (0, 1)

NODE_TYPES = ("exec_attempt", "exec_success", "exec_failed", "exit",
              "file_open", "net_connect", "priv_change")
LIST_NAMES = ("execs", "files", "nets", "privs", "ppid_changes")

ANOMALY_NAMES = (
    "bad_json_lines",
    "invalid_utf8_lines",
    "not_an_object",
    "unsupported_schema_version",
    "unknown_event_type",
    "missing_identity",
    "key_mismatch",
    "malformed_field",
    "ppid_missing",
)


def is_int(value):
    return type(value) is int


def reject_constant(name):
    raise ValueError("not valid JSON: " + name)


def make_key(pid, start_time_ns):
    return "%d:%d" % (pid, start_time_ns)


def int_or_none(value):
    return value if is_int(value) else None


class Node:
    """placeholder stands in for a parent and has no start time and its key is "<pid>:unknown" """

    def __init__(self, key, pid, start_time_ns, placeholder=False):
        self.key = key
        self.pid = pid
        self.start_time_ns = start_time_ns
        self.placeholder = placeholder
        self.ppid = None
        self.ppid_latest = None
        self.parent_key = None
        
        #how the parent link was made
        self.link = None
        self.uid = None
        self.gid = None
        self.comm = None
        self.first_seen_ts = None
        self.last_seen_ts = None
        self.execs = []
        self.files = []
        self.nets = []
        self.privs = []
        self.ppid_changes = []
        self.dropped = dict.fromkeys(LIST_NAMES, 0)
        self.exit = None

    def to_dict(self):
        return {
            "key": self.key,
            "pid": self.pid,
            "start_time_ns": self.start_time_ns,
            "placeholder": self.placeholder,
            "ppid": self.ppid,
            "parent_key": self.parent_key,
            "link": self.link,
            "uid": self.uid,
            "gid": self.gid,
            "comm": self.comm,
            "first_seen_ts": self.first_seen_ts,
            "last_seen_ts": self.last_seen_ts,
            "execs": self.execs,
            "exit": self.exit,
            "files": self.files,
            "nets": self.nets,
            "privs": self.privs,
            "ppid_changes": self.ppid_changes,
            "dropped": self.dropped,
        }


class ProcessGraph:

    def __init__(self, max_nodes=MAX_NODES, max_list=MAX_EVENTS_PER_LIST,
                 max_depth=MAX_ANCESTRY_DEPTH):
        self.max_nodes = max_nodes
        self.max_list = max_list
        self.max_depth = max_depth
        self.nodes = {}
        self.children_of = {}
        #pid -> sorted list of real nodes only are used to resolve a ppid
        self.by_pid = {}
        self.placeholders = {}
        self.exited = OrderedDict()

        self.lines_read = 0
        self.blank_lines = 0
        self.events_ingested = 0
        self.type_counts = {}
        self.unknown_names = []
        self.anomalies = dict.fromkeys(ANOMALY_NAMES, 0)
        self.lost_events = 0
        self.lost_dropped = 0
        self.dropped = dict.fromkeys(LIST_NAMES, 0)
        self.evicted = 0
        self.over_limit = 0
        self.placeholders_created = 0
        self.placeholders_adopted = 0
        self.repeat_exits = 0
        self.events_after_exit = 0
        self.ppid_changes = 0

    def ingest_line(self, line):
        if isinstance(line, bytes):
            try:
                line = line.decode("utf-8")
            except UnicodeDecodeError:
                line = line.decode("utf-8", "replace")
                self.anomalies["invalid_utf8_lines"] += 1
        text = line.strip()
        if not text:
            self.blank_lines += 1
            return
        self.lines_read += 1
        try:
            ev = json.loads(text, parse_constant=reject_constant)
        except (ValueError, RecursionError):
            self.anomalies["bad_json_lines"] += 1
            return
        if not isinstance(ev, dict):
            self.anomalies["not_an_object"] += 1
            return
        self.ingest(ev)

    def ingest(self, ev):
        version = ev.get("schema_version")
        if not is_int(version) or version != SUPPORTED_SCHEMA_VERSION:
            self.anomalies["unsupported_schema_version"] += 1
            return
        typ = ev.get("type")
        if typ == "lost":
            self.type_counts["lost"] = self.type_counts.get("lost", 0) + 1
            self.lost_events += 1
            dropped = ev.get("dropped")
            if is_int(dropped):
                self.lost_dropped += dropped
            else:
                self.anomalies["malformed_field"] += 1
            return
        if not isinstance(typ, str) or typ not in NODE_TYPES:
            self.anomalies["unknown_event_type"] += 1
            name = typ if isinstance(typ, str) else repr(typ)
            if name not in self.unknown_names and len(self.unknown_names) < MAX_UNKNOWN_NAMES:
                self.unknown_names.append(name)
            return
        self.type_counts[typ] = self.type_counts.get(typ, 0) + 1

        node = self._node_for(ev)
        if node is None:
            return
        self.events_ingested += 1
        ts = int_or_none(ev.get("ts_ns"))
        if ts is not None:
            if node.first_seen_ts is None:
                node.first_seen_ts = ts
            if node.last_seen_ts is None or ts > node.last_seen_ts:
                node.last_seen_ts = ts
        comm = ev.get("comm")
        if isinstance(comm, str):
            node.comm = comm
        #process exited earlier
        if node.exit is not None and typ != "exit":
            self.events_after_exit += 1

        if typ in ("exec_success", "exec_failed"):
            self._on_exec(node, ev, ts, typ == "exec_failed")
        elif typ == "exit":
            self._on_exit(node, ev, ts)
        elif typ == "file_open":
            self._append(node, "files", {
                "ts_ns": ts, "path": ev.get("path"), "path_truncated": ev.get("path_truncated"),
                "flags": ev.get("flags"), "ret": ev.get("ret")})
        elif typ == "net_connect":
            self._append(node, "nets", {
                "ts_ns": ts, "family": ev.get("family"),
                "remote_addr": ev.get("remote_addr"), "remote_port": ev.get("remote_port")})
        elif typ == "priv_change":
            self._append(node, "privs", {
                "ts_ns": ts, "syscall": ev.get("syscall"), "ids": ev.get("ids")})

    def _node_for(self, ev):
        """find the node for an event or create it; returns None if the event has no usable pid and start time"""
        pid = ev.get("pid")
        start = ev.get("start_time_ns")
        if not (is_int(pid) and is_int(start)):
            self.anomalies["missing_identity"] += 1
            return None
        #key is rebuilt from the fields so a wrong process_key in the input cannot split or merge nodes
        key = make_key(pid, start)
        given = ev.get("process_key")
        if given is not None and given != key:
            self.anomalies["key_mismatch"] += 1
        node = self.nodes.get(key)
        if node is None:
            return self._create(ev, key, pid, start)
        ppid = ev.get("ppid")
        if is_int(ppid) and node.ppid is not None and ppid != node.ppid_latest:
            #changed ppid usually means a reparent after parent exited so its noted on the node and no edge is added
            self._append(node, "ppid_changes", {"ts_ns": int_or_none(ev.get("ts_ns")), "ppid": ppid})
            node.ppid_latest = ppid
            self.ppid_changes += 1
        return node

    def _create(self, ev, key, pid, start):
        node = Node(key, pid, start)
        node.ppid = int_or_none(ev.get("ppid"))
        node.ppid_latest = node.ppid
        if node.ppid is None:
            self.anomalies["ppid_missing"] += 1
        node.uid = int_or_none(ev.get("uid"))
        node.gid = int_or_none(ev.get("gid"))
        self.nodes[key] = node
        self._link(node)
        bisect.insort(self.by_pid.setdefault(pid, []), (start, key))
        self._adopt_children(node)
        self._evict()
        return node

    def _link(self, node):
        if node.ppid is None or node.ppid == 0:
            return
        parent = self._find_parent(node)
        link = "observed"
        if parent is None:
            if node.ppid in ROOT_PPIDS:
                return
            parent = self._placeholder(node.ppid)
            link = "placeholder"
        node.parent_key = parent.key
        node.link = link
        self.children_of.setdefault(parent.key, []).append(node.key)

    def _find_parent(self, node):
        """pick process with child's ppid and latest start time (that isnt later than the child's) since pids are reused"""
        known = self.by_pid.get(node.ppid)
        if not known:
            return None
        i = bisect.bisect_right(known, (node.start_time_ns, "￿"))
        if i == 0:
            return None
        candidate = self.nodes[known[i - 1][1]]
        #candidate that exited before the child started cannot be its parent
        if candidate.exit is not None and candidate.exit["ts_ns"] is not None \
                and candidate.exit["ts_ns"] < node.start_time_ns:
            return None
        return candidate

    def _placeholder(self, pid):
        """return the placeholder for a parent pid that wasnt seen and creating it if needed.
        There is one placeholder per pid, even if pid reuse means the children had different parents."""
        key = self.placeholders.get(pid)
        if key is not None and key in self.nodes:
            return self.nodes[key]
        node = Node("%d:unknown" % pid, pid, None, placeholder=True)
        self.nodes[node.key] = node
        self.placeholders[pid] = node.key
        self.placeholders_created += 1
        return node

    def _adopt_children(self, node):
        """when process appears for a pid that has a placeholder then move the placeholder's children (that started at or after it) to the real node and drop the placeholder once it has none left"""
        ph_key = self.placeholders.get(node.pid)
        if ph_key is None:
            return
        kids = self.children_of.get(ph_key, [])
        moved = [k for k in kids if self.nodes[k].start_time_ns >= node.start_time_ns]
        for k in moved:
            child = self.nodes[k]
            child.parent_key = node.key
            child.link = "late"
            self.children_of.setdefault(node.key, []).append(k)
        self.placeholders_adopted += len(moved)
        kids = [k for k in kids if k not in moved]
        if kids:
            self.children_of[ph_key] = kids
        else:
            self.children_of.pop(ph_key, None)
            del self.nodes[ph_key]
            del self.placeholders[node.pid]

    def _evict(self):
        """drop the oldest exited nodes until the graph is back under the limit; a live node is never dropped so the graph can stay over the limit and that is still counted"""
        while len(self.nodes) > self.max_nodes:
            if not self.exited:
                self.over_limit += 1
                return
            key, _ = self.exited.popitem(last=False)
            node = self.nodes.pop(key)
            self.children_of.pop(key, None)
            siblings = self.children_of.get(node.parent_key)
            if siblings is not None and key in siblings:
                siblings.remove(key)
            known = self.by_pid[node.pid]
            known.remove((node.start_time_ns, key))
            if not known:
                del self.by_pid[node.pid]
            self.evicted += 1

    def _append(self, node, name, item):
        items = getattr(node, name)
        if len(items) < self.max_list:
            items.append(item)
        else:
            node.dropped[name] += 1
            self.dropped[name] += 1

    def _on_exec(self, node, ev, ts, failed):
        exe = ev.get("exe", ev.get("filename"))
        cmdline = ev.get("cmdline", "")
        if not isinstance(exe, str) or not isinstance(cmdline, str):
            self.anomalies["malformed_field"] += 1
            exe = exe if isinstance(exe, str) else ""
            cmdline = cmdline if isinstance(cmdline, str) else ""
        entry = {"exe": exe, "cmdline": cmdline, "ts_ns": ts, "failed": failed}
        if failed:
            entry["reason"] = ev.get("reason")
        self._append(node, "execs", entry)

    def _on_exit(self, node, ev, ts):
        if node.exit is not None:
            self.repeat_exits += 1
            return
        node.exit = {"ts_ns": ts,
                     "exit_code": int_or_none(ev.get("exit_code")),
                     "exit_status": int_or_none(ev.get("exit_status")),
                     "exit_signal": int_or_none(ev.get("exit_signal"))}
        self.exited[node.key] = True

    def children(self, key):
        return list(self.children_of.get(key, []))

    def find_by_pid(self, pid, ts_ns):
        """Return the key of the process that held this pid at ts_ns: the latest start not after ts_ns, unless that process had already exited. Returns None if there is none."""
        known = self.by_pid.get(pid)
        if not known:
            return None
        i = bisect.bisect_right(known, (ts_ns, "￿"))
        if i == 0:
            return None
        node = self.nodes[known[i - 1][1]]
        if node.exit is not None and node.exit["ts_ns"] is not None and node.exit["ts_ns"] < ts_ns:
            return None
        return node.key

    def keys_for_pid(self, pid):
        return [key for _, key in self.by_pid.get(pid, [])]

    def ancestry(self, key):
        """returns {"chain": [keys, process first], "stop": reason}
        The reasons are root, placeholder, cycle, depth_cap, parent_missing, no_parent_info (no ppid was recorded) and unknown_key"""
        chain = []
        seen = set()
        cur = key
        while True:
            node = self.nodes.get(cur)
            if node is None:
                return {"chain": chain, "stop": "parent_missing" if chain else "unknown_key"}
            if cur in seen:
                return {"chain": chain, "stop": "cycle"}
            seen.add(cur)
            chain.append(cur)
            if node.placeholder:
                return {"chain": chain, "stop": "placeholder"}
            if node.parent_key is None:
                return {"chain": chain, "stop": "root" if node.ppid in ROOT_PPIDS else "no_parent_info"}
            if len(chain) >= self.max_depth:
                return {"chain": chain, "stop": "depth_cap"}
            cur = node.parent_key

    def summary(self):
        links = {"observed": 0, "placeholder": 0, "late": 0}
        for node in self.nodes.values():
            if node.link in links:
                links[node.link] += 1
        return {
            "lines_read": self.lines_read,
            "blank_lines": self.blank_lines,
            "events_ingested": self.events_ingested,
            "nodes": len(self.nodes),
            "edges": sum(len(kids) for kids in self.children_of.values()),
            "edges_by_link": links,
            "placeholders": len(self.placeholders),
            "placeholders_created": self.placeholders_created,
            "placeholders_adopted": self.placeholders_adopted,
            "exited": len(self.exited),
            "evicted": self.evicted,
            "over_limit_while_live": self.over_limit,
            "dropped_by_list": dict(self.dropped),
            "events_by_type": dict(self.type_counts),
            "lost_events": self.lost_events,
            "lost_records_dropped": self.lost_dropped,
            "repeat_exits": self.repeat_exits,
            "events_after_exit": self.events_after_exit,
            "ppid_changes": self.ppid_changes,
            "anomalies": dict(self.anomalies),
            "unknown_type_names": list(self.unknown_names),
        }

    def to_dict(self):
        edges = []
        for parent_key, kids in self.children_of.items():
            for k in kids:
                edges.append({"parent": parent_key, "child": k, "link": self.nodes[k].link})
        return {"summary": self.summary(),
                "nodes": [n.to_dict() for n in self.nodes.values()],
                "edges": edges}


def summary_lines(summary):
    lines = ["process graph summary",
             "lines read: %d (blank lines skipped: %d), events attached to nodes: %d" % (
                 summary["lines_read"], summary["blank_lines"], summary["events_ingested"]),
             "nodes: %d, edges: %d" % (summary["nodes"], summary["edges"]),
             "edges by link: " + ", ".join("%s %d" % kv for kv in summary["edges_by_link"].items()),
             "placeholders now: %d (created %d, replaced by a real parent %d)" % (
                 summary["placeholders"], summary["placeholders_created"], summary["placeholders_adopted"]),
             "exited nodes held: %d, evicted: %d, creations over the limit with no exited node to drop: %d" % (
                 summary["exited"], summary["evicted"], summary["over_limit_while_live"]),
             "events dropped by list cap: " + ", ".join("%s %d" % kv for kv in summary["dropped_by_list"].items()),
             "events by type:"]
    for typ, n in sorted(summary["events_by_type"].items()):
        lines.append("  %s: %d" % (typ, n))
    lines.append("lost events: %d, records dropped: %d" % (summary["lost_events"], summary["lost_records_dropped"]))
    lines.append("repeat exits: %d, events after exit: %d, ppid changes noted: %d" % (
        summary["repeat_exits"], summary["events_after_exit"], summary["ppid_changes"]))
    lines.append("anomalies:")
    for name in ANOMALY_NAMES:
        lines.append("  %s: %d" % (name, summary["anomalies"][name]))
    if summary["unknown_type_names"]:
        lines.append("unknown type names (first %d): %s" % (
            MAX_UNKNOWN_NAMES, ", ".join(summary["unknown_type_names"])))
    return lines


def describe(graph, key):
    node = graph.nodes[key]
    if node.placeholder:
        return "%s  (placeholder: parent never seen, started before the loader or not recorded)" % key
    exe = node.execs[-1]["exe"] if node.execs else "-"
    return "%s  comm=%s exe=%s link=%s%s" % (
        key, node.comm, exe, node.link, " exited" if node.exit is not None else "")


def build_graph(inp):
    graph = ProcessGraph()
    for line in inp:
        graph.ingest_line(line)
    return graph


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build a process graph from normalized JSON lines.")
    ap.add_argument("-i", "--input", default="-", help="normalized JSON lines file, or - for standard input")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("summary", help="print counts for the graph")
    anc = sub.add_parser("ancestry", help="print the chain from a process up to its root")
    which = anc.add_mutually_exclusive_group(required=True)
    which.add_argument("--pid", type=int)
    which.add_argument("--key", help="process key, <pid>:<start_time_ns>")
    anc.add_argument("--ts", type=int, help="with --pid, pick the process that held the pid at this ts_ns")
    dump = sub.add_parser("dump", help="print the whole graph as JSON")
    dump.add_argument("-o", "--output", default="-", help="output file, or - for standard output")
    args = ap.parse_args(argv)

    try:
        if args.input == "-":
            graph = build_graph(sys.stdin.buffer)
        else:
            with open(args.input, "rb") as inp:
                graph = build_graph(inp)
    except OSError as e:
        print("process_graph: %s" % e, file=sys.stderr)
        return 2

    if args.command == "summary":
        print("\n".join(summary_lines(graph.summary())))
        return 0

    if args.command == "ancestry":
        if args.key is not None:
            keys = [args.key] if args.key in graph.nodes else []
        elif args.ts is not None:
            found = graph.find_by_pid(args.pid, args.ts)
            keys = [found] if found is not None else []
        else:
            keys = graph.keys_for_pid(args.pid)
        if not keys:
            print("no matching process in the graph", file=sys.stderr)
            return 1
        for key in keys:
            result = graph.ancestry(key)
            print("ancestry of %s" % key)
            for k in result["chain"]:
                print("  " + describe(graph, k))
            print("stop reason: %s" % result["stop"])
        return 0

    text = json.dumps(graph.to_dict(), indent=1, ensure_ascii=True, allow_nan=False) + "\n"
    if args.output == "-":
        sys.stdout.write(text)
    else:
        try:
            with open(args.output, "w", encoding="ascii") as out:
                out.write(text)
        except OSError as e:
            print("process_graph: %s" % e, file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
