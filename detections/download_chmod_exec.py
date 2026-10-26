"""
Detection download_chmod_exec: file downloaded by curl or wget and made executable by chmod and then executed
The telemetry has no chmod or file-write event so each step is inferred from an exec_success and its argv
"""
import copy
import os
import posixpath
import re
import sys
from collections import OrderedDict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts"))
import alert  # noqa: E402
from exec_from_tmp import clean_path  # noqa: E402
from shell_from_service import basename, unevaluable  # noqa: E402

DETECTION_NAME = "download_chmod_exec"

#first guess: how long after the download that the final exec may come in and how many downloaded paths are tracked, and lastly how many characters of argv are stored per tracked event
CHAIN_WINDOW_NS = 600 * 1000000000
MAX_TRACKED_PATHS = 4096
MAX_STORED_ARGV_CHARS = 1024

#short flags that take no value and a cluster such as -sSLo is read only if every letter before the o or O is one of these
CURL_NOVALUE = set("sSLfkvgiIjJZ#NR0123456")
WGET_NOVALUE = set("qvdcNrkxpmSb")


def url_name(url):
    path = url.split("#", 1)[0].split("?", 1)[0].partition("://")[2].partition("/")[2]
    return path.rsplit("/", 1)[-1]


def read_value(args, i, attached):
    if attached:
        return attached, i
    if i < len(args):
        return args[i], i + 1
    return None, i


def short_cluster(arg, wanted, novalue):
    body = arg[1:]
    pos = next((n for n, ch in enumerate(body) if ch in wanted), None)
    if pos is None or any(ch not in novalue for ch in body[:pos]):
        return None
    return body[pos], body[pos + 1:]


def parse_curl(args):
    """
    returns: (files, to_stdout, unparsed)
    handles -o FILE, -oFILE, --output FILE, --output=FILE, -O and --remote-name (name from the URL saved in current directory) and flag clusters like -sSLo FILE
    not handled: --output-dir, --create-dirs, a URL without ://, and pairing several URLs with several -o or -O options
    """
    outputs, remote, urls = [], False, []
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a == "--output":
            value, i = read_value(args, i, "")
            if value is not None:
                outputs.append(value)
        elif a.startswith("--output="):
            outputs.append(a[len("--output="):])
        elif a == "--remote-name":
            remote = True
        elif a.startswith("--"):
            continue
        elif a.startswith("-") and len(a) > 1:
            found = short_cluster(a, "oO", CURL_NOVALUE)
            if found is None:
                continue
            if found[0] == "O":
                remote = True
            else:
                value, i = read_value(args, i, found[1])
                if value is not None:
                    outputs.append(value)
        elif "://" in a:
            urls.append(a)
    if outputs:
        return [o for o in outputs if o != "-"], sum(1 for o in outputs if o == "-"), False
    if remote:
        names = [url_name(u) for u in urls]
        if not names or not all(names):
            return [], 0, True
        return names, 0, False
    return [], 1, False


def parse_wget(args):
    """
    returns: (files, to_stdout, unparsed). Handles -O FILE, -OFILE, --output-document FILE, --output-document=FILE, -P DIR, --directory-prefix DIR and =DIR, and default name from the URL (index.html if it ends in a slash)
    not handled: a URL without ://, --input-file, and several URLs (only the first one is used)
    """
    document, prefix, urls = None, None, []
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a == "--output-document":
            document, i = read_value(args, i, "")
        elif a.startswith("--output-document="):
            document = a[len("--output-document="):]
        elif a == "--directory-prefix":
            prefix, i = read_value(args, i, "")
        elif a.startswith("--directory-prefix="):
            prefix = a[len("--directory-prefix="):]
        elif a.startswith("--"):
            continue
        elif a.startswith("-") and len(a) > 1:
            found = short_cluster(a, "OP", WGET_NOVALUE)
            if found is None:
                continue
            value, i = read_value(args, i, found[1])
            if found[0] == "O":
                document = value
            else:
                prefix = value
        elif "://" in a:
            urls.append(a)
    if document is not None:
        return ([], 1, False) if document == "-" else ([document], 0, False)
    if urls:
        name = url_name(urls[0]) or "index.html"
        return [posixpath.join(prefix, name) if prefix else name], 0, False
    return [], 0, True


def is_exec_mode(mode):
    """
    true if a chmod mode makes a file executable in terms of a symbolic clause that adds or sets x (+x, a+x, u+x, ug+x, =rwx, a=rx) or an octal mode whose user, group, or other digit is odd
    for a 4 digit octal mode only the last three digits count because the first digit holds setuid, setgid, sticky and not execute; X is therefore not counted
    """
    if re.fullmatch(r"[0-7]{3,4}", mode):
        return any(int(d) % 2 == 1 for d in mode[-3:])
    for clause in mode.split(","):
        m = re.fullmatch(r"[ugoa]*((?:[-+=](?:[rwxXst]*|[ugo]))+)", clause)
        if m is None:
            return False
        if any(op in "+=" and "x" in perms for op, perms in re.findall(r"([-+=])([rwxXst]*)", m.group(1))):
            return True
    return False


def parse_chmod(args):
    rest, options_done = [], False
    for a in args:
        if not options_done and a == "--":
            options_done = True
        elif not options_done and a.startswith("-") and len(a) > 1:
            continue
        else:
            rest.append(a)
    if len(rest) < 2:
        return False, []
    return is_exec_mode(rest[0]), rest[1:]


def scope_of(graph, event):
    """key of parent node of the current acting process (or None if the parent is unknown or a placeholder); relative paths are only comparable inside one parent"""
    node = graph.nodes.get(alert.trigger_key(event))
    if node is None or node.parent_key is None:
        return None
    parent = graph.nodes.get(node.parent_key)
    if parent is None or parent.placeholder:
        return None
    return node.parent_key


def path_key(path, scope):
    if path.startswith("/"):
        cleaned = clean_path(path)
        return "abs:" + cleaned, False, cleaned
    name = posixpath.normpath(path)
    if scope is None:
        return None, True, name
    return "rel:%s:%s" % (scope, name), True, name


def store_copy(event):
    kept = copy.deepcopy(event)
    cmdline, argv = kept.get("cmdline"), kept.get("argv")
    cut = False
    if isinstance(cmdline, str) and len(cmdline) > MAX_STORED_ARGV_CHARS:
        kept["cmdline"], cut = cmdline[:MAX_STORED_ARGV_CHARS], True
    if isinstance(argv, list):
        total, items = 0, []
        for item in argv:
            total += len(str(item))
            if total > MAX_STORED_ARGV_CHARS:
                cut = True
                break
            items.append(item)
        kept["argv"] = items
    if cut:
        kept["stored_text_cut_by_detection"] = True
    return kept


def int_ts(event):
    ts = event.get("ts_ns")
    return ts if type(ts) is int else None


def tracked_names(state):
    return {e["name"] for e in state["paths"].values() if e["relative"]}


def match_exec(graph, event, ctx, state):
    filename = event.get("filename")
    ts = int_ts(event)
    if (not isinstance(filename, str) or not filename or ts is None or not state["paths"]
            or event.get("filename_truncated") is True or event.get("user_read_failed") is True):
        return None
    scope = None if filename.startswith("/") else scope_of(graph, event)
    key, relative, name = path_key(filename, scope)
    if key is None:
        if name in tracked_names(state):
            unevaluable(ctx, "relative_unknown_parent")
        return None
    entry = state["paths"].get(key)
    if entry is None or entry["chmod"] is None:
        return None
    d_ts, c_ts = entry["ts"], entry["chmod"]["ts"]
    if not (d_ts < c_ts < ts and ts - d_ts <= CHAIN_WINDOW_NS):
        return None
    return alert.build_alert(graph, DETECTION_NAME, event,
                             [entry["event"], entry["chmod"]["event"], event])


def track_download(graph, event, ctx, state, base, ts):
    args = event.get("argv")
    args = [str(a) for a in args[1:]] if isinstance(args, list) else None
    if args is None:
        unevaluable(ctx, "download_unparsed")
        return
    files, to_stdout, unparsed = (parse_curl if base == "curl" else parse_wget)(args)
    counts = ctx["counts"]
    if to_stdout:
        counts["download_to_stdout"] = counts.get("download_to_stdout", 0) + to_stdout
    if unparsed:
        unevaluable(ctx, "download_unparsed")
    scope = scope_of(graph, event)
    for path in files:
        key, relative, name = path_key(path, scope)
        if key is None:
            unevaluable(ctx, "relative_unknown_parent")
            continue
        state["paths"].pop(key, None)
        state["paths"][key] = {"ts": ts, "event": store_copy(event), "chmod": None,
                               "relative": relative, "name": name}
        while len(state["paths"]) > MAX_TRACKED_PATHS:
            state["paths"].popitem(last=False)


def track_chmod(graph, event, ctx, state, ts):
    args = event.get("argv")
    if not isinstance(args, list):
        return
    makes_exec, targets = parse_chmod([str(a) for a in args[1:]])
    if not makes_exec:
        return
    scope = scope_of(graph, event)
    for target in targets:
        key, relative, name = path_key(target, scope)
        if key is None:
            if name in tracked_names(state):
                unevaluable(ctx, "relative_unknown_parent")
            continue
        entry = state["paths"].get(key)
        if entry is not None and entry["chmod"] is None and entry["ts"] < ts:
            entry["chmod"] = {"ts": ts, "event": store_copy(event)}


def detect(graph, event, ctx):
    """return alert for an exec_success of the path that has a download entry and also a later chmod entry (or otherwise it is None); the state currently lives in ctx under this detection's name so the result depends only on the event stream"""
    if not isinstance(event, dict) or event.get("type") != "exec_success":
        return None
    state = ctx.setdefault("state", {}).setdefault(DETECTION_NAME, {"paths": OrderedDict()})
    found = match_exec(graph, event, ctx, state)
    exe = event.get("exe", event.get("filename"))
    ts = int_ts(event)
    if isinstance(exe, str) and ts is not None:
        base = basename(exe)
        if base in ("curl", "wget"):
            track_download(graph, event, ctx, state, base, ts)
        elif base == "chmod":
            track_chmod(graph, event, ctx, state, ts)
    return found
