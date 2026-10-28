"""Detection interpreter_chain: shell that runs below other shells of two or more kinds with inline code somewhere in the run"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts"))
import alert  # noqa: E402
import attack_map  # noqa: E402
from rapid_spawn import count  # noqa: E402
from shell_from_service import basename  # noqa: E402
from unusual_ancestry import watched  # noqa: E402

DETECTION_NAME = "interpreter_chain"

#first guess: members needed in the chain (the trigger plus its watched ancestors) and distinct families among them
CHAIN_MIN_LENGTH = 3
MIN_DISTINCT_FAMILIES = 2

FAMILY_SHELL = "shell"
FAMILY_PYTHON = "python"
PYTHON_PREFIX = "python"

#inline code option tokens by family (editable); shell matches short option cluster that holds the letter i.e. -lc
INLINE_OPTIONS = {FAMILY_SHELL: ("-c",), FAMILY_PYTHON: ("-c",), "perl": ("-e", "-E"), "ruby": ("-e",),
                  "php": ("-r",), "node": ("-e", "-p", "--eval", "--print")}
CLUSTER_FAMILIES = (FAMILY_SHELL,)
CLUSTER_LETTER = "c"

#how a run of watched programs can end; these two are end of the chain and anything else could hide a longer chain
COMPLETE_ENDS = ("root", "not_watched")


def family(base):
    kind = watched(base)
    if kind == "shell":
        return FAMILY_SHELL
    if kind == "interpreter":
        return FAMILY_PYTHON if base.startswith(PYTHON_PREFIX) else base
    return None


def is_inline(fam, tokens):
    """true if token is inline code option of the family; from a joined command line, the tokens are cut on whitespace which loses quoting so it can miss an option or read one inside quoted text"""
    options = INLINE_OPTIONS.get(fam, ())
    for token in tokens:
        if token in options:
            return True
        if fam in CLUSTER_FAMILIES and token.startswith("-") and not token.startswith("--") \
                and token[1:].isalpha() and CLUSTER_LETTER in token:
            return True
    return False


def trigger_tokens(event):
    argv = event.get("argv")
    if isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv):
        return argv[1:]
    cmdline = event.get("cmdline")
    return cmdline.split()[1:] if isinstance(cmdline, str) else []


def latest_exec(node):
    for entry in reversed(getattr(node, "execs", None) or []):
        if isinstance(entry, dict) and not entry.get("failed"):
            return entry
    return None


def chain_for(graph, key, event):
    """returns (members, end) for exec_success of a watched program: the trigger first and then each ancestor while its latest successful exec is a watched program as dicts with key, exe (basename), family, and inline end says why the run stopped which is root, not_watched, placeholder, no_history, unknown (a node or exe that cant be read), or the graph's stop reason when the ancestry was cut"""
    exe = basename(event.get("exe", event.get("filename")))
    fam = family(exe)
    members = [{"key": key, "exe": exe, "family": fam, "inline": is_inline(fam, trigger_tokens(event))}]
    result = graph.ancestry(key)
    for k in result["chain"][1:]:
        node = graph.nodes.get(k)
        if node is None:
            return members, "unknown"
        if getattr(node, "placeholder", False):
            return members, "placeholder"
        entry = latest_exec(node)
        if entry is None:
            return members, "no_history"
        path = entry.get("exe")
        if not isinstance(path, str):
            return members, "unknown"
        fam = family(basename(path))
        if fam is None:
            return members, "not_watched"
        cmdline = entry.get("cmdline")
        tokens = cmdline.split()[1:] if isinstance(cmdline, str) else []
        members.append({"key": k, "exe": basename(path), "family": fam, "inline": is_inline(fam, tokens)})
    return members, result["stop"]


def detect(graph, event, ctx):
    """
    return an alert for exec_success of shell in which the chain (itself and the watched programs above it) has at least CHAIN_MIN_LENGTH members, MIN_DISTINCT_FAMILIES families, and one member with inline code (otherwise None)
    a chain shorter than minimum that ends where more could be hidden (placeholder, no exec history, cut ancestry) is counted as chain_incomplete and a trigger with no node as chain_not_in_graph
    """
    if not isinstance(event, dict) or event.get("type") != "exec_success":
        return None
    exe = event.get("exe", event.get("filename"))
    if not isinstance(exe, str) or family(basename(exe)) is None:
        return None
    key = alert.trigger_key(event)
    if key not in graph.nodes:
        count(ctx, "chain_not_in_graph")
        return None

    members, end = chain_for(graph, key, event)
    if len(members) < CHAIN_MIN_LENGTH:
        if end not in COMPLETE_ENDS:
            count(ctx, "chain_incomplete")
        return None
    if len({m["family"] for m in members}) < MIN_DISTINCT_FAMILIES or not any(m["inline"] for m in members):
        return None

    attempt = ctx["attempts"].get(key)
    evidence = [attempt, event] if attempt is not None else [event]
    return alert.build_alert(graph, DETECTION_NAME, event, evidence, technique=attack_map.technique_for(DETECTION_NAME))
