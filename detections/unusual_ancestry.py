"""Detection unusual_ancestry: shell, interpreter, or network tool runs somewhere below a process with service name"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts"))
import alert  # noqa: E402
from shell_from_service import SHELL_NAMES, basename, is_service, unevaluable  # noqa: E402

DETECTION_NAME = "unusual_ancestry"

#watched program names (editable); a shell is any name in SHELL_NAMES and an interpreter is one of these names or a name that starts with python (such as python3.12)
INTERPRETER_NAMES = ("perl", "ruby", "php", "node")
INTERPRETER_PREFIXES = ("python",)
NETWORK_TOOLS = ("nc", "ncat", "netcat", "socat")


def watched(base):
    """return "shell", "interpreter", "network_tool", or None for basename of executable"""
    if base in SHELL_NAMES:
        return "shell"
    if base in INTERPRETER_NAMES or base.startswith(INTERPRETER_PREFIXES):
        return "interpreter"
    if base in NETWORK_TOOLS:
        return "network_tool"
    return None


def detect(graph, event, ctx):
    """
    return alert for exec_success of the watched program that has a service-named process anywhere above it in the graph's chain (otherwise None)
    a shell's direct parent is the service (is left to shell_from_service); the process itself is never counted as its own ancestor so a service that execs a watched program in place is judged by its parent (as in shell_from_service)
    if no service is found and the chain doesnt end at the root then the answer is unknown and its counted as unevaluable
    """
    if not isinstance(event, dict) or event.get("type") != "exec_success":
        return None
    exe = event.get("exe", event.get("filename"))
    if not isinstance(exe, str):
        return None
    kind = watched(basename(exe))
    if kind is None:
        return None

    key = alert.trigger_key(event)
    if key not in graph.nodes:
        unevaluable(ctx, "not_in_graph")
        return None
    result = graph.ancestry(key)
    ancestors = [graph.nodes[k] for k in result["chain"][1:] if k in graph.nodes]
    services = [n for n in ancestors if isinstance(n.comm, str) and is_service(n.comm)]
    if not services:
        if result["stop"] != "root":
            unevaluable(ctx, "ancestry_incomplete")
        return None
    if kind == "shell" and ancestors[0] is services[0]:
        return None

    attempt = ctx["attempts"].get(key)
    evidence = [attempt, event] if attempt is not None else [event]
    return alert.build_alert(graph, DETECTION_NAME, event, evidence)
