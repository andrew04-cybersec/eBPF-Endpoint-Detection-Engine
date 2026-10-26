"""Detection shell_from_service: shell started by any process whose name looks like a network service"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts"))
import alert  # noqa: E402

DETECTION_NAME = "shell_from_service"

#inferred name lists (editable); comm is the executable's file name cut to 15 characters by the kernel, not argv[0]
SHELL_NAMES = ("sh", "bash", "dash", "zsh", "ash", "ksh", "csh", "tcsh", "fish")
SERVICE_NAMES = ("nginx", "apache2", "httpd", "mysqld", "postgres", "redis-server", "mongod")
SERVICE_PREFIXES = ("php-fpm",)


def basename(path):
    return path.rsplit("/", 1)[-1]


def is_service(comm):
    return comm in SERVICE_NAMES or comm.startswith(SERVICE_PREFIXES)


def unevaluable(ctx, reason):
    counts = ctx["counts"]
    counts["unevaluable"] = counts.get("unevaluable", 0) + 1
    counts["unevaluable_" + reason] = counts.get("unevaluable_" + reason, 0) + 1


def detect(graph, event, ctx):
    """
    return an alert for an exec_success of a shell whose direct parent node has a service name (otherwise None); shell whose parent is a placeholder and has no comm, (or isnt known cant be judged) so it is counted as unevaluable and doesnt alert
    ctx["attempts"] holds the latest exec_attempt per process key, which is added to the evidence when there is one
    """
    if not isinstance(event, dict) or event.get("type") != "exec_success":
        return None
    exe = event.get("exe", event.get("filename"))
    if not isinstance(exe, str) or basename(exe) not in SHELL_NAMES:
        return None

    nodes = graph.nodes
    key = alert.trigger_key(event)
    node = nodes.get(key)
    if node is None:
        unevaluable(ctx, "shell_not_in_graph")
        return None
    if node.parent_key is None:
        unevaluable(ctx, "no_parent")
        return None
    parent = nodes.get(node.parent_key)
    if parent is None:
        unevaluable(ctx, "parent_missing")
        return None
    if parent.placeholder:
        unevaluable(ctx, "placeholder_parent")
        return None
    if not isinstance(parent.comm, str) or not parent.comm:
        unevaluable(ctx, "parent_no_comm")
        return None
    if not is_service(parent.comm):
        return None

    attempt = ctx["attempts"].get(key)
    evidence = [attempt, event] if attempt is not None else [event]
    return alert.build_alert(graph, DETECTION_NAME, event, evidence)
