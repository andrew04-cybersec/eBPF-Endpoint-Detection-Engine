"""ATT&CK mapping: technique each detection puts on its alerts with the inclusion of the technique table it comes from (standard library)"""
import re

ATTACK_VERSION = "v20.0"
VERIFIED_DATE = "2026-10-28"

#names, tactics, and platforms were read from each technique page on attack.mitre.org in the version and date above... page_version is the version number and the page itself showed for that technique
TECHNIQUES = {
    "T1003.008": {"name": "/etc/passwd and /etc/shadow", "tactics": ("Credential Access",), "platforms": "Linux", "page_version": "1.2", "verified": True},
    "T1037": {"name": "Boot or Logon Initialization Scripts", "tactics": ("Persistence", "Privilege Escalation"), "platforms": "ESXi, Linux, Network Devices, Windows, macOS", "page_version": "2.4", "verified": True},
    "T1037.004": {"name": "RC Scripts", "tactics": ("Persistence", "Privilege Escalation"), "platforms": "ESXi, Linux, Network Devices, macOS", "page_version": "2.2", "verified": True},
    "T1053.003": {"name": "Cron", "tactics": ("Execution", "Persistence", "Privilege Escalation"), "platforms": "ESXi, Linux, macOS", "page_version": "1.3", "verified": True},
    "T1059": {"name": "Command and Scripting Interpreter", "tactics": ("Execution",), "platforms": "Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS", "page_version": "2.7", "verified": True},
    "T1059.004": {"name": "Unix Shell", "tactics": ("Execution",), "platforms": "ESXi, Linux, Network Devices, macOS", "page_version": "1.4", "verified": True},
    "T1059.006": {"name": "Python", "tactics": ("Execution",), "platforms": "ESXi, Linux, Windows, macOS", "page_version": "1.1", "verified": True},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactics": ("Privilege Escalation",), "platforms": "Containers, Linux, Windows, macOS", "page_version": "1.6", "verified": True},
    "T1071": {"name": "Application Layer Protocol", "tactics": ("Command and Control",), "platforms": "ESXi, Linux, Network Devices, Windows, macOS", "page_version": "2.4", "verified": True},
    "T1071.001": {"name": "Web Protocols", "tactics": ("Command and Control",), "platforms": "ESXi, Linux, Network Devices, Windows, macOS", "page_version": "1.5", "verified": True},
    "T1095": {"name": "Non-Application Layer Protocol", "tactics": ("Command and Control",), "platforms": "ESXi, Linux, Network Devices, Windows, macOS", "page_version": "2.4", "verified": True},
    "T1098.004": {"name": "SSH Authorized Keys", "tactics": ("Persistence", "Privilege Escalation"), "platforms": "ESXi, IaaS, Linux, Network Devices, macOS", "page_version": "1.4", "verified": True},
    "T1105": {"name": "Ingress Tool Transfer", "tactics": ("Command and Control",), "platforms": "ESXi, Linux, Network Devices, Windows, macOS", "page_version": "2.6", "verified": True},
    "T1136.001": {"name": "Local Account", "tactics": ("Persistence",), "platforms": "Containers, ESXi, Linux, Network Devices, Windows, macOS", "page_version": "1.5", "verified": True},
    "T1222.002": {"name": "Linux and Mac Permissions", "tactics": ("Defense Impairment",), "platforms": "Linux, macOS", "page_version": "2.0", "verified": True},
    "T1505.003": {"name": "Web Shell", "tactics": ("Persistence",), "platforms": "Linux, Network Devices, Windows, macOS", "page_version": "1.5", "verified": True},
    "T1543.002": {"name": "Systemd Service", "tactics": ("Persistence", "Privilege Escalation"), "platforms": "Linux", "page_version": "1.6", "verified": True},
    "T1546.004": {"name": "Unix Shell Configuration Modification", "tactics": ("Privilege Escalation", "Persistence"), "platforms": "Linux, macOS", "page_version": "2.2", "verified": True},
    "T1547.013": {"name": "XDG Autostart Entries", "tactics": ("Persistence", "Privilege Escalation"), "platforms": "Linux", "page_version": "1.2", "verified": True},
    "T1548.001": {"name": "Setuid and Setgid", "tactics": ("Privilege Escalation",), "platforms": "Linux, macOS", "page_version": "2.0", "verified": True},
    "T1548.003": {"name": "Sudo and Sudo Caching", "tactics": ("Privilege Escalation",), "platforms": "Linux, macOS", "page_version": "2.0", "verified": True},
    "T1552.004": {"name": "Private Keys", "tactics": ("Credential Access",), "platforms": "Linux, Network Devices, Windows, macOS", "page_version": "1.3", "verified": True},
    "T1556.003": {"name": "Pluggable Authentication Modules", "tactics": ("Defense Impairment", "Persistence", "Credential Access"), "platforms": "Linux, macOS", "page_version": "3.0", "verified": True},
    "T1574.006": {"name": "Dynamic Linker Hijacking", "tactics": ("Stealth", "Execution"), "platforms": "Linux, macOS", "page_version": "3.0", "verified": True},
}

CONFIDENCES = ("direct", "partial", "weak")

#the mapping is a design choice (one technique per alert as (technique id, confidence)); a detection with categories has its own table below and isnt listed here
DETECTIONS = {
    "shell_from_service": ("T1059.004", "direct"),
    "unusual_ancestry": ("T1059", "partial"),
    "exec_from_tmp": ("T1059", "weak"),
    "download_chmod_exec": ("T1105", "direct"),
    "outbound_after_exec": ("T1095", "partial"),
    "privilege_escalation": ("T1068", "partial"),
    "interpreter_chain": ("T1059", "direct"),
    "rapid_spawn": ("T1059", "weak"),
}

SENSITIVE_FILE = {
    "shadow": ("T1003.008", "direct"),
    "passwd": ("T1003.008", "direct"),
    "ssh_private_key": ("T1552.004", "direct"),
    "sudoers": ("T1548.003", "weak"),
}

PERSISTENCE_FILE = {
    "cron": ("T1053.003", "direct"),
    "systemd": ("T1543.002", "direct"),
    "shell_startup": ("T1546.004", "direct"),
    "ld_preload": ("T1574.006", "direct"),
    "ld_conf": ("T1574.006", "direct"),
    "ssh_keys": ("T1098.004", "direct"),
    "pam": ("T1556.003", "direct"),
    "init": ("T1037.004", "direct"),
    "accounts": ("T1136.001", "partial"),
    "user_autostart": ("T1547.013", "partial"),
    "motd": ("T1037", "weak"),
}

PERSISTENCE_COMMAND = {
    "crontab": ("T1053.003", "direct"),
    "systemctl": ("T1543.002", "direct"),
}

CATEGORY_TABLES = {
    "sensitive_file_access": SENSITIVE_FILE,
    "persistence_write": PERSISTENCE_FILE,
    "persistence_command": PERSISTENCE_COMMAND,
}

#related techniques that are described in the docs only and they are never put on an alert
RELATED = {
    "shell_from_service": ("T1505.003",),
    "unusual_ancestry": ("T1505.003",),
    "exec_from_tmp": (),
    "download_chmod_exec": ("T1222.002",),
    "outbound_after_exec": ("T1071", "T1071.001"),
    "privilege_escalation": ("T1548.001",),
    "interpreter_chain": ("T1059.004", "T1059.006"),
    "rapid_spawn": (),
}

#these two repeat SSH_KEY_DIR and SSH_NOT_PRIVATE of sensitive_file_access and a test checks that both modules agree on every path
SSH_KEY_PATH = re.compile(r"/(?:root|home/[^/]+)/\.ssh/([^/]+)")
SSH_NOT_PRIVATE = ("known_hosts", "known_hosts.old", "config", "authorized_keys", "authorized_keys2")


def sensitive_category(path):
    """category of a cleaned absolute path that sensitive_file_access alerts on (or None); kept here so the detection only has to look the technique up"""
    if path in ("/etc/shadow", "/etc/gshadow"):
        return "shadow"
    if path == "/etc/passwd":
        return "passwd"
    if path == "/etc/sudoers" or (path.startswith("/etc/sudoers.d/") and len(path) > len("/etc/sudoers.d/")):
        return "sudoers"
    m = SSH_KEY_PATH.fullmatch(path)
    if m is not None and not m.group(1).endswith(".pub") and m.group(1) not in SSH_NOT_PRIVATE:
        return "ssh_private_key"
    return None


def entry_for(detection, category=None):
    """(technique id, confidence) for a detection and/or its category or command (it is None only if the key is unknown)"""
    table = CATEGORY_TABLES.get(detection)
    if table is not None:
        return table.get(category)
    return DETECTIONS.get(detection) if category is None else None


def technique_for(detection, category=None):
    entry = entry_for(detection, category)
    return entry[0] if entry is not None else None


def confidence_for(detection, category=None):
    entry = entry_for(detection, category)
    return entry[1] if entry is not None else None
