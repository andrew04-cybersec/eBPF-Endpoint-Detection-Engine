"""scenario files for the evaluation harness; loading, validation, the script lint and the label hashes (standard library only)"""
import hashlib
import json
import os
import re
import shlex
import sys

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(EVAL_DIR)
sys.path.insert(0, os.path.join(ROOT, "detections"))
import attack_map  # noqa: E402

DETECTION_NAMES = tuple(sorted(set(attack_map.DETECTIONS) | set(attack_map.CATEGORY_TABLES)))

REQUIRED = ("id", "title", "kind", "technique", "threat_model", "phase", "marker", "expected", "acceptable",
            "timeout_seconds", "known_gap", "notes")
OPTIONAL = ("requires", "tmp_staging")
KINDS = ("attack", "benign")
PHASES = ("after_loader", "before_loader")
ID_PATTERN = re.compile(r"[A-Za-z0-9_]+")
MARKER_PATTERN = re.compile(r"EVT_EVAL_[A-Z0-9_]+")
SCRIPTS = ("setup", "action", "teardown")

WORK_PREFIX = "/opt/evt_eval_"
TMP_PREFIX = "/tmp/evt_eval_"


def scenario_env(sid):
    """the environment every script of scenario gets; its own work directory under /opt and own staging directory under /tmp"""
    return {"EVT_EVAL_ID": sid, "EVT_EVAL_WORK": WORK_PREFIX + sid.lower(), "EVT_EVAL_TMP": TMP_PREFIX + sid.lower()}


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    with open(path, "rb") as f:
        return sha256_bytes(f.read())


def set_hash(hashes):
    text = "".join("%s:%s\n" % (sid, hashes[sid]) for sid in sorted(hashes))
    return sha256_bytes(text.encode("ascii"))


PROTECTED = re.compile(r"/(etc|usr|bin|lib|lib64|sbin|root|home)(/|$)")
FAKE_HOME = re.compile(r"/(home|root)/evt_eval_")
BARE_COMMANDS = ("sudo", "su", "pkexec", "doas", "systemctl", "crontab", "shutdown", "reboot", "poweroff", "halt",
                 "iptables", "ip6tables", "nft", "mkfs", "mkfs.ext4", "mkfs.ext3", "mkfs.xfs", "mkfs.vfat", "mkfs.btrfs")
BARE_PATTERN = re.compile(r"(?<![\w./$-])(%s)(?![\w./-])" % "|".join(re.escape(c) for c in BARE_COMMANDS))
WRITE_ALL = ("tee", "touch", "mkdir", "rmdir", "chmod", "chown", "truncate", "rm", "mkfifo", "mknod", "mv")
WRITE_LAST = ("cp", "ln", "install")
OPERATORS = (";", "&&", "||", "|", "&", "(", ")")
WORK_VAR = re.compile(r"\$\{?EVT_EVAL_(WORK|TMP)\}?(/.*)?")


def strip_comment(line):
    return re.sub(r"(^|\s)#.*$", "", line)


def tokens_of(line):
    lex = shlex.shlex(line, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError:
        return line.split()


def segments(tokens):
    seg = []
    for t in tokens:
        if t in OPERATORS:
            if seg:
                yield seg
            seg = []
        else:
            seg.append(t)
    if seg:
        yield seg


def lint_script(text, allow_tmp=False):
    """list of (line number, rule) for everything in a scenario script the safety net refuses; its a safety net against mistakes and not a sandbox: a script that builds a command from pieces or also runs another file is not understood by it"""
    problems = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = strip_comment(raw)
        if not line.strip():
            continue
        for m in BARE_PATTERN.finditer(line):
            problems.append((number, "command %s is not allowed" % m.group(1)))
        if re.search(r"\bdd\b[^\n;|&]*\bof=", line):
            problems.append((number, "dd with of= is not allowed"))
        if "ld.so.preload" in line:
            problems.append((number, "/etc/ld.so.preload is not allowed"))
        for m in re.finditer(r"/tmp/\S*|/tmp(?![\w-])|\$\{?EVT_EVAL_TMP", line):
            word = m.group(0)
            if not allow_tmp:
                problems.append((number, "%s is not allowed without tmp_staging" % word))
            elif word.startswith("/tmp") and not word.startswith(TMP_PREFIX):
                problems.append((number, "%s is outside %s*" % (word, TMP_PREFIX)))
        for seg in segments(tokens_of(line)):
            name, args = os.path.basename(seg[0]), seg[1:]
            targets = [a for a in args if not a.startswith("-") and a not in (">", ">>", "<", "<<")]
            if name == "rm" and any(a.startswith("--recursive") or (a.startswith("-") and not a.startswith("--") and re.search("[rR]", a)) for a in args):
                for t in targets:
                    if not WORK_VAR.fullmatch(t):
                        problems.append((number, "rm -r of %s is outside the work directory variable" % t))
            writes = []
            if name in WRITE_ALL and name != "rm":
                writes = targets
            elif name in WRITE_LAST and targets:
                writes = targets[-1:]
            for prev, t in zip(seg, seg[1:]):
                if prev in (">", ">>") or re.fullmatch(r"\d?>>?", prev):
                    writes.append(t)
            for t in writes:
                if PROTECTED.match(t) and not FAKE_HOME.match(t):
                    problems.append((number, "write to %s is not allowed" % t))
    return problems


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def load_scenarios(directory):
    scenarios, problems = [], []
    if not os.path.isdir(directory):
        return [], ["scenario directory %s does not exist" % directory]
    for entry in sorted(os.listdir(directory)):
        folder = os.path.join(directory, entry)
        if not os.path.isdir(folder):
            continue
        path = os.path.join(folder, "scenario.json")
        if not os.path.isfile(path):
            problems.append("%s: scenario.json is missing" % entry)
            continue
        try:
            with open(path, "rb") as f:
                raw = f.read()
            sc = json.loads(raw.decode("utf-8"))
        except (ValueError, OSError) as e:
            problems.append("%s: scenario.json cannot be read (%s)" % (entry, e))
            continue
        if not isinstance(sc, dict):
            problems.append("%s: scenario.json is not an object" % entry)
            continue
        sc["_dir"] = folder
        sc["_sha256"] = sha256_bytes(raw)
        sc["_scripts"] = {k: (os.path.join(folder, k + ".sh") if os.path.isfile(os.path.join(folder, k + ".sh")) else None)
                          for k in SCRIPTS}
        scenarios.append(sc)
    scenarios.sort(key=lambda s: str(s.get("id")))
    problems += validate(scenarios)
    return scenarios, problems


def check_entries(label, name, entries, need_count):
    problems = []
    if not isinstance(entries, list):
        return ["%s: %s must be a list" % (label, name)]
    for e in entries:
        if need_count:
            if not (isinstance(e, dict) and set(e) == {"detection", "min_count"}):
                problems.append("%s: each %s entry needs exactly detection and min_count" % (label, name))
                continue
            det, count = e["detection"], e["min_count"]
            if type(count) is not int or count < 1:
                problems.append("%s: min_count of %s must be an integer of at least 1" % (label, det))
        else:
            det = e
        if det not in DETECTION_NAMES:
            problems.append("%s: unknown detection name %r in %s" % (label, det, name))
    return problems


def validate(scenarios):
    problems = []
    seen_ids, seen_markers = {}, {}
    for sc in scenarios:
        sid = sc.get("id")
        label = str(sid)
        missing = [k for k in REQUIRED if k not in sc]
        unknown = [k for k in sc if not k.startswith("_") and k not in REQUIRED and k not in OPTIONAL]
        if missing:
            problems.append("%s: missing fields %s" % (label, missing))
            continue
        if unknown:
            problems.append("%s: unknown fields %s" % (label, unknown))
        if not (isinstance(sid, str) and ID_PATTERN.fullmatch(sid)):
            problems.append("%s: id must be letters, digits and underscores" % label)
        elif os.path.basename(sc["_dir"]) != sid:
            problems.append("%s: id does not match its directory name %s" % (label, os.path.basename(sc["_dir"])))
        if sid in seen_ids:
            problems.append("%s: duplicate id" % label)
        seen_ids[sid] = True
        for k in ("title", "threat_model", "notes"):
            if not (isinstance(sc[k], str) and sc[k].strip()):
                problems.append("%s: %s must be a non-empty string" % (label, k))
        if sc["known_gap"] is not None and not isinstance(sc["known_gap"], str):
            problems.append("%s: known_gap must be a string or null" % label)
        if sc["kind"] not in KINDS:
            problems.append("%s: kind must be attack or benign" % label)
        if sc["phase"] not in PHASES:
            problems.append("%s: phase must be after_loader or before_loader" % label)
        marker = sc["marker"]
        if not (isinstance(marker, str) and MARKER_PATTERN.fullmatch(marker)):
            problems.append("%s: marker must look like EVT_EVAL_NAME" % label)
        elif marker in seen_markers:
            problems.append("%s: marker %s is also used by %s" % (label, marker, seen_markers[marker]))
        else:
            seen_markers[marker] = label
        if type(sc["timeout_seconds"]) is not int or sc["timeout_seconds"] < 1:
            problems.append("%s: timeout_seconds must be a positive integer" % label)
        if sc["kind"] == "attack":
            if sc["technique"] not in attack_map.TECHNIQUES:
                problems.append("%s: technique %r is not in the attack map" % (label, sc["technique"]))
        elif sc["kind"] == "benign" and sc["technique"] is not None:
            problems.append("%s: a benign scenario has technique null" % label)
        problems += check_entries(label, "expected", sc["expected"], True)
        problems += check_entries(label, "acceptable", sc["acceptable"], False)
        if sc["kind"] == "benign" and sc["expected"]:
            problems.append("%s: a benign scenario has an empty expected list" % label)
        if sc["kind"] == "attack" and not sc["expected"]:
            problems.append("%s: an attack scenario needs at least one expected entry" % label)
        if "requires" in sc and not (isinstance(sc["requires"], list) and all(isinstance(r, str) for r in sc["requires"])):
            problems.append("%s: requires must be a list of command names" % label)
        if "tmp_staging" in sc and type(sc["tmp_staging"]) is not bool:
            problems.append("%s: tmp_staging must be true or false" % label)
        if sc["_scripts"]["action"] is None:
            problems.append("%s: action.sh is missing" % label)
        if sc["phase"] == "before_loader" and sc["_scripts"]["setup"] is None:
            problems.append("%s: a before_loader scenario needs setup.sh" % label)
        for name, path in sc["_scripts"].items():
            if path is None:
                continue
            for number, rule in lint_script(read_text(path), allow_tmp=bool(sc.get("tmp_staging"))):
                problems.append("%s: unsafe script %s.sh line %d: %s" % (label, name, number, rule))
    ids = [sc.get("marker") for sc in scenarios if isinstance(sc.get("marker"), str)]
    for a in ids:
        for b in ids:
            if a != b and a in b:
                problems.append("marker %s is contained in marker %s, which would mix their alerts" % (a, b))
    return problems


def label_hashes(scenarios):
    per = {sc["id"]: sc["_sha256"] for sc in scenarios}
    return {"scenarios": per, "set": set_hash(per)}
