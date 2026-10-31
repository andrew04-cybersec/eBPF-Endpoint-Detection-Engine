"""resource sampler of evaluation harness in which a CPU time and memory of pipeline processes from /proc once per interval (standard library only)"""
import os
import threading
import time

SAMPLE_INTERVAL_SECONDS = 1.0
CSV_HEADER = "elapsed_ns,role,pid,utime_ticks,stime_ticks,vmrss_kb,vmhwm_kb"


def parse_stat(text):
    """(utime, stime) in clock ticks from text of /proc/<pid>/stat (or None); the command name is in brackets and may hold spaces so the fields are counted after the last closing bracket"""
    try:
        fields = text.rsplit(")", 1)[1].split()
        return int(fields[11]), int(fields[12])
    except (IndexError, ValueError):
        return None


def parse_status(text):
    found = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        if key in ("VmRSS", "VmHWM"):
            parts = rest.split()
            if parts and parts[0].isdigit():
                found[key] = int(parts[0])
    return found


class Sampler:
    """samples the given {role: pid} every interval and appends one CSV row per live process and its own cost is not subtracted from anything"""

    def __init__(self, pids, out_path, interval=SAMPLE_INTERVAL_SECONDS, clock=time.monotonic_ns, proc_root="/proc"):
        self.pids = dict(pids)
        self.interval = interval
        self.clock = clock
        self.proc_root = proc_root
        self.out = open(out_path, "w", encoding="ascii")
        self.out.write(CSV_HEADER + "\n")
        self.start_ns = clock()
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.rows = 0

    def read(self, pid, name):
        try:
            with open("%s/%d/%s" % (self.proc_root, pid, name), encoding="ascii", errors="replace") as f:
                return f.read()
        except OSError:
            return None

    def sample_once(self):
        elapsed = self.clock() - self.start_ns
        for role in sorted(self.pids):
            pid = self.pids[role]
            stat, status = self.read(pid, "stat"), self.read(pid, "status")
            ticks = parse_stat(stat) if stat is not None else None
            if ticks is None:
                continue
            mem = parse_status(status) if status is not None else {}
            self.out.write("%d,%s,%d,%d,%d,%s,%s\n" % (elapsed, role, pid, ticks[0], ticks[1],
                                                       mem.get("VmRSS", ""), mem.get("VmHWM", "")))
            self.rows += 1
        self.out.flush()

    def loop(self):
        while not self.stopping.is_set():
            self.sample_once()
            self.stopping.wait(self.interval)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stopping.set()
        if self.thread.is_alive():
            self.thread.join(timeout=5)
        self.sample_once()
        self.out.close()
