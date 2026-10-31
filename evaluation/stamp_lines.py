#!/usr/bin/env python3
"""
read lines from standard input with unbuffered reads and write each one to a file as monotonic time in ns, a tab, and the line
Usage: stamp_lines.py OUTPUT (harness starts it on the standard output of the runner)
"""
import os
import signal
import sys
import time


def stamp(read, out, clock=time.monotonic_ns):
    """
    stamp every line with clock value taken when the read that completed it returned and also return the number of lines written
    lines that arrive in one read share a stamp and a last line without a newline is stamped when the input ends
    """
    pending = b""
    count = 0
    while True:
        chunk = read()
        if not chunk:
            break
        now = clock()
        pending += chunk
        while b"\n" in pending:
            line, pending = pending.split(b"\n", 1)
            out.write(b"%d\t%s\n" % (now, line))
            count += 1
        out.flush()
    if pending:
        out.write(b"%d\t%s\n" % (clock(), pending))
        count += 1
    out.flush()
    return count


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: stamp_lines.py OUTPUT", file=sys.stderr)
        return 2
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    with open(argv[0], "wb") as out:
        stamp(lambda: os.read(0, 65536), out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
