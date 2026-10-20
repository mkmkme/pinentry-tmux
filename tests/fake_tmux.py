#!/usr/bin/python3
"""Test double: only terminal metadata goes through this process."""
import json
import os
from pathlib import Path
import pty
import subprocess
import sys
import time

config = json.loads(Path(__file__).with_name("scenario.json").read_text())
args = sys.argv[1:]
socket = None
if args[:1] == ["-S"]:
    socket = args[1]
    args = args[2:]
assert socket == config.get("expected_socket"), "incorrect tmux server socket"
if args[0] == "list-panes":
    print(f"{config['tty']}\t%1\t$1")
elif args[0] == "list-clients":
    print("/dev/pts/999\t$1\t0")
    if config.get("ambiguous"):
        print("/dev/pts/998\t$1\t0")
elif args[0] == "display-popup":
    Path(__file__).with_name("popup-args.json").write_text(json.dumps(args))
    # Secrets/environment tokens must not have been forwarded by the wrapper.
    assert "TEST_ENV_SECRET" not in os.environ
    if config.get("fail"):
        sys.exit(1)
    if config.get("no_connect"):
        time.sleep(30)
        sys.exit(1)
    master, slave = pty.openpty()
    i = args.index("--popup")
    child = subprocess.Popen(args[i - 1:], stdin=slave, stdout=slave, stderr=slave,
                             env={"TERM": "xterm-256color", "PATH": "/usr/bin:/bin"})
    os.close(slave)
    try:
        if config.get("close"):
            time.sleep(0.3)
            child.terminate()
        child.wait(timeout=35)
    finally:
        child.kill() if child.poll() is None else None
        child.wait()
        os.close(master)
else:
    sys.exit(1)
