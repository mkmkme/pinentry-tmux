#!/usr/bin/python3
"""Dummy Assuan peer; no real keys or secrets are used."""
import json
import os
from pathlib import Path
import sys
import time

scenario = json.loads(Path(__file__).with_name("scenario.json").read_text())
assert "TEST_ENV_SECRET" not in os.environ
tty = None
print("OK dummy pinentry", flush=True)
for raw in sys.stdin.buffer:
    line = raw.rstrip(b"\r\n")
    keyword, separator, rest = line.partition(b" ")
    line = keyword.upper() + separator + rest
    if line.startswith(b"OPTION ttyname="):
        tty = line.split(b"=", 1)[1].decode()
    if line == b"GETPIN":
        assert tty and tty != scenario["tty"] and tty.startswith("/dev/pts/")
        if scenario.get("stall"):
            time.sleep(30)
        if scenario.get("inquire"):
            print("INQUIRE QUALITY dummy%25secret", flush=True)
            first = sys.stdin.buffer.readline()
            if not first.startswith((b"CAN", b"ERR", b"END")):
                assert first == b"D 100\n"
                assert sys.stdin.buffer.readline() == b"END\n"
        if scenario.get("cancel"):
            print("ERR 83886179 cancelled", flush=True)
            continue
        print("D dummy%25secret", flush=True)
    elif line == b"GETINFO flavor":
        print("D curses", flush=True)
    elif line.startswith(b"UNSUPPORTED"):
        print("ERR 83886275 unknown command", flush=True)
        continue
    print("OK", flush=True)
    if line == b"BYE":
        break
