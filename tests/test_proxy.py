"""Protocol/lifecycle tests with fake pinentry and an isolated fake tmux.

Run: python3 -m unittest discover -s tests -v
Build first with cargo build. PINENTRY_TMUX_BINARY can select a release binary.
"""
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("PINENTRY_TMUX_BINARY", ROOT / "target/debug/pinentry-tmux")).resolve()


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="proxy-test-", dir="/tmp/opencode")
        self.directory = Path(self.temp.name)
        self.master, self.slave = pty.openpty()
        self.tty = os.ttyname(self.slave)
        for name in ["fake_tmux.py", "fake_pinentry.py"]:
            shutil.copyfile(ROOT / "tests" / name, self.directory / name)
            (self.directory / name).chmod(0o700)
        self.process = None

    def tearDown(self):
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
            self.process.communicate(timeout=3)
        os.close(self.master)
        os.close(self.slave)
        self.temp.cleanup()

    def start(self, timeout=4, **scenario):
        (self.directory / "scenario.json").write_text(json.dumps({"tty": self.tty, **scenario}))
        env = {**os.environ, "TEST_ENV_SECRET": "do-not-forward-this"}
        self.process = subprocess.Popen(
            [str(BINARY), "--backend", str(self.directory / "fake_pinentry.py"),
             "--tmux-program", str(self.directory / "fake_tmux.py"),
             "--session-timeout", str(timeout)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
            bufsize=0)
        self.assertEqual(self.line(), b"OK dummy pinentry\n")

    def line(self):
        value = bytearray()
        deadline = time.monotonic() + 12
        while not value.endswith(b"\n"):
            ready, _, _ = select.select([self.process.stdout], [], [], max(0, deadline - time.monotonic()))
            self.assertTrue(ready, "wrapper did not respond")
            chunk = os.read(self.process.stdout.fileno(), 1)
            if not chunk:
                break
            value.extend(chunk)
        return bytes(value)

    def send(self, line):
        self.process.stdin.write(line)

    def setup_tty(self):
        self.send(f"OPTION ttyname={self.tty}\n".encode())
        self.assertEqual(self.line(), b"OK\n")

    def finish(self):
        self.send(b"BYE\n")
        self.assertEqual(self.line(), b"OK\n")
        stdout, stderr = self.process.communicate(timeout=3)
        self.assertEqual(self.process.returncode, 0, stderr)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"")
        args_file = self.directory / "popup-args.json"
        if args_file.exists():
            args = json.loads(args_file.read_text())
            socket = Path(args[args.index("--popup") + 1])
            self.assertFalse(socket.parent.exists(), "leaked private socket directory")

    def test_success_and_explicit_targeting(self):
        self.start()
        self.setup_tty()
        self.send(b"OPTION ttytype=evil-terminal\n")
        self.assertEqual(self.line(), b"OK\n")
        self.send(b"SETDESC example\n")
        self.assertEqual(self.line(), b"OK\n")
        self.send(b"GETPIN\n")
        self.assertEqual(self.line(), b"D dummy%25secret\n")
        self.assertEqual(self.line(), b"OK\n")
        args = json.loads((self.directory / "popup-args.json").read_text())
        self.assertEqual(args[args.index("-c") + 1], "/dev/pts/999")
        self.assertEqual(args[args.index("-t") + 1], "%1")
        self.assertNotIn("do-not-forward-this", str(args))
        self.finish()

    def test_inquiries_are_forwarded_bidirectionally(self):
        self.start(inquire=True)
        self.setup_tty()
        self.send(b"GETPIN\n")
        self.assertEqual(self.line(), b"INQUIRE QUALITY dummy%25secret\n")
        self.send(b"D 100\nEND\n")
        self.assertEqual(self.line(), b"D dummy%25secret\n")
        self.assertEqual(self.line(), b"OK\n")
        self.finish()

    def test_backend_cancellation_is_preserved(self):
        self.start(cancel=True)
        self.setup_tty()
        self.send(b"GETPIN\n")
        self.assertEqual(self.line(), b"ERR 83886179 cancelled\n")
        self.finish()

    def test_inquiry_error_terminates_inquiry(self):
        self.start(inquire=True)
        self.setup_tty()
        self.send(b"GETPIN\n")
        self.assertEqual(self.line(), b"INQUIRE QUALITY dummy%25secret\n")
        self.send(b"ERR 83886179 cancelled\n")
        self.assertEqual(self.line(), b"D dummy%25secret\n")
        self.assertEqual(self.line(), b"OK\n")
        self.finish()

    def test_assuan_option_syntax_and_lowercase_commands(self):
        self.start()
        self.send(b"# ignored comment\n\n")
        self.send(f"option\t --ttyname = {self.tty} \n".encode())
        self.assertEqual(self.line(), b"OK\n")
        self.send(b"option --ttytype ignored\n")
        self.assertEqual(self.line(), b"OK\n")
        self.send(b"getpin\n")
        self.assertEqual(self.line(), b"D dummy%25secret\n")
        self.assertEqual(self.line(), b"OK\n")
        self.finish()

    def test_repeated_prompts_reuse_popup(self):
        self.start()
        self.setup_tty()
        for _ in range(2):
            self.send(b"GETPIN\n")
            self.assertEqual(self.line(), b"D dummy%25secret\n")
            self.assertEqual(self.line(), b"OK\n")
        self.finish()

    def test_retargeting_active_popup_is_rejected(self):
        self.start()
        self.setup_tty()
        self.send(b"GETPIN\n")
        self.assertEqual(self.line(), b"D dummy%25secret\n")
        self.assertEqual(self.line(), b"OK\n")
        self.send(f"option --ttyname {self.tty}\n".encode())
        self.assertTrue(self.line().startswith(b"ERR "))
        self.process.communicate(timeout=2)
        self.assertEqual(self.process.returncode, 1)

    def test_embedded_nul_is_rejected(self):
        self.start()
        self.send(b"GETPIN\x00hidden\n")
        self.assertTrue(self.line().startswith(b"ERR "))
        self.process.communicate(timeout=2)
        self.assertEqual(self.process.returncode, 1)

    def test_socket_permissions_and_metadata_only_arguments(self):
        self.start(stall=True)
        self.setup_tty()
        self.send(b"GETPIN\n")
        args_file = self.directory / "popup-args.json"
        deadline = time.monotonic() + 2
        while not args_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        args = json.loads(args_file.read_text())
        socket = Path(args[args.index("--popup") + 1])
        self.assertEqual(socket.stat().st_mode & 0o777, 0o600)
        self.assertEqual(socket.parent.stat().st_mode & 0o777, 0o700)
        self.assertNotIn("dummy", str(args))
        self.process.terminate()
        self.process.communicate(timeout=2)
        self.assertFalse(socket.parent.exists())

    def test_popup_that_never_connects_times_out(self):
        self.start(timeout=1, no_connect=True)
        self.setup_tty()
        self.send(b"GETPIN\n")
        self.assertTrue(self.line().startswith(b"ERR "))
        self.process.communicate(timeout=2)
        self.assertEqual(self.process.returncode, 1)

    def test_confirmation_and_message_open_a_popup(self):
        self.start()
        self.setup_tty()
        self.send(b"CONFIRM --one-button\n")
        self.assertEqual(self.line(), b"OK\n")
        self.assertTrue((self.directory / "popup-args.json").exists())
        self.send(b"MESSAGE\n")
        self.assertEqual(self.line(), b"OK\n")
        self.finish()

    def test_unknown_commands_are_not_falsely_acknowledged(self):
        self.start()
        self.send(b"UNSUPPORTED\n")
        self.assertTrue(self.line().startswith(b"ERR "))
        self.finish()

    def test_no_terminal_fails_without_popup(self):
        self.start()
        self.send(b"GETPIN\n")
        self.assertTrue(self.line().startswith(b"ERR "))
        self.process.communicate(timeout=2)
        self.assertEqual(self.process.returncode, 1)
        self.assertFalse((self.directory / "popup-args.json").exists())

    def test_multiple_clients_fail_closed(self):
        self.start(ambiguous=True)
        self.setup_tty()
        self.send(b"GETPIN\n")
        self.assertTrue(self.line().startswith(b"ERR "))
        self.process.communicate(timeout=2)
        self.assertFalse((self.directory / "popup-args.json").exists())

    def test_failed_popup_is_bounded(self):
        self.start(timeout=2, fail=True)
        self.setup_tty()
        self.send(b"GETPIN\n")
        self.assertTrue(self.line().startswith(b"ERR "))
        self.process.communicate(timeout=3)
        self.assertEqual(self.process.returncode, 1)

    def test_backend_stall_times_out(self):
        self.start(timeout=2, stall=True)
        self.setup_tty()
        self.send(b"GETPIN\n")
        self.assertTrue(self.line().startswith(b"ERR "))
        self.process.communicate(timeout=3)
        self.assertEqual(self.process.returncode, 1)

    def test_popup_disconnect_cancels_backend(self):
        self.start(close=True, stall=True)
        self.setup_tty()
        self.send(b"GETPIN\n")
        self.assertTrue(self.line().startswith(b"ERR "))
        self.process.communicate(timeout=2)
        self.assertEqual(self.process.returncode, 1)

    def test_signal_terminates_blocked_session(self):
        self.start(stall=True)
        self.setup_tty()
        self.send(b"GETPIN\n")
        time.sleep(0.3)
        self.process.send_signal(signal.SIGTERM)
        self.process.communicate(timeout=2)
        self.assertEqual(self.process.returncode, 1)

    def test_agent_eof_terminates_blocked_backend(self):
        self.start(stall=True)
        self.setup_tty()
        self.send(b"GETPIN\n")
        time.sleep(0.3)
        self.process.stdin.close()
        self.process.stdin = None
        self.process.communicate(timeout=2)
        self.assertEqual(self.process.returncode, 1)

    def test_oversized_line_fails(self):
        self.start()
        self.send(b"X" * (16 * 1024 + 1) + b"\n")
        self.assertTrue(self.line().startswith(b"ERR "))
        self.process.communicate(timeout=2)
        self.assertEqual(self.process.returncode, 1)


if __name__ == "__main__":
    unittest.main()
