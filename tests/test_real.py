"""Opt-in tests against real tmux, curses pinentry, and a disposable GPG key.

PINENTRY_TMUX_REAL_TESTS=1 python3 -m unittest discover -s tests -p test_real.py -v
No real user keyring, agent, tmux server, or GPG configuration is touched.
"""
import fcntl
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import struct
import subprocess
import tempfile
import termios
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("PINENTRY_TMUX_BINARY", ROOT / "target/debug/pinentry-tmux")).resolve()


@unittest.skipUnless(os.environ.get("PINENTRY_TMUX_REAL_TESTS") == "1", "opt-in real GPG/tmux test")
class RealTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pe-real-")
        self.directory = Path(self.temp.name)
        self.home = self.directory / "gnupg"
        self.home.mkdir(mode=0o700)
        self.socket = self.directory / "tmux"
        self.env = {**os.environ, "GNUPGHOME": str(self.home), "TERM": "xterm-256color"}
        self.env.pop("TMUX", None)
        self.env.pop("GPG_TTY", None)
        self.client = None
        self.rendered = bytearray()
        self.master = None
        self.slave = None
        self.addCleanup(self.cleanup)
        launcher = self.directory / "pinentry"
        launcher.write_text("#!/bin/sh\nexec " + shlex.join([
            str(BINARY), "--tmux-socket", str(self.socket), "--session-timeout", "20"
        ]) + ' "$@"\n')
        launcher.chmod(0o700)
        (self.home / "gpg-agent.conf").write_text(f"pinentry-program {launcher}\n")
        self.gpg("--batch", "--pinentry-mode", "loopback", "--passphrase", "disposable-test-only",
                 "--quick-generate-key", "Popup Test <popup@example.invalid>", "ed25519", "sign", "1d")
        (self.directory / "input").write_text("isolated popup signing test\n")
        self.tmux("new-session", "-d", "-s", "test", "-x", "100", "-y", "35", "/bin/bash --noprofile --norc")
        self.pane = self.tmux("list-panes", "-t", "test", "-F", "#{pane_id}").stdout.strip()
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 35, 100, 0, 0))

        def controlling_terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.client = subprocess.Popen(
            ["/usr/bin/tmux", "-S", str(self.socket), "attach-session", "-t", "test"],
            stdin=self.slave, stdout=self.slave, stderr=self.slave, env=self.env,
            preexec_fn=controlling_terminal)
        self.until(lambda: self.tmux("list-clients", "-F", "#{client_name}").stdout.strip())
        self.gpgconf("--kill", "gpg-agent")  # discard the key-generation cache

    def cleanup(self):
        subprocess.run(["/usr/bin/tmux", "-S", str(self.socket), "kill-server"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self.client:
            if self.client.poll() is None:
                self.client.terminate()
            self.client.wait(timeout=3)
        for fd in [self.master, self.slave]:
            if fd is not None:
                os.close(fd)
        self.gpgconf("--kill", "all")
        self.temp.cleanup()

    def tmux(self, *args):
        return subprocess.run(["/usr/bin/tmux", "-f", "/dev/null", "-S", str(self.socket), *args], env=self.env,
                              capture_output=True, text=True, check=True, timeout=5)

    def gpg(self, *args):
        return subprocess.run(["/usr/bin/gpg", "--homedir", str(self.home), *args], env=self.env,
                              capture_output=True, check=True, timeout=20)

    def gpgconf(self, *args):
        return subprocess.run(["/usr/bin/gpgconf", "--homedir", str(self.home), *args],
                              env=self.env, capture_output=True, check=True, timeout=5)

    def until(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = predicate()
            if result:
                return result
            # Drain the pseudo terminal to avoid backpressure on tmux rendering.
            ready, _, _ = select.select([self.master], [], [], 0.05)
            if ready:
                try:
                    self.rendered.extend(os.read(self.master, 65536))
                except OSError:
                    pass
        self.fail("timed out waiting for isolated tmux/GPG test")

    def start_sign(self, name):
        self.rendered.clear()
        output = self.directory / (name + ".asc")
        status = self.directory / (name + ".status")
        log = self.directory / (name + ".log")
        command = "export GPG_TTY=$(tty); " + shlex.join([
            "/usr/bin/gpg", "--homedir", str(self.home), "--yes", "--clearsign",
            "--output", str(output), str(self.directory / "input")
        ]) + f" 2>{shlex.quote(str(log))}; echo $? >{shlex.quote(str(status))}"
        self.tmux("send-keys", "-t", self.pane, "-l", command)
        self.tmux("send-keys", "-t", self.pane, "Enter")
        return output, status, log

    def wait_prompt(self):
        # Read actual rendered output rather than sleeping and potentially
        # sending a dummy passphrase into the underlying shell.
        self.until(lambda: b"Passphrase:" in self.rendered)

    def test_real_signing_and_cached_retry(self):
        output, status, log = self.start_sign("signed")
        self.wait_prompt()
        os.write(self.master, b"disposable-test-only\r")
        self.until(status.exists)
        self.assertEqual(status.read_text().strip(), "0", log.read_text())
        self.gpg("--verify", str(output))
        output2, status2, log2 = self.start_sign("cached")
        self.until(status2.exists)
        self.assertEqual(status2.read_text().strip(), "0", log2.read_text())
        self.gpg("--verify", str(output2))
        self.assertTrue(self.tmux("list-clients").stdout.strip())

    def test_real_pinentry_cancellation(self):
        _, status, log = self.start_sign("cancelled")
        self.wait_prompt()
        os.write(self.master, b"\x03")  # Ctrl+C cancels pinentry/the popup helper.
        self.until(status.exists)
        self.assertNotEqual(status.read_text().strip(), "0", log.read_text())
        # A subsequent command must still execute in the original pane.
        restored = self.directory / "restored"
        self.tmux("send-keys", "-t", self.pane, "-l", f"touch {shlex.quote(str(restored))}")
        self.tmux("send-keys", "-t", self.pane, "Enter")
        self.until(restored.exists)

    def test_real_tmux_client_disconnect(self):
        _, status, _ = self.start_sign("disconnected")
        self.wait_prompt()
        self.client.send_signal(signal.SIGHUP)
        self.client.wait(timeout=3)
        self.until(status.exists)
        self.assertNotEqual(status.read_text().strip(), "0")


if __name__ == "__main__":
    unittest.main()
