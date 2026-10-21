# pinentry-tmux

A small Linux/Rust proxy that runs `/usr/bin/pinentry-curses` in a separate,
explicitly targeted tmux popup. Intended to avoid pinentry corrupting an
OpenCode, Claude Code, Codex, or another full-screen application's terminal.

Independently written, informed by the design and pitfalls of
[eth-p/pinentry-tmux](https://github.com/eth-p/pinentry-tmux) and the
[tmux popup pinentry article](https://zenn.dev/ngicks/articles/pinentry-in-tmux-popup).
No source code from those projects is incorporated.

## Requirements

- Linux, tmux **3.3 or newer** (`display-popup -T`; tested: 3.4), and curses pinentry
  (tested: 1.2.1).
- Rust **1.85 or newer** to build; `rust-toolchain.toml` selects stable for
  development. One dependency:
  `libc`, pinned through `Cargo.lock`. The executable needs no Rust installation
  or Python runtime. It dynamically links the system C library.
- `just` for build recipes; Python 3 and GnuPG for tests only.
- GPG must supply `OPTION ttyname` naming the signing shell's tmux pane.
  See the guarded `GPG_TTY` setup below.
- Exactly **one non-control client** must be attached across the sessions
  containing that pane. Ambiguous or detached sessions fail closed.

## Build, test, install

```sh
just test
just test-real
just install
```

The real tests create a **disposable** passphrase-protected signing key, a
separate GPG home/agent, an isolated tmux server, and a pseudo-terminal client.
They verify signing, cached signing without another prompt, Ctrl+C cancellation,
and client disconnects. They do not use your existing keys, agent, or tmux server.
Test-only key passphrases are deliberately public dummy data.

`just install` installs `~/.local/bin/pinentry-tmux` and does **not** change
GPG configuration. To install elsewhere: `just install /absolute/destination`.

After testing, manually replace the existing `pinentry-program` directive in
`~/.gnupg/gpg-agent.conf` with your absolute installed path (replace the
placeholder below):

```conf
pinentry-program /absolute/path/to/pinentry-tmux
```

Then run `gpgconf --reload gpg-agent`. Keep a copy of your old directive so you
can restore it and reload the agent to revert. Do not add multiple directives.

**This is a tmux-only pinentry.** Because the agent configuration is global,
uncached operations outside tmux will also fail. It never automatically falls
back to drawing on another terminal or silently skips commit signing.

### Set GPG_TTY only when a terminal is available

In Bash or Zsh shell configuration:

```sh
if [ -t 0 ]; then
    export GPG_TTY="$(tty)"
fi
```

In fish:

```fish
if isatty stdin
    set -gx GPG_TTY (tty)
end
```

Do not run the assignment unconditionally: a non-interactive subshell can
re-source the configuration and overwrite a valid inherited value with
`not a tty`.

For a coding agent's background service, verify that **its GPG request** supplies
the correct `GPG_TTY`. Guarding shell configuration prevents clobbering an
inherited value; it does not repair a missing or stale value in an already-running
service. The wrapper does not guess the terminal. Real GPG tests are not proof of
end-to-end behavior in every coding agent's service setup.

### Options / non-default tmux server

```text
--backend /absolute/path       default: /usr/bin/pinentry-curses
--tmux-program /absolute/path  default: /usr/bin/tmux
--tmux-socket /absolute/path   default: tmux's default server socket
--session-timeout SECONDS      default: 300, allowed: 1..3600
```

`gpg-agent.conf`'s `pinentry-program` accepts a path, not a shell command. If you
need options (for example `tmux -L work` or `tmux -S ...`), point it at a small
launcher containing an `exec` of the installed binary with the appropriate
`--tmux-socket /absolute/server/socket` argument. Run
`tmux display-message -p '#{socket_path}'` inside your tmux session to obtain it.
The wrapper deliberately does not trust an inherited, potentially stale `TMUX`
variable from a long-running GPG agent.

Tmux queries run with a cleared environment, so default socket lookup uses
tmux's standard directory and ignores `TMUX_TMPDIR`. For a server using a custom
socket directory, supply `--tmux-socket` explicitly as described above.

### Unsupported popup setups

- Signing from a shell inside another tmux popup is unsupported: its terminal
  is not listed by `list-panes`, so routing fails.
- tmux permits only one popup per client. If a popup is already open on the
  selected client, the pinentry popup cannot be opened there.

These situations fail closed instead of falling back to the original terminal.

### Failure diagnostics

Wrapper errors include a static reason in the Assuan `ERR` reply; timeouts use
the timeout error code rather than cancellation. These details are useful when
running the protocol by hand or inspecting agent debug output, but **gpg may
display only the error code's generic description**, such as "Operation
cancelled", instead of the reason. A daemonized agent may also discard the
wrapper's stderr. There is currently no persistent failure log option.
Avoid sharing agent debug logs without reviewing and redacting sensitive data.

## Design and security boundaries

1. Start the fixed curses backend on anonymous stdin/stdout pipes, initially
   pointing at `/dev/null` so it cannot draw on the original terminal.
2. Relay Assuan commands/replies and bidirectional inquiries. Intercept terminal
   routing options, including Assuan's optional `--`/`=` syntax and command
   case-insensitivity. Reject Emacs redirection. No protocol debugging/logging.
3. On the first GETPIN, CONFIRM, or MESSAGE, locate the original tty's pane and
   its unique attached client. Explicitly target both client and pane.
4. Create a private mode-0700 directory under `/tmp` (`TMPDIR` is ignored) holding
   a mode-0600 Unix socket. A fixed, short base avoids depending on the agent's
   inherited environment and keeps socket paths short. The popup helper exchanges
   **only terminal metadata** over it, never passphrases. Both ends check Linux
   peer credentials: the same user on each side, and the helper also requires its
   connection to be with the proxy process that launched the popup.
5. Direct curses to the popup terminal. Passphrase replies stay on anonymous
   pipes between backend, proxy, and agent: not disk, argv, environment, or
   the tmux control channel. Obviously, curses display/input uses tmux itself.
6. Bound setup to 10 seconds and the whole session to 300 seconds by default.
   Cancellation, signals, pipe EOF, and popup disconnects stop the session.
   Kill/reap the backend before releasing the popup, avoiding late terminal
   writes. Linux parent-death signalling also kills the backend if the proxy
   is forcibly killed.

The wrapper forwards no bulk environment to tmux command arguments. Child
commands get a minimal environment (`PATH`, `LANG`, and `HOME`); the popup helper
itself starts with tmux's normal session environment. Locale configuration from
GPG is relayed to curses. Executable paths must be absolute. No shell is used
to construct the popup command.

Core dumps are disabled; Linux dumpability is disabled in the proxy/helper;
fixed protocol buffers are wiped with volatile writes before reuse and drop.
**These are mitigations, not secure-memory guarantees:** buffers are not locked
against swap, and the compiler/OS may retain copies. Root, a compromised account,
an untrusted backend, a compromised tmux server, or another client with access to
the session remain outside the protection boundary. Anyone sharing a tmux
session can potentially observe keystrokes; do not share sessions used for
passphrase entry. SIGKILL can leave an empty/private metadata socket directory;
normal shutdown and handled signals remove it. No passphrases are stored there.

This is new code with automated tests, **not a security-audited replacement for
GnuPG/pinentry**. Verify it with disposable credentials before using real ones.
