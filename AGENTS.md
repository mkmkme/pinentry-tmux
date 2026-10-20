# Working on pinentry-tmux

Read `README.md` for architecture, setup, requirements, supported configurations,
and security boundaries. This file covers maintenance rules, not user setup.

## Approval and scope

- **Before every commit, show the exact subject and body and wait for explicit
  approval.** A request to implement or commit is not approval of an unseen
  message. Approval of several shown messages covers only those commits.
- Keep one concern per commit, with directly relevant tests. Separate behaviour
  changes, refactoring, and unrelated cleanups. Separate subject/body with a blank
  line and wrap body prose at about 72 columns without splitting URLs or code.
- Commit locally only; never push or open PRs. Ask before amending or rewriting
  history. Preserve unrelated user changes.
- **Ask before installing/reinstalling**, changing shell/GPG configuration, or
  touching live keys, agents, or tmux sessions, except for normal signing of an
  approved commit. Building/testing is not installation approval.
- Leave commit signing enabled. Approved commits may use the installed
  pinentry-tmux; if signing fails, report it rather than bypassing signing.

## Project map and compatibility

- `src/main.rs`: proxy, CLI, polling, child cleanup, popup helper, Rust unit tests.
- `tests/test_proxy.py`: protocol/lifecycle tests; `fake_pinentry.py` returns dummy
  data and `fake_tmux.py` checks routing and explicit socket arguments.
- `tests/test_real.py`: isolated tmux/GPG tests with disposable keys and a public
  test-only passphrase. Python is test-only, not a runtime dependency.
- `justfile`: build/test/install recipes. `Cargo.toml` and `Cargo.lock`: minimum
  Rust and locked dependencies. `rust-toolchain.toml`: stable for development.
- Preserve Rust 1.85 / edition 2024 and Linux ARM64 compatibility. Use
  `libc::c_char` for C character buffers; its signedness varies by platform.
- Do not use tmux features newer than 3.3 without updating the README requirement.
- Release settings (`panic = "abort"`, LTO, stripping, `codegen-units = 1`) are
  deliberate. Release panics skip Rust cleanup, leaving directories and unwiped
  buffers; the parent-death signal still kills the backend. Debug tests do not
  expose this abort behaviour. Return `Err` for operational failures.

## Routing, protocol, and security

- Preserve the README's routing, IPC, and security checks. Fail closed; do not add
  fallbacks or heuristics such as inherited `TMUX` or the most recent client to
  compensate for missing `GPG_TTY`.
- The popup helper is this same executable, invoked as
  `--popup <socket> <proxy-pid> <timeout>`. Change both sides together.
- Relayed backend replies to agent commands, including `ERR`, pass through
  unchanged. The proxy itself answers `OPTION ttyname`/`ttytype`/`display` with
  `OK` and rejects `allow-emacs-prompt`; an invalid `ttyname` or one sent after
  the popup opens ends the session. Replies to its own backend
  `OPTION ttyname`/`ttytype` setup are consumed; failures become fixed messages.
- Preserve command case-insensitivity and supported OPTION syntax (optional
  `--`, whitespace, `=`); option keys are case-sensitive. Inquiry replies end with
  END or CAN.
- Keep the four user configuration options (`--backend`, `--tmux-program`,
  `--tmux-socket`, `--session-timeout`) aligned in `Config::parse`, `--help`, and
  the README's options/timeouts. GPG compatibility arguments are `--ttyname`
  (validated; sets the original terminal) and the ignored `--display`, `--ttytype`,
  `--lc-ctype`, and `--lc-messages`. Informational `--help`/`--version` are handled
  separately in `main`.
- Error lines are an interface; update affected tests when changing wording.
  Keep errors `&'static str`. In protocol mode, text equal to `SESSION_TIMEOUT`
  gets the timeout code; other failures get cancellation. `STARTUP_REJECTED`
  suppresses a second reply because the backend's greeting error was relayed.
  Failures before the backend greeting send the wrapper's own `ERR` instead;
  emit only one greeting result. Intercepted options can have their own format/code.
- In protocol mode, fd 1 is exclusively Assuan replies; static-text diagnostics
  go to stderr. `--help` and `--version` print ordinary stdout outside that mode.
  Helper failures write only to stderr; their stdout is the popup terminal.
- New request-path reads/writes must use `Line::read` / `write_bytes` and their
  deadline-aware `poll_ready` machinery. Pass the relevant watched descriptors:
  agent stdin and the popup connection when present. Preserve line limits and
  detection of EOF, popup closure, signals, and deadlines.
- `--session-timeout` is one deadline for the whole session, not per prompt.
  Target lookup and helper handshake have a 10-second cap within it; subsequent
  backend terminal setup uses the session deadline. Polls use at most 100 ms slices.
- Kill/reap curses before releasing the popup. Field drop order in `Session` and
  `Popup`, plus parent-death signalling, is intentional. Never change a terminal's
  descriptor flags: O_NONBLOCK is shared with the shell and normal-exit restoration
  cannot cover SIGKILL or aborting panics.
- Preserve buffer wiping and core-dump mitigations; do not claim secure memory or
  a security audit. Do not add logging without approval; any log must exclude
  protocol data, passphrases, and inquiry payloads.

## Verification

```sh
just build       # release executable; does not install
just check       # formatting, clippy with warnings denied, Rust unit tests
just test        # check + debug build + proxy tests
just test-real   # release build + isolated real tmux/GPG tests
git diff --check
```

Run `just test` for code/test changes, plus `just test-real` for protocol, routing,
cleanup, or popup changes. Reproduce application bugs before fixing when feasible
and verify afterward. Avoid duplicate coverage unless it exercises another
boundary. For documentation-only changes, inspect the diff; do not claim tests
were run when they were not.

For individual tests (build the debug binary before running proxy tests):

```sh
cargo test --locked <name>
python3 -m unittest discover -s tests -p test_proxy.py -k <name> -v
```

Python suites accept `PINENTRY_TMUX_BINARY`. Real tests additionally need
`PINENTRY_TMUX_REAL_TESTS=1`; **`just test-real`** supplies both. They require
`/usr/bin/tmux`, `/usr/bin/gpg`, `/usr/bin/gpgconf`, `/usr/bin/pinentry-curses`,
`/usr/bin/gpg-agent`, `/bin/bash`, and pseudo-terminals. Rust unit and proxy tests
also open PTYs; proxy tests need `/usr/bin/python3` and writable `/tmp`. For every
suite, report unavailable tools, unwritable paths, or sandbox-blocked PTYs as
blocked/unverified, not code bugs. Never substitute real keyrings or live services.

For compatibility-sensitive changes, with Rust 1.85.0 and its ARM64 target
installed, also run:

```sh
cargo +1.85.0 test --locked
cargo +1.85.0 check --locked --tests --target aarch64-unknown-linux-gnu
```

Report missing prerequisites. Cross-checking is not ARM64 execution/link testing.

## Style, privacy, and handoff

- Follow rustfmt's default 100-column width; split long strings (for example with
  `concat!`) without changing their output.
- Use generic examples, never personal home paths, usernames, or hostnames.
- Use Python's `tempfile` for tests and keep Unix socket paths short.
- Summarize changes, checks actually run, limitations, and commit status concisely.
  Report blockers before proposing a commit.
