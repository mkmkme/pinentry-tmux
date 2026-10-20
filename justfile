set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Build the optimized executable with the selected stable toolchain.
build:
    cargo build --locked --release

# Formatting, linting, and unit tests.
check:
    cargo fmt --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked

# Protocol and lifecycle tests; no actual GPG keys or tmux clients are used.
test: check
    cargo build --locked
    python3 -m unittest discover -s tests -p test_proxy.py -v

# Disposable GPG key + isolated tmux server, including real curses input.
test-real: build
    PINENTRY_TMUX_BINARY="{{justfile_directory()}}/target/release/pinentry-tmux" PINENTRY_TMUX_REAL_TESTS=1 python3 -m unittest discover -s tests -p test_real.py -v

# Installs the executable only. Does NOT edit or reload your GPG configuration.
install destination=(env_var("HOME") + "/.local/bin/pinentry-tmux"): build
    install -D -m 0755 -- target/release/pinentry-tmux "{{destination}}"
