//! Linux-only, fail-closed Assuan proxy. The popup socket carries terminal
//! metadata only; pinentry's secret responses use anonymous pipes exclusively.
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, &'static str>;
const MAX_LINE: usize = 16 * 1024;
const GPG_ERR_CANCELED: u32 = 83886179;
const GPG_ERR_TIMEOUT: u32 = 83886142;
const GPG_ERR_UNKNOWN_OPTION: u32 = 83886254;
const SESSION_TIMEOUT: &str = "session timed out";
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(300);
const POPUP_SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const VALID_TIMEOUT_SECS: std::ops::RangeInclusive<u64> = 1..=3600;
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn harden() -> Result<()> {
    // Neither wrapper nor backend should leave passphrases in core dumps.
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0
            || libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0
        {
            return Err("cannot disable core dumps/process inspection");
        }
        libc::umask(0o077);
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = stop as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err("cannot install signal handler");
            }
        }
    }
    Ok(())
}

struct Config {
    backend: PathBuf,
    tmux: PathBuf,
    socket: Option<PathBuf>,
    timeout: Duration,
    original_tty: Option<String>,
}

impl Config {
    fn parse(args: &[String]) -> Result<Self> {
        let mut config = Self {
            backend: "/usr/bin/pinentry-curses".into(),
            tmux: "/usr/bin/tmux".into(),
            socket: None,
            timeout: DEFAULT_SESSION_TIMEOUT,
            original_tty: None,
        };
        let mut i = 0;
        while i < args.len() {
            let (name, inline) = args[i]
                .split_once('=')
                .map_or((args[i].as_str(), None), |(k, v)| (k, Some(v)));
            let value = match inline {
                Some(value) => value,
                None => {
                    i += 1;
                    args.get(i).ok_or("missing option value")?
                }
            };
            match name {
                "--backend" => config.backend = value.into(),
                "--tmux-program" => config.tmux = value.into(),
                "--tmux-socket" => config.socket = Some(value.into()),
                "--session-timeout" => {
                    let seconds: u64 = value.parse().map_err(|_| "invalid timeout")?;
                    if !VALID_TIMEOUT_SECS.contains(&seconds) {
                        return Err("timeout must be 1..3600 seconds");
                    }
                    config.timeout = Duration::from_secs(seconds);
                }
                "--ttyname" => config.original_tty = Some(value.to_owned()),
                // gpg-agent can supply --display. Never pass it to curses.
                "--display" | "--ttytype" | "--lc-ctype" | "--lc-messages" => (),
                _ => return Err("unsupported command-line option"),
            }
            i += 1;
        }
        if !config.backend.is_absolute()
            || !config.tmux.is_absolute()
            || config.socket.as_ref().is_some_and(|p| !p.is_absolute())
        {
            return Err("executable and socket paths must be absolute");
        }
        Ok(config)
    }

    fn tmux_command(&self) -> Command {
        let mut command = clean_command(&self.tmux);
        if let Some(socket) = &self.socket {
            command.arg("-S").arg(socket);
        }
        command
    }
}

fn clean_command(program: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8");
    // tmux default-socket lookup and user configuration may need HOME.
    if let Some(home) = env::var_os("HOME") {
        command.env("HOME", home);
    }
    command
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// Kill/reap only our own child, never a client-wide popup or unrelated pane.
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn check_deadline(deadline: Instant) -> Result<()> {
    if STOP.load(Ordering::Relaxed) {
        Err("operation cancelled by signal")
    } else if Instant::now() >= deadline {
        Err(SESSION_TIMEOUT)
    } else {
        Ok(())
    }
}

/// Pipes and sockets are nonblocking; terminal flags are never changed. Polling
/// bounds waits and notices agent EOF or popup closure during backend requests.
fn poll_ready(fd: RawFd, events: i16, deadline: Instant, guards: &[RawFd]) -> Result<()> {
    while !poll_once(fd, events, deadline, guards)? {}
    Ok(())
}

/// Poll once so callers with a child process can also check its exit status.
fn poll_once(fd: RawFd, events: i16, deadline: Instant, guards: &[RawFd]) -> Result<bool> {
    check_deadline(deadline)?;
    let mut fds = vec![libc::pollfd {
        fd,
        events,
        revents: 0,
    }];
    for &guard in guards {
        if guard != fd {
            fds.push(libc::pollfd {
                fd: guard,
                events: 0,
                revents: 0,
            });
        }
    }
    let timeout = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(100) as i32;
    let count = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout) };
    if count < 0 {
        return if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            Ok(false)
        } else {
            Err("poll failed")
        };
    }
    if fds
        .iter()
        .skip(1)
        .any(|p| p.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0)
    {
        return Err("agent or popup disconnected");
    }
    Ok(fds[0].revents != 0)
}

fn nonblocking(fd: RawFd) -> Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err("cannot set nonblocking descriptor");
        }
    }
    Ok(())
}

fn write_bytes(fd: RawFd, bytes: &[u8], deadline: Instant, guards: &[RawFd]) -> Result<()> {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        poll_ready(fd, libc::POLLOUT, deadline, guards)?;
        let count = unsafe { libc::write(fd, remaining.as_ptr().cast(), remaining.len()) };
        if count > 0 {
            remaining = &remaining[count as usize..];
        } else if count == 0 {
            return Err("closed output");
        } else {
            match io::Error::last_os_error().kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => (),
                _ => return Err("output disconnected"),
            }
        }
    }
    Ok(())
}

/// A fixed buffer is wiped on drop (including responses containing secrets).
struct Line {
    bytes: [u8; MAX_LINE],
    len: usize,
}
impl Line {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_LINE],
            len: 0,
        }
    }
    fn data(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    fn read(&mut self, fd: RawFd, deadline: Instant, guards: &[RawFd]) -> Result<bool> {
        wipe(&mut self.bytes);
        self.len = 0;
        loop {
            poll_ready(fd, libc::POLLIN, deadline, guards)?;
            if self.len == MAX_LINE {
                return Err("protocol line too long");
            }
            // Read one byte to avoid retaining a second copy or consuming the
            // next protocol message. Pinentry messages are normally very short.
            let count = unsafe { libc::read(fd, self.bytes[self.len..].as_mut_ptr().cast(), 1) };
            if count == 0 {
                return if self.len == 0 {
                    Ok(false)
                } else {
                    Err("truncated protocol line")
                };
            }
            if count < 0 {
                match io::Error::last_os_error().kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => continue,
                    _ => return Err("input disconnected"),
                }
            }
            self.len += 1;
            if self.bytes[self.len - 1] == 0 {
                return Err("NUL in protocol line");
            }
            if self.bytes[self.len - 1] == b'\n' {
                return Ok(true);
            }
        }
    }
}
fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
}
impl Drop for Line {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

fn keyword(line: &[u8], word: &[u8]) -> bool {
    line.get(..word.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(word))
        && line.get(word.len()).is_none_or(|b| b.is_ascii_whitespace())
}

fn is_final_reply(line: &[u8]) -> bool {
    keyword(line, b"OK") || keyword(line, b"ERR")
}

fn parse_option<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if !keyword(line, b"OPTION") {
        return None;
    }
    let rest = line[6..].trim_ascii();
    let rest = rest.strip_prefix(b"--").unwrap_or(rest);
    let key_end = rest
        .iter()
        .position(|b| b.is_ascii_whitespace() || *b == b'=')
        .unwrap_or(rest.len());
    // Assuan command names are case-insensitive; pinentry option keys are not.
    if &rest[..key_end] != name {
        return None;
    }
    let value = rest[key_end..].trim_ascii();
    Some(value.strip_prefix(b"=").unwrap_or(value).trim_ascii())
}

fn checked_tty(value: &[u8]) -> Result<String> {
    let value = std::str::from_utf8(value).map_err(|_| "invalid terminal")?;
    let number = value
        .strip_prefix("/dev/pts/")
        .ok_or("expected a /dev/pts terminal")?;
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err("expected a /dev/pts terminal");
    }
    let metadata = fs::metadata(value).map_err(|_| "terminal is unavailable")?;
    if !metadata.file_type().is_char_device() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err("terminal is not owned by this user");
    }
    Ok(value.into())
}

fn choose_target(panes: &str, clients: &str, tty: &str) -> Result<(String, String)> {
    let mut sessions = BTreeSet::new();
    let mut pane_ids = BTreeSet::new();
    for line in panes.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() == 3 && fields[0] == tty {
            pane_ids.insert(fields[1]);
            sessions.insert(fields[2]);
        }
    }
    if pane_ids.len() != 1 {
        return Err("original terminal is not a unique tmux pane");
    }
    let mut matches = BTreeSet::new();
    for line in clients.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() == 3 && sessions.contains(fields[1]) && fields[2] == "0" {
            matches.insert(fields[0]);
        }
    }
    if matches.len() != 1 {
        return Err("need exactly one attached tmux client for the signing pane's session");
    }
    Ok((
        matches.first().unwrap().to_string(),
        pane_ids.first().unwrap().to_string(),
    ))
}

fn query(config: &Config, args: &[&str], deadline: Instant) -> Result<String> {
    let mut child = Process(
        config
            .tmux_command()
            .args(args)
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| "cannot start tmux")?,
    );
    let stdout = child.0.stdout.take().unwrap();
    nonblocking(stdout.as_raw_fd())?;
    let mut line = Line::new();
    let mut output = Vec::new();
    while line.read(stdout.as_raw_fd(), deadline, &[0])? {
        if output.len() + line.len > 1024 * 1024 {
            return Err("tmux query output too large");
        }
        output.extend_from_slice(line.data());
    }
    loop {
        check_deadline(deadline)?;
        if let Some(status) = child.0.try_wait().map_err(|_| "cannot wait for tmux")? {
            if !status.success() {
                return Err("tmux query failed; check the server socket");
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    String::from_utf8(output).map_err(|_| "invalid tmux query output")
}

struct PrivateDir(PathBuf);
impl PrivateDir {
    fn new() -> Result<Self> {
        // mkdtemp atomically creates mode 0700. TMPDIR is deliberately ignored.
        let mut template = b"/tmp/pinentry-tmux-XXXXXX\0".to_vec();
        if unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) }.is_null() {
            return Err("cannot create private directory");
        }
        template.pop();
        Ok(Self(String::from_utf8(template).unwrap().into()))
    }
}
impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("control"));
        let _ = fs::remove_dir(&self.0);
    }
}

struct Popup {
    // Drop the connection first, so the helper exits and tmux restores the UI.
    connection: UnixStream,
    _command: Process,
    _directory: PrivateDir,
    tty: String,
    term: String,
}

impl Popup {
    fn open(config: &Config, original: &str, deadline: Instant) -> Result<Self> {
        let setup_deadline = deadline.min(Instant::now() + POPUP_SETUP_TIMEOUT);
        let (client, pane) = locate_target(config, original, setup_deadline)?;
        let directory = PrivateDir::new()?;
        let socket = directory.0.join("control");
        let listener = UnixListener::bind(&socket).map_err(|_| "cannot bind private socket")?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
            .map_err(|_| "cannot protect socket")?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "cannot configure socket")?;
        let executable = env::current_exe().map_err(|_| "cannot locate executable")?;
        // tmux accepts multiple command arguments without invoking a shell.
        let mut command = Process(
            config
                .tmux_command()
                .args([
                    "display-popup",
                    "-E",
                    "-c",
                    &client,
                    "-t",
                    &pane,
                    "-T",
                    "GPG passphrase",
                    "-w",
                    "90%",
                    "-h",
                    "80%",
                ])
                .arg(executable)
                .arg("--popup")
                .arg(&socket)
                .arg(std::process::id().to_string())
                .arg(config.timeout.as_secs().to_string())
                .spawn()
                .map_err(|_| "cannot start popup")?,
        );
        let connection = accept_popup(&listener, &mut command.0, setup_deadline)?;
        let (tty, term) = read_popup_terminal(&connection, setup_deadline)?;
        Ok(Self {
            connection,
            _command: command,
            _directory: directory,
            tty,
            term,
        })
    }
}

fn locate_target(config: &Config, original: &str, deadline: Instant) -> Result<(String, String)> {
    let panes = query(
        config,
        &[
            "list-panes",
            "-a",
            "-F",
            "#{pane_tty}\t#{pane_id}\t#{session_id}",
        ],
        deadline,
    )?;
    let clients = query(
        config,
        &[
            "list-clients",
            "-F",
            "#{client_name}\t#{session_id}\t#{client_control_mode}",
        ],
        deadline,
    )?;
    choose_target(&panes, &clients, original)
}

fn accept_popup(
    listener: &UnixListener,
    command: &mut Child,
    deadline: Instant,
) -> Result<UnixStream> {
    loop {
        if command
            .try_wait()
            .map_err(|_| "cannot wait for popup")?
            .is_some()
        {
            return Err("tmux popup failed or was closed");
        }
        check_deadline(deadline)?;
        match listener.accept() {
            Ok((stream, _)) => {
                verify_peer(&stream, None)?;
                return Ok(stream);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // One bounded poll lets us recheck the process if it exits
                // without ever connecting, instead of waiting until timeout.
                poll_once(listener.as_raw_fd(), libc::POLLIN, deadline, &[0])?;
            }
            Err(_) => return Err("cannot accept popup connection"),
        }
    }
}

fn read_popup_terminal(connection: &UnixStream, deadline: Instant) -> Result<(String, String)> {
    nonblocking(connection.as_raw_fd())?;
    let mut line = Line::new();
    if !line.read(connection.as_raw_fd(), deadline, &[0])? {
        return Err("popup closed during setup");
    }
    validate_popup_terminal(line.data())
}

fn validate_popup_terminal(data: &[u8]) -> Result<(String, String)> {
    let text = std::str::from_utf8(data)
        .map_err(|_| "invalid popup metadata")?
        .trim_end();
    let (tty, term) = text.split_once('\t').ok_or("invalid popup metadata")?;
    let tty = checked_tty(tty.as_bytes())?;
    if term.is_empty()
        || term.len() > 128
        || !term
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))
    {
        return Err("invalid popup terminal type");
    }
    Ok((tty, term.into()))
}

fn verify_peer(stream: &UnixStream, expected_pid: Option<u32>) -> Result<()> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&credentials) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut size,
        )
    };
    if result != 0
        || credentials.uid != unsafe { libc::geteuid() }
        || expected_pid.is_some_and(|pid| credentials.pid as u32 != pid)
    {
        return Err("unexpected popup peer");
    }
    Ok(())
}

fn helper(args: &[String]) -> Result<()> {
    if args.len() != 3 {
        return Err("invalid popup invocation");
    }
    let pid: u32 = args[1].parse().map_err(|_| "invalid parent PID")?;
    let seconds: u64 = args[2].parse().map_err(|_| "invalid timeout")?;
    if !VALID_TIMEOUT_SECS.contains(&seconds) {
        return Err("invalid timeout");
    }
    let mut tty = [0 as libc::c_char; 256];
    if unsafe { libc::ttyname_r(0, tty.as_mut_ptr(), tty.len()) } != 0 {
        return Err("popup has no terminal");
    }
    let tty = unsafe { std::ffi::CStr::from_ptr(tty.as_ptr()) }
        .to_str()
        .map_err(|_| "invalid terminal")?;
    let tty = checked_tty(tty.as_bytes())?;
    let term = env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    let mut connection = UnixStream::connect(&args[0]).map_err(|_| "cannot connect to wrapper")?;
    verify_peer(&connection, Some(pid))?;
    writeln!(connection, "{tty}\t{term}").map_err(|_| "cannot send popup terminal")?;
    nonblocking(connection.as_raw_fd())?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    poll_ready(connection.as_raw_fd(), libc::POLLIN, deadline, &[])?;
    // The parent only closes the socket. No input/secret is ever sent here.
    Ok(())
}

struct Backend {
    _process: Process,
    input: ChildStdin,
    output: std::process::ChildStdout,
}
impl Backend {
    fn start(config: &Config) -> Result<Self> {
        let mut command = clean_command(&config.backend);
        command
            .args(["--ttyname", "/dev/null", "--ttytype", "xterm-256color"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        // If this proxy is killed even by SIGKILL, Linux also kills its backend.
        let parent = std::process::id() as libc::pid_t;
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    libc::_exit(1);
                }
                Ok(())
            });
        }
        let mut process = Process(command.spawn().map_err(|_| "cannot start curses backend")?);
        let input = process.0.stdin.take().unwrap();
        let output = process.0.stdout.take().unwrap();
        nonblocking(input.as_raw_fd())?;
        nonblocking(output.as_raw_fd())?;
        Ok(Self {
            _process: process,
            input,
            output,
        })
    }
    fn send(&self, line: &[u8], deadline: Instant, guards: &[RawFd]) -> Result<()> {
        write_bytes(self.input.as_raw_fd(), line, deadline, guards)
    }
    fn relay_reply(&self, deadline: Instant, guards: &[RawFd]) -> Result<bool> {
        let mut line = Line::new();
        loop {
            if !line.read(self.output.as_raw_fd(), deadline, guards)? {
                return Err("curses backend exited");
            }
            write_bytes(1, line.data(), deadline, guards)?;
            if keyword(line.data(), b"INQUIRE") {
                self.relay_inquiry_answer(deadline, guards)?;
            }
            if is_final_reply(line.data()) {
                return Ok(keyword(line.data(), b"OK"));
            }
        }
    }

    fn relay_inquiry_answer(&self, deadline: Instant, guards: &[RawFd]) -> Result<()> {
        let mut answer = Line::new();
        loop {
            if !answer.read(0, deadline, guards)? {
                return Err("agent disconnected during inquiry");
            }
            self.send(answer.data(), deadline, guards)?;
            if keyword(answer.data(), b"END") || keyword(answer.data(), b"CAN") {
                return Ok(());
            }
        }
    }

    fn expect_ok_reply(&self, deadline: Instant, guards: &[RawFd]) -> Result<()> {
        let mut line = Line::new();
        loop {
            if !line.read(self.output.as_raw_fd(), deadline, guards)? {
                return Err("curses backend exited");
            }
            if keyword(line.data(), b"INQUIRE") {
                return Err("unexpected backend inquiry");
            }
            if keyword(line.data(), b"ERR") {
                return Err("backend rejected popup terminal");
            }
            if keyword(line.data(), b"OK") {
                return Ok(());
            }
        }
    }

    fn setup(&self, command: &[u8], deadline: Instant, guards: &[RawFd]) -> Result<()> {
        self.send(command, deadline, guards)?;
        self.expect_ok_reply(deadline, guards)
    }
}

// Rust drops fields in declaration order: kill/reap curses BEFORE closing the
// popup, so it cannot draw on the terminal after tmux restores the underlying UI.
struct Session {
    backend: Backend,
    popup: Option<Popup>,
}

fn run(config: Config) -> Result<()> {
    for fd in [0, 1] {
        // O_NONBLOCK belongs to the shared open file description, so changing
        // a terminal here would also affect the shell, even after SIGKILL.
        if unsafe { libc::isatty(fd) } == 0 {
            nonblocking(fd)?;
        }
    }
    let deadline = Instant::now() + config.timeout;
    let mut session = Session {
        backend: Backend::start(&config)?,
        popup: None,
    };
    if !session.backend.relay_reply(deadline, &[0])? {
        return Err("backend rejected startup");
    }
    let mut original = config.original_tty.clone();
    let mut line = Line::new();
    loop {
        let guards: Vec<_> = session
            .popup
            .iter()
            .map(|p| p.connection.as_raw_fd())
            .collect();
        if !line.read(0, deadline, &guards)? {
            return Ok(());
        }
        if line.data().trim_ascii().is_empty() || line.data().starts_with(b"#") {
            continue;
        }
        if let Some(tty) = parse_option(line.data(), b"ttyname") {
            if session.popup.is_some() {
                return Err("cannot retarget an active popup");
            }
            original = Some(checked_tty(tty)?);
            write_bytes(1, b"OK\n", deadline, &guards)?;
            continue;
        }
        // Keep terminal routing under this proxy's control. Display is irrelevant
        // to curses, and enabling an Emacs prompt would bypass the popup.
        if parse_option(line.data(), b"ttytype").is_some()
            || parse_option(line.data(), b"display").is_some()
        {
            write_bytes(1, b"OK\n", deadline, &guards)?;
            continue;
        }
        if parse_option(line.data(), b"allow-emacs-prompt").is_some() {
            let reply = format!("ERR {GPG_ERR_UNKNOWN_OPTION} unsupported option\n");
            write_bytes(1, reply.as_bytes(), deadline, &guards)?;
            continue;
        }
        let show = [b"GETPIN".as_slice(), b"CONFIRM", b"MESSAGE"]
            .iter()
            .any(|word| keyword(line.data(), word));
        if show && session.popup.is_none() {
            let tty = original
                .as_ref()
                .ok_or("no original terminal supplied by GPG; set GPG_TTY in the signing shell")?;
            session.popup = Some(Popup::open(&config, tty, deadline)?);
            let created = session.popup.as_ref().unwrap();
            let guards = [0, created.connection.as_raw_fd()];
            session.backend.setup(
                format!("OPTION ttyname={}\n", created.tty).as_bytes(),
                deadline,
                &guards,
            )?;
            session.backend.setup(
                format!("OPTION ttytype={}\n", created.term).as_bytes(),
                deadline,
                &guards,
            )?;
        }
        let mut guards = vec![0];
        guards.extend(session.popup.iter().map(|p| p.connection.as_raw_fd()));
        session.backend.send(line.data(), deadline, &guards)?;
        session.backend.relay_reply(deadline, &guards)?;
        if keyword(line.data(), b"BYE") {
            return Ok(());
        }
    }
}

fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    if args == ["--help"] {
        println!(
            "pinentry-tmux [--backend /absolute/pinentry-curses] [--tmux-socket /absolute/socket]\n  [--session-timeout 1..3600] [--tmux-program /absolute/tmux]\n\nLinux only. Requires a /dev/pts GPG_TTY in a tmux session with exactly one client.\nNo automatic fallback outside tmux. Default timeout: 300 seconds."
        );
        return;
    }
    if args == ["--version"] {
        println!("pinentry-tmux {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let is_helper = args.first().is_some_and(|s| s == "--popup");
    let result = harden().and_then(|()| {
        if is_helper {
            helper(&args[1..])
        } else {
            Config::parse(&args).and_then(run)
        }
    });
    if let Err(error) = result {
        // Never include raw protocol input, backend output, or OS errors with
        // untrusted paths in diagnostics. The error type enforces static text.
        eprintln!("pinentry-tmux: {error}");
        if !is_helper {
            let code = if error == SESSION_TIMEOUT {
                GPG_ERR_TIMEOUT
            } else {
                GPG_ERR_CANCELED
            };
            let reply = format!("ERR {code} pinentry-tmux: {error}\n");
            // Allow a short, bounded final reply even after a handled signal.
            STOP.store(false, Ordering::Relaxed);
            let _ = write_bytes(
                1,
                reply.as_bytes(),
                Instant::now() + Duration::from_millis(100),
                &[],
            );
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd};

    fn test_terminal() -> (OwnedFd, OwnedFd, Vec<u8>) {
        let mut master = -1;
        let mut slave = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        let mut name = [0 as libc::c_char; 256];
        assert_eq!(
            unsafe { libc::ttyname_r(slave.as_raw_fd(), name.as_mut_ptr(), name.len()) },
            0
        );
        let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
            .to_bytes()
            .to_vec();
        (master, slave, name)
    }

    #[test]
    fn checked_tty_accepts_an_owned_pseudoterminal() {
        let (_master, _slave, name) = test_terminal();
        assert_eq!(checked_tty(&name).unwrap().as_bytes(), name);
    }

    #[test]
    fn checked_tty_rejects_invalid_or_missing_terminals() {
        for value in [
            b"".as_slice(),
            b"/dev/null",
            b"/dev/pts/",
            b"/dev/pts/-1",
            b"/dev/pts/../0",
            b"/dev/pts/0/extra",
            b"/dev/pts/\xff",
            b"/dev/pts/999999999999",
        ] {
            assert!(checked_tty(value).is_err());
        }
    }

    #[test]
    fn popup_terminal_metadata_accepts_an_owned_terminal_and_type() {
        let (_master, _slave, name) = test_terminal();
        let mut metadata = name.clone();
        metadata.extend_from_slice(b"\txterm-256color\n");
        let (tty, term) = validate_popup_terminal(&metadata).unwrap();
        assert_eq!(tty.as_bytes(), name);
        assert_eq!(term, "xterm-256color");
    }

    #[test]
    fn popup_terminal_metadata_rejects_invalid_input() {
        for data in [
            b"".as_slice(),
            b"\xff",
            b"/dev/pts/0",
            b"/dev/null\txterm\n",
        ] {
            assert!(validate_popup_terminal(data).is_err());
        }
        let (_master, _slave, name) = test_terminal();
        for term in [
            "",
            "../../xterm",
            "xterm\tother",
            "\x1b[31m",
            &"x".repeat(129),
        ] {
            let mut metadata = name.clone();
            metadata.push(b'\t');
            metadata.extend_from_slice(term.as_bytes());
            assert!(validate_popup_terminal(&metadata).is_err());
        }
    }

    #[test]
    fn option_parser_rejects_other_commands_and_keys() {
        for line in [
            b"OPTION ttynamex=/dev/pts/0\n".as_slice(),
            b"OPTION --ttynamex=/dev/pts/0\n",
            b"OPTION TTYNAME=/dev/pts/0\n",
            b"OPTION display=:0\n",
            b"OPTIONAL ttyname=/dev/pts/0\n",
            b"GETPIN ttyname=/dev/pts/0\n",
        ] {
            assert!(parse_option(line, b"ttyname").is_none());
        }
    }

    #[test]
    fn config_accepts_equals_form_arguments() {
        let args = [
            "--backend=/usr/bin/pinentry-curses",
            "--tmux-program=/usr/bin/tmux",
            "--tmux-socket=/tmp/test-server",
            "--session-timeout=12",
            "--display=:0",
        ]
        .map(String::from);
        let config = Config::parse(&args).unwrap();
        assert_eq!(config.backend, Path::new("/usr/bin/pinentry-curses"));
        assert_eq!(config.tmux, Path::new("/usr/bin/tmux"));
        assert_eq!(
            config.socket.as_deref(),
            Some(Path::new("/tmp/test-server"))
        );
        assert_eq!(config.timeout, Duration::from_secs(12));
    }
    #[test]
    fn targets_only_the_original_session() {
        let panes = "/dev/pts/4\t%1\t$1\n/dev/pts/5\t%2\t$2\n";
        let clients = "/dev/pts/0\t$1\t0\n/dev/pts/1\t$2\t0\n";
        assert_eq!(
            choose_target(panes, clients, "/dev/pts/5").unwrap(),
            ("/dev/pts/1".into(), "%2".into())
        );
        assert!(choose_target(panes, clients, "/dev/pts/9").is_err());
    }
    #[test]
    fn rejects_ambiguous_detached_and_control_clients() {
        let panes = "/dev/pts/4\t%1\t$1\n";
        for clients in [
            "",
            "/dev/pts/0\t$1\t1\n",
            "/dev/pts/0\t$1\t0\n/dev/pts/1\t$1\t0\n",
        ] {
            assert!(choose_target(panes, clients, "/dev/pts/4").is_err());
        }
    }
    #[test]
    fn linked_panes_are_not_arbitrarily_targeted() {
        let panes = "/dev/pts/4\t%1\t$1\n/dev/pts/4\t%1\t$2\n";
        assert!(choose_target(panes, "a\t$1\t0\nb\t$2\t0\n", "/dev/pts/4").is_err());
    }
    #[test]
    fn protocol_keywords_have_boundaries() {
        assert!(keyword(b"CONFIRM --one-button\n", b"CONFIRM"));
        assert!(!keyword(b"GETPINOTHER\n", b"GETPIN"));
        assert!(!is_final_reply(b"OKAY\n"));
        assert_eq!(
            parse_option(b"OPTION ttyname=/dev/pts/4\n", b"ttyname"),
            Some(b"/dev/pts/4".as_slice())
        );
        for line in [
            b"option\t --ttyname = /dev/pts/4 \n".as_slice(),
            b"OPTION ttyname /dev/pts/4\n",
        ] {
            assert_eq!(
                parse_option(line, b"ttyname"),
                Some(b"/dev/pts/4".as_slice())
            );
        }
    }
    #[test]
    fn config_requires_absolute_paths_and_bounded_timeouts() {
        for args in [
            vec!["--backend", "pinentry"],
            vec!["--session-timeout", "0"],
            vec!["--session-timeout", "3601"],
            vec!["--debug", "1"],
        ] {
            assert!(
                Config::parse(&args.into_iter().map(String::from).collect::<Vec<_>>()).is_err()
            );
        }
    }
}
