//! Running the REAL `yadgar-iam` binary the way a pod runs it: with
//! `/etc/yadgar/config/shared/shared.yaml` mounted, as the only file it reads
//! from a fixed path (ledger 748).
//!
//! **WHY A MOUNT NAMESPACE.** `yadgar_lifecycle::rotate::Configuration::mounted`
//! reads `/etc/yadgar/config/shared/shared.yaml` unconditionally and has no
//! environment override, by design: the path is the chart's `mountPath`. A test
//! cannot write under the host's `/etc`, so every run goes through
//! `unshare -rm`, which gives the binary a private mount table in which `/etc`
//! is an overlay over the real one. The document's DIRECTORY is a bind mount of
//! a per-test host directory, which is the shape kubelet gives a ConfigMap
//! volume — and it is what lets a test rewrite the file from outside the
//! namespace. Writing into an overlay's upperdir while it is mounted is
//! undefined behaviour; renaming inside a bind-mounted directory is not.
//!
//! `exec` at the end of the script replaces `sh`, and `unshare` without
//! `--fork` replaces itself, so the pid `Command` returns IS the binary's pid:
//! a SIGTERM sent to it reaches the process under test and nothing in between.
//!
//! **NO PROBE, NO SKIP.** If the runner forbids unprivileged user namespaces,
//! `mount` fails, the script exits non-zero before the binary starts, and every
//! wait below reports that with the captured stderr. `no-test-skips` forbids
//! probe-and-skip, and a harness that passed without running would certify
//! nothing.
//!
//! **EVERY WAIT FAILS ON ITS DEADLINE.** There is no wait here that returns
//! `None`: on its deadline it kills the child and panics, naming the wait and
//! printing every line the binary wrote.
//!
//! **`YADGAR_KEYS_DIR` IS NOT UNDER THE MOUNT.** `crypto::Keys::from_env` reads
//! it as an ordinary environment variable with no fixed path — unlike
//! `shared.yaml` it is not `iam`'s mount-path decision to make — so a per-test
//! directory of two 32-byte files, created directly under the system temp dir,
//! is all a boot that must get past it needs.

// Each test target compiles its own copy of this module and uses a subset of it.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// The binary under test.
pub const BIN: &str = env!("CARGO_BIN_EXE_yadgar-iam");

/// The rotation schedule every run is given: poll each second, no splay. A
/// rewrite is therefore noticed within one second and acted on at once.
pub const FIXTURE: &str = "tlsRotation:\n  pollSeconds: 1\n  splayMaxSeconds: 0\n";

/// The poll and splay in [`FIXTURE`], for deadlines derived from them.
pub const POLL: Duration = Duration::from_secs(1);
pub const SPLAY_MAX: Duration = Duration::from_secs(0);

/// What every deadline adds on top of the time the binary is allowed. Generous,
/// because a shared CI runner is slow, and `Keys::from_env` hashes a dummy
/// password with Argon2id on every boot — the waits it bounds are seconds long
/// either way.
pub const MARGIN: Duration = Duration::from_secs(10);

/// How long a boot may take to reach its "listening" line.
pub const BOOT_DEADLINE: Duration = Duration::from_secs(20);

/// The script `unshare` runs. Paths arrive as positional arguments — `$1` the
/// per-test root, `$2` the binary — rather than interpolated into the text.
const SCRIPT: &str = r#"set -e
mount -t overlay overlay -o "lowerdir=/etc,upperdir=$1/upper,workdir=$1/work" /etc
mkdir -p /etc/yadgar/config/shared
mount --bind "$1/shared" /etc/yadgar/config/shared
exec "$2""#;

/// A fresh directory holding `encryption.key` and `blind-index.key`, 32 bytes
/// each — the shape `crypto::Keys::from_dir` reads. Fixed, not random: nothing
/// in this harness ever encrypts or decrypts, so the bytes only need to be the
/// right LENGTH, and a fixed pattern keeps the fixture reviewable.
///
/// Not under `/etc`, and deliberately so: see the module doc for why
/// `YADGAR_KEYS_DIR` needs no mount namespace of its own.
///
/// Owns its directory and removes it on `Drop`, the same way [`Booted`] owns
/// and removes its root — a test that returns early, panics, or just ends
/// must not leave this behind in the system temp dir for every run.
/// `Deref<Target = Path>` so a `&KeysDir` passes anywhere a `&Path` already
/// did.
pub struct KeysDir(PathBuf);

impl std::ops::Deref for KeysDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for KeysDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn fresh_keys_dir() -> KeysDir {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "yadgar-iam-exit-chain-keys-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("the keys directory must be created");
    std::fs::write(dir.join("encryption.key"), [0x11u8; 32])
        .expect("the encryption key fixture must be written");
    std::fs::write(dir.join("blind-index.key"), [0x22u8; 32])
        .expect("the blind-index key fixture must be written");
    KeysDir(dir)
}

/// The environment the chart's `deployment.yaml` renders for a cleartext
/// deployment, with loopback addresses, plus a `YADGAR_KEYS_DIR` pointing at
/// `keys_dir`.
///
/// Port 0 on both listeners, because the cases in a target run in parallel.
/// `IAM_DB_HOST` is an address rather than a name, so no case depends on DNS:
/// the dial is lazy (ADR-0532), so nothing needs to answer on it — including
/// the key-identity round trip `tests/assembly.rs`'s sibling `main.rs` starts
/// after boot, which retries for ever against an absent twin and never
/// resolves (ADR-0764). Both `*_TLS_ENABLED` are stated as `"0"` rather than
/// left absent, `LISTEN_TLS_CLIENT_AUTH` is stated as `off` (ADR-0854: it has
/// no default either, TLS on or off), and both response floors are `"0"` — a
/// real number, not a default, is all `boot::response_floors` asks for.
pub fn cleartext_env(keys_dir: &Path) -> Vec<(&'static str, String)> {
    vec![
        ("IAM_DB_HOST", "127.0.0.1".to_string()),
        ("IAM_DB_PORT", "50051".to_string()),
        ("LISTEN", "127.0.0.1:0".to_string()),
        ("METRICS_LISTEN", "127.0.0.1:0".to_string()),
        ("LISTEN_TLS_ENABLED", "0".to_string()),
        ("LISTEN_TLS_CLIENT_AUTH", "off".to_string()),
        ("IAM_DB_TLS_ENABLED", "0".to_string()),
        ("YADGAR_KEYS_DIR", keys_dir.display().to_string()),
        ("LOGIN_RESPONSE_FLOOR_MS", "0".to_string()),
        ("REDEEM_RESPONSE_FLOOR_MS", "0".to_string()),
    ]
}

/// One line the binary wrote, and which stream it came from.
enum Line {
    Out(String),
    Err(String),
}

/// The binary, running in its own mount namespace, with its output pumped.
pub struct Booted {
    child: Child,
    lines: Receiver<Line>,
    seen: Vec<String>,
    root: PathBuf,
}

impl Booted {
    /// Start the binary with exactly `vars` (and `PATH`) in its environment.
    pub fn start(vars: &[(&str, String)]) -> Self {
        let root = fresh_root();
        // `unshare`, `mount` and `sh` are found on the caller's PATH; on some
        // hosts none of them is under /usr/bin. A rig with no PATH fails here
        // rather than guessing one.
        let path = std::env::var_os("PATH").expect("the test runner must have a PATH");
        let mut child = Command::new("unshare")
            .args(["-rm", "sh", "-c", SCRIPT, "sh"])
            .arg(&root)
            .arg(BIN)
            .env_clear()
            .env("PATH", path)
            .envs(vars.iter().map(|(k, v)| (*k, v.as_str())))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("`unshare` could not be started: {e}"));

        // ONE THREAD PER STREAM, pumping for the life of the child. Reading
        // only until the "listening" line would leave the pipe to fill and the
        // binary to block on its next log line.
        let (tx, lines) = mpsc::channel();
        let out = child.stdout.take().expect("stdout was piped");
        let err = child.stderr.take().expect("stderr was piped");
        let tx_err = tx.clone();
        std::thread::spawn(move || pump(out, move |l| tx.send(Line::Out(l)).is_ok()));
        std::thread::spawn(move || pump(err, move |l| tx_err.send(Line::Err(l)).is_ok()));

        Self {
            child,
            lines,
            seen: Vec::new(),
            root,
        }
    }

    /// The binary's pid. `exec` all the way down makes it the direct child.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Wait for a line satisfying `matches`, or fail on `deadline`.
    ///
    /// A child whose output ends first — it exited, or the mount namespace was
    /// refused and it never started — fails at once with what it printed,
    /// rather than as a timeout.
    pub fn wait_for_line(
        &mut self,
        what: &str,
        deadline: Duration,
        matches: impl Fn(&str) -> bool,
    ) -> String {
        let until = Instant::now() + deadline;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(Line::Out(l) | Line::Err(l)) => {
                    self.seen.push(l.clone());
                    if matches(&l) {
                        return l;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.fail(&format!("waited {deadline:?} for {what}; it never came"))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let status = self.reap(Duration::from_secs(5));
                    self.fail(&format!(
                        "the binary's output ended before {what} ({})",
                        describe(status)
                    ))
                }
            }
        }
    }

    /// Wait for the boot to reach the line `serve_and_drain` logs once the
    /// signal handlers are armed and the server is spawned.
    pub fn wait_until_listening(&mut self) {
        self.wait_for_line("the \"iam listening\" line", BOOT_DEADLINE, |l| {
            l.contains("\"iam listening\"")
        });
    }

    /// Send SIGTERM, the way kubelet ends a pod.
    pub fn terminate(&mut self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.pid().to_string()])
            .status()
            .unwrap_or_else(|e| panic!("`kill` could not be started: {e}"));
        if !status.success() {
            self.fail(&format!("`kill -TERM` failed: {status}"));
        }
    }

    /// Wait for the process to exit, or fail on `deadline`.
    pub fn wait_for_exit(&mut self, what: &str, deadline: Duration) -> ExitStatus {
        match self.reap(deadline) {
            Some(status) => {
                self.drain_lines();
                status
            }
            None => self.fail(&format!(
                "waited {deadline:?} for the process to exit {what}; it was still running"
            )),
        }
    }

    /// Replace the mounted `shared.yaml` the way kubelet replaces a projected
    /// file: write a sibling, then rename it over the original.
    pub fn rewrite_shared(&self, contents: &str) {
        let dir = self.root.join("shared");
        let staged = dir.join(".shared.yaml.next");
        std::fs::write(&staged, contents).expect("the staged document must be written");
        std::fs::rename(&staged, dir.join("shared.yaml"))
            .expect("the staged document must replace the mounted one");
    }

    /// Every line the binary has written so far.
    pub fn seen(&self) -> &[String] {
        &self.seen
    }

    /// Fail the test: kill the child, then panic with everything it printed.
    pub fn fail(&mut self, why: &str) -> ! {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.drain_lines();
        panic!(
            "{why}\n--- everything the binary wrote ---\n{}",
            self.seen.join("\n")
        );
    }

    fn reap(&mut self, deadline: Duration) -> Option<ExitStatus> {
        let until = Instant::now() + deadline;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) if Instant::now() >= until => return None,
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => panic!("the child could not be waited on: {e}"),
            }
        }
    }

    fn drain_lines(&mut self) {
        // The pumps end at EOF, which follows the exit closely; a short bound
        // keeps a stray grandchild holding the pipe from hanging the test.
        while let Ok(Line::Out(l) | Line::Err(l)) =
            self.lines.recv_timeout(Duration::from_millis(500))
        {
            self.seen.push(l);
        }
    }
}

impl Drop for Booted {
    fn drop(&mut self) {
        // A panicking test must not leave a server running.
        let _ = self.child.kill();
        let _ = self.child.wait();
        remove_root(&self.root);
    }
}

/// Run the binary to completion under the same mounts, for a boot that is
/// expected to refuse. Returns the status and stderr.
pub fn run_to_exit(vars: &[(&str, String)]) -> (ExitStatus, String) {
    let mut booted = Booted::start(vars);
    let status = booted.wait_for_exit("after refusing its boot", BOOT_DEADLINE);
    (status, booted.seen().join("\n"))
}

/// The exit status as a sentence that says whether a signal ended it.
pub fn describe(status: Option<ExitStatus>) -> String {
    match status {
        None => "still running".to_string(),
        Some(s) => format!("code {:?}, signal {:?}", s.code(), s.signal()),
    }
}

/// A per-test directory: the overlay's upper and work dirs, and the directory
/// bind-mounted as `/etc/yadgar/config/shared`.
///
/// Under the system temp dir, which must not itself be an overlay: an overlay's
/// upperdir cannot sit on one. The name carries a counter as well as the pid,
/// because the cases of a target run on threads of one process (ledger 706).
fn fresh_root() -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "yadgar-iam-exit-chain-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    for dir in ["upper", "work", "shared"] {
        std::fs::create_dir_all(root.join(dir)).expect("the test root must be created");
    }
    std::fs::write(root.join("shared").join("shared.yaml"), FIXTURE)
        .expect("the fixture document must be written");
    root
}

/// Best effort. Overlayfs leaves `work/work` with mode 0, so it is opened up
/// before the tree is removed.
fn remove_root(root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(
        root.join("work").join("work"),
        std::fs::Permissions::from_mode(0o700),
    );
    let _ = std::fs::remove_dir_all(root);
}

fn pump(stream: impl Read, mut send: impl FnMut(String) -> bool) {
    for line in BufReader::new(stream).lines() {
        let Ok(line) = line else { return };
        if !send(line) {
            return;
        }
    }
}
