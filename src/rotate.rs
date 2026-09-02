//! What this process does when the certificate it is serving is replaced
//! underneath it.
//!
//! **Serving certificates are read ONCE, when the listener is built.**
//! [`crate::serve::builder`] hands tonic an acceptor holding an
//! `Arc<ServerConfig>` built there and then, and nothing afterwards can swap it:
//! `tonic 0.14`'s TLS settings are documented as ignored under
//! `serve_with_incoming`, which is the only custom-acceptor path there is. So a
//! pod started today serves its day-0 leaf until it restarts, whatever cert-manager
//! writes into the Secret in the meantime.
//!
//! The chart mounts those Secrets as DIRECTORIES rather than with `subPath`,
//! deliberately, so kubelet does refresh the files inside the pod. Only the
//! process never re-reads them.
//!
//! # The ruling: exit on change
//!
//! This module polls a digest of every TLS input the process read at boot — one
//! per file, so a change can be reported by NAME. The set is the serving
//! certificate, the private key belonging to it, the CA bundle `iam-db` is
//! verified against, and the CA every D73 enrolment token carries. On a change
//! it logs which file, and the old and new leaf fingerprint, waits out a per-pod
//! splay, and ends — and the caller selects on that, drains, and returns
//! `Ok(())`.
//!
//! **THE ENROLMENT CA IS IN THAT SET, and it is not a transport input.** The
//! chart mounts it as a DIRECTORY for the propagation a rotation needs, and
//! `iam` reads it once. Left unwatched, a gateway CA rotation leaves this
//! process minting tokens carrying a CA that no longer signs anything: no exit,
//! no gauge movement, no log. That is the silently-stale material this whole
//! ruling exists to refuse, so it is in scope by the ruling's own test.
//! Kubelet restarts the container and the new process reads the fresh file. **A
//! change is not an error, so the exit code is 0.**
//!
//! In-process hot reload was rejected and is not available anyway, for the
//! reason above. A reloader operator was rejected because it fails silent until
//! the deadline and leaves off-reference adopters broken (D80).
//!
//! # THE PROPERTY THAT DECIDED IT, and the one every change here must keep
//!
//! **If the watcher dies you get today's behaviour, never worse.** A file that
//! cannot be read is not a changed one; an unparsable certificate is not a
//! changed one; no TLS at all means no watch. Nothing here may end the watch
//! over a state it is merely unsure about, because ending it exits the process.
//!
//! # A hash, never a modification time
//!
//! Kubelet rotates a mounted Secret by writing a whole new timestamped directory
//! and `rename`ing a replacement `..data` symlink over the old one. Every path
//! the process holds then resolves to a DIFFERENT inode with a fresh
//! modification time — on every resync, whether or not a single byte changed. An
//! mtime check restarts both replicas for nothing; a content hash does not.
//! `tests/tls_rotation.rs` performs that exact swap rather than overwriting a
//! file in place.
//!
//! # The splay, and why a PDB is not a substitute
//!
//! Both replicas see the refreshed file inside the same kubelet sync window, so
//! an unsplayed exit can drop both at once. **A PodDisruptionBudget does not
//! govern a self-exit** — it constrains eviction, and nothing is evicting
//! anything here. The splay is the only control. Renewal lands 30 days before
//! expiry, so the slack is enormous and minutes of waiting cost nothing.
//!
//! # The gauge is the half that makes a failure loud
//!
//! [`Inputs::export_not_after`] publishes the expiry of the certificate this
//! process ACTUALLY LOADED (D67).
//!
//! # "TLS is off" does NOT mean "nothing is watched"
//!
//! The enrolment CA is in the set, and the chart ships `enrolment.caSecret` with
//! a default — so a default install serving CLEARTEXT still has a non-empty
//! watch set and still exits on a gateway CA rotation. The set is empty only
//! when neither a listener certificate nor an enrolment CA was read. If the watcher dies, that gauge still shows
//! the loaded leaf ageing out — which is what a watcher whose own failure is
//! silent would not give anybody.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

/// When the certificate this process loaded stops being valid, in seconds since
/// the epoch.
///
/// **NO fingerprint label and no path label.** D67's boundary is that an
/// unbounded dimension goes on a wide event, never on a metric label — a
/// fingerprint label is one new time series per rotation, forever. The
/// fingerprints go in the log line, where the cardinality costs nothing.
pub const CERTIFICATE_NOT_AFTER: &str = "yadgar_tls_certificate_not_after_seconds";

/// How often the files are re-hashed.
const POLL_KEY: &str = "TLS_ROTATION_POLL_SECS";

/// The longest a pod waits before ending its watch.
const SPLAY_MAX_KEY: &str = "TLS_ROTATION_SPLAY_MAX_SECS";

/// Three small files a minute costs nothing, against a deadline 30 days wide.
const DEFAULT_POLL: Duration = Duration::from_secs(60);

/// Five minutes of spread between two replicas, against those same 30 days.
const DEFAULT_SPLAY_MAX: Duration = Duration::from_secs(300);

/// What a deployment got wrong about the rotation watcher.
#[derive(Debug, thiserror::Error)]
pub enum ScheduleError {
    #[error(
        "{key} is {value:?}, which is not a whole number of seconds ({source}). It is refused \
         rather than replaced with the default, because a deployment that believes it set this \
         and did not would run an interval nobody chose and see nothing wrong."
    )]
    Unparsable {
        key: &'static str,
        value: String,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error(
        "{POLL_KEY} is 0, which is not a poll interval. Sleeping for no time at all turns the \
         rotation watcher into a loop that re-reads and re-hashes the TLS files as fast as a \
         core allows, for the life of the pod. Set it to at least 1. Nothing is turned OFF by \
         setting it to 0 — leaving TLS off is what leaves the watcher idle. {SPLAY_MAX_KEY} is \
         different: 0 there means exit at once, which is a supported choice."
    )]
    ZeroPoll,
}

/// How often the watcher looks, and how long this pod waits once it has seen
/// something.
///
/// **A default nobody chose is fine here and would not be on a security
/// control**, which is why this has defaults at all while the response-time
/// floors do not. A value that was SET and cannot be used is still an error:
/// silently substituting one leaves an operator who believes they changed the
/// interval running the old one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    poll: Duration,
    splay_max: Duration,
}

impl Default for Schedule {
    fn default() -> Self {
        Self::new(DEFAULT_POLL, DEFAULT_SPLAY_MAX)
    }
}

impl Schedule {
    pub fn new(poll: Duration, splay_max: Duration) -> Self {
        Self { poll, splay_max }
    }

    /// Read the schedule from the environment.
    pub fn from_env() -> Result<Self, ScheduleError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// The same decision, over an injected lookup.
    ///
    /// **A seam, because environment variables are process-global** — the same
    /// reason [`crate::serve::ServerTls::from_lookup`] takes one.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ScheduleError> {
        let seconds = |key: &'static str, default: Duration| match lookup(key) {
            None => Ok(default),
            Some(raw) => raw
                .trim()
                .parse()
                .map(Duration::from_secs)
                .map_err(|source| ScheduleError::Unparsable {
                    key,
                    value: raw,
                    source,
                }),
        };

        let poll = seconds(POLL_KEY, DEFAULT_POLL)?;
        if poll.is_zero() {
            return Err(ScheduleError::ZeroPoll);
        }
        Ok(Self::new(poll, seconds(SPLAY_MAX_KEY, DEFAULT_SPLAY_MAX)?))
    }

    /// How long between readings.
    pub fn poll(&self) -> Duration {
        self.poll
    }

    /// The top of the range this pod's wait is drawn from.
    pub fn splay_max(&self) -> Duration {
        self.splay_max
    }
}

/// One watched file, and what it held when this process read it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Watched {
    path: PathBuf,
    /// SHA-256 of the bytes AS LOADED. `None` when the file could not be read
    /// at that moment, which is a deployment already broken in a way the boot
    /// log carries.
    loaded: Option<[u8; 32]>,
}

/// The TLS files this process read at boot, and what they held when it read
/// them.
///
/// **Built from the configuration that was already resolved**, never by reading
/// the environment a second time: the point is to watch the files the process
/// actually opened, and a second reading could name different ones.
///
/// **THE BASELINE IS CAPTURED HERE, EAGERLY, AND THAT IS THE POINT.** Every
/// builder method below reads its file immediately, so each digest is taken
/// beside the code that loaded it rather than later. Deferring the first reading
/// to the watcher's first poll would put the whole of the rest of boot — the
/// `iam-db` dial, the broker connect — inside a window where a kubelet swap
/// makes the NEW file the baseline. The real rotation is then never noticed, and
/// the gauge describes a certificate the listener is not serving.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inputs {
    /// The DER of the leaf this service PRESENTS, **as it was read** — kept
    /// rather than re-read, so the fingerprint and the gauge describe the
    /// certificate actually loaded even after the file underneath has changed.
    certificate: Option<Vec<u8>>,
    /// Where that leaf was read from, so the certificate ON DISK can be
    /// fingerprinted after a rotation without re-deriving which file it was.
    certificate_path: Option<PathBuf>,
    /// Every watched file, the certificate included, in the order they were
    /// added.
    files: Vec<Watched>,
}

impl Inputs {
    /// The certificate this service presents to its callers.
    ///
    /// Read NOW: the leaf kept here is the one the fingerprint and the gauge
    /// speak for.
    pub fn serving_certificate(mut self, path: &Path) -> Self {
        let bytes = std::fs::read(path).ok();
        self.certificate = bytes
            .as_deref()
            .and_then(|b| CertificateDer::pem_slice_iter(b).next()?.ok())
            .map(|der| der.to_vec());
        self.certificate_path = Some(path.to_path_buf());
        self.files.push(Watched {
            path: path.to_path_buf(),
            loaded: bytes.as_deref().map(digest_of),
        });
        self
    }

    /// The listener's certificate and the private key belonging to it, or
    /// nothing at all when this deployment serves cleartext.
    ///
    /// **A method taking the RESOLVED CONFIGURATION rather than two paths spelled
    /// out in `main`.** Membership in the watch set is exactly the kind of thing
    /// that is silently wrong — a file quietly missing costs nothing at boot and
    /// everything at renewal — and nothing in a binary entry point is reachable
    /// from a test. Here it is: `tests/tls_rotation.rs` asserts what each of
    /// these three puts in.
    pub fn listener(self, tls: Option<&crate::serve::ServerTls>) -> Self {
        match tls {
            None => self,
            Some(tls) => self
                .serving_certificate(tls.cert_file())
                .also(tls.key_file()),
        }
    }

    /// The CA bundle an upstream's certificate is verified against.
    pub fn upstream(self, tls: Option<&crate::upstream::UpstreamTls>) -> Self {
        match tls {
            None => self,
            Some(tls) => self.also(tls.ca_file()),
        }
    }

    /// The CA every D73 enrolment token carries.
    ///
    /// **NOT a transport input, and watched anyway.** The chart mounts it as a
    /// DIRECTORY for the propagation a rotation needs. Left out, a gateway CA
    /// rotation leaves this process minting tokens carrying a CA that no longer
    /// signs anything — no exit, no gauge movement, no log.
    ///
    /// `None` for the path, rather than for the config, is the deployment that
    /// uses system trust: nothing was read, so there is nothing to watch.
    pub fn enrolment(self, config: Option<&crate::service::EnrolmentConfig>) -> Self {
        match config.and_then(|c| c.ca_path()) {
            None => self,
            Some(path) => self.also(path),
        }
    }

    /// A TLS file read at boot that is not the serving certificate: the private
    /// key belonging to it, the CA bundle each upstream is verified against, and
    /// the CA every enrolment token carries.
    pub fn also(mut self, path: &Path) -> Self {
        self.files.push(Watched {
            path: path.to_path_buf(),
            loaded: std::fs::read(path).ok().as_deref().map(digest_of),
        });
        self
    }

    /// Nothing was configured, so there is nothing to watch.
    ///
    /// **NOT the same as "TLS is off".** The enrolment CA is watched too, and
    /// the chart ships `enrolment.caSecret` with a default, so a cleartext
    /// deployment has a non-empty watch set on a default install.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Every file being watched, in order. For tests that assert MEMBERSHIP,
    /// which is the half no rotation case can prove.
    pub fn watched(&self) -> Vec<&Path> {
        self.files.iter().map(|f| f.path.as_path()).collect()
    }

    /// What the files held when this process read them.
    ///
    /// `None` when any of them was unreadable then: there is no baseline to
    /// compare against, so every later reading would look like a change.
    fn baseline(&self) -> Option<Vec<[u8; 32]>> {
        self.files.iter().map(|f| f.loaded).collect()
    }

    /// What they hold now.
    ///
    /// **ONE DIGEST PER FILE, POSITIONALLY**, rather than one hash over all of
    /// them: it is what lets the change be reported by NAME, and it is why two
    /// files exchanging contents is a change rather than a wash.
    ///
    /// `None` when any of them cannot be read, which is a state to wait out
    /// rather than act on: kubelet is halfway through a swap, or a Secret has
    /// not been mounted yet.
    fn on_disk(&self) -> Option<Vec<[u8; 32]>> {
        self.files
            .iter()
            .map(|f| std::fs::read(&f.path).ok().as_deref().map(digest_of))
            .collect()
    }

    /// Which watched files differ from what this process read.
    fn differing(&self, current: &[[u8; 32]]) -> Vec<String> {
        self.files
            .iter()
            .zip(current)
            .filter(|(f, now)| f.loaded.as_ref() != Some(*now))
            .map(|(f, _)| f.path.display().to_string())
            .collect()
    }

    /// The leaf certificate this service presents, as it was loaded.
    ///
    /// **THE FIRST certificate in the file, and that is load-bearing.**
    /// cert-manager writes the leaf followed by the chain that issued it, so the
    /// LAST one is an authority whose expiry is years away — reporting it would
    /// keep the gauge green while the certificate actually on the wire ages out.
    fn leaf(&self) -> Option<CertificateDer<'static>> {
        Some(CertificateDer::from(self.certificate.clone()?))
    }

    /// The fingerprint of whatever the certificate file holds RIGHT NOW, which
    /// is what a rotation replaced the loaded one with.
    ///
    /// The only reading in this module that deliberately goes back to disk: the
    /// "after" half of the log line has no other source.
    fn fingerprint_on_disk(&self) -> Option<String> {
        let bytes = std::fs::read(self.certificate_path.as_ref()?).ok()?;
        let der = CertificateDer::pem_slice_iter(&bytes).next()?.ok()?;
        Some(hex(&Sha256::digest(&der)))
    }

    /// SHA-256 over the leaf's DER, in hex.
    ///
    /// The same BYTES `openssl x509 -fingerprint -sha256` prints, in a different
    /// rendering: lowercase and unseparated, where openssl gives uppercase
    /// separated by colons. Comparable after case-folding and stripping the
    /// colons, and not by eye.
    ///
    /// **This is what answers "which certificate am I on".** It is the first
    /// question anybody asks when a rotation is suspected, and without it the
    /// log line saying one happened is unfalsifiable.
    pub fn fingerprint(&self) -> Option<String> {
        Some(hex(&Sha256::digest(self.leaf()?)))
    }

    /// When the loaded leaf stops being valid, in seconds since the epoch.
    pub fn not_after(&self) -> Option<i64> {
        let der = self.leaf()?;
        let (_, parsed) = X509Certificate::from_der(&der).ok()?;
        Some(parsed.validity().not_after.timestamp())
    }

    /// Publish that expiry as a gauge (D67).
    ///
    /// Called by the BINARY after the exporter is installed — a value recorded
    /// before there is a recorder is a value nobody ever sees. Absent or
    /// unparsable, nothing is published: an invented number is worse than a
    /// missing series, because a dashboard cannot tell it apart from a real one.
    pub fn export_not_after(&self) {
        let Some(seconds) = self.not_after() else {
            return;
        };
        metrics::gauge!(CERTIFICATE_NOT_AFTER, "service" => crate::service::SERVICE)
            .set(seconds as f64);
        tracing::info!(
            not_after = seconds,
            fingerprint = self.fingerprint().unwrap_or_else(unknown),
            "serving certificate loaded; its expiry is exported as {CERTIFICATE_NOT_AFTER}"
        );
    }
}

/// Wait until the TLS files this process read at boot have changed, then wait
/// out this pod's splay.
///
/// **The caller selects on this future and drains.** It resolves at most once,
/// and never for any reason but a change it could actually read.
pub async fn watch(inputs: Inputs, schedule: Schedule) {
    watch_with_seed(inputs, schedule, seed()).await
}

/// The same watch over an injected splay seed.
///
/// **A seam, because a splay drawn from the clock cannot be asserted.** The test
/// passes `u64::MAX` and gets the whole configured maximum, which turns "the
/// exit waits" into an equality rather than a coin toss.
pub async fn watch_with_seed(inputs: Inputs, schedule: Schedule, seed: u64) {
    if inputs.is_empty() {
        // TLS IS OFF, which is the default. Nothing was read, so nothing can
        // rotate. The watch must NEVER end: the caller treats that as a
        // rotation and exits a process that has no certificate at all.
        tracing::debug!("no TLS inputs; this process will not exit on a rotation");
        never().await
    }
    let Some(booted) = inputs.baseline() else {
        // CONFIGURED AND UNREADABLE. There is no baseline to compare against, so
        // every later reading would look like a change. Today's behaviour —
        // serve what was loaded — is the safe answer, and the boot log already
        // carries whatever went wrong.
        tracing::warn!("the TLS inputs could not be read; rotation will not be noticed");
        never().await
    };
    let before = inputs.fingerprint().unwrap_or_else(unknown);

    loop {
        tokio::time::sleep(schedule.poll).await;
        let Some(current) = inputs.on_disk() else {
            // NOT A CHANGE. A file that cannot be read is a mount mid-swap or a
            // Secret not yet there, and restarting over it would make this
            // watcher's failure worse than not having one.
            tracing::warn!("a TLS input could not be read; keeping the certificate already loaded");
            continue;
        };
        if current == booted {
            continue;
        }

        let waited = splay(schedule.splay_max, seed);
        tracing::warn!(
            before,
            after = inputs.fingerprint_on_disk().unwrap_or_else(unknown),
            changed = inputs.differing(&current).join(", "),
            splay_secs = waited.as_secs(),
            "the TLS files read at boot have CHANGED on disk. tonic cannot swap a running \
             listener's certificate, so this process drains and exits 0 to be restarted onto \
             the new one; the wait is this pod's splay, so both replicas do not go at once"
        );
        tokio::time::sleep(waited).await;
        tracing::warn!("splay elapsed; draining");
        return;
    }
}

/// How long THIS pod waits before ending its watch.
///
/// A pure function of the maximum and the seed, spread evenly over the range:
/// seed `0` waits not at all and `u64::MAX` waits the whole of it.
fn splay(max: Duration, seed: u64) -> Duration {
    // MILLISECONDS, not nanoseconds, and `saturating_mul` beside it. In
    // nanoseconds this product overflows `u128` once the configured maximum
    // passes roughly 1.85e10 seconds — measured, not reasoned about — and a
    // splay is a wait of minutes, so nanosecond resolution buys nothing to pay
    // for it with. `.min(max)` is the belt: whatever the arithmetic does at the
    // absurd end of the range, the wait never exceeds what was configured.
    let millis = u128::from(seed).saturating_mul(max.as_millis()) / u128::from(u64::MAX);
    Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX)).min(max)
}

/// This pod's splay seed.
///
/// **The process start time, hashed.** Two replicas of the same rollout never
/// start in the same nanosecond, and hashing decorrelates the digits that are
/// close together — which is all the spread this needs. A restarted pod draws a
/// new one, which is correct: it is a new process, and the replica it must avoid
/// colliding with has moved on too.
///
/// Deliberately NOT a random-number generator: an estate with no `rand`
/// dependency does not grow one for a value that has to be assertable.
fn seed() -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("SHA-256 is 32 bytes"))
}

/// A future that never resolves.
///
/// Spelled out rather than inlined because the mistake it prevents is
/// invisible: a `watch` that RETURNED when there was nothing to watch would look
/// to the caller exactly like a detected rotation, and exit the process.
async fn never() -> ! {
    let never: std::convert::Infallible = std::future::pending().await;
    match never {}
}

/// What a fingerprint reads as when the file holds no certificate this can
/// parse. Never an empty string: a log field that renders blank looks like a
/// bug in the logging rather than an answer.
fn unknown() -> String {
    "unknown".to_string()
}

/// SHA-256 of one file's contents.
fn digest_of(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: Duration = Duration::from_secs(300);

    /// The ends of the range, which is what makes the seam assertable at all:
    /// the test that proves the exit waits passes `u64::MAX` and expects the
    /// whole maximum back.
    #[test]
    fn the_splay_spans_the_whole_configured_range() {
        assert_eq!(splay(MAX, 0), Duration::ZERO);
        assert_eq!(splay(MAX, u64::MAX), MAX);
    }

    /// Never longer than what was configured. A splay that overshot would hold a
    /// pod on a certificate it has already been told to stop using.
    #[test]
    fn the_splay_never_exceeds_its_maximum() {
        for seed in [1, 7, 1_000, u64::MAX / 3, u64::MAX / 2, u64::MAX - 1] {
            assert!(splay(MAX, seed) <= MAX, "{seed} overshot");
        }
    }

    /// ZERO IS A USABLE SETTING, not a bug: it is how a single-replica or a
    /// development deployment says it wants the restart immediately.
    #[test]
    fn a_zero_maximum_waits_not_at_all() {
        assert_eq!(splay(Duration::ZERO, u64::MAX), Duration::ZERO);
    }

    /// THE POINT OF THE SPLAY. Different pods must draw different waits —
    /// a function that returned the same value for every seed would leave both
    /// replicas exiting together, which is the failure it exists to prevent.
    #[test]
    fn different_seeds_wait_for_different_times() {
        let waits: std::collections::BTreeSet<_> =
            (1..=8).map(|n| splay(MAX, u64::MAX / 9 * n)).collect();
        assert_eq!(waits.len(), 8, "seeds must spread across the range");
    }

    /// The seed is drawn from the clock, so two draws in one process differ —
    /// the property two pods rely on, tested where it can be observed.
    #[test]
    fn the_seed_moves() {
        assert_ne!(seed(), seed());
    }

    /// Nothing configured is the DEFAULT today, and it must not look like a
    /// deployment whose certificate has gone missing.
    #[test]
    fn nothing_configured_is_empty() {
        assert!(Inputs::default().is_empty());
        assert!(!Inputs::default()
            .serving_certificate(Path::new("/etc/yadgar/tls.pem"))
            .is_empty());
    }

    /// A file that does not exist yields no baseline — the state `watch` refuses
    /// to act on, because every later reading would look like a change.
    #[test]
    fn an_unreadable_input_has_no_baseline() {
        let inputs = Inputs::default().also(Path::new("/etc/yadgar/quokka-4d81/absent.pem"));
        assert_eq!(inputs.baseline(), None);
        assert_eq!(inputs.on_disk(), None);
        assert_eq!(inputs.fingerprint(), None);
        assert_eq!(inputs.not_after(), None);
    }

    /// AN ABSURD MAXIMUM MUST NOT PANIC OR OVERSHOOT. In nanoseconds the product
    /// overflows here; the measured threshold is around 1.85e10 seconds.
    #[test]
    fn an_absurd_maximum_neither_panics_nor_overshoots() {
        for max in [
            Duration::from_secs(20_000_000_000),
            Duration::from_secs(u64::MAX / 1000),
        ] {
            for seed in [0, 1, u64::MAX / 2, u64::MAX] {
                assert!(splay(max, seed) <= max, "{max:?}/{seed} overshot");
            }
        }
    }

    fn lookup<'a>(
        pairs: &'a [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    /// Nothing configured is the ordinary case, and the defaults are the ones
    /// the chart also writes.
    #[test]
    fn an_unconfigured_schedule_is_the_default_one() {
        assert_eq!(
            Schedule::from_lookup(lookup(&[])).unwrap(),
            Schedule::default()
        );
        assert_eq!(Schedule::default().poll(), Duration::from_secs(60));
        assert_eq!(Schedule::default().splay_max(), Duration::from_secs(300));
    }

    /// Both values travel, proved with numbers no default could have produced.
    #[test]
    fn both_values_arrive() {
        let vars = [
            ("TLS_ROTATION_POLL_SECS", "17"),
            ("TLS_ROTATION_SPLAY_MAX_SECS", "941"),
        ];
        let schedule = Schedule::from_lookup(lookup(&vars)).unwrap();
        assert_eq!(schedule.poll(), Duration::from_secs(17));
        assert_eq!(schedule.splay_max(), Duration::from_secs(941));
    }

    /// A ZERO POLL IS A HOT LOOP, not a way of turning the watcher off. Sleeping
    /// for no time at all re-reads and re-hashes the files as fast as a core
    /// allows, for the life of the pod — a setting nobody asked for, running
    /// quietly, which is the failure the strict parse exists to prevent.
    #[test]
    fn a_zero_poll_interval_is_refused() {
        let vars = [("TLS_ROTATION_POLL_SECS", "0")];
        assert!(matches!(
            Schedule::from_lookup(lookup(&vars)),
            Err(ScheduleError::ZeroPoll)
        ));
    }

    /// A zero SPLAY is the opposite: a supported choice, and what a
    /// single-replica or development deployment wants.
    #[test]
    fn a_zero_splay_is_allowed() {
        let vars = [("TLS_ROTATION_SPLAY_MAX_SECS", "0")];
        let schedule = Schedule::from_lookup(lookup(&vars)).unwrap();
        assert_eq!(schedule.splay_max(), Duration::ZERO);
        assert_eq!(schedule.poll(), Duration::from_secs(60));
    }

    /// PARSED, NOT SALVAGED. A value that was set and cannot be used fails boot
    /// naming the variable, rather than leaving an operator who believes they
    /// changed the interval running the old one. An empty string is a SET value
    /// — that is what a values override nulling the block renders.
    #[test]
    fn a_value_that_cannot_be_parsed_is_refused() {
        for (key, value) in [
            ("TLS_ROTATION_POLL_SECS", ""),
            ("TLS_ROTATION_POLL_SECS", "60s"),
            ("TLS_ROTATION_POLL_SECS", "-1"),
            ("TLS_ROTATION_SPLAY_MAX_SECS", "five minutes"),
            ("TLS_ROTATION_SPLAY_MAX_SECS", "1.5"),
        ] {
            let vars = [(key, value)];
            assert!(
                matches!(
                    Schedule::from_lookup(lookup(&vars)),
                    Err(ScheduleError::Unparsable { key: named, .. }) if named == key
                ),
                "{key}={value:?} must be refused, naming the variable"
            );
        }
    }

    #[test]
    fn hex_renders_every_byte_as_two_digits() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
