//! What this process does when the material it read at boot is replaced
//! underneath it — and, now, WHICH FILES this service puts in front of the
//! watcher that does it.
//!
//! **The watcher itself moved out.** `Schedule`, `Inputs`, `Presented`, `watch`
//! and the `yadgar_tls_certificate_not_after_seconds` gauge live in
//! [`yadgar_lifecycle::rotate`], pinned by tag per ADR-0526. This file was the
//! ORIGINAL, and `task` and `gateway` each carried a near-byte-identical copy of
//! it — the state ADR-0523 asked to be ended before it arrived: *"the watcher
//! core is repo-agnostic and is about to exist in four copies; lift it into a
//! shared crate before the third."* What is left here is the half that is
//! genuinely this service's, and this service reads more at boot than either of
//! the other two.
//!
//! # The ruling: exit on change
//!
//! Serving certificates are read ONCE, when the listener is built.
//! [`crate::serve::builder`] hands tonic an acceptor holding an
//! `Arc<ServerConfig>` built there and then, and nothing afterwards can swap it.
//! So a pod started today serves its day-0 leaf until it restarts, whatever
//! cert-manager writes into the Secret in the meantime. The chart mounts those
//! Secrets as DIRECTORIES rather than with `subPath`, deliberately, so kubelet
//! does refresh the files inside the pod. Only the process never re-reads them.
//!
//! [`yadgar_lifecycle::rotate::watch`] polls a digest of every file in
//! [`crate::rotate::watch_set`] — one per file, so a change can be reported by NAME. On a
//! change it logs which file, and the old and new leaf fingerprints, waits out a
//! per-pod splay, and ends. The caller selects on that, drains, and returns
//! `Ok(())`. **A change is not an error, so the exit code is 0.**
//!
//! **THE SET IS NOT "THE TLS FILES", AND TWO OF ITS SEVEN MEMBERS SAY SO.**
//! ADR-0523's rule is about PROVENANCE, never payload: every file the process
//! read at boot is watched, whatever the bytes inside it are for. The enrolment
//! CA is token payload and the broker password is not a certificate at all; both
//! are mounted as directories precisely so they can rotate, and both are read
//! exactly once. A rule that admitted only transport material would let each of
//! them go stale in silence, which is the failure this whole module exists to
//! refuse. `File::read` and `File::certificate` are watched identically in the
//! crate for exactly that reason — the role decides only what is REPORTED.
//!
//! **THE CLIENT CERTIFICATE IS THE MEMBER WITH THE WORST TRANSPORT FAILURE.**
//! ADR-0516 records that an expired CLIENT leaf STOPS a hop rather than degrading
//! it, so a process that read it once and never again keeps serving perfectly and
//! stops being able to reach its own store — on a date, with nothing having
//! warned. The serving leaf is the milder case this module was written for.
//!
//! **THE ENROLMENT CA IS IN THAT SET, and it is not a transport input.** The
//! chart mounts it as a DIRECTORY for the propagation a rotation needs, and
//! `iam` reads it once. Left unwatched, a gateway CA rotation leaves this process
//! minting tokens carrying a CA that no longer signs anything: no exit, no gauge
//! movement, no log.
//!
//! # THE BROKER PASSWORD IS IN THAT SET, and its failure is the worst of them
//!
//! `boot::nats_credentials` reads `NATS_PASSWORD_FILE` once, and
//! [`crate::invalidate::Invalidator::connect`] builds one
//! `async_nats::ConnectOptions` from it and caches the `Client` for the life of
//! the process. NATS authenticates per CONNECTION, at handshake time, so a
//! rotated Secret breaks NOTHING until the next reconnect — a broker restart or
//! a TCP blip — and then re-authentication fails carrying the password the pod
//! booted with.
//!
//! **AND THEN NOTHING FAILS LOUDLY.** `async-nats` retries a refused reconnect
//! FOR EVER by default, so the handler task never ends, `Client::publish` keeps
//! returning `Ok(())` out of a local buffer, and the error arm in
//! [`crate::invalidate`] never runs — measured against a real broker rather than
//! reasoned about. **A revoked credential stays usable for the whole of its D72
//! cache TTL, at every gateway, until somebody restarts the pod.** No exit, no
//! gauge movement, and no publish error. This watch set is what makes the pod
//! restart instead of sitting in that state.
//!
//! **Exit-on-change rather than re-authentication, and the alternative is real.**
//! `async_nats::ConnectOptions::with_auth_callback` is invoked from
//! `Connector::try_connect_to` on EVERY dial, internal reconnects included, so a
//! callback that re-read the file would genuinely pick up a rotated password
//! without a restart. It is rejected on three grounds, none of them "it cannot be
//! done": it OVERWRITES every other auth method, so the credential path stops
//! being the one `tests/nats_auth.rs` asserts the bytes of; it would give this one
//! member of the set a second, different rotation behaviour, and a watch set where
//! membership does not imply a uniform consequence is one nobody can reason about;
//! and it fixes only the reconnect, leaving a live process holding a credential the
//! deployment has retired with no way for an operator to tell.
//!
//! **NO GAUGE FOR IT, and that is not an omission.** `Inputs::export_not_after`
//! publishes the `notAfter` of a certificate; a password has no validity period
//! to publish, and inventing one would put a number on a dashboard that means
//! nothing. A rotation of it is reported the way the private key and the CA
//! bundle are: by NAME, in the WARN line the exit is logged with.
//!
//! # WHY THE SET IS A FUNCTION AND NOT A RUN OF STATEMENTS IN `main`
//!
//! It used to be FOUR builder calls scattered across `main.rs` — one beside each
//! piece of boot that read a file, up to a hundred and fifty lines apart. No test
//! in this repository spawned the binary then, so deleting any one of them
//! compiled, passed the whole suite, and shipped a process that would never notice that
//! file rotating. `tests/tls_rotation.rs` could not catch it either: it rebuilt
//! the same assembly by hand through the same four methods, so `main.rs` and the
//! test could disagree while both stayed green — and a builder that quietly added
//! nothing is a defect this repository has actually had.
//!
//! [`crate::rotate::watch_set`] is the one expression naming this service's material, and
//! `main.rs` calls it rather than repeating it. `tests/assembly.rs` calls the SAME
//! function, so deleting a member from the list below turns a test red.
//!
//! # THE PROPERTY THAT DECIDED IT, and the one every change here must keep
//!
//! **If the watcher dies you get today's behaviour, never worse.** A file that
//! cannot be read is not a changed one; an unparsable certificate is not a
//! changed one; no material at all means no watch. Nothing may end the watch over
//! a state it is merely unsure about, because ending it exits the process. The
//! crate holds that property and the tests for it.

pub use yadgar_lifecycle::rotate::{
    watch, Configuration, File, Inputs, Material, Presented, Schedule, ScheduleError,
    CERTIFICATE_NOT_AFTER, WATCHED_FILES_UNREADABLE,
};

use crate::invalidate::Credentials;
use crate::serve::ServerTls;
use crate::service::{EnrolmentConfig, SERVICE};
use crate::upstream::UpstreamTls;

// THE LISTENER'S `Material` IS THE CRATE'S (B-U5). `ServerTls` is
// `yadgar_lifecycle::serve_tls::ServerTls` now, and the crate implements the
// trait beside the type: the serving certificate, its key, and the client CA
// bundle exactly when `LISTEN_TLS_CLIENT_AUTH` verifies — the files its
// `builder` reads, and no others. This file's own impl covered the first two;
// it is deleted rather than kept, which the orphan rule would refuse anyway.

/// The CA bundle `iam-db`'s certificate is verified against, AND the client
/// certificate this service presents to it.
///
/// **BOTH HALVES, and the second one is the load-bearing member.** The client
/// certificate and its key are read once in `yadgar_dial::TlsOptions::prepare`,
/// out of a directory mount that rotates. Left out of the set, this process
/// works perfectly until that leaf expires and then fails hard, with no exit, no
/// gauge movement and no log.
///
/// The identity is `Some`/`Some` or `None`/`None` and cannot be half of one:
/// [`crate::upstream::UpstreamTls`] refuses a certificate without its key at
/// boot, so there is no half-configured arm to handle here.
impl Material for UpstreamTls {
    fn files(&self) -> Vec<File<'_>> {
        let mut files = vec![File::read(self.ca_file())];
        if let (Some(certificate), Some(key)) =
            (self.client_certificate_file(), self.client_key_file())
        {
            files.push(File::certificate(Presented::Client, certificate));
            files.push(File::read(key));
        }
        files
    }
}

/// The password this service presents to the broker.
///
/// Not a certificate, and watched on exactly the same ground — see the module
/// documentation for why its rotation is the one with no other signal at all.
impl Material for Credentials {
    fn files(&self) -> Vec<File<'_>> {
        vec![File::read(self.password_file())]
    }
}

/// The CA every D73 enrolment token carries.
///
/// **Token payload rather than transport, and `None` is an ordinary state.** A
/// deployment may configure a gateway without naming a CA file, and then there
/// is nothing to watch — not a certificate that failed to load.
impl Material for EnrolmentConfig {
    fn files(&self) -> Vec<File<'_>> {
        self.ca_path().map(File::read).into_iter().collect()
    }
}

/// Everything this deployment read at boot, hashed as it was read.
///
/// **THE LIST IS THE ASSERTION, and this service's list is the longest in the
/// estate.** Six materials, up to twelve files. Each of the first five is
/// opt-in and `Option<M>: Material` folds an absent one to nothing, so no
/// argument needs a branch at the call site — which is what let the four
/// per-role builder methods this module used to carry collapse into one trait.
///
/// **`nats_tls` IS NOT FOLDED THROUGH [`UpstreamTls`]'s OWN `Material` IMPL,
/// AND THAT IS DELIBERATE (B-N3, ADR-0885).** `yadgar_lifecycle::rotate::Inputs`
/// keeps exactly ONE `Leaf` per [`Presented`] kind (`certificate` overwrites
/// whatever the kind already held, keyed on the kind alone, never on the
/// path) — true of `upstream`'s own client leaf already, harmless there
/// because nothing else in this service presents one. ADR-0885 gives the
/// broker hop its OWN client certificate, independent of `iamDb.tls`'s, so a
/// deployment presenting both would have TWO `Presented::Client` leaves —
/// and folding the second one through the same impl would silently
/// overwrite the first in `CERTIFICATE_NOT_AFTER{kind="client"}`'s gauge,
/// reporting only whichever leaf this function happened to fold last.
///
/// **ROTATION SAFETY IS NOT WHAT THIS COSTS.** `Inputs::also` de-duplicates
/// and hashes by PATH, not by kind, so the broker's CA, its client
/// certificate and its key are watched and exit-on-change exactly as every
/// other file here does — an expired or rotated broker leaf still restarts
/// this pod (ADR-0516). What is lost is ONLY the expiry GAUGE for this one
/// leaf; see the PR that added this comment for the measurement and the
/// follow-up this gap was filed as (a per-path, not per-kind, gauge in
/// `yadgar-lifecycle` — out of this repository's reach while that crate is
/// pinned by tag).
///
/// **THE MOUNTED CONFIGURATION DOCUMENT IS THE LAST MEMBER, AND THE ONLY ONE
/// THAT IS NEVER ABSENT (step 2a).** `config` is `shared/shared.yaml`, mounted
/// from `yadgarhq/config`'s `shared` ConfigMap, and it is a [`Material`] like
/// the first five: `Configuration` implements the trait by returning the one
/// file it read its schedule from, so folding it in here joins the document to
/// the ADR-0523 watch set through the exact same `Inputs::of` path the
/// certificates, the broker password and the enrolment CA already take. An
/// operator editing `shared.yaml` restarts this pod exactly as editing a CA
/// bundle would. It is `&Configuration`, not `Option<&Configuration>` —
/// unlike the other five, there is no deployment shape in which this service
/// has none.
///
/// **A cleartext `iam` already watched something before this**, unlike `task`
/// and `gateway`: the chart ships a default enrolment CA, so the set was
/// non-empty with TLS off at both ends. Now every `iam`, cleartext or not,
/// watches the mounted document too.
///
/// Called from `main.rs` INSIDE boot, beside the code that read these files:
/// every entry is hashed as it is added, so the baseline is the bytes the process
/// actually loaded. Collecting paths and reading them when the watcher first
/// polls would put the rest of boot inside a window where a kubelet swap quietly
/// becomes the baseline, and the real rotation would never be noticed.
///
/// **SIX ARGUMENTS, AND THE ALTERNATIVE IS WORSE THAN THE LINT.** Grouping
/// them into a struct is what clippy asks for, and a struct that satisfied
/// the call sites would carry `Default` — at which point a per-half case in
/// `tests/assembly.rs` could omit a member with `..Default::default()`, and
/// a NEW member added later would be silently absent from every one of
/// them. Positional arguments make every call site name every member, which
/// is what turns a deleted one red instead of quiet.
#[allow(clippy::too_many_arguments)]
pub fn watch_set(
    listener: Option<&ServerTls>,
    upstream: Option<&UpstreamTls>,
    broker: Option<&Credentials>,
    nats_tls: Option<&UpstreamTls>,
    enrolment: Option<&EnrolmentConfig>,
    config: &Configuration,
) -> Inputs {
    // THE SAME FOLD `Inputs::of` PERFORMS, split around the one member that
    // is not a plain `Material` call: `nats_tls`'s files are watched by
    // `also` (see this function's own doc), positioned here, between
    // `broker` and `enrolment`, so a deployment's watched-files list reads
    // in the same order its arguments do — `config` stays genuinely LAST.
    let inputs = Inputs::new(SERVICE)
        .take(&listener)
        .take(&upstream)
        .take(&broker);
    let inputs = match nats_tls {
        None => inputs,
        Some(tls) => {
            let inputs = inputs.also(tls.ca_file());
            match (tls.client_certificate_file(), tls.client_key_file()) {
                (Some(certificate), Some(key)) => inputs.also(certificate).also(key),
                // `UpstreamTls` holds both or neither, so this arm is "neither".
                _ => inputs,
            }
        }
    };
    inputs.take(&enrolment).take(config)
}
