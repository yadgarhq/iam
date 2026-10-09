//! WHICH FILES THIS DEPLOYMENT WATCHES — the half of the rotation watcher that
//! is this service's own, and the longest such list in the estate.
//!
//! The watcher's behaviour is `yadgar-lifecycle`'s and is tested there, against
//! the atomic `..data` swap kubelet really performs: that a change ends the
//! watch, that an identical-bytes swap does not, that an unreadable mount is
//! survived, that the leaf rather than the issuer is what the gauge reports.
//! None of that is repeated here. What is here is the claim only this repository
//! can make: **an `iam` configured this way reads exactly these nine files, so
//! exactly these nine files are watched.**
//!
//! **THE MUTANT THIS FILE EXISTS TO KILL.** The watch set used to be FOUR builder
//! calls scattered across `main.rs`, up to a hundred and fifty lines apart, and
//! no test in this repository spawned the binary then — so deleting any one of them
//! compiled, passed the whole suite, and shipped a process that would never
//! notice that file rotating. The old `tests/tls_rotation.rs` could not catch it:
//! it rebuilt the same assembly by hand through the same four methods, so
//! `main.rs` and the test could disagree while both stayed green. Every case
//! below goes through [`yadgar_iam::rotate::watch_set`] — the SAME function
//! `main.rs` calls — so a member deleted from that list turns this red.
//!
//! **THREE OF THE NINE ARE NOT TRANSPORT MATERIAL.** The broker password is not
//! a certificate and the enrolment CA is token payload; both are read once at
//! boot out of directory mounts that rotate, and ADR-0523's rule is about
//! provenance rather than payload. The mounted configuration document (step 2a)
//! is the third — `yadgarhq/config`'s `shared.yaml`, read for the rotation
//! schedule itself rather than for any transport role. A watch set that admitted
//! only TLS files would let each of them go stale in silence.
//!
//! CERTIFICATES ARE MINTED PER RUN, for the reason `tests/serve_tls.rs` gives: a
//! fixture key in the repository is a secret in the repository, and it expires on
//! a date nobody is watching.

use std::path::{Path, PathBuf};

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};

use yadgar_iam::invalidate::Credentials;
use yadgar_iam::rotate::{
    self, Configuration, Presented, CERTIFICATE_NOT_AFTER, WATCHED_FILES_UNREADABLE,
};
use yadgar_iam::serve::{self, ServerTls};
use yadgar_iam::service::EnrolmentConfig;
use yadgar_iam::upstream::{self, UpstreamTls};

/// The leaf's expiry, and the issuing authority's — DELIBERATELY DIFFERENT and
/// deliberately a decade apart. cert-manager writes the leaf first and the chain
/// after it, so an implementation that parsed the LAST certificate in the file
/// would report an expiry ten years out.
const LEAF_NOT_AFTER: i64 = 1_813_017_600; // 2027-06-15T00:00:00Z

/// The CLIENT leaf's expiry — a year past the serving leaf's, and deliberately
/// so. Both are exported under one metric name, separated only by the `kind`
/// label, so an implementation that gauged the wrong one would land on a
/// plausible number. A distinct date turns that into a failing equality.
const CLIENT_NOT_AFTER: i64 = 1_844_640_000; // 2028-06-15T00:00:00Z

/// The BROKER's OWN client leaf's expiry (B-N3, ADR-0885) — A THIRD,
/// DISTINCT DATE, two years past `CLIENT_NOT_AFTER`'s. A leaf that merely
/// reused `client_leaf`'s bytes under a second file name would make
/// `the_brokers_own_client_leaf_is_watched_without_touching_iam_dbs_gauge`
/// vacuous: folding it through the SAME `Presented::Client` slot
/// `rotate::watch_set` deliberately avoids would overwrite with an
/// identical value, and the case would pass whether or not that avoidance
/// held. A distinct expiry is what makes "the gauge still reports iam-db's"
/// a claim a mutation can falsify.
const BROKER_CLIENT_NOT_AFTER: i64 = 1_907_712_000; // 2030-06-15T00:00:00Z

/// One generation of the mount: the file names the chart writes, and their
/// contents.
type Generation = Vec<(String, String)>;

/// Everything a fully configured `iam` reads at boot, as a whole mount's worth
/// of files.
///
/// `tls.pem` holds the leaf FOLLOWED BY the authority that issued it, which is
/// the shape cert-manager writes.
fn generation(san: &str) -> Generation {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_after = date_time_ymd(2037, 6, 15);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "yadgar-iam assembly test authority");
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_after = date_time_ymd(2027, 6, 15);
    params.distinguished_name.push(DnType::CommonName, san);
    let leaf = params.signed_by(&key, &ca).unwrap();

    // THE CLIENT LEAF, and it is a DIFFERENT certificate issued for a DIFFERENT
    // purpose (ADR-0516). `ClientAuth` rather than `ServerAuth`, because a peer
    // verifying a client chain refuses a leaf naming the wrong one even though
    // it trusts the issuer perfectly well.
    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(vec![format!("{san}-caller")]).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.not_after = date_time_ymd(2028, 6, 15);
    client_params
        .distinguished_name
        .push(DnType::CommonName, format!("{san}-caller"));
    let client_leaf = client_params.signed_by(&client_key, &ca).unwrap();

    // THE BROKER'S OWN CLIENT LEAF (B-N3, ADR-0885) — A SEPARATE certificate
    // from `client_leaf` above, from the same authority but its own key and
    // its own, DELIBERATELY DIFFERENT `not_after`
    // (`BROKER_CLIENT_NOT_AFTER`). Reusing `client_leaf`'s bytes here would
    // make the collision-avoidance case this leaf exists for pass whether
    // or not the avoidance held — see that constant's own doc.
    let broker_client_key = KeyPair::generate().unwrap();
    let mut broker_client_params =
        CertificateParams::new(vec![format!("{san}-broker-caller")]).unwrap();
    broker_client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    broker_client_params.not_after = date_time_ymd(2030, 6, 15);
    broker_client_params
        .distinguished_name
        .push(DnType::CommonName, format!("{san}-broker-caller"));
    let broker_client_leaf = broker_client_params
        .signed_by(&broker_client_key, &ca)
        .unwrap();

    vec![
        ("tls.pem".to_string(), format!("{}{}", leaf.pem(), ca.pem())),
        ("tls-key.pem".to_string(), key.serialize_pem()),
        // THE AUTHORITY THE LISTENER VERIFIES ITS CALLERS AGAINST (B-U5), from
        // `tls.clientCaSecret`. The same authority here, as in the reference
        // deployment; a separate FILE, because it is a separate mount.
        ("client-ca.pem".to_string(), ca.pem()),
        ("ca.pem".to_string(), ca.pem()),
        ("enrolment-ca.pem".to_string(), ca.pem()),
        (
            "client.pem".to_string(),
            format!("{}{}", client_leaf.pem(), ca.pem()),
        ),
        ("client-key.pem".to_string(), client_key.serialize_pem()),
        // NOT A CERTIFICATE, and in the set for the reason the enrolment CA is:
        // the process read it at boot, the chart mounts it as a DIRECTORY
        // precisely so it can rotate, and `async_nats` bakes it into the
        // `ConnectOptions` of a client cached for the life of the process. A
        // TRAILING NEWLINE, because `kubectl create secret --from-file` keeps
        // the one an editor added and `boot::nats_credentials` trims it.
        (
            "nats-password".to_string(),
            format!("sentinel-broker-password-{}\n", unique()),
        ),
        // THE BROKER'S OWN CA AND CLIENT LEAF (B-N3, ADR-0885) — DISTINCT
        // FILE NAMES from `ca.pem`/`client.pem`/`client-key.pem` above,
        // because ADR-0885's whole point is that the broker hop's identity
        // has its OWN mount rather than sharing `iam-db`'s. Reusing the SAME
        // AUTHORITY is fine (one issuer, every leaf in this estate); reusing
        // the SAME client leaf is not — see `BROKER_CLIENT_NOT_AFTER`.
        ("nats-ca.pem".to_string(), ca.pem()),
        (
            "nats-client.pem".to_string(),
            format!("{}{}", broker_client_leaf.pem(), ca.pem()),
        ),
        (
            "nats-client-key.pem".to_string(),
            broker_client_key.serialize_pem(),
        ),
    ]
}

/// A directory shaped the way kubelet shapes a mounted Secret.
///
/// ```text
///   <root>/..1234-5678/tls.pem
///   <root>/..data      -> ..1234-5678
///   <root>/tls.pem     -> ..data/tls.pem
/// ```
///
/// The service is handed `<root>/tls.pem` and never learns any of the rest,
/// which is exactly what the chart does: a DIRECTORY mount, never `subPath`,
/// because a `subPath` mount is a one-time copy kubelet never refreshes. The
/// shape is kept here even though nothing below rotates the mount, so that what
/// the configuration names is a symlink through `..data` — the path shape the
/// deployed process actually holds.
struct Mount {
    root: PathBuf,
}

impl Mount {
    fn new(files: &Generation) -> Self {
        let root = std::env::temp_dir().join(format!("yadgar-iam-assembly-{}", unique()));
        std::fs::create_dir(&root).unwrap();
        let generation = root.join(format!("..{}", unique()));
        std::fs::create_dir(&generation).unwrap();
        for (name, contents) in files {
            std::fs::write(generation.join(name), contents).unwrap();
        }
        std::os::unix::fs::symlink(generation.file_name().unwrap(), root.join("..data")).unwrap();
        for (name, _) in files {
            std::os::unix::fs::symlink(Path::new("..data").join(name), root.join(name)).unwrap();
        }
        Self { root }
    }

    /// The path the SERVICE is given — a symlink through `..data`.
    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A name no other case in this run can collide with.
fn unique() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

/// The listener's transport as a DEPLOYMENT states it — through the same five
/// variables the chart renders, with client authentication `required` so the
/// client CA joins the set (B-U5).
///
/// **Built from the configuration rather than from paths spelled out here.** A
/// helper naming nine paths would prove only that the watcher watches what it is
/// handed; going through the real loaders proves that a deployment's
/// CONFIGURATION puts them there, which is the half that can silently be wrong.
fn listener_tls(mount: &Mount) -> ServerTls {
    let vars = [
        ("LISTEN_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "LISTEN_TLS_CERT_FILE".to_string(),
            mount.path("tls.pem").display().to_string(),
        ),
        (
            "LISTEN_TLS_KEY_FILE".to_string(),
            mount.path("tls-key.pem").display().to_string(),
        ),
        ("LISTEN_TLS_CLIENT_AUTH".to_string(), "required".to_string()),
        (
            "LISTEN_TLS_CLIENT_CA_FILE".to_string(),
            mount.path("client-ca.pem").display().to_string(),
        ),
    ];
    serve::from_lookup(move |k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()))
        .expect("a complete configuration")
        .expect("the flag is set")
}

/// How `iam-db` is verified, and who this service says it is on that hop.
fn upstream_tls(mount: &Mount) -> UpstreamTls {
    let vars = [
        ("IAM_DB_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "IAM_DB_TLS_CA_FILE".to_string(),
            mount.path("ca.pem").display().to_string(),
        ),
        (
            "IAM_DB_TLS_CLIENT_CERT_FILE".to_string(),
            mount.path("client.pem").display().to_string(),
        ),
        (
            "IAM_DB_TLS_CLIENT_KEY_FILE".to_string(),
            mount.path("client-key.pem").display().to_string(),
        ),
    ];
    UpstreamTls::from_lookup(upstream::IAM_DB, upstream::IAM_DB_CHART_KEY, move |k| {
        vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    })
    .expect("a complete configuration")
    .expect("the flag is set")
}

/// The broker credential as a DEPLOYMENT states it — through the same two
/// variables the chart renders, and through `boot::nats_credentials` rather than
/// by naming the path.
///
/// **The whole point is the wiring.** Handing the watch set a path spelled out
/// here would say nothing about whether the value `main` actually resolves
/// carries the path at all. The gap this closes was exactly that shape: a
/// password file read at boot and absent from every builder.
fn broker_credentials(mount: &Mount) -> Credentials {
    let vars = [
        (
            "NATS_USER".to_string(),
            "sentinel-broker-account".to_string(),
        ),
        (
            "NATS_PASSWORD_FILE".to_string(),
            mount.path("nats-password").display().to_string(),
        ),
    ];
    yadgar_iam::boot::nats_credentials(move |k| {
        vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    })
    .expect("a complete configuration")
    .expect("both variables are set")
}

/// The broker hop's OWN transport (B-N3, ADR-0885) — through
/// `boot::nats_tls` rather than by naming the path, for the same reason
/// [`broker_credentials`] goes through `boot::nats_credentials`.
fn nats_tls_fixture(mount: &Mount) -> UpstreamTls {
    let vars = [
        ("NATS_TLS_ENABLED".to_string(), "1".to_string()),
        (
            "NATS_TLS_CA_FILE".to_string(),
            mount.path("nats-ca.pem").display().to_string(),
        ),
        (
            "NATS_TLS_CLIENT_CERT_FILE".to_string(),
            mount.path("nats-client.pem").display().to_string(),
        ),
        (
            "NATS_TLS_CLIENT_KEY_FILE".to_string(),
            mount.path("nats-client-key.pem").display().to_string(),
        ),
    ];
    yadgar_iam::boot::nats_tls("nats://nats:4222", move |k| {
        vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    })
    .expect("a complete configuration")
    .expect("the flag is set")
}

/// The enrolment CA, loaded the way `main` loads it — which is what records the
/// path alongside the PEM.
fn enrolment_config(mount: &Mount) -> EnrolmentConfig {
    EnrolmentConfig::load(
        "https://gateway.invalid:18443",
        mount.path("enrolment-ca.pem").to_str(),
    )
    .expect("a gateway and a readable CA")
}

/// The mounted document `yadgarhq/config` renders into the `shared` ConfigMap
/// (step 2a) — under its OWN root, never [`Mount`]'s, because the two
/// ConfigMaps land in separate directories in the real deployment and nothing
/// here should suggest otherwise.
fn configuration(body: &str) -> Configuration {
    let root = std::env::temp_dir().join(format!("yadgar-iam-assembly-config-{}", unique()));
    std::fs::create_dir_all(root.join("shared")).unwrap();
    std::fs::write(root.join("shared").join("shared.yaml"), body).unwrap();
    Configuration::under(root)
}

/// EVERY FILE THE CONFIGURATION NAMED IS IN THE WATCH SET, IN ORDER, AND NOTHING
/// ELSE.
///
/// This is the assertion the whole lift was for. Delete any of the five
/// materials from the list in `rotate::watch_set` and this case goes red; before
/// the lift the equivalent edit in `main.rs` was a mutant nothing killed — and
/// dropping the enrolment CA in particular used to pass every rotation case this
/// repository had.
///
/// **THE MOUNTED CONFIGURATION DOCUMENT IS LAST**, which is what one client leaf
/// presented to `iam-db`, plus the broker password and the enrolment CA, plus the
/// shared document every service now mounts (step 2a), looks like once folded.
#[test]
fn the_watch_set_holds_every_file_this_deployment_configured() {
    let mount = Mount::new(&generation("iam"));
    let config = configuration("tlsRotation:\n  pollSeconds: 17\n  splayMaxSeconds: 941\n");

    assert_eq!(
        rotate::watch_set(
            Some(&listener_tls(&mount)),
            Some(&upstream_tls(&mount)),
            Some(&broker_credentials(&mount)),
            None,
            Some(&enrolment_config(&mount)),
            &config,
        )
        .watched(),
        vec![
            mount.path("tls.pem").as_path(),
            mount.path("tls-key.pem").as_path(),
            mount.path("client-ca.pem").as_path(),
            mount.path("ca.pem").as_path(),
            mount.path("client.pem").as_path(),
            mount.path("client-key.pem").as_path(),
            mount.path("nats-password").as_path(),
            mount.path("enrolment-ca.pem").as_path(),
            config.path(),
        ],
        "a fully configured `iam` reads nine files at boot: the listener's leaf, its key \
         and the authority it verifies callers against (B-U5), the bundle `iam-db` is \
         verified against, the client identity presented on that hop (ADR-0516), the \
         broker password, the CA every D73 token carries, and the mounted configuration \
         document every service now watches (step 2a)"
    );
}

/// THE CERTIFICATE IS FIRST, because it is the one the gauge and the
/// fingerprints speak for — and the CLIENT leaf is a different one.
///
/// Two distinct expiry dates rather than one: an implementation that reported the
/// serving leaf under both `kind` labels would land on a plausible number and
/// pass an assertion that only checked one.
#[test]
fn each_certificate_is_reported_as_the_one_it_is() {
    let mount = Mount::new(&generation("iam"));
    let config = configuration("tlsRotation:\n  pollSeconds: 17\n  splayMaxSeconds: 941\n");
    let inputs = rotate::watch_set(
        Some(&listener_tls(&mount)),
        Some(&upstream_tls(&mount)),
        Some(&broker_credentials(&mount)),
        None,
        Some(&enrolment_config(&mount)),
        &config,
    );

    assert_eq!(
        inputs.watched().first(),
        Some(&mount.path("tls.pem").as_path())
    );
    assert_eq!(inputs.not_after(Presented::Serving), Some(LEAF_NOT_AFTER));
    assert_eq!(inputs.not_after(Presented::Client), Some(CLIENT_NOT_AFTER));
}

/// EACH MATERIAL CONTRIBUTES ON ITS OWN, so a deployment running cleartext with
/// an enrolment CA still has something to watch — which is what a default install
/// of this chart actually is, and where `iam` differs from `task` and `gateway`.
///
/// **NOTHING CONFIGURED IS NO LONGER NOTHING TO WATCH (step 2a).** The mounted
/// configuration document is unconditional — `&Configuration`, not
/// `Option<&Configuration>` — so even the emptiest `iam` now watches
/// `shared.yaml` and restarts when an operator edits it.
#[test]
fn each_configured_material_contributes_on_its_own() {
    let mount = Mount::new(&generation("iam"));
    let config = configuration("tlsRotation:\n  pollSeconds: 17\n  splayMaxSeconds: 941\n");

    assert_eq!(
        rotate::watch_set(None, None, None, None, None, &config).watched(),
        vec![config.path()],
        "with nothing else configured, the mounted configuration document is the only \
         thing watched — it is unconditional, unlike the four materials beside it"
    );

    assert_eq!(
        rotate::watch_set(Some(&listener_tls(&mount)), None, None, None, None, &config).watched(),
        vec![
            mount.path("tls.pem").as_path(),
            mount.path("tls-key.pem").as_path(),
            mount.path("client-ca.pem").as_path(),
            config.path(),
        ],
        "a listener reads its certificate, the key belonging to it and — when client \
         authentication verifies — the client CA, plus the mounted document"
    );

    assert_eq!(
        rotate::watch_set(None, Some(&upstream_tls(&mount)), None, None, None, &config).watched(),
        vec![
            mount.path("ca.pem").as_path(),
            mount.path("client.pem").as_path(),
            mount.path("client-key.pem").as_path(),
            config.path(),
        ],
        "the client certificate and its key both join the set beside the bundle, and the \
         mounted document beside both"
    );

    assert_eq!(
        rotate::watch_set(
            None,
            None,
            Some(&broker_credentials(&mount)),
            None,
            None,
            &config
        )
        .watched(),
        vec![mount.path("nats-password").as_path(), config.path()],
        "the broker password is watched on the same ground as a certificate: the process \
         read it at boot"
    );

    // TLS OFF, enrolment CA set: the chart's DEFAULT shape.
    assert_eq!(
        rotate::watch_set(
            None,
            None,
            None,
            None,
            Some(&enrolment_config(&mount)),
            &config
        )
        .watched(),
        vec![mount.path("enrolment-ca.pem").as_path(), config.path()],
        "a cleartext deployment with an enrolment CA still watches it, plus the mounted \
         document"
    );

    // A gateway with a publicly-trusted certificate reads no CA at all, so there
    // is no path to watch beyond the mounted document even though the
    // configuration exists.
    let no_ca = EnrolmentConfig::load("https://gateway.invalid:18443", None)
        .expect("no CA is a deployment, not an error");
    assert_eq!(
        rotate::watch_set(None, None, None, None, Some(&no_ca), &config).watched(),
        vec![config.path()],
        "no CA configured leaves only the mounted document, which is never absent"
    );

    // THE BROKER'S OWN TRANSPORT (B-N3, ADR-0885): its CA and its client pair
    // are watched by PATH, on their own, independent of `iam-db`'s.
    assert_eq!(
        rotate::watch_set(
            None,
            None,
            None,
            Some(&nats_tls_fixture(&mount)),
            None,
            &config
        )
        .watched(),
        vec![
            mount.path("nats-ca.pem").as_path(),
            mount.path("nats-client.pem").as_path(),
            mount.path("nats-client-key.pem").as_path(),
            config.path(),
        ],
        "the broker hop's CA and client pair are watched on their own, at their own \
         paths — never `iam-db`'s"
    );
}

/// ADR-0885's WHOLE POINT, PROVED: the broker's client leaf is watched at
/// its OWN path alongside `iam-db`'s, and the two neither collide nor
/// silently replace each other in the watched-files list.
///
/// **THE GAUGE IS THE OTHER HALF, AND IT DOES NOT DOUBLE.** `rotate.rs`'s
/// own doc explains why: `yadgar_lifecycle::rotate::Inputs` keeps one
/// `Leaf` per `Presented` kind, so a second `Presented::Client` leaf would
/// overwrite `iam-db`'s in `CERTIFICATE_NOT_AFTER{kind="client"}` — this is
/// why the broker's leaf is watched by `Inputs::also` rather than folded
/// through `UpstreamTls`'s `Material` impl. This case asserts the
/// consequence directly: with BOTH client leaves configured, the gauge
/// still emits exactly two series — one `serving`, one `client` — and the
/// `client` one is still `iam-db`'s own expiry, unperturbed by the broker's
/// leaf being watched at all.
#[test]
fn the_brokers_own_client_leaf_is_watched_without_touching_iam_dbs_gauge() {
    // THE PRECONDITION THIS WHOLE CASE RESTS ON: the two leaves' expiries
    // must actually differ, or an implementation that overwrote iam-db's
    // with the broker's would pass this case by accident.
    assert_ne!(BROKER_CLIENT_NOT_AFTER, CLIENT_NOT_AFTER);

    let mount = Mount::new(&generation("iam"));
    let config = configuration("tlsRotation:\n  pollSeconds: 17\n  splayMaxSeconds: 941\n");

    let inputs = rotate::watch_set(
        None,
        Some(&upstream_tls(&mount)),
        None,
        Some(&nats_tls_fixture(&mount)),
        None,
        &config,
    );
    let watched = inputs.watched();
    assert!(
        watched.contains(&mount.path("client.pem").as_path()),
        "iam-db's client leaf must still be watched: {watched:?}"
    );
    assert!(
        watched.contains(&mount.path("nats-client.pem").as_path()),
        "the broker's own client leaf must be watched too, at its own path: {watched:?}"
    );

    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        rotate::watch_set(
            None,
            Some(&upstream_tls(&mount)),
            None,
            Some(&nats_tls_fixture(&mount)),
            None,
            &config,
        )
        .export_not_after()
    });
    let emitted = snapshotter.snapshot().into_vec();
    assert_eq!(
        emitted.len(),
        1,
        "with no listener configured, exactly one gauge — iam-db's client leaf — must \
         be published; a second series here would mean the broker's leaf gained its own \
         gauge, which this repository has no `kind` label for: {emitted:?}"
    );
    let (composite, _unit, _description, value) = &emitted[0];
    let labels: Vec<(String, String)> = composite
        .key()
        .labels()
        .map(|l| (l.key().to_string(), l.value().to_string()))
        .collect();
    assert_eq!(
        labels,
        vec![
            ("service".to_string(), "iam".to_string()),
            ("kind".to_string(), "client".to_string()),
        ]
    );
    match value {
        DebugValue::Gauge(seconds) => assert_eq!(
            seconds.into_inner(),
            CLIENT_NOT_AFTER as f64,
            "the one gauge must still be iam-db's own client leaf's expiry, unperturbed \
             by the broker's leaf being configured and watched alongside it"
        ),
        other => panic!("expected a gauge, got {other:?}"),
    }
}

/// THE GAUGE THIS PROCESS PUBLISHES SAYS `service = "iam"`.
///
/// The metric NAME belongs to the crate and is asserted there. What belongs here
/// is the label a dashboard selects this service on: it comes from
/// `crate::service::SERVICE`, and a value that drifted would blank a panel with
/// nothing failing.
///
/// **AND THE BROKER PASSWORD PUBLISHES NOTHING, NOR DOES THE MOUNTED
/// CONFIGURATION DOCUMENT.** A password has no validity period, and neither
/// does a YAML file; inventing one, or reusing the `kind` label for something
/// that is not a presented leaf, would put a number on a dashboard that means
/// nothing. Two series from nine watched files is the assertion that says so.
///
/// A plain `#[test]`: `with_local_recorder` is thread-local and
/// `export_not_after` is synchronous, so there is no runtime to involve.
#[test]
fn the_gauge_names_this_service_and_each_certificate_it_holds() {
    let mount = Mount::new(&generation("iam"));
    let config = configuration("tlsRotation:\n  pollSeconds: 17\n  splayMaxSeconds: 941\n");
    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        rotate::watch_set(
            Some(&listener_tls(&mount)),
            Some(&upstream_tls(&mount)),
            Some(&broker_credentials(&mount)),
            None,
            Some(&enrolment_config(&mount)),
            &config,
        )
        .export_not_after()
    });

    let emitted = snapshotter.snapshot().into_vec();
    // A metrics-util built against another `metrics` major links a SECOND
    // facade: everything compiles, nothing is captured, and the assertions below
    // would pass vacuously against an empty snapshot.
    assert_eq!(
        emitted.len(),
        2,
        "one gauge per CERTIFICATE this process loaded, and nothing for the four watched \
         files that are not certificates — check for a duplicate `metrics` crate"
    );

    let mut seen: Vec<(Vec<(String, String)>, f64)> = emitted
        .iter()
        .map(|(composite, _unit, _description, value)| {
            let key = composite.key();
            assert_eq!(key.name(), CERTIFICATE_NOT_AFTER);
            let labels = key
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            let seconds = match value {
                DebugValue::Gauge(seconds) => seconds.into_inner(),
                other => panic!("expected a gauge, got {other:?}"),
            };
            (labels, seconds)
        })
        .collect();
    seen.sort_by(|a, b| a.0.cmp(&b.0));

    assert_eq!(
        seen,
        vec![
            (
                vec![
                    ("service".to_string(), "iam".to_string()),
                    ("kind".to_string(), "client".to_string()),
                ],
                CLIENT_NOT_AFTER as f64
            ),
            (
                vec![
                    ("service".to_string(), "iam".to_string()),
                    ("kind".to_string(), "serving".to_string()),
                ],
                LEAF_NOT_AFTER as f64
            ),
        ],
        "each gauge carries the expiry of the leaf it names, and the two are not \
         interchangeable: an expired CLIENT leaf STOPS this hop (ADR-0516)"
    );
}

/// THE UNREADABLE-FILES GAUGE COUNTS EVERY WATCHED FILE, NOT ONLY THE
/// CERTIFICATES, AND A ZERO IS ONE OF ITS VALUES.
///
/// `yadgar-lifecycle` v0.1.2 added `yadgar_rotation_watched_files_unreadable`
/// and the crate tests what it counts. What only this repository can say is that
/// the series a dashboard would select — this service's name, on this service's
/// own watch set — is the one that arrives, and that it arrives when NOTHING is
/// wrong. A gauge appearing only on the bad day cannot be told apart from an
/// exporter that is not running.
///
/// **THE FILE REMOVED HERE IS THE BROKER PASSWORD, DELIBERATELY.** The case
/// above asserts that a password publishes no EXPIRY, because it has none. This
/// one asserts the other half: it is still a watched file, so it still counts
/// here — and the worst failure in this service's watch set is the one a
/// certificate gauge can never speak for.
///
/// **NOTHING IS REGISTERED FOR IT AT THE SERVICE END, and this is the check that
/// says so rather than an assumption.** `yadgar_telemetry::metrics::install_prometheus`
/// installs `PrometheusBuilder::new()` with no allow-list and no idle timeout,
/// and `metrics-exporter-prometheus`'s `render` walks the gauge snapshot and
/// consults `descriptions` only for the `# HELP` line — so an undescribed gauge
/// renders, and no `describe_gauge!` call is needed here.
///
/// A plain `#[test]`, for the reason the case above gives.
#[test]
fn the_unreadable_gauge_carries_this_service_and_is_published_at_zero_too() {
    let mount = Mount::new(&generation("iam"));
    let config = configuration("tlsRotation:\n  pollSeconds: 17\n  splayMaxSeconds: 941\n");
    let inputs = rotate::watch_set(
        Some(&listener_tls(&mount)),
        Some(&upstream_tls(&mount)),
        Some(&broker_credentials(&mount)),
        None,
        Some(&enrolment_config(&mount)),
        &config,
    );

    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    let gone = mount.path("nats-password");

    let (nothing_wrong, at_zero, one_gone, at_one) =
        metrics::with_local_recorder(&recorder, || {
            let nothing_wrong = inputs.export_unreadable();
            let at_zero = snapshotter.snapshot().into_vec();
            std::fs::remove_file(&gone).expect("the mount is this test's own");
            let one_gone = inputs.export_unreadable();
            let at_one = snapshotter.snapshot().into_vec();
            (nothing_wrong, at_zero, one_gone, at_one)
        });

    assert!(
        nothing_wrong.is_empty(),
        "every one of the seven files this mount names, plus the mounted configuration \
         document, is readable: {nothing_wrong:?}"
    );
    assert_eq!(
        one_gone,
        vec![gone.display().to_string()],
        "the broker password was removed, so it is the one unreadable file and the \
         seven beside it — including the mounted configuration document — are not"
    );

    for (emitted, expected) in [(at_zero, 0.0_f64), (at_one, 1.0_f64)] {
        // A metrics-util built against another `metrics` major links a SECOND
        // facade: everything compiles, nothing is captured, and the assertions
        // below would pass vacuously against an empty snapshot.
        assert_eq!(
            emitted.len(),
            1,
            "one series for the whole watch set, labelled by service and by nothing \
             per-path — check for a duplicate `metrics` crate"
        );
        let (composite, _unit, _description, value) = &emitted[0];
        let key = composite.key();
        assert_eq!(key.name(), WATCHED_FILES_UNREADABLE);
        let labels: Vec<(String, String)> = key
            .labels()
            .map(|l| (l.key().to_string(), l.value().to_string()))
            .collect();
        assert_eq!(
            labels,
            vec![("service".to_string(), "iam".to_string())],
            "a path label would make this metric's cardinality a property of a \
             deployment's configuration"
        );
        match value {
            DebugValue::Gauge(count) => assert_eq!(count.into_inner(), expected),
            other => panic!("expected a gauge, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// THE CHART'S mountPath MUST AGREE WITH WHAT THE BINARY READS.
//
// Before v0.2.0, `Schedule::from_lookup` answered an unmatched key with a
// DEFAULT rather than an error, so a variable nobody read was silent in both
// directions — and this file used to derive the chart's env-var spelling from
// the TEMPLATE and feed it straight to that reader, a real coupling test. Both
// `from_lookup` and `from_env` are deleted from `yadgar-lifecycle` now, and
// this binary reads `rotate::Configuration::mounted()` instead (`main.rs`), so
// that particular coupling has nothing left to assert.
//
// STEP 2B (MIGRATION_NOTES.md, ADR-0569/ADR-0570) deleted the chart's two
// TLS_ROTATION_* environment variables, and with them the guard test that kept
// the chart rendering both for the OLD binary while this release's digest was
// still in flight to `yadgarhq/argocd`. That guard's job ended the moment the
// digest landed; it is not a coupling this binary needs to keep passing.
//
// WHAT STILL HAS TO HOLD: the chart's `mountPath` must keep agreeing with the
// path the binary reads, asserted below by deriving the expected path from
// `Configuration::mounted()` itself, so a rename in `yadgar-lifecycle` turns
// this red rather than agreeing with a copy of itself.
// ---------------------------------------------------------------------------

/// The template this service is deployed from, read at COMPILE TIME so this can
/// never pass against a chart that is not in the tree.
const DEPLOYMENT: &str = include_str!("../chart/templates/deployment.yaml");

/// THE CHART'S `mountPath` AND THE PATH THIS BINARY ACTUALLY READS MUST AGREE.
///
/// Naming the expected path a second time here would agree with itself for
/// ever, so it is derived from `Configuration::mounted()` — the exact call
/// `main.rs` makes — and a rename inside `yadgar-lifecycle` turns this red
/// instead.
#[test]
fn the_chart_mounts_the_shared_configmap_where_this_binary_looks_for_it() {
    let mounted = Configuration::mounted();
    let shared_dir = mounted
        .path()
        .parent()
        .expect("the mounted document has a parent directory")
        .display()
        .to_string();

    assert!(
        DEPLOYMENT
            .lines()
            .any(|line| line.trim() == format!("mountPath: {shared_dir}")),
        "yadgar_lifecycle::rotate::Configuration::mounted() reads {}, but no volumeMount in \
         this chart's deployment.yaml names {shared_dir} as its mountPath — a pod would exit \
         at boot naming a path this chart never mounts",
        mounted.path().display()
    );
}
