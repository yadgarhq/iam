# iam

The identity module's **logic service**: business rules, no store.

Decisions in [`yadgarhq/docs`](https://github.com/yadgarhq/docs): D4 (the twin
split), D23 (client-side balancing), D70 (how the protos get here), D72 (what a
credential is and how it is resolved).

## It holds no store, and that absence is the design

There is no `sqlx` and no `yadgar-store` in this crate's dependency tree. A logic
service reaches its data only over the `-db` API — which is what makes the twin a
**connection concentrator** rather than merely a boundary. N replicas of this
service with embedded pools would multiply connections against an engine with
hard limits (D4).

`proto-contract-design.md` keeps a per-repo check that the binary has no store
SDK in its dependency tree, for exactly this reason.

## What it adds over `iam-db`

Everything a credential store has no business doing itself (D72):

- **Hashing and encryption happen here, never at the store.** Passwords are
  compared against an Argon2id hash; personal data (a username, a display name)
  is AES-GCM encrypted before it crosses into `iam-db`, with a blind index
  computed alongside it for equality lookup. `iam-db` holds ciphertext and
  hashes, and nothing that lets it recover the plaintext on its own.
- **A credential is an opaque bearer token**, random and hashed at rest.
  `ResolveCredential` is the one RPC on the request path — the gateway calls it
  on a cache miss, never per request, because `recall` is the latency-critical
  path (D25) and every call crosses this boundary.
- **Minting is administrative, not an agent operation.** `IssueCredential`,
  `CreateUser` and the team-membership RPCs are GitOps or CLI surface; an agent
  presents a credential, it never issues one.

## Enrolment: the admin creates the account, the person sets the password

`IssueEnrolment` mints a single-use secret and `RedeemEnrolment` spends it (D73).
The admin never learns the password, so an audit trail can tell the person from
whoever onboarded them, and the password never travels through a chat message.

What the admin hands over is one base64 string. It carries the secret **and the
trust anchor** — the gateway address and the root CA — because a client that has
never met this deployment has nothing else to verify the gateway against. `iam`
fills both from its own configuration, so an admin assembles neither and cannot
get either wrong.

**An unconfigured deployment disables `IssueEnrolment` and nothing else.** `iam`
warns at boot naming `ENROLMENT_GATEWAY`, and the RPC refuses with
`FAILED_PRECONDITION` naming it again. That keeps the contract's rule whole — the
fields have no presence, so a token minted without them would be structurally
valid and point at nothing — without the availability cost of refusing to start.
The crypto keys are the opposite case and still fail boot: without them every
request touching a credential fails, so there is no reduced service left to
protect. Here there is, and `iam` is the authentication plane for the estate.

**`RedeemEnrolment` is unauthenticated by construction** — the secret is the
whole authenticator — so it carries `Login`'s enumeration problem in a sharper
form, and takes three precautions rather than two:

- **One failure, not three.** Unknown, spent and expired are all
  `UNAUTHENTICATED` with one message. The store tells them apart and records
  which; the caller cannot.
- **Constant work.** The chosen password is hashed with Argon2id _before_ the
  secret is looked up, and the refusal path pays the same verification the
  success path pays. Both cost two Argon2id operations, so the response time is
  not a function of what the store found.
- **Validation before lookup.** Every check that does not need the secret runs
  first. Otherwise `INVALID_ARGUMENT` arrives only once the secret is confirmed
  and the status code itself says the secret was good — an oracle cleaner than
  timing, and one constant work does not touch.

**It has its own response-time floor, and not `Login`'s.** The three refusals are
decided inside `iam-db`, so any timing difference between them arises in another
process and no amount of constant work here can equalise it; only a floor over
the whole handler covers that. The value is separate because a redemption
legitimately costs more — two Argon2id operations and a further round trip — and
`Login`'s floor would be exceeded by every successful redemption, turning the
warning that says "raise this" into one that fires on every call.

Two residuals are accepted rather than hidden, and both are in the contract:

- A retry mints a **fresh** credential, because a token shown once and kept as a
  hash cannot be replayed. Every attempt but the last leaves an orphan.
  `ListCredentials` exists to find those and is **not implemented yet** — until
  it is, an orphan is reachable only in the store.
- A **replayed `IssueEnrolment` key returns a token that cannot be redeemed.**
  The key is forwarded and the store deduplicates it, so the replay answers with
  the original `enrolment_id` while keeping the original secret's hash — and the
  secret in the token was minted afresh. The store keeps only a hash, which is
  the same fact that puts token _resend_ outside D73's first cut. The recovery is
  the one this RPC already is: mint another.

## The inheritable setting, which this service carries and never resolves

ADR-0522 makes "an owner reads their own record" a setting rather than a
constant. An organisation states a value and a lock; a team may hold an
override, and it applies only where the organisation has not locked.

`ResolveCredential` carries that setting outward beside the identity, and
`SetInheritedSetting` writes one level of it by forwarding to `iam-db`. **This
service resolves none of it.** The answer depends on the team of the _row_ being
read, which no caller upstream of the query knows, so the resolution belongs
where the reach is computed. What travels here are the inputs.

**Nothing is substituted for an unstated value.** When the organisation row is
not there, `iam-db` answers with `org_value` `SETTING_VALUE_UNSPECIFIED` and
`org_locked` false. An absent setting is contract-legal too, and the whole-value
move carries either one without telling them apart. False is the permissive half
of a policy the deployment never stated. The value and the lock are carried
through exactly as received, so a reader that enforces the setting refuses rather
than inheriting a default nobody chose.

**The write validates here.** The clause list lives on
`yadgar.common.v1.SettingScope` and every clause is `INVALID_ARGUMENT`. Each
refusal lands before the store is called, so a rejected request leaves no row and
burns no idempotency key. Withdrawing a team's override costs an affirmative
`clear` byte: an omitted value on its own is refused rather than read as a
deletion (ADR-0524).

**Two gaps, stated rather than left to be found.** The request carries no
attested caller identity, in common with every administrative RPC here — so
`iam` can neither verify the caller is an administrator nor record who changed a
policy governing who may read which records. The check belongs at the gateway,
which is the one place identity is attested (ADR-0488). And a change binds only
once the gateway's cached credential is gone: an organisation-level write touches
every cached credential in the deployment and no event on the contract says so,
so a deployment that tightens this policy waits the cache out.

## Client-side balancing, and the part that gets forgotten

gRPC holds **one** long-lived HTTP/2 connection. A normal Service balances at
connection time, so a client would open one connection, get one pod, and send
everything there for the life of the process — the other replicas idle while
looking healthy, and D68's autoscaler responding to the latency by adding more
pods that also receive nothing.

So `iam-db`'s Service is **headless**: DNS returns every pod address and this
service balances across them itself.

**Re-resolution is the half that must not be forgotten**, and it is wired up: a
background task re-resolves every 5s and applies the difference to the channel's
endpoint set. Resolving once at startup would pin the client to whichever pods
existed then — new replicas getting no traffic, and a rolling update leaving it
talking to addresses that no longer exist.

Two things the loop deliberately does not do:

- **It never acts on an empty resolution.** A headless Service briefly returns
  nothing during some rollouts, and removing every endpoint on that basis is a
  self-inflicted outage from a transient DNS answer.
- **It never tears down a working channel because DNS failed.** A blip is not a
  reason to stop using endpoints that currently work.

`balance::diff` is a pure function over two address sets, extracted so the part
that is easy to get silently wrong is testable: re-inserting an unchanged
endpoint churns connections every tick and looks like working code.

`iam`'s own Service is an ordinary `ClusterIP` — nothing balances across `iam`
replicas client-side yet, the same gap `gateway`'s `upstream.rs` documents for
`task`.

## It does not wait for `iam-db` to be ready — but it does wait for its keys

This heading was **false until `yadgar-dial` v0.2.0**, which is worth writing
down rather than quietly correcting. The twin gates its own boot — probe,
migrate, then listen (D69) — so an `iam-db` that is not ready has no endpoint
behind the headless Service; `yadgar_dial::connect` returned
`BalanceError::Dns` for that — CoreDNS answers NXDOMAIN for a headless Service
with no ready endpoint, and the resolver's error was propagated before the
empty-answer branch was ever reached — and `main` propagated it with `?`. This service therefore DID wait for
`iam-db`, by exiting. ADR-0532 made the boot dial lazy: the name is seeded into
the balancer and dialled until an address answers, so `connect` returns a channel
and the failure moves to the request.

Blocking this service's startup on the twin would turn one module's slow
migration into a cascading outage, and under D68 a pod stuck in startup is one
the autoscaler cannot help. A request that cannot reach the store fails with
`UNAVAILABLE`, which is recoverable; refusing to start is not.

**What it costs now that it is real, said plainly.** The readiness probe is a
`tcpSocket` on the gRPC port, so this pod is Ready as soon as it is listening —
and with `iam-db` absent it is Ready and answers `UNAVAILABLE` to everything
touching a credential or an encrypted personal-data field. The probe is
deliberately not changed to gate on the upstream, and the reason is D69's own
scope rather than a preference: D69's boot-failure rule is about a capability of
an engine the module OWNS, which is why the sequence it names is probe, migrate,
then listen and why `iam-db` is where that sequence lives. This service owns no
engine of its own to probe, so the only thing it could gate on is an RPC asking
`iam-db` whether `iam-db` is up — inference by proxy, which D69's first rule
refuses by name. The discriminator that generalises is whether a restart could
change the outcome: a permanent gap (an unusable CA bundle, a missing client
certificate, absent crypto keys) still fails boot, and a transient absence dials
lazily.

`yadgar-dial`'s re-resolution loop logs at ERROR on every tick while a host has
NEVER resolved, distinctly from the warning a blip gets. **That line reaches
`kubectl logs` and nothing else today** — `dial` exports no metric for the
never-resolved state, this chart ships no `PrometheusRule`, and nothing ships
logs off the node — so the signal exists and is not yet alertable. That is the
part of the crash loop this change genuinely removes.

The crypto keys are the opposite case, deliberately: their absence fails boot.
A service that started without them would pass its readiness probe and then
fail every request touching a credential or a personal-data field — a pod that
looks healthy and is wrong. `main.rs` calls `crypto::Keys::from_env()` before
binding the listener for exactly that reason.

## A renewed certificate arrives by restart, not by reload

The certificate this service presents is read ONCE, when the listener is built,
and `tonic 0.14` cannot swap a running server's TLS configuration:
`Server::tls_config` builds an acceptor there and then, and TLS settings are
documented as ignored under `serve_with_incoming`, the only custom-acceptor path.
cert-manager renews 30 days before expiry and kubelet refreshes the mounted files
— the chart mounts those Secrets as DIRECTORIES rather than with `subPath`
precisely so it does — but nothing would make the process re-read them.

So `rotate` hashes the files `main` opened, one digest per file, as each is read:
the serving certificate, its key, the CA bundle `iam-db` is verified against, the
client certificate and key this service presents to `iam-db` (ADR-0516), the
password this service presents to the broker, and the CA every D73 enrolment
token carries. When one of them changes it logs which file, and the old and new
leaf fingerprint, waits out this pod's splay, drains through the same
`serve_with_shutdown` a signal takes, and returns. **A rotated certificate is not
an error, so the process exits 0.**

**The set is not "the TLS files", and two of its seven members say so.** ADR-0523
asks where a file came from, never what is inside it: every file the process read
at boot is watched, whatever the bytes are for.

**The enrolment CA is watched even though it is token payload rather than a
transport input.** The chart mounts it as a directory so a rotation propagates
into the pod; left unwatched, a gateway CA rotation would leave this process
minting tokens carrying a CA that no longer signs anything, with no exit, no
gauge movement and no log. It also means the watcher RUNS ON A DEFAULT INSTALL
WITH TLS OFF: `enrolment.caSecret` ships with a default, so the watch set is
empty only when `tls.enabled` is false and that value is unset.

**The broker password is watched for the same reason, and its failure is the
worst of them.** `boot::nats_credentials` reads `NATS_PASSWORD_FILE` once, and
`Invalidator::connect` bakes it into an `async_nats::ConnectOptions` whose client
is cached for the life of the process. NATS authenticates per CONNECTION, so a
rotated Secret breaks nothing until the next reconnect — a broker restart, a TCP
blip — and then re-authentication fails carrying the password the pod booted
with.

**And then nothing fails loudly.** `async-nats` retries a refused reconnect for
ever by default, so `Client::publish` keeps returning `Ok(())` out of a local
buffer and the publish error path never runs — measured against a real broker.
**A revoked credential stays usable for the whole of its D72 cache TTL, at every
gateway, until somebody restarts the pod**, and the only trace is the
`Disconnected` and `authorization violation` warnings the event callback in
`invalidate` emits. The watch set is what ends that state; the callback is what
makes it visible while it lasts.

Exit-on-change rather than re-authentication, and the alternative is real:
`async_nats::ConnectOptions::with_auth_callback` runs on every dial, reconnects
included, so a callback re-reading the file would pick up a rotation without a
restart. The decisive objection is that it only ever acts on the NEXT dial: a
process whose connection stays up keeps presenting a credential the deployment
has retired, indefinitely, with nothing to say so. It also OVERWRITES every other
auth method, taking the credential path out from under the byte-level assertions
in `tests/nats_auth.rs`, and it would give one member of the watch set a second,
different rotation behaviour. It gets no gauge either: a password has no
`notAfter` to publish, and the rotation is named in the exit log like the private
key's and the CA bundle's, which have no gauge for the same reason.

**The baseline is the bytes that were loaded**, captured beside the code that
loaded them rather than when the watcher first polls. Otherwise the rest of boot
— the `iam-db` dial, the broker connect — is a window in which a kubelet swap
quietly becomes the baseline, and the real rotation is never noticed.

**The drain is bounded.** Nothing outside the process ends a drain the process
started: `terminationGracePeriodSeconds` never runs for a self-exit, and tokio
keeps its signal handler installed after the rotation arm wins, so a later
SIGTERM is swallowed rather than fatal. `yadgar_lifecycle::DRAIN_BUDGET` is 25s
against the default 30s grace period; on expiry the process logs an error and
ends anyway. The budget must also outlast the slowest legitimate call, and
`DEFAULT_REDEEM_RESPONSE_FLOOR` is the estate's only real lower bound for that —
so the test comparing the two lives in this repository, where both numbers are.

**The budget's clock starts when shutdown is REQUESTED, not when the server
starts**, which is why `yadgar_lifecycle::drain_within` takes an already-spawned
server and the sender that asks it to stop. Wrapping the serving future in
`tokio::time::timeout` instead bounds the server's whole life, and ends the
process one budget after boot on every boot, with nothing having asked it to
stop. That defect shipped on this branch and passed 123 tests; the crate's
`tests/drain.rs` keeps it dead.

**That drain had to be fixed first.** `main` registered `tokio::signal::ctrl_c`
alone, which is SIGINT — a signal Kubernetes never sends. It sends SIGTERM, waits
out `terminationGracePeriodSeconds`, then SIGKILLs, so the drain was reached on
no rollout at all and whatever was in flight died with the process.
`yadgar_lifecycle::shutdown` now hears both, armed before the server is spawned
so a signal arriving in that window cannot take SIGTERM's default disposition.

**That last property is asserted by no test in this estate, and saying so is
better than the sentence this replaces.** The crate's `tests/shutdown.rs` sends a
real SIGTERM to the test process and proves the server RETURNED and released its
port — which a killed process could not do — so the DRAIN is covered. The ARMING
WINDOW is not: every rig waits for the port to accept before raising the signal,
and a port that accepts belongs to a task the executor has already polled, so a
mutant that armed the handlers lazily inside the returned future survives. The
missing rig has to raise SIGTERM before the serving task is first polled, and it
belongs in the crate once rather than in each adopter.

**A hash, never a modification time.** Kubelet rotates a mounted Secret by
renaming a new `..data` symlink over the old one, so every path resolves to a new
inode with a fresh mtime on every resync, changed or not. An mtime check would
restart both replicas for nothing. `yadgar-lifecycle`'s `tests/rotation.rs`
performs that exact swap, including the case where the new generation holds
identical bytes.

**The splay is the only thing separating the replicas.** They see the refreshed
file inside the same kubelet sync window, and a PodDisruptionBudget constrains
eviction — it does not govern a process that exits on its own.

**And if the watcher dies you get the old behaviour, never worse.** An unreadable
file is not a changed one, and an empty watch set means no watch.
`yadgar_tls_certificate_not_after_seconds` is the half that makes that failure
loud: it carries the expiry of the certificates this process actually loaded, so
a watcher that stopped working still shows up as a leaf ageing out. One series
per certificate, told apart by a `kind` label carrying `serving` or `client` —
two values, forever, which is what keeps a bounded label inside D67's rule.

**The client certificate is the member of that set with the worst failure.**
ADR-0516 records that an expired client leaf STOPS a hop rather than weakening
it, so this service would keep serving and stop being able to reach its own
store. Both files are mounted as a DIRECTORY and both are watched, in the same
change that mounted them.

## Local development

```bash
make proto     # refresh the vendored protos from PROTO_VERSION (D70)
cargo test     # the rules; they need no engine and no -db
```

`protoc` must be on `PATH` — types are generated, never hand-written (D16).

## Configuration

| variable                                                     | default            |                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------------------------ | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `IAM_DB_HOST` / `IAM_DB_PORT`                                | `iam-db` / `50051` | the twin's headless Service                                                                                                                                                                                                                                                                                                                                                                       |
| `YADGAR_KEYS_DIR`                                            | —                  | where `crypto::Keys::from_env` reads the AES-GCM/HMAC keys (D72)                                                                                                                                                                                                                                                                                                                                  |
| `LISTEN`                                                     | `0.0.0.0:50052`    |                                                                                                                                                                                                                                                                                                                                                                                                   |
| `LISTEN_TLS_ENABLED`                                         | unset              | serve gRPC over TLS. Exactly `1` enables it; anything else, `true` included, leaves the plaintext listener. Off by default                                                                                                                                                                                                                                                                        |
| `LISTEN_TLS_CERT_FILE` / `LISTEN_TLS_KEY_FILE`               | unset              | the PEM certificate this service PRESENTS, and its private key. Both required when `LISTEN_TLS_ENABLED` is `1`. A missing path, an unreadable file, a PEM holding no certificate, and a key that does not match the certificate each refuse the boot, naming the file                                                                                                                             |
| `IAM_DB_TLS_ENABLED`                                         | unset              | dial `iam-db` over TLS. Exactly `1` enables it. Off by default. The opposite direction from `LISTEN_TLS_*`                                                                                                                                                                                                                                                                                        |
| `IAM_DB_TLS_CA_FILE` / `IAM_DB_TLS_DOMAIN`                   | unset              | the PEM bundle `iam-db`'s certificate is VERIFIED against, and the name to check it for. The CA file is required when `IAM_DB_TLS_ENABLED` is `1`; the domain defaults to `IAM_DB_HOST`                                                                                                                                                                                                           |
| `IAM_DB_TLS_CLIENT_CERT_FILE` / `IAM_DB_TLS_CLIENT_KEY_FILE` | unset              | the certificate this service PRESENTS to `iam-db`, and its key — mutual TLS (ADR-0516). A third direction beside the two above, and off by default even when `IAM_DB_TLS_ENABLED` is `1`. Both or neither: half of an identity is refused at boot naming the variable. Both join the rotation watch set, because an expired client leaf STOPS the hop rather than degrading it                    |
| `TLS_ROTATION_POLL_SECS` / `TLS_ROTATION_SPLAY_MAX_SECS`     | deleted (step 2b)  | no longer an environment variable. This binary reads the rotation schedule from `yadgarhq/config`'s `shared.yaml` (`tlsRotation.pollSeconds` / `splayMaxSeconds`), mounted at `/etc/yadgar/config/shared/shared.yaml`. No compiled-in default: an absent or empty knob refuses to boot (ADR-0569)                                                                                                 |
| `METRICS_LISTEN`                                             | `0.0.0.0:9090`     |                                                                                                                                                                                                                                                                                                                                                                                                   |
| `LOGIN_RESPONSE_FLOOR_MS`                                    | `250`              | the shortest time `Login` may answer in                                                                                                                                                                                                                                                                                                                                                           |
| `REDEEM_RESPONSE_FLOOR_MS`                                   | `750`              | the same, for `RedeemEnrolment`, which does more work                                                                                                                                                                                                                                                                                                                                             |
| `ENROLMENT_GATEWAY`                                          | —                  | the address enrolment tokens carry; unset disables IssueEnrolment only                                                                                                                                                                                                                                                                                                                            |
| `ENROLMENT_CA_PEM_FILE`                                      | —                  | PEM of the root CA; absent means system trust applies                                                                                                                                                                                                                                                                                                                                             |
| `NATS_URL`                                                   | —                  | the broker D72's cache invalidation is published on. Absent or unreachable is survivable and loudly logged                                                                                                                                                                                                                                                                                        |
| `NATS_USER` / `NATS_PASSWORD_FILE`                           | unset              | the broker account and a FILE holding its password. Unset connects unauthenticated and WARNs. An unreadable or empty password file, or a password with no user, EXITS at boot rather than connecting anonymously. The file joins the rotation watch set, because the password is baked into a client cached for the life of the process and a rotated Secret is invisible until a reconnect fails |
