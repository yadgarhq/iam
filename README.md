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

The twin gates its own boot — probe, migrate, then listen (D69) — so an `iam-db`
that is not ready has no endpoint behind the headless Service and
`balance::connect` fails loudly. Blocking this service's startup on that would
turn one module's slow migration into a cascading outage, and under D68 a pod
stuck in startup is one the autoscaler cannot help. A request that cannot reach
the store fails with `UNAVAILABLE`, which is recoverable; refusing to start is
not.

The crypto keys are the opposite case, deliberately: their absence fails boot.
A service that started without them would pass its readiness probe and then
fail every request touching a credential or a personal-data field — a pod that
looks healthy and is wrong. `main.rs` calls `crypto::Keys::from_env()` before
binding the listener for exactly that reason.

## Local development

```bash
make proto     # refresh the vendored protos from PROTO_VERSION (D70)
cargo test     # the rules; they need no engine and no -db
```

`protoc` must be on `PATH` — types are generated, never hand-written (D16).

## Configuration

| variable                                       | default            |                                                                                                                                                                                                                                                                       |
| ---------------------------------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `IAM_DB_HOST` / `IAM_DB_PORT`                  | `iam-db` / `50051` | the twin's headless Service                                                                                                                                                                                                                                           |
| `YADGAR_KEYS_DIR`                              | —                  | where `crypto::Keys::from_env` reads the AES-GCM/HMAC keys (D72)                                                                                                                                                                                                      |
| `LISTEN`                                       | `0.0.0.0:50052`    |                                                                                                                                                                                                                                                                       |
| `LISTEN_TLS_ENABLED`                           | unset              | serve gRPC over TLS. Exactly `1` enables it; anything else, `true` included, leaves the plaintext listener. Off by default                                                                                                                                            |
| `LISTEN_TLS_CERT_FILE` / `LISTEN_TLS_KEY_FILE` | unset              | the PEM certificate this service PRESENTS, and its private key. Both required when `LISTEN_TLS_ENABLED` is `1`. A missing path, an unreadable file, a PEM holding no certificate, and a key that does not match the certificate each refuse the boot, naming the file |
| `IAM_DB_TLS_ENABLED`                           | unset              | dial `iam-db` over TLS. Exactly `1` enables it. Off by default. The opposite direction from `LISTEN_TLS_*`                                                                                                                                                            |
| `IAM_DB_TLS_CA_FILE` / `IAM_DB_TLS_DOMAIN`     | unset              | the PEM bundle `iam-db`'s certificate is VERIFIED against, and the name to check it for. The CA file is required when `IAM_DB_TLS_ENABLED` is `1`; the domain defaults to `IAM_DB_HOST`                                                                               |
| `METRICS_LISTEN`                               | `0.0.0.0:9090`     |                                                                                                                                                                                                                                                                       |
| `LOGIN_RESPONSE_FLOOR_MS`                      | `250`              | the shortest time `Login` may answer in                                                                                                                                                                                                                               |
| `REDEEM_RESPONSE_FLOOR_MS`                     | `750`              | the same, for `RedeemEnrolment`, which does more work                                                                                                                                                                                                                 |
| `ENROLMENT_GATEWAY`                            | —                  | the address enrolment tokens carry; unset disables IssueEnrolment only                                                                                                                                                                                                |
| `ENROLMENT_CA_PEM_FILE`                        | —                  | PEM of the root CA; absent means system trust applies                                                                                                                                                                                                                 |
| `NATS_URL`                                     | —                  | the broker D72's cache invalidation is published on. Absent or unreachable is survivable and loudly logged                                                                                                                                                            |
| `NATS_USER` / `NATS_PASSWORD_FILE`             | unset              | the broker account and a FILE holding its password. Unset connects unauthenticated and WARNs. An unreadable or empty password file, or a password with no user, EXITS at boot rather than connecting anonymously                                                      |
