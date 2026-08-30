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

| variable                      | default            |                                                                  |
| ----------------------------- | ------------------ | ---------------------------------------------------------------- |
| `IAM_DB_HOST` / `IAM_DB_PORT` | `iam-db` / `50051` | the twin's headless Service                                      |
| `YADGAR_KEYS_DIR`             | —                  | where `crypto::Keys::from_env` reads the AES-GCM/HMAC keys (D72) |
| `LISTEN`                      | `0.0.0.0:50052`    |                                                                  |
| `METRICS_LISTEN`              | `0.0.0.0:9090`     |                                                                  |
