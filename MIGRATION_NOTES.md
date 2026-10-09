# Migration notes

Commands for a human to run, and orderings a human must decide. Nothing here is
applied automatically.

## The broker hop's TLS switch is now required (B-N3, ADR-0852, ADR-0845, ADR-0885)

**Breaking: `nats.tls.enabled` must be set to `true` or `false` explicitly.**
The expand release (B-N3E) made it optional; this release makes it `required`
in the schema with no chart default, guarded in
`templates/render-checks.yaml` the same way `tls.enabled` and
`iamDb.tls.enabled` already are. A values source without it is refused at
`helm template` / `helm lint --strict` / an Argo sync, naming the key. The
binary refuses to boot when `NATS_URL` is set and `NATS_TLS_ENABLED` is
absent, empty, or not `1`/`0`.

- `yadgarhq/chart`'s `chart/ci/values.yaml` and `example/values.yaml` already
  state `iam.nats.tls.enabled: false` (chart#39, B-P2).
- `false` renders exactly what the expand rendered: `NATS_TLS_ENABLED="0"`
  and nothing else.
- `true` dials the broker over TLS. It verifies the broker against
  `nats.tls.caSecret` / `caSecretKey` (default `nats-tls` / `ca.crt`, one key
  mounted at `/var/run/config/nats-ca/ca.pem`) and nothing else. It refuses a
  broker that serves no TLS. It presents `nats.tls.clientCertSecret` when
  that is set (default `iam-client-tls`, mounted at its own path,
  `/var/run/secrets/nats-client-tls`). Set it only after platform's NATS
  serves TLS (B-N4.1). The flip is B-N4.2.
- **ADR-0885: a SEPARATE chart key from `iamDb.tls.clientCertSecret`, with
  its OWN mount.** `iam` does not share one client-identity mount across
  every upstream the way `gateway` does; its only client leaf mount before
  this release was `iam-db-client-cert`, gated on `iamDb.tls`. Turning
  `iamDb.tls` off or rotating `iamDb.tls.clientCertSecret` has no effect on
  the broker hop's identity, and vice versa — even though both key's
  defaults name the same underlying Secret, `iam-client-tls`.

Revert is a straight `git revert`.

## The broker password — this image first, the broker second (ledger 518)

`iam` can now present a credential to the broker it publishes D72's cache
invalidation on. **Nothing to run against the cluster from here**, and nothing in
this repository changes what the running deployment does until
`yadgarhq/deploy` gives the broker an `authorization` block.

**The ordering is not symmetric.** Merge this repository first and
`yadgarhq/deploy` second:

- **This image against a broker with no authorization block**: unchanged
  behaviour. `nats.passwordSecret` is empty by default, so the chart sends the
  binary no credential and `iam` connects exactly as it always did. It logs a
  warning at every boot saying the hop is unauthenticated, which is true and is
  the point.
- **The broker with an authorization block, under an image that predates this**:
  every connection is refused, `iam` starts anyway, and **no invalidation is ever
  published**. A revoked credential then keeps working at the gateway for the
  whole of `credentialCache.ttlSeconds`, which is exactly the failure D72's event
  exists to close. `iam` keeps authenticating, so nothing looks broken.

Argo auto-syncs `yadgarhq/deploy`, so that ordering is decided by which pull
request merges first.

**The three ways to be half-configured all fail the boot**, naming the variable:
`NATS_PASSWORD_FILE` pointing at a file that cannot be read, a file that is
empty, and a password with no `NATS_USER`. Each describes a deployment that asked
for authentication and cannot perform it, and the only alternative to refusing is
connecting anonymously — which succeeds and looks healthy.

**A broker that REFUSES the credential does not fail the boot**, and that
asymmetry is deliberate. `iam` is the authentication plane: refusing to start
would turn a broker fault into an estate-wide authentication outage once the
gateway's credential cache expired. It starts, logs the refusal as a deployment
error rather than as an outage — the two have different messages, because an
operator who reads "cannot reach the broker" for a wrong password goes looking
for a network fault that is not there — and D72's TTL is the backstop meanwhile.

**To revert**, clear `nats.passwordSecret` in the chart. That is one value and no
new image — but it is only the revert while the broker still accepts an
unauthenticated client, so revert `yadgarhq/deploy` first if the authorization
block has already landed.

## The ServiceAccount (ledger 511)

`iam` now runs under a ServiceAccount of its own with
`automountServiceAccountToken: false`, rather than the namespace's `default`.

**Nothing to run.** An ordinary GitOps sync creates the account and rolls the
Deployment onto it. It grants nothing: there is no Role and no RoleBinding,
because `iam` calls no Kubernetes API.

The one thing to know before reverting: if a future change needs `iam` to call
the API server, the token mount has to be turned back on in **two** places — this
chart's `serviceaccount.yaml` and the pod spec — because the pod spec wins where
they disagree.

## The inheritable setting — this image before any -db that enforces it (ledger 532)

`iam` now carries ADR-0522's `owner_reads_own_record` outward on
`ResolveCredential` and writes one level of it through `SetInheritedSetting`.
**Nothing to run against the cluster from here**, and nothing in this repository
changes what the running deployment does until a `-db` starts reading the
setting.

**The ordering is not symmetric.** Deploy this image before any `-db` that
enforces the setting:

- **This image against a `-db` that does not read the setting yet**: unchanged
  behaviour. The setting travels on the response and nothing consumes it.
- **A `-db` that enforces the setting, under an `iam` image that predates this**:
  the field is never populated, so the organisation's value arrives
  `SETTING_VALUE_UNSPECIFIED`. That is `INVALID_ARGUMENT` at the reader rather
  than a silent fall back to the strict policy, which is the refusal ADR-0522
  exists to make writable. Reads fail loudly instead of quietly narrowing.

**The new verb is inert today, and the ordering for it runs the other way.**
`iam` serves `SetInheritedSetting` on this image, and every call to it fails
today, on two independent counts:

- `iam-db` is pinned at proto **v1.8.0**, and its `IamDbService` declares
  thirteen RPCs with no `SetInheritedSetting`. The forward from `iam` therefore
  fails `UNIMPLEMENTED`, which the caller sees as `UNIMPLEMENTED` with the fixed
  message `the iam-db call failed`. The verb stays inert until `iam-db` pins
  **v1.9.0 or later and implements the RPC**.
- `gateway` is pinned at proto **v1.6.0**, and names neither
  `SetInheritedSetting` nor `owner_reads_own_record`. Nothing exposes the verb to
  an administrator, and the field reaches no reader, until `gateway` pins
  **v1.9.0 or later** as well.

So the write path needs `iam-db` first and the read path needs `gateway`, both
**after** this image rather than before it. Neither is a reason to hold this
image back: an inert verb changes nothing that runs today.

**A policy change is not instant, and there is no event to cut it short.** The
setting travels on the credential the gateway caches, and an organisation-level
write touches every cached credential in the deployment. No invalidation subject
on this contract says so — the ones `iam` publishes are keyed on a `user_id` a
setting write does not carry. **A deployment that tightens this policy waits the
cache out**, bounded by `credentialCache.ttlSeconds`.

**The write is unattributable, and that is a property of the contract.**
`SetInheritedSetting` carries no attested caller identity, in common with every
administrative RPC on this service. The authorisation check is the gateway's, on
D73's admin flag. **D73's bootstrap token must NOT be extended to this verb** —
it reaches `CreateUser` and `SetUserAdmin` and nothing else, and a token that
exists to create the first admin must not rewrite the read policy for the whole
deployment before an admin exists to notice.

**A release is needed for any of this to run anywhere.** Merging publishes no
image; a `v*` tag does.
