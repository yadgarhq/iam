# Migration notes

Commands for a human to run, and orderings a human must decide. Nothing here is
applied automatically.

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
