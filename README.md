# Synthetic branch protection laboratory

A public test repository with synthetic fixtures and an ephemeral synthetic
signing key. It contains no application code, owner credential, or production
configuration. The public key is committed. The synthetic private key is not.

The read-only verification job executes only the trusted base. An operator
reruns the PR event after a receipt is recorded. The job fails if the event
SHA is stale or if the candidate changes the workflow or verifier.

## PR-scoped decision experiment

`scripts/premerge_decision.py` models a gate that runs immediately before
merge. It accepts a live PR and owner receipt, verifies both, then checks a
second signature from a separately configured verifier. The verdict is
bound to the PR, comment, base, head, protected-path digest and exact
receipt bytes. It expires after 60 seconds. Before permitting in the
simulation, the gate reads the PR and receipt again. A withdrawn or
expired receipt wins over an earlier CI success.

The tests use ephemeral independent signing keys and simulated GitHub
readers. The experiment publishes no status and performs no merge.
Passing its job says nothing about whether GitHub's branch rule calls
it. The existing required lab check remains in place.

For native enforcement, evaluate a protected merge queue with checks over
the unique merge-group context in an authorized organization-owned public
lab. Alternatively, authorize a dedicated GitHub App as the only actor
allowed to update the protected branch, subject to all other rules.
Before any production proposal, test the check's authenticated source,
same-SHA isolation, auto-invalidation on receipt withdrawal and expiry,
and races between authorization and the actual merge.
