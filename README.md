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

## GitHub App Checks API contract

The adapter prepares one check name per PR and a deterministic external ID
bound to this repository, its PR number and the exact head. A check read or
update validates the numeric App ID reported by GitHub as well as the run
ID, name, external ID and head. Two PRs sharing a head get separate runs.
The lab tests inject a synthetic Checks API. No App is installed.

For a live lab installation, scope a dedicated App to this repository
only. Grant Checks write, Pull requests read, Issues read, Contents read
and the implicit Metadata read. Use a short-lived installation token in a
trusted service, not a checked-out candidate or a PR workflow. These
permissions allow reading approval context and publishing checks. They do
not allow merging, content writes or repository administration.

A withdrawal or expiration makes the fresh decision deny even when a
previous check still says success. Reconciliation then changes only that
PR and SHA's check to failure. In a live service schedule expiry and
handle PR synchronization, comment edits and deletions, with webhook
authentication and periodic reconciliation. If GitHub cannot be read,
the decision must remain blocked.

The per-PR name and external ID are application context. GitHub's branch
rule does not interpret external IDs and cannot use a fixed required
check name to express this distinction. The current protected check
stays required. Before activation, prove the App's identity against the
live API and use either a protected merge queue with unique merge context
or a separate authorized decision path that enforces fresh authorization
at merge. This adapter has no merge operation.
