# Synthetic branch protection laboratory

A public test repository with synthetic fixtures and an ephemeral synthetic
signing key. It contains no application code, owner credential, or production
configuration. The public key is committed. The synthetic private key is not.

The read-only verification job executes only the trusted base. An operator
reruns the PR event after a receipt is recorded. The job fails if the event
SHA is stale or if the candidate changes the workflow or verifier.
