"""Public synthetic lab: verify a fresh merge decision without performing a merge."""
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from spec_guard_approval import (
    ApprovalError, REPOSITORY, SIGNATURE, require, scope_from_github, verify,
)


VERIFIER_NAMESPACE = "synthetic-premerge@lab.example.invalid"
VERDICT_LIFETIME = timedelta(seconds=60)


def timing(instant: datetime) -> str:
    return instant.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def verdict_message(scope, receipt: str, verifier_id: int, checked_at: datetime) -> bytes:
    receipt_hash = hashlib.sha256(receipt.encode("utf-8")).hexdigest()
    return (
        f"schema=synthetic-premerge/v2\nrepository={REPOSITORY}\n"
        f"pull_request={scope.pr}\nreceipt_id={scope.comment_id}\nowner_id={scope.owner_id}\n"
        f"verifier_id={verifier_id}\nbase_sha={scope.base_sha}\nhead_sha={scope.head_sha}\n"
        f"protected_paths_sha256={scope.paths_sha256}\nreceipt_sha256={receipt_hash}\n"
        f"checked_at={timing(checked_at)}\ndecision=permit-synthetic-merge\n"
    ).encode("ascii")


def check_verifier_signature(message: bytes, signature: str, allowed_signers: Path, verifier_id: int):
    require(isinstance(signature, str) and len(signature) <= 4096 and SIGNATURE.fullmatch(signature),
            "Invalid verifier signature format")
    require(allowed_signers.is_file(), "Missing trusted verifier keyring")
    with TemporaryDirectory() as folder:
        file = Path(folder) / "verdict.sig"
        file.write_text(signature.rstrip("\n") + "\n", encoding="ascii")
        result = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(allowed_signers.resolve()),
             "-I", f"lab-verifier-{verifier_id}", "-n", VERIFIER_NAMESPACE, "-s", str(file)],
            input=message, capture_output=True, timeout=10,
        )
    require(result.returncode == 0, "Verdict did not come from the configured verifier")


def evaluate(*, get_pr, get_receipt, pr: int, receipt_id: int, owner_id: int,
             verifier_id: int, repository: Path, owners: Path, verifiers: Path,
             signature: str, checked_at: datetime, now):
    """Testable authorization decision. Readers must query the current GitHub state."""
    require(type(verifier_id) is int and verifier_id > 0, "Invalid verifier identity")
    require(checked_at.tzinfo is not None and checked_at.microsecond == 0,
            "Verifier timestamp must use whole UTC seconds")
    pr_state, receipt = get_pr(pr), get_receipt(receipt_id)
    scope = scope_from_github(pr_state, receipt, pr, receipt_id, owner_id, repository)
    require(pr_state.get("draft") is False, "Draft PR cannot be authorized for merge")
    receipt_until = verify(receipt, scope, owners, now())
    message = verdict_message(scope, receipt["body"], verifier_id, checked_at)
    check_verifier_signature(message, signature, verifiers, verifier_id)

    current_pr, current_receipt = get_pr(pr), get_receipt(receipt_id)
    current_scope = scope_from_github(current_pr, current_receipt, pr, receipt_id, owner_id, repository)
    require(current_pr.get("draft") is False and current_scope == scope
            and current_receipt.get("body") == receipt["body"],
            "PR or receipt changed before the decision")
    decision_at = now()
    require(checked_at <= decision_at < checked_at + VERDICT_LIFETIME, "Verifier result expired")
    require(decision_at <= receipt_until, "Owner receipt expired while making the decision")
    return {"result": "permitted-in-simulation", "pr": pr, "head_sha": scope.head_sha}


def decision(**kwargs):
    try:
        return evaluate(**kwargs)
    except (ApprovalError, KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError):
        return {"result": "blocked", "pr": kwargs["pr"]}
