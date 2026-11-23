"""Synthetic lab only. The caller supplies a dry-run merge transport."""
from app_scoped_checks import AppScopedChecks, CheckTarget


def simulate_controlled_merge(*, checks: AppScopedChecks, target: CheckTarget,
                              check_id: int, verify_current_receipt, merge_transport):
    """Call the simulated transport only after the live decision passes.

    The transport receives the expected head SHA. A real transport would also
    need a server-side guarantee for receipt and base changes during the call.
    """
    if not checks.permit_in_simulation(target, check_id, verify_current_receipt):
        return {"result": "blocked", "pr": target.pr}

    return merge_transport(pr=target.pr, expected_head=target.head)
