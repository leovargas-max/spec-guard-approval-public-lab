from datetime import timedelta
import unittest

from app_scoped_checks import AppScopedChecks, CheckTarget, GitHubChecks
from premerge_decision import decision
from spec_guard_approval import ApprovalError
from test_premerge_decision import PremergeDecisionFixture


class SyntheticChecksAPI:
    def __init__(self, app_id):
        self.app_id = app_id
        self.runs = {}

    def __call__(self, method, path, payload=None):
        if method == "POST" and path == "check-runs":
            check_id = len(self.runs) + 1
            self.runs[check_id] = {**payload, "id": check_id, "app": {"id": self.app_id}}
        else:
            check_id = int(path.removeprefix("check-runs/"))
            if method == "PATCH":
                self.runs[check_id].update(payload)
        return dict(self.runs[check_id])


class AppScopedCheckTest(PremergeDecisionFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.api = SyntheticChecksAPI(81)
        self.checks = AppScopedChecks(81, self.api)
        self.target = CheckTarget(7, self.scope.head_sha)
        self.receipt = self.sign()
        self.signature = self.verdict(self.receipt)

    def live(self, receipt=None, **changes):
        body = self.receipt if receipt is None else receipt
        fields = dict(
            get_pr=lambda pr: self.pr, get_receipt=lambda ident: body, pr=7, receipt_id=12,
            owner_id=42, verifier_id=81, repository=self.repo, owners=self.allowed,
            verifiers=self.verifiers, signature=self.signature, checked_at=self.time, now=lambda: self.time,
        )
        return lambda: decision(**{**fields, **changes})

    def test_same_sha_pr_checks_are_independent(self):
        other = CheckTarget(8, self.scope.head_sha)
        run = self.checks.reconcile(self.target, self.live())
        other_run = self.checks.reconcile(other, self.live())
        self.assertEqual(run["head_sha"], other_run["head_sha"])
        self.assertNotEqual(run["name"], other_run["name"])
        self.assertNotEqual(run["external_id"], other_run["external_id"])
        self.assertEqual(run["conclusion"], "success")
        self.assertEqual(other_run["conclusion"], "failure")
        self.assertTrue(self.checks.permit_in_simulation(self.target, run["id"], self.live()))
        self.assertFalse(self.checks.permit_in_simulation(other, run["id"], self.live()))
        with self.assertRaises(ApprovalError):
            self.checks.reconcile(other, self.live(), run_id=run["id"])
        self.assertEqual(self.checks.read(self.target, run["id"])["conclusion"], "success")

    def test_old_green_never_overrides_revocation_or_expiry(self):
        run = self.checks.reconcile(self.target, self.live())
        removed = {**self.receipt, "body": "withdrawn"}
        revoked = self.live(removed)
        expired = self.live(now=lambda: self.time + timedelta(seconds=60))
        self.assertFalse(self.checks.permit_in_simulation(self.target, run["id"], expired))
        self.assertFalse(self.checks.permit_in_simulation(self.target, run["id"], revoked))
        self.assertEqual(self.checks.read(self.target, run["id"])["conclusion"], "success")
        updated = self.checks.reconcile(self.target, revoked, run_id=run["id"])
        self.assertEqual(updated["id"], run["id"])
        self.assertEqual(updated["conclusion"], "failure")

    def test_wrong_app_or_updated_head_cannot_authorize(self):
        run = self.checks.reconcile(self.target, self.live())
        changed = CheckTarget(7, "b" * 40)
        self.assertFalse(self.checks.permit_in_simulation(changed, run["id"], self.live()))
        wrong = AppScopedChecks(82, self.api)
        self.assertFalse(wrong.permit_in_simulation(self.target, run["id"], self.live()))
        with self.assertRaises(ApprovalError):
            wrong.reconcile(self.target, self.live(), run_id=run["id"])

    def test_adapter_has_no_merge_or_unrelated_write_route(self):
        adapter = GitHubChecks("synthetic-unused-token")
        with self.assertRaises(ApprovalError):
            adapter("PUT", "pulls/7/merge", {})
        with self.assertRaises(ApprovalError):
            adapter("POST", "statuses/" + self.scope.head_sha, {})
