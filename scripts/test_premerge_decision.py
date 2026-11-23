from datetime import timedelta
from pathlib import Path
import unittest

import premerge_decision as gate
from test_spec_guard_approval import ApprovalFixture


class PremergeDecisionFixture(ApprovalFixture):
    def setUp(self):
        super().setUp()
        self.verifier = self.root / "verifier"
        self.run_command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.verifier))
        self.verifiers = self.root / "verifiers"
        self.verifiers.write_text("lab-verifier-81 " + Path(str(self.verifier) + ".pub").read_text())

    def verdict(self, receipt, key=None, scope=None, issued=None):
        path = self.root / ("verdict-" + str(len(list(self.root.glob("verdict-*.sig")))))
        path.write_bytes(gate.verdict_message(scope or self.scope, receipt["body"], 81, issued or self.time))
        self.run_command("ssh-keygen", "-Y", "sign", "-f", str(key or self.verifier),
                         "-n", gate.VERIFIER_NAMESPACE, str(path))
        return Path(str(path) + ".sig").read_text()

    def decide(self, receipt, signature, **changes):
        fields = dict(
            get_pr=lambda number: self.pr, get_receipt=lambda identifier: receipt,
            pr=7, receipt_id=12, owner_id=42, verifier_id=81, repository=self.repo,
            owners=self.allowed, verifiers=self.verifiers, signature=signature,
            checked_at=self.time, now=lambda: self.time,
        )
        return gate.decision(**{**fields, **changes})["result"]


class PremergeDecisionTest(PremergeDecisionFixture, unittest.TestCase):
    def test_same_sha_does_not_share_authorization_between_prs(self):
        receipt = self.sign()
        signature = self.verdict(receipt)
        self.assertEqual(self.decide(receipt, signature), "permitted-in-simulation")
        pr2 = {**self.pr, "number": 8}
        copied = {**receipt, "id": 13, "issue_url": receipt["issue_url"].replace("/7", "/8")}
        self.assertEqual(self.decide(copied, signature, pr=8, receipt_id=13,
                         get_pr=lambda number: pr2), "blocked")
        self.assertEqual(self.decide(receipt, signature), "permitted-in-simulation")

    def test_expiration_and_revocation_override_old_success(self):
        receipt = self.sign()
        signature = self.verdict(receipt)
        self.assertEqual(self.decide(receipt, signature), "permitted-in-simulation")
        self.assertEqual(self.decide(receipt, signature,
                                    now=lambda: self.time + timedelta(seconds=60)), "blocked")
        digest = iter([receipt, {**receipt, "body": "withdrawn"}])
        self.assertEqual(self.decide(receipt, signature, get_receipt=lambda identifier: next(digest)), "blocked")
        near_expiration = self.sign(time=self.time - timedelta(hours=24) + timedelta(seconds=1))
        instants = iter([self.time, self.time + timedelta(seconds=2)])
        self.assertEqual(self.decide(near_expiration, self.verdict(near_expiration),
                                    now=lambda: next(instants)), "blocked")
        expired = self.sign(time=self.time - timedelta(hours=25))
        self.assertEqual(self.decide(expired, self.verdict(expired)), "blocked")

    def test_wrong_publisher_receipt_and_stale_head_are_rejected(self):
        receipt = self.sign()
        signature = self.verdict(receipt)
        self.assertEqual(self.decide(receipt, self.verdict(receipt, key=self.key)), "blocked")
        self.assertEqual(self.decide(self.sign(time=self.time - timedelta(seconds=1)), signature), "blocked")
        newer = {**self.pr, "head": {**self.pr["head"], "sha": "a" * 40}}
        snapshots = iter([self.pr, newer])
        self.assertEqual(self.decide(receipt, signature, get_pr=lambda number: next(snapshots)), "blocked")
