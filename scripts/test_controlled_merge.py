import unittest
from unittest.mock import Mock

from app_scoped_checks import AppScopedChecks, CheckTarget
from controlled_merge import simulate_controlled_merge


class ControlledMergeTests(unittest.TestCase):
    def setUp(self):
        self.target = CheckTarget(10, "1" * 40)
        self.run = {"id": 99, "app": {"id": 5891226}, "name": self.target.name,
                    "external_id": self.target.external_id, "head_sha": self.target.head,
                    "status": "completed", "conclusion": "success"}
        self.checks = AppScopedChecks(5891226, Mock(return_value=self.run))
        self.transport = Mock(return_value={"result": "simulated"})
        self.decision = {"result": "permitted-in-simulation",
                         "pr": self.target.pr, "head_sha": self.target.head}

    def invoke(self, decision):
        return simulate_controlled_merge(checks=self.checks, target=self.target,
                                         check_id=99, verify_current_receipt=decision,
                                         merge_transport=self.transport)

    def test_valid_receipt_pins_the_head(self):
        decision = Mock(return_value=self.decision)
        self.assertEqual(self.invoke(decision), {"result": "simulated"})
        decision.assert_called_once_with()
        self.transport.assert_called_once_with(pr=10, expected_head=self.target.head)

    def test_old_green_check_cannot_authorize_a_withdrawn_or_expired_receipt(self):
        decision = Mock(return_value={"result": "blocked", "pr": 10})
        self.assertEqual(self.invoke(decision), {"result": "blocked", "pr": 10})
        decision.assert_called_once_with()
        self.transport.assert_not_called()

    def test_wrong_pr_or_sha_cannot_reach_transport(self):
        for change in ({"pr": 11}, {"head_sha": "2" * 40}):
            with self.subTest(change=change):
                self.assertEqual(self.invoke(lambda: self.decision | change)["result"], "blocked")
        self.transport.assert_not_called()

    def test_wrong_app_cannot_reach_transport(self):
        self.run["app"]["id"] = 15368
        decision = Mock(return_value=self.decision)
        self.assertEqual(self.invoke(decision)["result"], "blocked")
        decision.assert_not_called()
        self.transport.assert_not_called()
