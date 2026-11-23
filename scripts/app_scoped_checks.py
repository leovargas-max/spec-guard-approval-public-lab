"""Lab-only Checks API contract. No merge operation or activation entry point."""
from dataclasses import dataclass
import json
import re
from urllib.error import URLError
from urllib.request import Request, build_opener

from spec_guard_approval import ApprovalError, NoRedirect, REPOSITORY, SHA, require


@dataclass(frozen=True)
class CheckTarget:
    pr: int
    head: str

    def __post_init__(self):
        require(type(self.pr) is int and self.pr > 0, "Invalid pull request")
        require(isinstance(self.head, str) and SHA.fullmatch(self.head), "Invalid head SHA")

    @property
    def name(self):
        return f"synthetic-spec-guard/pr-{self.pr}"

    @property
    def external_id(self):
        return f"synthetic-spec-guard/v1:{REPOSITORY}:{self.pr}:{self.head}"


class GitHubChecks:
    """Use an installation token scoped to the synthetic repository."""

    def __init__(self, installation_token: str):
        require(installation_token, "Installation token required")
        self.token = installation_token
        self.opener = build_opener(NoRedirect())

    def __call__(self, method: str, path: str, payload=None):
        allowed = (method == "POST" and path == "check-runs"
                   or method in {"GET", "PATCH"} and re.fullmatch(r"check-runs/[1-9][0-9]*", path))
        require(allowed, "Only Checks API operations are allowed")
        request = Request(f"https://api.github.com/repos/{REPOSITORY}/{path}",
                          method=method, headers={
                              "Authorization": f"Bearer {self.token}",
                              "Accept": "application/vnd.github+json",
                              "Content-Type": "application/json",
                              "User-Agent": "Synthetic-Spec-Guard-Lab",
                              "X-GitHub-Api-Version": "2022-11-28",
                          }, data=None if payload is None else json.dumps(payload).encode("utf-8"))
        with self.opener.open(request, timeout=10) as response:
            raw = response.read(524289)
        require(len(raw) <= 524288, "Checks API response too large")
        return json.loads(raw)


class AppScopedChecks:
    def __init__(self, app_id: int, api):
        require(type(app_id) is int and app_id > 0, "Expected GitHub App ID required")
        self.app_id = app_id
        self.api = api

    def verify_source(self, run, target: CheckTarget, run_id=None):
        require(type(run.get("id")) is int and run["id"] > 0
                and (run_id is None or run["id"] == run_id), "Unexpected check run ID")
        require(run.get("app", {}).get("id") == self.app_id, "Unexpected GitHub App")
        require(run.get("name") == target.name and run.get("external_id") == target.external_id
                and run.get("head_sha") == target.head, "Check belongs to another PR or head")
        return run

    def read(self, target: CheckTarget, run_id: int):
        require(type(run_id) is int and run_id > 0, "Invalid check run ID")
        return self.verify_source(self.api("GET", f"check-runs/{run_id}"), target, run_id)

    @staticmethod
    def is_permitted(target: CheckTarget, decision):
        return (decision.get("result") == "permitted-in-simulation"
                and decision.get("pr") == target.pr and decision.get("head_sha") == target.head)

    def reconcile(self, target: CheckTarget, fresh_decision, run_id=None):
        """Create or update an advisory check. Read a stored run before updating it."""
        if run_id is not None:
            self.read(target, run_id)
        permitted = self.is_permitted(target, fresh_decision())
        conclusion = "success" if permitted else "failure"
        payload = {"name": target.name, "external_id": target.external_id,
                   "status": "completed", "conclusion": conclusion,
                   "output": {"title": "Synthetic receipt evaluation",
                              "summary": "Valid at evaluation time." if permitted else "Approval unavailable or invalid."}}
        if run_id is None:
            run = self.api("POST", "check-runs", {**payload, "head_sha": target.head})
        else:
            run = self.api("PATCH", f"check-runs/{run_id}", payload)
        require(run.get("status") == "completed" and run.get("conclusion") == conclusion,
                "Checks API did not confirm the requested result")
        return self.verify_source(run, target, run_id)

    def permit_in_simulation(self, target: CheckTarget, run_id: int, fresh_decision):
        """An old success is insufficient: re-evaluate the live receipt independently."""
        try:
            run = self.read(target, run_id)
            if run.get("status") != "completed" or run.get("conclusion") != "success":
                return False
            return self.is_permitted(target, fresh_decision())
        except (ApprovalError, URLError, OSError, KeyError, TypeError, ValueError):
            return False
