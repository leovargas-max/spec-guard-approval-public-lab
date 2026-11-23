"""Evaluate only the public lab's trusted base code."""
import os
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory

from spec_guard_approval import REPOSITORY, SCHEMA, protected_paths, read_github


pr_number = int(os.environ["LAB_PR"])
owner_id = int(os.environ["LAB_OWNER"])
token = os.environ["GH_TOKEN"]
pr = read_github(f"pulls/{pr_number}", token)
if (pr["base"]["repo"]["full_name"] != REPOSITORY or pr["head"]["repo"]["full_name"] != REPOSITORY
        or pr["base"]["ref"] != "main" or pr["state"] != "open"):
    sys.exit("Unexpected lab PR")
head = pr["head"]["sha"]
base = pr["base"]["sha"]
if not all(re.fullmatch(r"[a-f0-9]{40}", value) for value in [head, base]):
    sys.exit("Invalid commit identifiers")
if os.environ["LAB_EVENT_HEAD"] != head:
    sys.exit("Event refers to a stale head")
if subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != base:
    sys.exit("Trusted base changed during the run")
subprocess.run(["git", "fetch", "--no-tags", "origin", head], check=True)
paths = protected_paths(Path.cwd(), base, head)
if any(name.startswith(b".github/") for name in paths):
    sys.exit("Lab candidates may not modify the trusted workflow")
changed = subprocess.check_output(
    ["git", "--no-replace-objects", "diff", "--no-ext-diff", "--no-renames",
     "--name-only", "-z", f"{base}...{head}", "--"],
).split(b"\0")
if any(name.startswith(b"scripts/") for name in changed):
    sys.exit("Lab candidates may not modify verifier files")
comments = read_github(f"issues/{pr_number}/comments?per_page=100", token)
if len(comments) >= 100:
    sys.exit("Receipt search exceeded the lab limit")
receipts = [comment["id"] for comment in comments
            if comment.get("body", "").startswith(f"schema={SCHEMA}\n")]
if len(receipts) != 1:
    sys.exit("Exactly one scoped receipt is required")
with TemporaryDirectory(prefix="lab-public-signers-") as tmp:
    allowed = Path(tmp) / "allowed_signers"
    allowed.write_text(f"github-user-{owner_id} " + Path("scripts/synthetic-public-key.pub").read_text())
    subprocess.run([sys.executable, "scripts/spec_guard_approval.py",
                    "--repository-dir", str(Path.cwd()), "--pr", str(pr_number),
                    "--comment-id", str(receipts[0]), "--owner-id", str(owner_id),
                    "--allowed-signers", str(allowed)], check=True)
