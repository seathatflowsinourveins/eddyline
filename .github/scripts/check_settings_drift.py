#!/usr/bin/env python3
"""Compare recorded GitHub policy with an offline API snapshot or live GETs.

Adapted from native-agent-stack 8bffa2c4's ActionsAllowListTests and GitHub's
REST API 2022-11-28. No settings endpoint is ever written.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
API_VERSION = "2022-11-28"
RULE_METADATA = {"node_id", "_links", "created_at", "updated_at", "current_user_can_bypass"}


class SettingsError(Exception):
    """A failed or incomplete observation; response bodies are never printed."""


def get(endpoint: str, *, pages: bool = False):
    command = ["gh", "api", "--method", "GET", "-H", f"X-GitHub-Api-Version: {API_VERSION}", endpoint]
    if pages:
        command.extend(["--paginate", "--slurp"])
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        raise SettingsError(f"GET failed: {endpoint.split('?')[0]}") from None
    if result.returncode:
        raise SettingsError(f"GET failed: {endpoint.split('?')[0]}")
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise SettingsError("GET returned invalid JSON") from None


def live_snapshot(recorded: dict) -> dict:
    repository = recorded["repository"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise SettingsError("invalid repository name")
    base = f"repos/{repository}"
    private = get(base)["private"]
    summaries = [rule for page in get(base + "/rulesets?includes_parents=true&per_page=100", pages=True)
                 for rule in page]
    rulesets = []
    for rule in summaries:
        # Use only the documented API path, never a response-supplied URL.
        rulesets.append(get(base + f"/rulesets/{int(rule['id'])}"))
    permissions = get(base + "/actions/permissions")
    responses = {
        "permissions": permissions,
        "selected_actions": (get(base + "/actions/permissions/selected-actions")
                             if permissions["allowed_actions"] == "selected" else None),
        "workflow_permissions": get(base + "/actions/permissions/workflow"),
        # GitHub returns 422 for this endpoint on private repositories.
        "fork_pr_contributor_approval": (None if private else
                                         get(base + "/actions/permissions/fork-pr-contributor-approval")),
    }
    return {"repository": repository, "private": private, "rulesets": rulesets, "actions": responses}


def actions_policy(snapshot: dict) -> dict:
    actions = snapshot["actions"]
    permissions = {key: value for key, value in actions["permissions"].items()
                   if key != "selected_actions_url"}
    permissions.update(actions["selected_actions"] or {})
    permissions["workflow_permissions"] = actions["workflow_permissions"]
    approval = actions["fork_pr_contributor_approval"]
    permissions["approval_policy"] = approval["approval_policy"] if approval else None
    return permissions


def ruleset_policy(snapshot: dict) -> list:
    rulesets = []
    for rule in snapshot["rulesets"]:
        if "bypass_actors" not in rule:
            raise SettingsError("ruleset observation omits bypass_actors; use an account with write access")
        rulesets.append({key: value for key, value in rule.items() if key not in RULE_METADATA})
    return rulesets


def canonical(value):
    """Policy collections are unordered; duplicates and every field are retained."""
    if isinstance(value, dict):
        return {key: canonical(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return sorted((canonical(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    return value


def integration_policy(snapshot: dict) -> dict:
    """Record each required check's observed producer and immutable evidence."""
    checks = []
    for ruleset in snapshot["rulesets"]:
        for rule in ruleset["rules"]:
            if rule["type"] == "required_status_checks":
                for check in rule["parameters"]["required_status_checks"]:
                    runs = [run for run in snapshot["integrations"]["check_runs"]
                            if run["name"] == check["context"]]
                    if not runs:
                        raise SettingsError("required check has no recorded producer observation")
                    checks.append({"ruleset_id": ruleset["id"], "context": check["context"],
                                   "integration_id": check.get("integration_id"),
                                   "observed_producing_app_ids": sorted({run["app"]["id"] for run in runs}),
                                   "evidence": [{"commit_sha": run["head_sha"], "check_run_id": run["id"],
                                                 "app_id": run["app"]["id"]} for run in runs]})
    return {"required_status_checks": checks}


def differences(expected, actual, path: str) -> list[str]:
    if type(expected) is not type(actual):
        return [path]
    if isinstance(expected, dict):
        result = []
        for key in sorted(expected.keys() | actual.keys()):
            child = f"{path}.{key}"
            result.extend([child] if key not in expected or key not in actual else
                          differences(expected[key], actual[key], child))
        return result
    if isinstance(expected, list):
        if len(expected) != len(actual):
            return [path]
        return [child for index, (left, right) in enumerate(zip(expected, actual))
                for child in differences(left, right, f"{path}[{index}]")]
    return [] if expected == actual else [path]


def workflow_drift(root: Path, policy: dict, *, github_only: bool) -> list[str]:
    result = []
    for path in sorted((root / ".github/workflows").glob("*.y*ml")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = re.search(r"\buses:\s*([^\s]+)", line.split("#", 1)[0])
            if not match:
                continue
            target = match.group(1).strip("'\"")
            if target.startswith("./"):
                continue
            owner = target.split("/", 1)[0]
            github_owned = owner in {"actions", "github"}
            allowed = policy["allowed_actions"] == "all" or (
                policy["allowed_actions"] == "selected" and (
                    github_owned and policy.get("github_owned_allowed", False) or
                    any(fnmatch.fnmatchcase(target, pattern) for pattern in policy.get("patterns_allowed", []))))
            # Verified publishers cannot be established offline; all current targets
            # must be covered by GitHub ownership or an explicit recorded pattern.
            pinned = bool(re.fullmatch(r"[^@]+@[0-9a-f]{40}", target))
            if not policy["enabled"] or not allowed or github_only and not github_owned or (
                    policy.get("sha_pinning_required", False) and not pinned):
                result.append(f"workflow:{path.name}:{number}")
    return result


def check(root: Path, snapshot: dict, *, github_only: bool = False) -> list[str]:
    policy = json.loads((root / ".github/actions-permissions.json").read_text(encoding="utf-8"))
    rulesets = json.loads((root / ".github/rulesets.json").read_text(encoding="utf-8"))
    result = differences(canonical(policy), canonical(actions_policy(snapshot)), "actions_permissions")
    result.extend(differences(canonical(rulesets), canonical(ruleset_policy(snapshot)), "rulesets"))
    result.extend(workflow_drift(root, policy, github_only=github_only))
    if "integrations" in snapshot:
        integrations = json.loads((root / ".github/integration-ids.json").read_text(encoding="utf-8"))
        result.extend(differences(canonical(integrations), canonical(integration_policy(snapshot)), "integrations"))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--live", action="store_true", help="observe GitHub via authenticated gh GETs")
    args = parser.parse_args(argv)
    try:
        recorded = json.loads((args.root / ".github/github-settings-snapshot.json").read_text(encoding="utf-8"))
        if recorded["api_version"] != API_VERSION:
            raise SettingsError("unsupported recorded API version")
        observed = live_snapshot(recorded) if args.live else recorded
        if args.live and "integrations" in recorded:
            observed["integrations"] = dict(recorded["integrations"])
            # Re-read producers at the evidence commit so unrelated main changes
            # do not change this historical observation.
            sha = recorded["integrations"]["check_run_commit_sha"]
            if not re.fullmatch(r"[0-9a-f]{40}", sha):
                raise SettingsError("invalid check-run commit")
            runs = []
            for evidence in recorded["integrations"]["check_runs"]:
                run = get(f"repos/{recorded['repository']}/check-runs/{int(evidence['id'])}")
                if run["head_sha"] != sha:
                    raise SettingsError("check-run evidence belongs to a different commit")
                runs.append({"id": run["id"], "name": run["name"], "head_sha": run["head_sha"],
                             "app": {"id": run["app"]["id"]}})
            observed["integrations"]["check_runs"] = runs
        drift = check(args.root, observed, github_only=recorded["repository"].endswith("/us-equities-trading"))
        if observed["private"] != recorded["private"]:
            drift.append("repository.private")
    except (OSError, ValueError, KeyError, TypeError, SettingsError):
        print("settings-drift: observation or record incomplete; no response body printed", file=sys.stderr)
        return 2
    for field in drift:
        print(f"settings-drift: {field}")
    print(f"settings-drift: {len(drift)} difference(s), mode={'live' if args.live else 'offline'}")
    return 1 if drift else 0


if __name__ == "__main__":
    raise SystemExit(main())
