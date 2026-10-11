"""Independent API snapshot comparisons and mutations; no network in CI."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github/scripts/check_settings_drift.py"
spec = importlib.util.spec_from_file_location("settings_drift", SCRIPT)
drift = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drift)


class SettingsDriftTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = json.loads((ROOT / ".github/github-settings-snapshot.json").read_text())
        self.github_only = self.snapshot["repository"].endswith("/us-equities-trading")

    def test_recorded_settings_match_independent_api_snapshot_and_workflows(self):
        self.assertEqual(drift.check(ROOT, self.snapshot, github_only=self.github_only), [])

    def test_every_actions_setting_mutation_is_detected(self):
        policy = drift.actions_policy(self.snapshot)
        for key in policy:
            changed = copy.deepcopy(self.snapshot)
            if key in {"github_owned_allowed", "verified_allowed", "patterns_allowed"}:
                changed["actions"]["selected_actions"][key] = ["changed"] if key == "patterns_allowed" else not policy[key]
            elif key == "workflow_permissions":
                changed["actions"][key]["can_approve_pull_request_reviews"] = not policy[key]["can_approve_pull_request_reviews"]
            elif key == "approval_policy":
                changed["actions"]["fork_pr_contributor_approval"] = {"approval_policy": "first_time_contributors"}
            else:
                changed["actions"]["permissions"][key] = not policy[key] if isinstance(policy[key], bool) else "all"
            with self.subTest(key=key):
                self.assertTrue(drift.check(ROOT, changed))

    def test_ruleset_changes_additions_removals_and_integration_ids_are_detected(self):
        for change in ("enforcement", "missing", "added", "integration"):
            changed = copy.deepcopy(self.snapshot)
            if change == "enforcement":
                changed["rulesets"][0]["enforcement"] = "disabled"
            elif change == "missing":
                changed["rulesets"] = []
            elif change == "added":
                changed["rulesets"].append(dict(changed["rulesets"][0], id=999))
            else:
                checks = next(rule for rule in changed["rulesets"][0]["rules"]
                              if rule["type"] == "required_status_checks")
                checks["parameters"]["required_status_checks"][0]["integration_id"] = 999
            with self.subTest(change=change):
                self.assertTrue(drift.check(ROOT, changed))

    def test_transport_metadata_and_collection_order_do_not_create_policy_drift(self):
        changed = copy.deepcopy(self.snapshot)
        changed["rulesets"][0]["updated_at"] = "transport metadata"
        changed["rulesets"][0]["current_user_can_bypass"] = "always"
        changed["rulesets"][0]["rules"].reverse()
        changed["actions"]["permissions"]["selected_actions_url"] = "transport metadata"
        self.assertEqual(drift.check(ROOT, changed, github_only=self.github_only), [])

    def test_missing_bypass_actor_observation_fails_closed(self):
        del self.snapshot["rulesets"][0]["bypass_actors"]
        with self.assertRaises(drift.SettingsError):
            drift.check(ROOT, self.snapshot)

    def test_new_api_policy_fields_are_detected(self):
        self.snapshot["actions"]["permissions"]["future_setting"] = True
        self.assertTrue(drift.check(ROOT, self.snapshot))

    def test_actual_json_field_edit_makes_offline_command_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github").mkdir()
            for name in ("actions-permissions.json", "rulesets.json", "github-settings-snapshot.json", "integration-ids.json"):
                (root / ".github" / name).write_bytes((ROOT / ".github" / name).read_bytes())
            policy = json.loads((root / ".github/actions-permissions.json").read_text())
            policy["enabled"] = not policy["enabled"]
            (root / ".github/actions-permissions.json").write_text(json.dumps(policy))
            result = subprocess.run([sys.executable, str(SCRIPT), "--root", str(root)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("actions_permissions.enabled", result.stdout)
            self.assertNotIn(tmp, result.stdout + result.stderr)

    def test_unpinned_and_disallowed_workflows_are_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github/workflows").mkdir(parents=True)
            path = root / ".github/workflows/test.yml"
            policy = drift.actions_policy(self.snapshot)
            for target in ("actions/checkout@main", "unlisted/action@" + "a" * 40, "docker://image"):
                path.write_text("steps:\n  - uses: " + target + "\n")
                with self.subTest(target=target):
                    self.assertTrue(drift.workflow_drift(root, policy, github_only=self.github_only))

    def test_paginated_gets_use_explicit_read_only_method_and_version(self):
        response = subprocess.CompletedProcess([], 0, '[[{"id": 1}], [{"id": 2}]]', '')
        with patch.object(drift.subprocess, "run", return_value=response) as run:
            self.assertEqual(len(drift.get("repos/example/project/rulesets", pages=True)), 2)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--method") + 1], "GET")
        self.assertIn("X-GitHub-Api-Version: 2022-11-28", command)
        self.assertIn("--paginate", command)
        self.assertIn("--slurp", command)

    def test_live_mode_gets_all_rulesets_and_skips_private_fork_approval(self):
        observed = []
        actions = self.snapshot["actions"]
        def fake_get(endpoint, *, pages=False):
            observed.append(endpoint)
            if endpoint.endswith("/rulesets?includes_parents=true&per_page=100"):
                self.assertTrue(pages)
                return [[{"id": rule["id"]}] for rule in self.snapshot["rulesets"]]
            if "/rulesets/" in endpoint:
                return next(rule for rule in self.snapshot["rulesets"] if endpoint.endswith(str(rule["id"])))
            for suffix, key in (("/actions/permissions/selected-actions", "selected_actions"),
                                ("/actions/permissions/workflow", "workflow_permissions"),
                                ("/actions/permissions/fork-pr-contributor-approval", "fork_pr_contributor_approval"),
                                ("/actions/permissions", "permissions")):
                if endpoint.endswith(suffix):
                    return actions[key]
            return {"private": self.snapshot["private"]}
        with patch.object(drift, "get", side_effect=fake_get):
            self.assertEqual(drift.check(ROOT, drift.live_snapshot(self.snapshot)), [])
        approval_read = any(endpoint.endswith("fork-pr-contributor-approval") for endpoint in observed)
        self.assertEqual(approval_read, not self.snapshot["private"])

    def test_failed_get_is_an_error_without_response_body(self):
        response = subprocess.CompletedProcess([], 1, 'response content', 'diagnostic content')
        with patch.object(drift.subprocess, "run", return_value=response):
            with self.assertRaises(drift.SettingsError) as raised:
                drift.get("repos/example/project/actions/permissions")
        self.assertNotIn("content", str(raised.exception))

    def test_integration_ids_and_producer_evidence_match_snapshot(self):
        policy = drift.integration_policy(self.snapshot)
        self.assertTrue(all(check["integration_id"] is None for check in policy["required_status_checks"]))
        self.assertEqual(len(policy["required_status_checks"]), 4)
        for check in policy["required_status_checks"]:
            self.assertEqual(check["observed_producing_app_ids"], [15368])
            self.assertTrue(check["evidence"])
            for evidence in check["evidence"]:
                self.assertEqual(evidence["app_id"], 15368)
                self.assertEqual(evidence["commit_sha"], self.snapshot["integrations"]["check_run_commit_sha"])
                self.assertIsInstance(evidence["check_run_id"], int)

    def test_check_publisher_id_mutation_is_detected(self):
        self.snapshot["integrations"]["check_runs"][0]["app"]["id"] = 999
        self.assertTrue(any(field.startswith("integrations.") for field in drift.check(ROOT, self.snapshot)))

    def test_required_check_without_producer_evidence_fails_closed(self):
        self.snapshot["integrations"]["check_runs"] = []
        with self.assertRaises(drift.SettingsError):
            drift.check(ROOT, self.snapshot)

    def test_live_command_detects_a_changed_producer_without_writing_settings(self):
        observed = copy.deepcopy(self.snapshot)
        changed = copy.deepcopy(observed["integrations"]["check_runs"][0])
        changed["app"]["id"] = 999
        import contextlib
        import io
        def fake_get(endpoint, *, pages=False):
            self.assertIn("/check-runs/", endpoint)
            self.assertFalse(pages)
            original = next(run for run in self.snapshot["integrations"]["check_runs"]
                            if endpoint.endswith(str(run["id"])))
            return changed if original["id"] == changed["id"] else original
        with patch.object(drift, "live_snapshot", return_value=observed), \
                patch.object(drift, "get", side_effect=fake_get), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(drift.main(["--root", str(ROOT), "--live"]), 1)
        self.assertIn("integrations.required_status_checks", output.getvalue())


if __name__ == "__main__":
    unittest.main()
