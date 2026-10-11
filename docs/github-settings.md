# GitHub settings records

`.github/actions-permissions.json` records the live Actions policy in the same
flat shape as native-agent-stack's record. `.github/rulesets.json` records all
repository rulesets, including inherited rulesets, bypass actors and required
check integration IDs. These files describe the observed settings; they do
not apply settings to GitHub.

`.github/github-settings-snapshot.json` is the independent REST observation
captured with gh 2.102.0 and API version 2022-11-28. Offline CI compares both
records with this snapshot and checks workflow ownership and SHA pins:

```sh
python3 .github/scripts/check_settings_drift.py
python3 -m unittest discover -s tests -p test_settings_drift.py -v
```

The host can compare the records with fresh GitHub observations:

```sh
python3 .github/scripts/check_settings_drift.py --live
```

Live mode uses the installed gh client's authentication and explicit GET
requests only. It follows every ruleset page and reads each detail. Missing
bypass-actor visibility, API failure or an incomplete record is an error
(exit 2); observed policy drift is exit 1; matching settings are exit 0.
Output names differing fields and workflow locations without printing values
or API response bodies. The live mode does not rewrite records or snapshots.

The repository is public. The observed fork PR contributor approval policy is
`all_external_contributors`. The current policy permits GitHub-owned actions
and `zizmorcore/zizmor-action@*`, requires SHA pins, defaults workflow
permissions to read, and prevents approving PR reviews.

Offline agreement proves consistency with the retained observation, not the
current GitHub state. Update both the observation and records after a reviewed
external settings change, then run live mode. Metadata (links, node IDs,
timestamps and caller-specific bypass capability) is excluded from policy
comparison. Policy collections are compared without relying on API ordering;
all policy fields and duplicate entries are retained.

The mutation tests edit an actual JSON field and run the command, requiring
exit 1. They also cover ruleset additions/removals, integration-ID changes,
future policy fields, missing visibility, pagination and failed API reads.
The existing unittest CI discovers these tests offline.

## Integration observations

`.github/integration-ids.json` records the exact required-check bindings:
all four checks currently omit `integration_id`, represented as null. The
record also names each observed producer App ID, commit and check-run ID.
All four are produced by GitHub Actions (15368). Live mode re-reads those exact
check-run IDs and verifies their commit, so a rerun or an unrelated main change
cannot replace the historical evidence. Missing producer evidence fails closed.

The live ruleset JSON preserves its current null bindings. Proposed bindings
appear separately in the PR description for the owner or coordinator to
apply. After a reviewed settings change, a follow-up commit updates the
snapshot and JSON records. Producer evidence establishes who emitted each
check; it does not enumerate every App installed on the repository.

Source: [GitHub check runs REST API, version 2022-11-28](https://docs.github.com/en/rest/checks/runs?apiVersion=2022-11-28#list-check-runs-for-a-git-reference).

## SOTA sources

- [GitHub rulesets REST API, version 2022-11-28](https://docs.github.com/en/rest/repos/rules?apiVersion=2022-11-28#get-all-repository-rulesets),
  including [detail visibility](https://docs.github.com/en/rest/repos/rules?apiVersion=2022-11-28#get-a-repository-ruleset).
- [GitHub Actions permissions REST API, version 2022-11-28](https://docs.github.com/en/rest/actions/permissions?apiVersion=2022-11-28):
  repository policy, selected actions, default workflow permissions and fork
  contributor approval.
- [GitHub REST OpenAPI definitions at 58b1e0c00b39b9e46c24dc4a0ba6a2669c90e9c1](https://github.com/github/rest-api-description/blob/58b1e0c00b39b9e46c24dc4a0ba6a2669c90e9c1/descriptions/api.github.com/api.github.com.json).
- [GitHub CLI v2.102.0](https://github.com/cli/cli/releases/tag/v2.102.0),
  source pin `fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd`, with the supported
  [`gh api` GET and pagination interface](https://cli.github.com/manual/gh_api).
- [native-agent-stack Actions policy at 8bffa2c41692ef483e91b68e3b15aeb331423d2c](https://github.com/seathatflowsinourveins/native-agent-stack/blob/8bffa2c41692ef483e91b68e3b15aeb331423d2c/.github/actions-permissions.json)
  and [`ActionsAllowListTests`](https://github.com/seathatflowsinourveins/native-agent-stack/blob/8bffa2c41692ef483e91b68e3b15aeb331423d2c/tests/test_workflow_hardening.py).
  Inspection corrected the task brief's description: that upstream test
  verifies workflow allow-list conformance, rather than live API drift. This
  change keeps that check and adds independent snapshot comparison.
