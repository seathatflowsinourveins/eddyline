"""Tests for scripts/privacy_scan.py and the gitleaks configuration.

Every positive canary is assembled at runtime from fragments, so the
repository never holds a literal canary for the scanner or gitleaks to find.
Each rule has a positive canary and a clean twin.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import string
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "privacy_scan.py"
GITLEAKS_CONFIG = ROOT / ".gitleaks.toml"


def _load_scanner():
    spec = importlib.util.spec_from_file_location("privacy_scan", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


scanner = _load_scanner()


def cat(*parts: str) -> str:
    return "".join(parts)


def mixed(length: int) -> str:
    """Deterministic high-entropy alphanumerics without a dictionary run."""
    alphabet = string.ascii_letters + string.digits
    return "".join(alphabet[(index * 7 + 3) % len(alphabet)] for index in range(length))


LATE = cat("2026", "-10-", "10")  # first day the date guard rejects
LATER = cat("2026", "-11-", "02")
CUTOFF = cat("2026", "-10-", "09")  # last day it accepts

# (rule id, positive canary, clean twin)
CONTENT_CASES = (
    ("session-uuid", cat("1" * 8, "-", "2" * 4, "-", "3" * 4, "-", "4" * 4, "-", "5" * 12), cat("1" * 8, "-", "2" * 4)),
    ("task-handle", cat("ta", "sk-", "a1" * 4, "-", "b2" * 3), cat("ta", "sk-", "runner")),
    ("home-path", cat("/", "ho", "me/", "canary/notes"), cat("/", "ho", "me/", "example/notes")),
    ("home-path", cat("/", "Us", "ers/", "canary/notes"), "/srv/app/notes"),
    ("windows-user-path", cat("C:", "\\", "Us", "ers", "\\", "canary"), cat("C:", "\\", "Program Files")),
    ("windows-user-path", cat("/mnt/c/", "Us", "ers/", "canary"), "/mnt/c/Windows"),
    ("encoded-home-path", cat("-", "ho", "me-", "canary-", "code-x"), "-homework-"),
    ("huggingface-token", cat("h", "f_", "Ab1" * 10), cat("h", "f_", "short")),
    ("github-token", cat("gh", "p_", "Ab1" * 12), cat("gh", "p_", "Ab1")),
    ("github-token", cat("github", "_pat_", "Ab1_" * 10), "github_pages"),
    ("tavily-token", cat("tv", "ly-", "Ab1" * 10), cat("tv", "ly-", "Ab1")),
    ("api-secret", cat("s", "k-", "Ab1" * 10), cat("s", "k-", "learn")),
    ("private-key", cat("-----BEGIN ", "PRIVATE KEY-----"), cat("-----BEGIN ", "PUBLIC KEY-----")),
    ("private-key", cat("-----BEGIN ", "OPENSSH ", "PRIVATE KEY-----"), "-----END-----"),
    ("bearer-credential", cat("Authorization: ", "Bea", "rer ", "Ab1" * 12), cat("Bea", "rer ", "Ab1")),
    ("alpaca-key-id", cat("P", "K", "Q7" * 9), cat("P", "K", "Q7" * 4)),
    ("alpaca-key-id", cat("A", "K", "Z9" * 9), "AKA"),
    ("broker-account-field", cat('"acc', 'ount_id": "', "PA", "12" * 5, '"'), cat('"acc', 'ount_id": "', "redacted", '"')),
    ("broker-account-field", cat("ac", "ct = ", "9" * 9), cat("ac", "ct = ", "none")),
    ("broker-api-host", cat("https://", "paper-api", ".alp", "aca.mar", "kets/v2"), "https://example.org/v2"),
    ("broker-api-host", cat("hist", ".data", "bento", ".com"), "historical data"),
    ("email-address", cat("someone", "@", "mail", ".test"), "someone at mail dot test"),
)


def write_tree(root: Path, files: dict[str, str | bytes]) -> None:
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))


def scan_tree(files: dict[str, str | bytes]) -> list:
    """Write files under a temporary root and scan exactly those paths."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_tree(root, files)
        findings, scanned = scanner.scan(root, [str(root / name) for name in files])
    if scanned != len(files):
        raise AssertionError(f"scanned {scanned} of {len(files)} files")
    return findings


def rules_for(text: str) -> set[str]:
    return {finding.rule for finding in scan_tree({"docs/sample.txt": text})}


class ContentRuleTest(unittest.TestCase):
    def test_every_content_rule_has_a_case(self):
        self.assertEqual({rule for rule, _, _ in CONTENT_CASES}, set(scanner.CONTENT_RULE_IDS))

    def test_positive_canaries_are_flagged(self):
        for rule, canary, _ in CONTENT_CASES:
            with self.subTest(rule=rule, canary_length=len(canary)):
                self.assertIn(rule, rules_for(cat("prefix ", canary, " suffix\n")))

    def test_clean_twins_pass_every_rule(self):
        for rule, _, clean in CONTENT_CASES:
            with self.subTest(rule=rule):
                self.assertEqual(rules_for(cat("prefix ", clean, " suffix\n")), set())

    def test_findings_carry_the_line_number(self):
        canary = CONTENT_CASES[0][1]
        findings = scan_tree({"docs/sample.txt": cat("clean\n", "clean\n", canary, "\n")})
        self.assertEqual(findings, [("docs/sample.txt", 3, "session-uuid")])


class DateGuardTest(unittest.TestCase):
    def test_json_fixture_with_a_late_as_of_is_flagged(self):
        findings = scan_tree({"fixtures/obs.json": cat('{"as_of": "', LATE, '"}\n')})
        self.assertEqual(findings, [("fixtures/obs.json", 1, "date-guard")])

    def test_csv_rows_are_flagged_on_their_own_line(self):
        findings = scan_tree({"fixtures/obs.csv": cat("asof,value\n", CUTOFF, ",1\n", LATER, ",2\n")})
        self.assertIn(("fixtures/obs.csv", 3, "date-guard"), findings)
        self.assertNotIn(("fixtures/obs.csv", 2, "date-guard"), findings)

    def test_data_directory_json_lines_are_flagged(self):
        findings = scan_tree({"data/obs.jsonl": cat('{"id": 1}\n', '{"observed_at": "', LATE, 'T09:30:00Z"}\n')})
        self.assertIn(("data/obs.jsonl", 2, "date-guard"), findings)
        self.assertIn(("data/obs.jsonl", 0, "path-not-allowed"), findings)

    def test_nested_keys_and_basic_format_are_flagged(self):
        files = {
            "fixtures/nested.json": cat('{"observations": {"', LATER, '": 1.5}}\n'),
            "fixtures/basic.json": cat('{"ts_event": "', "2026", "1012", 'T093000Z"}\n'),
        }
        self.assertEqual(
            scan_tree(files),
            [("fixtures/basic.json", 1, "date-guard"), ("fixtures/nested.json", 1, "date-guard")],
        )

    def test_parquet_sidecars_are_flagged(self):
        files = {
            "fixtures/bars.parquet": b"PAR1\x00\x00PAR1",
            "fixtures/bars.parquet.synthetic": "",
            "fixtures/bars.parquet.yaml": cat("timestamp_max: ", LATER, "\n"),
            "fixtures/bars.meta": cat("date_end = ", LATER, "\n"),
        }
        self.assertEqual(
            scan_tree(files),
            [("fixtures/bars.meta", 1, "date-guard"), ("fixtures/bars.parquet.yaml", 1, "date-guard")],
        )

    def test_synthetic_headers_exempt_the_file(self):
        files = {
            "fixtures/obs.csv": cat("SYNTHETIC\n", "asof,value\n", LATER, ",1\n"),
            "fixtures/obs.jsonl": cat('{"SYNTHETIC": true}\n', '{"ts": "', LATER, '"}\n'),
            "fixtures/obs.json": cat('{"SYNTHETIC": true, "as_of": "', LATER, '"}\n'),
            "fixtures/side.parquet.txt": cat("# SYNTHETIC sidecar\n", "observed: ", LATER, "\n"),
        }
        self.assertEqual(scan_tree(files), [])

    def test_cutoff_day_other_keys_invalid_dates_and_other_directories_pass(self):
        files = {
            "fixtures/cutoff.json": cat('{"as_of": "', CUTOFF, '"}\n'),
            "fixtures/label.json": cat('{"label": "', LATER, '"}\n'),
            "fixtures/invalid.json": cat('{"date": "', "2026", "-13-45", '"}\n'),
            "docs/obs.json": cat('{"as_of": "', LATER, '"}\n'),
        }
        self.assertEqual(scan_tree(files), [])


class PathAllowlistTest(unittest.TestCase):
    def test_paths_outside_the_allowlist_are_flagged(self):
        files = {"notes.txt": "x\n", "Makefile": "x\n", "data/readme.txt": "x\n", "build/out.txt": "x\n"}
        flagged = {finding.path for finding in scan_tree(files) if finding.rule == "path-not-allowed"}
        self.assertEqual(flagged, set(files))

    def test_allowlisted_paths_pass(self):
        files = {
            "README.md": "x\n",
            "LICENSE": "x\n",
            ".gitignore": "x\n",
            ".gitleaks.toml": "x\n",
            ".github/workflows/ci.yml": "x\n",
            "scripts/tool.py": "x\n",
            "tests/test_tool.py": "x\n",
            "src/pkg/mod.py": "x\n",
            "fixtures/readme.txt": "x\n",
            "docs/guide.md": "x\n",
        }
        self.assertEqual(scan_tree(files), [])


class SyntheticFixtureTest(unittest.TestCase):
    def test_unmarked_tabular_fixtures_are_flagged(self):
        files = {
            "fixtures/a.csv": "id,value\n1,2\n",
            "fixtures/b.jsonl": '{"id": 1}\n',
            "fixtures/c.parquet": b"PAR1\x00\x00PAR1",
            "fixtures/d.csv.gz": b"\x1f\x8b\x08\x00",
            "tests/fixtures/e.tsv": "id\tvalue\n1\t2\n",
        }
        flagged = {finding.path for finding in scan_tree(files) if finding.rule == "fixture-not-synthetic"}
        self.assertEqual(flagged, set(files))

    def test_marked_tabular_fixtures_pass(self):
        files = {
            "fixtures/a.csv": "SYNTHETIC\nid,value\n1,2\n",
            "fixtures/b.jsonl": '{"SYNTHETIC": true}\n{"id": 1}\n',
            "fixtures/c.parquet": b"PAR1\x00\x00PAR1",
            "fixtures/c.parquet.synthetic": "",
            "fixtures/d.csv": "# SYNTHETIC from a seeded generator\nid,value\n1,2\n",
            "fixtures/notes.json": '{"id": 1}\n',
        }
        self.assertEqual(scan_tree(files), [])


class CommandLineTest(unittest.TestCase):
    def run_main(self, *argv: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = scanner.main(list(argv))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_output_names_path_and_rule_but_never_the_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(Path(tmp), {"docs/leaks.txt": "\n".join(canary for _, canary, _ in CONTENT_CASES) + "\n"})
            code, out, err = self.run_main("--root", tmp, str(Path(tmp) / "docs" / "leaks.txt"))
        self.assertEqual(code, 1)
        for rule, canary, _ in CONTENT_CASES:
            with self.subTest(rule=rule):
                self.assertRegex(out, rf"(?m)^docs/leaks\.txt:\d+: {re.escape(rule)}$")
                self.assertNotIn(canary, out + err)
        self.assertNotIn(tmp, out + err)

    def test_clean_tree_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_tree(Path(tmp), {"docs/ok.md": "nothing to report\n"})
            code, out, err = self.run_main("--root", tmp, tmp)
        self.assertEqual((code, out), (0, ""))
        self.assertIn("0 finding(s) in 0 of 1 file(s)", err)

    def test_path_outside_root_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as other:
            code, _, err = self.run_main("--root", root, other)
        self.assertEqual(code, 2)
        self.assertIn("outside --root", err)

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_default_scan_covers_only_tracked_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "--quiet", tmp], check=True)
            write_tree(Path(tmp), {"README.md": "clean\n", "notes.txt": cat("ac", "ct = ", "9" * 9, "\n")})
            subprocess.run(["git", "-C", tmp, "add", "README.md"], check=True)
            untracked = self.run_main("--root", tmp)
            subprocess.run(["git", "-C", tmp, "add", "notes.txt"], check=True)
            tracked = self.run_main("--root", tmp)
        self.assertEqual(untracked[:2], (0, ""))
        self.assertEqual(tracked[0], 1)
        self.assertEqual(tracked[1].splitlines(), ["notes.txt: path-not-allowed", "notes.txt:1: broker-account-field"])


class RepositoryTreeTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_repository_tree_is_clean(self):
        inside = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--is-inside-work-tree"], capture_output=True)
        if inside.returncode != 0:
            self.skipTest("not a git checkout")
        result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stdout)
        summary = re.search(r"0 finding\(s\) in 0 of (\d+) file\(s\)", result.stderr)
        self.assertIsNotNone(summary, result.stderr)
        self.assertGreater(int(summary.group(1)), 0)


def allowlist_keys(node: object, trail: str = "") -> list[str]:
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{trail}.{key}" if trail else key
            if "allowlist" in key.lower():
                found.append(here)
            found.extend(allowlist_keys(value, here))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            found.extend(allowlist_keys(item, f"{trail}[{index}]"))
    return found


class GitleaksConfigTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = tomllib.loads(GITLEAKS_CONFIG.read_text(encoding="utf-8"))

    def test_gitleaks_config_extends_the_defaults_without_allowlists(self):
        self.assertEqual(self.config["extend"], {"useDefault": True})
        self.assertEqual(allowlist_keys(self.config), [])

    def test_gitleaks_rules_equal_the_scanner_broker_rules(self):
        rules = {rule["id"]: rule["regex"] for rule in self.config["rules"]}
        self.assertEqual(rules, scanner.BROKER_RULES)

    def test_gitleaks_flags_every_broker_canary(self):
        binary = os.environ.get("GITLEAKS_BIN") or shutil.which("gitleaks")
        if not binary:
            self.skipTest("gitleaks is not installed; set GITLEAKS_BIN to require this test")
        self.assertTrue(os.access(binary, os.X_OK), "gitleaks binary is not executable")
        canaries = [canary for rule, canary, _ in CONTENT_CASES if rule in scanner.BROKER_RULES]
        canaries.append(cat("gh", "p_", mixed(36)))  # a default rule, so useDefault is in effect
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as out:
            (Path(source) / "canaries.txt").write_text("\n".join(canaries) + "\n", encoding="utf-8")
            report = Path(out) / "report.json"
            result = subprocess.run(
                [binary, "dir", source, "--config", str(GITLEAKS_CONFIG), "--no-banner", "--redact",
                 "--log-level", "error", "--exit-code", "1",
                 "--report-format", "json", "--report-path", str(report)],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(result.returncode, 1, "gitleaks reported no leak or failed")
            found = {item["RuleID"] for item in json.loads(report.read_text(encoding="utf-8"))}
        self.assertLessEqual(set(scanner.BROKER_RULES) | {"github-pat"}, found)


if __name__ == "__main__":
    unittest.main()
