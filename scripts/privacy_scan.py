#!/usr/bin/env python3
"""Scan this repository for private, credential-like or out-of-policy content.

Usage: python3 scripts/privacy_scan.py [--root DIR] [PATH ...]

Without PATH arguments the scanner reads the git-tracked files under --root;
with them it reads the given files and walks the given directories, which
must lie inside --root. Every finding prints as "path:line: rule-id", or as
"path: rule-id" for whole-file rules; the matched text is never printed.
Exit status: 0 clean, 1 findings, 2 usage or read error.

Rules, by the id they print under:
  session-uuid, task-handle           local session identifier and task-handle shapes
  home-path, windows-user-path,
  encoded-home-path                   Linux, macOS, Windows and WSL home paths,
                                      including dash-encoded project directories
  huggingface-token, github-token,
  tavily-token, api-secret,
  private-key, bearer-credential      credentials
  alpaca-key-id, broker-account-field,
  broker-api-host, email-address      broker and account identifiers
  date-guard                          ISO date after 2026-10-09 in a field whose key
                                      contains observ, asof, as_of, timestamp, date
                                      or ts, in JSON, CSV or Parquet-sidecar text
                                      inside a data/ or fixtures/ directory, unless
                                      the file starts with a SYNTHETIC header
  path-not-allowed                    path outside the allowlist (ALLOWED_FILES and
                                      ALLOWED_DIRS below)
  fixture-not-synthetic               tabular file inside fixtures/ without a
                                      SYNTHETIC header line, or a binary one without
                                      a sibling "<name>.synthetic" marker

A SYNTHETIC header is a first line that starts with "SYNTHETIC" or
"# SYNTHETIC"; JSON and JSON Lines files may instead open line 1 with
{"SYNTHETIC": true.

The broker rule regexes avoid lookarounds so that .gitleaks.toml can carry the
same strings for Go RE2; tests/test_privacy_scan.py keeps both copies equal.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import io
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Iterable, Iterator
from datetime import date
from pathlib import Path, PurePosixPath
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]

# Session, home-path and credential shapes: the private-content pattern
# classes this policy derives from, kept unchanged so both scanners agree.
PRIVATE_CONTENT: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Historical prose can glue a UUID to a word; word boundaries miss it.
    ("session-uuid", re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", re.I)),
    ("task-handle", re.compile(r"task-[a-z0-9]{8}-[a-z0-9]{6}", re.I)),
    ("home-path", re.compile(r"/(?:home|Users)/(?!example(?:/|\b))[A-Za-z0-9_.-]+(?:/|\b)")),
    ("windows-user-path", re.compile(
        r"(?:[A-Za-z]:[/\\]+|/mnt/[A-Za-z]/)Users[/\\]+(?!example(?:[/\\]|\b))[A-Za-z0-9_.-]+", re.I)),
    # Tool project and scratch directories encode path separators as dashes,
    # including bare homes and Windows profiles reached through WSL mounts.
    # The Users branches ignore case; the Linux home branch does not.
    ("encoded-home-path", re.compile(
        r"(?<![\w-])(?:-home-|(?i:-Users-|[A-Za-z]--Users-|-mnt-[A-Za-z]-Users-))"
        r"(?!example(?:-|[/\\\"'\s`)\]]|$))[A-Za-z0-9_.]+(?:-|(?=[/\\\"'\s`)\]]|$))"
        # Graph project ids omit the leading dash. Every punctuation wrapper,
        # including '_' and '-', is a boundary; Unicode alphanumerics are not.
        r"|(?<![^\W_])home-(?!example-code-)[\w.]+(?:-+[\w.]+)*-*-code-")),
    ("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b")),
    ("tavily-token", re.compile(r"\btvly-(?:(?:prod|dev)-)?[A-Za-z0-9_-]{24,}\b")),
    ("api-secret", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("bearer-credential", re.compile(r"\bBearer\s+[A-Za-z0-9._~-]{30,}", re.I)),
)

# Broker and account identifiers, compiled with re.ASCII to match RE2's
# ASCII-only classes. A field value counts as account-number-like when it has
# at least four characters and at least one digit.
BROKER_RULES: dict[str, str] = {
    "alpaca-key-id": r"\b(?:PK|AK)[A-Z0-9]{18}\b",
    "broker-account-field": (
        r'''(?i)\b[a-z0-9_-]*(?:account|acct)(?:[_-]?(?:id|no|num|number))?["']?[ \t]*[:=][ \t]*["']?'''
        r"[a-z0-9-]*(?:[a-z0-9-]{3}[0-9]|[a-z0-9-]{2}[0-9][a-z0-9-]|[a-z0-9-][0-9][a-z0-9-]{2}|[0-9][a-z0-9-]{3})"
        r"[a-z0-9-]*"
    ),
    "broker-api-host": r"(?i)\b(?:[a-z0-9-]+\.)*(?:alpaca\.markets|databento\.com)\b",
    "email-address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b",
}

CONTENT_RULES: tuple[tuple[str, re.Pattern[str]], ...] = PRIVATE_CONTENT + tuple(
    (rule_id, re.compile(pattern, re.ASCII)) for rule_id, pattern in BROKER_RULES.items()
)
CONTENT_RULE_IDS: tuple[str, ...] = tuple(rule_id for rule_id, _ in CONTENT_RULES)
FILE_RULE_IDS: tuple[str, ...] = ("date-guard", "path-not-allowed", "fixture-not-synthetic")
RULE_IDS: tuple[str, ...] = CONTENT_RULE_IDS + FILE_RULE_IDS

ALLOWED_FILES = frozenset({"README.md", "LICENSE", ".gitignore", ".gitleaks.toml"})
ALLOWED_DIRS = frozenset({".github", "scripts", "tests", "src", "fixtures", "docs"})

DATE_GUARD_CUTOFF = date(2026, 10, 9)
DATE_GUARD_DIRS = frozenset({"data", "fixtures"})
DATE_KEY = re.compile(r"observ|asof|as_of|timestamp|date|ts", re.I)
DATE_FIELD = re.compile(r"""[\w.-]*(?:observ|asof|as_of|timestamp|date|ts)[\w.-]*["']?[ \t]*[:=]""", re.I)
ISO_DATE = re.compile(
    r"(?<![0-9])([0-9]{4})-([0-9]{2})-([0-9]{2})(?![0-9])"
    r"|(?<![0-9A-Za-z])([0-9]{4})([0-9]{2})([0-9]{2})T[0-9]{2}"
)

JSON_SUFFIXES = frozenset({".json", ".jsonl", ".ndjson", ".jsonlines", ".geojson"})
CSV_DELIMITERS = {".csv": ",", ".tsv": "\t"}
TEXT_TABULAR = frozenset({".csv", ".tsv", ".jsonl", ".ndjson", ".jsonlines"})
BINARY_TABULAR = frozenset({".parquet", ".feather", ".arrow", ".orc", ".avro", ".xlsx", ".xls"})
COMPRESSED = frozenset({".gz", ".bz2", ".xz", ".zst", ".zip"})
SYNTHETIC_LINE = re.compile(r"﻿?[ \t]*(?:#[ \t]*)?SYNTHETIC(?![A-Za-z0-9_])")
SYNTHETIC_JSON = re.compile(r'﻿?[ \t]*\{[ \t]*"SYNTHETIC"[ \t]*:[ \t]*true(?![A-Za-z0-9_])')

Exists = Callable[[PurePosixPath], bool]


class Finding(NamedTuple):
    path: str
    line: int  # 0 for whole-file rules
    rule: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}" if self.line else f"{self.path}: {self.rule}"


class ScanError(Exception):
    """A usage or read failure. Messages name paths, never file content."""


def has_synthetic_header(text: str, suffix: str = "") -> bool:
    if SYNTHETIC_LINE.match(text):
        return True
    return suffix in JSON_SUFFIXES and SYNTHETIC_JSON.match(text) is not None


def late_dates(value: str) -> list[str]:
    """Return the ISO dates in value that fall after DATE_GUARD_CUTOFF."""
    late = []
    for match in ISO_DATE.finditer(value):
        year, month, day = match.group(1, 2, 3) if match.group(1) else match.group(4, 5, 6)
        try:
            parsed = date(int(year), int(month), int(day))
        except ValueError:
            continue
        if parsed > DATE_GUARD_CUTOFF:
            late.append(match.group(0))
    return late


def _line_at(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _date_valued(node: object, under: bool = False) -> Iterator[str]:
    """Yield the strings at or below a date-like key, nested keys included."""
    if isinstance(node, dict):
        for key, value in node.items():
            if under:
                yield str(key)
            yield from _date_valued(value, under or DATE_KEY.search(str(key)) is not None)
    elif isinstance(node, list):
        for item in node:
            yield from _date_valued(item, under)
    elif under and isinstance(node, str):
        yield node


def _json_date_lines(text: str) -> set[int] | None:
    """Lines with late dates under date-like keys; None when text is not JSON."""
    documents: list[tuple[object, int]] = []
    try:
        documents.append((json.loads(text), 0))
    except (ValueError, RecursionError):
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                documents.append((json.loads(line), number))
            except (ValueError, RecursionError):
                return None
    lines: set[int] = set()
    try:
        for document, number in documents:
            for value in _date_valued(document):
                for hit in late_dates(value):
                    lines.add(number or _line_at(text, max(text.find(hit), 0)))
    except RecursionError:
        return None
    return lines


def _csv_date_lines(text: str, delimiter: str) -> set[int] | None:
    """Rows with late dates in date-like columns; None when text is not CSV."""
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter)
    lines: set[int] = set()
    try:
        header = next(reader, [])
        columns = [index for index, name in enumerate(header) if DATE_KEY.search(name)]
        for row in reader:
            if any(index < len(row) and late_dates(row[index]) for index in columns):
                lines.add(reader.line_num)
    except csv.Error:
        return None
    return lines


def _field_date_lines(text: str) -> set[int]:
    """Line-based fallback: a date-like key, then ":" or "=", then a late date."""
    lines: set[int] = set()
    for number, line in enumerate(text.splitlines(), 1):
        if any(late_dates(line[field.end():]) for field in DATE_FIELD.finditer(line)):
            lines.add(number)
    return lines


def _is_parquet_sidecar(rel: PurePosixPath, exists: Exists) -> bool:
    lowered = rel.name.lower()
    if lowered.endswith((".parquet", ".synthetic")):
        return False
    if ".parquet." in lowered:
        return True
    stem, dot, _ = rel.name.partition(".")
    return bool(dot) and exists(rel.with_name(stem + ".parquet"))


def date_guard_lines(rel: PurePosixPath, text: str, exists: Exists) -> set[int]:
    if DATE_GUARD_DIRS.isdisjoint(rel.parts[:-1]):
        return set()
    suffix = rel.suffix.lower()
    is_json = suffix in JSON_SUFFIXES
    if not (is_json or suffix in CSV_DELIMITERS or _is_parquet_sidecar(rel, exists)):
        return set()
    if has_synthetic_header(text, suffix):
        return set()
    if is_json:
        lines = _json_date_lines(text)
    elif suffix in CSV_DELIMITERS:
        lines = _csv_date_lines(text, CSV_DELIMITERS[suffix])
    else:
        lines = None
    return _field_date_lines(text) if lines is None else lines


def fixture_not_synthetic(rel: PurePosixPath, text: str, exists: Exists) -> bool:
    if "fixtures" not in rel.parts[:-1]:
        return False
    suffixes = [suffix.lower() for suffix in rel.suffixes]
    if not suffixes:
        return False
    if suffixes[-1] in TEXT_TABULAR:
        return not has_synthetic_header(text, suffixes[-1])
    binary = suffixes[-1] in BINARY_TABULAR or (
        suffixes[-1] in COMPRESSED and len(suffixes) > 1 and suffixes[-2] in TEXT_TABULAR | BINARY_TABULAR
    )
    return binary and not exists(rel.with_name(rel.name + ".synthetic"))


def path_allowed(rel: PurePosixPath) -> bool:
    if len(rel.parts) == 1:
        return rel.name in ALLOWED_FILES
    return rel.parts[0] in ALLOWED_DIRS


def scan_file(root: Path, rel: PurePosixPath, exists: Exists) -> list[Finding]:
    name = rel.as_posix()
    findings = [] if path_allowed(rel) else [Finding(name, 0, "path-not-allowed")]
    path = root / rel
    try:
        # A tracked symlink commits its target path, so scan that text.
        raw = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
    except (FileNotFoundError, IsADirectoryError):
        return findings  # deleted in the working tree, or a submodule
    except OSError as error:
        raise ScanError(f"cannot read {name} ({type(error).__name__})") from None
    try:
        text, is_text = raw.decode("utf-8"), True
    except UnicodeDecodeError:
        text, is_text = raw.decode("latin-1"), False
    newlines = [match.start() for match in re.finditer("\n", text)]
    for rule, pattern in CONTENT_RULES:
        lines = {bisect.bisect_left(newlines, match.start()) + 1 for match in pattern.finditer(text)}
        findings.extend(Finding(name, line, rule) for line in sorted(lines))
    if is_text:
        findings.extend(Finding(name, line, "date-guard") for line in sorted(date_guard_lines(rel, text, exists)))
    if fixture_not_synthetic(rel, text, exists):
        findings.append(Finding(name, 0, "fixture-not-synthetic"))
    return findings


def tracked_files(root: Path) -> list[PurePosixPath]:
    try:
        listing = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        raise ScanError("cannot list git-tracked files; is --root a git checkout?") from None
    return [PurePosixPath(os.fsdecode(entry)) for entry in listing.stdout.split(b"\0") if entry]


def files_from_paths(root: Path, paths: Iterable[str]) -> list[PurePosixPath]:
    found: list[PurePosixPath] = []
    for given in paths:
        absolute = Path(os.path.abspath(given))
        try:
            absolute.relative_to(root)
        except ValueError:
            raise ScanError(f"path outside --root: {given}") from None
        if absolute.is_dir() and not absolute.is_symlink():
            for directory, subdirs, names in os.walk(absolute):
                subdirs[:] = sorted(entry for entry in subdirs if entry != ".git")
                for entry in sorted(names):
                    if entry != ".git":
                        found.append(PurePosixPath((Path(directory) / entry).relative_to(root).as_posix()))
        elif os.path.lexists(absolute):
            found.append(PurePosixPath(absolute.relative_to(root).as_posix()))
        else:
            raise ScanError(f"no such file: {given}")
    return list(dict.fromkeys(found))


def scan(root: Path | str, paths: Iterable[str] | None = None) -> tuple[list[Finding], int]:
    """Return the sorted findings and the number of files scanned."""
    base = Path(os.path.abspath(root))
    given = list(paths or [])
    if given:
        files = files_from_paths(base, given)

        def exists(rel: PurePosixPath) -> bool:
            return os.path.lexists(base / rel)
    else:
        files = tracked_files(base)
        tracked = {rel.as_posix() for rel in files}

        def exists(rel: PurePosixPath) -> bool:
            return rel.as_posix() in tracked
    findings: set[Finding] = set()
    for rel in files:
        findings.update(scan_file(base, rel, exists))
    return sorted(findings), len(files)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n", 1)[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", metavar="PATH",
                        help="files or directories to scan instead of the git-tracked files")
    parser.add_argument("--root", type=Path, default=ROOT,
                        help="repository root that policy paths are relative to (default: this repository)")
    args = parser.parse_args(argv)
    try:
        findings, scanned = scan(args.root, args.paths)
    except ScanError as error:
        print(f"privacy_scan: error: {error}", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding.render())
    flagged = len({finding.path for finding in findings})
    print(f"privacy_scan: {len(findings)} finding(s) in {flagged} of {scanned} file(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
