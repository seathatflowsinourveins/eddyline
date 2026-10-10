# eddyline

This repository holds reproducible research tooling and its evidence receipts.
It uses synthetic and public data only, gives no advice of any kind, and
connects to no broker.

## Content policy

`scripts/privacy_scan.py` enforces this list on every pull request and every
push to `main`, next to a full-history gitleaks scan. A finding names the path
and the rule id, never the matched text. Run `python3 scripts/privacy_scan.py`
and `python3 -m unittest discover -s tests` before pushing.

- No personal home paths: Linux and macOS homes, Windows and WSL user
  profiles, or their dash-encoded forms.
- No local session identifiers (UUID shapes) or task handles.
- No credentials: GitHub, Hugging Face or Tavily tokens, `sk-` style API
  secrets, bearer credentials or private-key blocks.
- No broker or account identifiers: broker API key IDs, account-number fields,
  broker or paid market-data API hosts, or email addresses.
- No ISO date after 2026-10-09 in an observation, as-of, timestamp, date or
  `ts` field of JSON, CSV or Parquet-sidecar text under `data/` or
  `fixtures/`, unless the file starts with a `SYNTHETIC` header.
- Only `README.md`, `LICENSE`, `.gitignore`, `.gitleaks.toml`, `.github/`,
  `scripts/`, `tests/`, `src/`, `fixtures/` and `docs/` may exist.
- Every tabular fixture (CSV, Parquet, JSON Lines) under `fixtures/` starts
  with a `SYNTHETIC` header line, or has a sibling `<name>.synthetic` marker
  when it is binary. A JSON or JSON Lines file may open line 1 with
  `{"SYNTHETIC": true` instead.
