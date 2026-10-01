# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

YARA Scanner v2 is a Python wrapper around yara-python that provides change tracking of YARA rules and metadata-based scan filtering. Built for the ACE3 project.

The multi-process scanning client/server (`YaraScannerServer`, `ysc`, `yss`) was removed in 3.0.0; it now lives in ACE itself (`saq/yara_scanning/`).

## Commands

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .  # editable install, creates the scan console script

# Run all tests
pytest

# Run a single test
pytest tests/test_yara_scanner.py::test_data_scan_matching

# Run by marker
pytest -m unit
pytest -m integration

# Lint
pylint yara_scanner.py
```

## Architecture

The codebase is a single flat Python module (no package directory):

- **yara_scanner.py** — Core module (~1500 lines). Contains:
  - `YaraScanner` — Main class. Tracks rule sources (files, directories, git repos), compiles rules with dependency resolution via plyara, scans files/data, and filters results based on rule metadata (`file_ext`, `mime_type`, `file_name`, `full_path` with `sub:`, `re:`, `!` modifiers).
  - `main()` — CLI entry point for the `scan` command. Includes performance testing mode that tests individual rules/strings against random and repeating-byte buffers.

### Scan Result Structure

```python
{"target": str, "meta": dict, "namespace": str, "rule": str, "strings": [(offset, id, data), ...], "tags": list}
```

### Rule Change Detection

Three tracking strategies with unified interface: single files (mtime-based), directories (tracks .yar/.yara additions/changes/deletions), git repos (triggers only on new commits). `rules_changed()` reports (and re-tracks) source changes only; `check_rules()` additionally returns True while no rules are loaded, so a watcher that never compiles must use `rules_changed()`.

## Testing

Tests use pytest with pytest-datadir. Test data lives in `tests/data/` with YARA signatures in `tests/data/signatures/` and scan targets in `tests/data/scan_targets/`. Markers: `unit`, `integration`.
