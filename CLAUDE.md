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

### What Was Compiled

`compile_and_load_rules()` compiles each file on its own, drops those it cannot read or that do not compile, then compiles the rest together (one source per namespace). An include, nested or not, is relative to the file that has the include statement. It keeps a record of it: `scanner.compiled_sources` holds one `CompiledSource` per file read (path, namespace, the text read, its `IncludedSource`s, its compile error and warnings, its rule identifiers) and `scanner.compile_error` the combined compile's error. An include is read once per load and the combined compile is given that same text, so the record is exactly what the loaded rules came from. Rules loaded from a compiled file leave the record empty.

### Include Boundary

An include is read by `open_include()`: only a regular file inside the namespace's boundary, through no symbolic link other than a tracked directory inside the boundary (`get_tracked_dirs_inside()`), and refused (`IncludeRefusedError`, recorded as the `IncludedSource`'s error) before anything is opened otherwise. Absolute paths and paths that leave the boundary are refused by path arithmetic alone, so the refusal does not depend on the file existing. `scanner.include_boundaries` maps a namespace to its boundary (`get_include_boundary()` falls back to the tracked directory, or a tracked file's directory); the constructor uses `signature_dir` for the directories it finds. A rule file found by listing a directory is refused when it resolves outside the boundary and outside every tracked directory inside it (`rule_file_refusal()`), so a `signature_dir` entry can be a link to a checkout elsewhere. `allow_includes_outside=True` turns all of it off.

### Rule Change Detection

Three tracking strategies with unified interface: single files (mtime-based), directories (tracks .yar/.yara additions/changes/deletions), git repos (triggers only on new commits). `rules_changed()` reports (and re-tracks) source changes only; `check_rules()` additionally returns True while no rules are loaded, so a watcher that never compiles must use `rules_changed()`.

## Testing

Tests use pytest with pytest-datadir. Test data lives in `tests/data/` with YARA signatures in `tests/data/signatures/` and scan targets in `tests/data/scan_targets/`. Markers: `unit`, `integration`.
