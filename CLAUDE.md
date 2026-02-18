# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

YARA Scanner v2 is a Python wrapper around yara-python that provides change tracking of YARA rules, metadata-based scan filtering, and distributed multi-process scanning via Unix sockets. Built for the ACE3 project.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .  # editable install, creates console scripts: scan, ysc, yss

# Run all tests
pytest

# Run a single test
pytest tests/test_yara_scanner.py::test_data_scan_matching

# Run by marker
pytest -m unit
pytest -m integration

# Lint
pylint yara_scanner.py ysc.py yss.py
```

## Architecture

The codebase is three flat Python modules (no package directory):

- **yara_scanner.py** — Core module (~1900 lines). Contains:
  - `YaraScanner` — Main class. Tracks rule sources (files, directories, git repos), compiles rules with dependency resolution via plyara, scans files/data, and filters results based on rule metadata (`file_ext`, `mime_type`, `file_name`, `full_path` with `sub:`, `re:`, `!` modifiers).
  - `YaraScannerServer` — Multi-process server. Spawns one scanner process per CPU core, communicates over Unix sockets, monitors rules for changes, and auto-reloads (by respawning workers to avoid memory leaks).
  - `main()` — CLI entry point for the `scan` command. Includes performance testing mode that tests individual rules/strings against random and repeating-byte buffers.
- **ysc.py** — Lightweight client that connects to the scanner server socket to request scans.
- **yss.py** — Server daemon manager (start/stop/daemonize the `YaraScannerServer`).

### Client-Server Protocol

Unix socket protocol: command byte (`1`=file path, `2`=data stream), then data blocks as `(unsigned int length + bytes)`, external vars as JSON. Response is pickled scan results or exception.

### Scan Result Structure

```python
{"target": str, "meta": dict, "namespace": str, "rule": str, "strings": [(offset, id, data), ...], "tags": list}
```

### Rule Change Detection

Three tracking strategies with unified interface: single files (mtime-based), directories (tracks .yar/.yara additions/changes/deletions), git repos (triggers only on new commits).

## Testing

Tests use pytest with pytest-datadir. Test data lives in `tests/data/` with YARA signatures in `tests/data/signatures/` and scan targets in `tests/data/scan_targets/`. Markers: `unit`, `integration`.
