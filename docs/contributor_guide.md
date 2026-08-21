# MeshVault Contributor Guide

Welcome to the MeshVault project! This guide explains our development workflow, coding standards, Git branch strategy, and Agile practices.

---

## 1. Development Workflow & Agile Methodology

MeshVault development follows the Agile framework:

- **Sprint Structure**: Development is organized into 1.5 to 2-week iterations (sprints).
- **Standup Meetings**: Focused 30-minute syncs held twice a week to discuss:
  1. What was completed since the last standup.
  2. What is planned next.
  3. Blockers or technical challenges.
- **Kanban Board**: Task status must be kept updated on the GitHub Projects board.

---

## 2. Git Branching Strategy & Pull Requests

1. **Branch Naming**:
   - Feature branches: `feature/<issue-number>-<short-description>`
   - Bug fix branches: `fix/<issue-number>-<short-description>`
   - Documentation branches: `docs/<short-description>`
2. **Pull Request Scope**:
   - Every PR must maintain a strict, minimal scope addressing one issue or a focused set of related sub-tasks.
   - Never combine unrelated features or dump large code blobs.
   - Reference the issue number in the PR description (e.g. `Closes #123`).
3. **Reviews & Approvals**:
   - At least one code review and approval from a peer or mentor is required before merging into `main`.

---

## 3. Coding Standards & Quality Requirements

- **Python Version**: Python 3.9+ support.
- **Code Formatting**: Code must conform strictly to `black` formatting:
  ```bash
  black --check . --exclude '/(\.git|\.github|\.venv)/'
  ```
- **Linting**: Code must pass `flake8` checks without errors:
  ```bash
  flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
  flake8 . --count --max-complexity=10 --max-line-length=127 --statistics
  ```
- **Mandatory Testing**:
  - All new features and bug fixes must include comprehensive unit tests under `tests/`.
  - All tests must pass before submitting a PR:
    ```bash
    PYTHONPATH=. pytest --cov=. --cov-report=term-missing
    ```

---

## 4. Architecture Guidelines

- **Cryptographic Core (`crypto/`)**:
  - `sss.py`: Shamir's Secret Sharing over GF(256).
  - `channel.py`: X25519 ECDH key agreement and AES-256-GCM encryption.
  - `session_cache.py`: In-memory session key caching with TTL.
- **Networking Layer (`network/`)**:
  - `discovery.py`: Zeroconf/mDNS service registration and browsing (`_meshvault._tcp.local.`).
  - `transfer.py`: 4-byte length-prefixed TCP socket framing and secure share dispatch.
- **CLI & Coordination (`cli/`)**:
  - `split.py`: SSS splitting and distribution orchestration.
  - `recover.py`: Peer listening, share collection, and secret reconstruction.
  - `__main__.py`: Unified CLI entrypoint with `split` and `recover` subcommands.

---

## 5. Changelog Maintenance

Whenever a PR introduces new features, bug fixes, or architectural changes, remember to update `CHANGELOG.md` under the `[Unreleased]` section following the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format.
