# Changelog

All notable changes to the MeshVault project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure scaffolding (divided into top-level packages: `crypto/`, `network/`, `cli/`).
- GitHub Actions workflow configuration for Continuous Integration (`.github/workflows/ci.yml`).
- Repository configuration including `.gitignore`, issue templates, and pull request template.
- Formal, emoji-free `README.md` containing Agile project management guidelines, 5-mentee track assignments, detailed weekly deliverables, and reading resources.
- Shamir's Secret Sharing (SSS) core polynomial math, split, and Lagrange interpolation recovery over GF(256) (`crypto/sss.py`).
- Ephemeral X25519 ECDH key agreement, HKDF session key derivation, and AES-256-GCM authenticated channel encryption (`crypto/channel.py`).
- In-memory session key caching store with TTL expiration (`crypto/session_cache.py`).
- Zeroconf mDNS peer service registration and active LAN discovery listener (`network/discovery.py`).
- Length-prefixed TCP socket framing, share transmission, reception, and retry handling (`network/transfer.py`).
- Full CLI commands for `split` and `recover` with argument parsing and peer coordination (`cli/split.py`, `cli/recover.py`, `cli/__main__.py`).
- Contributor guide covering Agile workflows, PR guidelines, and coding standards (`docs/contributor_guide.md`).
- Comprehensive unit, cryptographic, networking, and end-to-end integration test suites (`tests/`).


