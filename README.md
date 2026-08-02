# MeshVault

MeshVault is a command-line tool for secure, decentralized, peer-to-peer secret sharing over a local network (LAN). It uses **Shamir's Secret Sharing (SSS)** combined with authenticated, encrypted communication channels to let teams distribute sensitive secrets — API keys, certificates, database credentials — without relying on a central server, cloud storage, or any external trust system.

> 🚧 **Project status:** MeshVault is under active development as part of a mentorship program. The cryptographic core, secure channel, peer discovery, and network transfer layer are implemented. The end-user CLI (`split` / `recover` commands) is currently in progress. See [Status](#status) below for details.

---

## Overview

Sharing secrets over messaging apps, email, or a single encrypted file in a repo all share the same weakness: one point of failure. If that one channel, key, or file is compromised, everything is exposed.

MeshVault takes a different approach: a secret is split into **N** cryptographic shares and distributed to **N** separate peers on the same LAN. The secret can only be reconstructed when at least **K** (K ≤ N) of those peers cooperate and combine their shares. No single peer — and no central server — ever holds enough information to recover the secret alone.

**Key properties:**
- **Decentralized** — no server, database, or cloud dependency
- **Automatic peer discovery** via multicast DNS (mDNS)
- **Encrypted channels** — ephemeral X25519 key exchange + AES-256-GCM
- **Information-theoretic security** — fewer than K shares reveal zero information about the secret (a mathematical guarantee of Shamir's Secret Sharing)

---

## Architecture

| Module | Responsibility |
|---|---|
| `crypto/sss.py` | Shamir's Secret Sharing — polynomial generation, share evaluation, Lagrange interpolation for reconstruction |
| `crypto/channel.py` | Secure channel setup — X25519 ECDH key exchange, AES-256-GCM encryption/decryption |
| `network/discovery.py` | Peer discovery via mDNS (`_meshvault._tcp.local`, using `zeroconf`) |
| `network/transfer.py` | TCP connection handling, length-prefixed message framing, retry logic for unreachable peers |
| `cli/split.py` | Orchestrates the `split` command: splits a secret, discovers peers, and distributes shares |
| `cli/recover.py` | Orchestrates the `recover` command: listens for incoming shares and reconstructs the secret |

---

## Installation

Requires Python 3.10 or newer (tested with Python 3.14).

> Note: this repository is currently developed locally and not yet pushed to a public remote. Once pushed, clone it and install dependencies:

```bash
git clone <repo-url>
cd MeshVault_soc26
pip install -r requirements.txt
```

`requirements.txt` includes:
- `zeroconf` — mDNS peer discovery
- `cryptography` — X25519 key exchange, AES-256-GCM
- `pytest`, `pytest-cov` — testing and coverage
- `black`, `flake8` — code formatting and linting

---

## Usage

> ⚠️ The end-to-end `split` and `recover` CLI commands are still under development and not yet runnable. This section will be updated with real command examples once `cli/split.py` and `cli/recover.py` are complete.

**Planned usage** (once finished):

```bash
# Split a secret into 5 shares, requiring any 3 to recover it
meshvault split --secret "my-api-key" --n 5 --k 3

# On a peer machine, listen for shares and reconstruct the secret
meshvault recover --k 3
```

In the meantime, the network transfer layer can be exercised directly — see `network/transfer.py` for `receive_shares()` and `send_share_with_retry()`, which handle peer-to-peer socket communication and are fully functional and tested.

---

## Running Tests

```bash
pytest
```

With coverage:

```bash
pytest --cov
```

---

## Status

| Component | Status |
|---|---|
| Shamir's Secret Sharing core (`crypto/sss.py`) | ✅ Implemented |
| Secure channel — X25519 + AES-GCM (`crypto/channel.py`) | ✅ Implemented |
| Peer discovery — mDNS (`network/discovery.py`) | ✅ Implemented |
| Transfer layer — framing, send/receive, retry (`network/transfer.py`) | ✅ Implemented |
| CLI — `split` command | ⏳ Not yet started |
| CLI — `recover` command | ⏳ Not yet started |
| End-to-end integration tests | ⏳ Not yet started |

---

## Contributing

This project follows an Agile workflow with iterative sprints, tracked via GitHub Issues and a Kanban project board.

Full details on git branching, sprint structure, standups, PR rules, and coding standards live in [`docs/contributor_guide.md`](docs/contributor_guide.md) — read that before opening a PR.

See `CHANGELOG.md` for a history of notable changes.

---

## References

- Shamir, A. (1979). ["How to Share a Secret"](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing). *Communications of the ACM*, 22(11), 612–613.
- [Python `cryptography` library — X25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/)
- [Python `cryptography` library — AEAD ciphers (AES-GCM)](https://cryptography.io/en/latest/hazmat/primitives/aead/)
- [python-zeroconf](https://github.com/python-zeroconf/python-zeroconf)
- [Python Socket Programming HOWTO](https://docs.python.org/3/howto/sockets.html)

---

## License

See [LICENSE](./LICENSE) for details.