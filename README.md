# MeshVault

MeshVault is a command-line interface (CLI) tool designed for secure, decentralized, peer-to-peer (P2P) secret sharing over a local area network (LAN). By utilizing Shamir's Secret Sharing (SSS) and authenticated, encrypted communication channels, MeshVault enables teams to distribute sensitive secrets without relying on central servers, cloud storage, or external trust systems.

## 1. Project Overview

In modern development environments, sharing sensitive secrets such as API keys, private certificates, and database credentials poses a significant security risk. MeshVault addresses this by splitting a secret into N cryptographic shares and distributing them to N distinct peers on the same LAN. The original secret can be reconstructed only when at least K (where K <= N) of these peers cooperate to combine their shares. 

Key characteristics of MeshVault include:
*   **Decentralized Architecture:** No central server, database, or cloud dependency.
*   **Automatic Peer Discovery:** Shares are distributed and collected using multicast DNS (mDNS).
*   **Secure Channels:** Ephemeral key exchange (X25519 ECDH) and channel encryption (AES-256-GCM) prevent interception.
*   **Mathematical Security:** Shamir's Secret Sharing provides information-theoretic security; possessing fewer than K shares reveals zero information about the secret.

---

## 2. Problem Statement and Goals

Traditional secret management solutions introduce specific vulnerabilities:
*   **Cloud Secrets Managers:** Require constant internet access and absolute trust in third-party providers.
*   **Encrypted Repository Files:** Creating a single encrypted file in a Git repository introduces a single point of failure; if the decryption key is compromised, all secrets are exposed.
*   **Ad-Hoc Sharing Methods:** Manual sharing via messaging applications or email lacks cryptographic guarantees and audit trails.
*   **Virtual Private Networks (VPNs):** Setting up private network drives or dedicated servers requires infrastructure that many smaller teams or student organizations cannot easily deploy or maintain.

### Project Goals
*   **Threshold Cryptography:** Implement Shamir's Secret Sharing to split a secret into N shares, enabling recovery with any K shares (K <= N).
*   **Zero Server Dependency:** Implement mDNS discovery for automatic peer detection and direct TCP socket transfer.
*   **End-to-End Encryption:** Establish encrypted communication channels using AES-GCM with keys negotiated via X25519 ECDH.
*   **Intuitive Command-Line Interface:** Develop a streamlined CLI featuring two primary commands: `split` and `recover`.
*   **Maintainable Codebase:** Define clear module boundaries, comprehensive test coverage, and clear developer onboarding paths.

---

## 3. Technical Architecture and Module Design

MeshVault is built with modularity in mind. The application logic is separated into independent layers:

### Cryptographic Core (`sss.py`)
Responsible for Shamir's Secret Sharing (SSS) calculations over a finite field (GF(256) or a large prime field).
*   **Polynomial Generation:** Generates a random polynomial of degree K-1 where the constant term is the secret.
*   **Evaluation:** Evaluates the polynomial at N distinct points to create N shares.
*   **Interpolation:** Reconstructs the constant term (the secret) using Lagrange interpolation from any K points.

### Channel Security (`channel.py`)
Ensures all communication between peers is authenticated and encrypted.
*   **Key Agreement:** Performs an X25519 Elliptic Curve Diffie-Hellman (ECDH) handshake to negotiate ephemeral session keys.
*   **Symmetric Encryption:** Encrypts and decrypts TCP payloads using AES-256-GCM, ensuring confidentiality, integrity, and authenticity.

### Networking and Discovery (`discovery.py`, `transfer.py`)
Handles peer detection and reliable network delivery.
*   **mDNS Peer Discovery:** Registers and discovers the `_meshvault._tcp.local` service using the Zeroconf protocol.
*   **TCP Transmission:** Establishes direct socket connections between peers, using structured message framing to transmit public keys and encrypted shares.

### CLI and Coordination (`split.py`, `recover.py`)
Provides the command-line interface and orchestrates the other modules.
*   **Split Command:** Inputs a secret, splits it, announces the service, and coordinates transmission to N available peers.
*   **Recover Command:** Listens for incoming socket connections from K shareholders, collects the shares, validates them, and reconstructs the secret.

---

## 4. Project Management and Agile Methodology

To ensure structured progress, the development team follows the Agile framework:

### Iterative Development and Scrums
*   **Scrum Cycles:** Development is organized into 1.5 to 2-week iterations (sprints).
*   **Standup Meetings:** Short, 30-minute status meetings are conducted to discuss project updates, identify blockers, and align on technical direction.

### Tracking and Coordination
*   **GitHub Projects:** A shared Kanban board is used to track project milestones, task status, and overall progress.
*   **Issue Tracking:** Task breakdowns, features, and bugs are tracked using open GitHub issues. Contributors should actively reference issue numbers in their commits and pull requests.
*   **Epic Stories:** High-level project milestones are drafted as Epic stories to group related feature sets. Mentors coordinate the drafting of these Epics, inviting active participation from contributors to define detailed tasks.

### Pull Requests and Branch Management
*   **No Code Blobs:** Large, monolithic commits or unstructured code dumps are strictly prohibited.
*   **Scope Maintenance:** Every Pull Request (PR) or Merge Request (MR) must focus on a single, well-defined scope (e.g., implementing a specific function or solving one issue).
*   **Reviews:** Code changes must be reviewed by at least one peer or mentor before merging into the main branch.

### Documentation and Changelogs
*   **Code Documentation:** Codebases must include Markdown (`.md`) documentation outlining module boundaries and usage instructions.
*   **Academic / Mathematical Research:** Research-heavy tasks or cryptographic proofs may be documented using LaTeX.
*   **Changelogs:** A central `CHANGELOG.md` file must be updated with every major feature addition, refactor, or bug fix to maintain transparency.

### Quality Assurance and Testing
*   **Mandatory Testing:** All modules must be accompanied by comprehensive tests.
*   **Pytest Suite:** Test scripts are executed via the `pytest` framework.
*   **Coverage:** Testing must address edge cases (e.g., K = N, K = 1, handling of invalid shares, connection timeouts, and peer dropouts).

---

## 5. Contributor Roles and Timeline

### Team Assignments
*   **Contributor A:** Implement and test the SSS core (`sss.py`) including finite field arithmetic, polynomial evaluation, and Lagrange interpolation.
*   **Contributor B:** Implement the secure channel logic (`channel.py`) including X25519 ECDH key exchange and AES-GCM encryption wrapper.
*   **Contributor C:** Implement peer discovery and transmission (`discovery.py`, `transfer.py`) including mDNS broadcasting/browsing and TCP socket framing.
*   **Contributor D:** Develop CLI integration (`split.py`, `recover.py`) to connect modules, orchestrate CLI arguments, and handle run-time user experience.

### Roadmap
*   **Week 1 (Onboarding and Setup):** Read reference cryptography material, configure repository structure, set up pre-commit hooks, and verify the testing environment.
*   **Week 2 (SSS Implementation):** Complete finite field arithmetic and base SSS logic in `sss.py`, backed by unit tests for threshold edge cases.
*   **Week 3 (Secure Channels & Networking):** Complete X25519 ECDH handshake, AES-GCM integration, mDNS announcement, and basic TCP socket transmissions.
*   **Week 4 (CLI Integration & End-to-End Flow):** Integrate CLI commands for `split` and `recover`, and perform initial end-to-end local network testing.
*   **Week 5 (Hardening and Optimization):** Implement error handling, handle peer disconnection scenarios, set socket timeouts, and test across different operating systems (Linux, macOS).
*   **Week 6 (Documentation and Validation):** Complete documentation, write final integration tests, execute a live demonstration on a local network, freeze the codebase, and submit the project.

---

## 6. References and Reading Material

*   **Shamir's Secret Sharing:** Shamir, A. (1979). "How to Share a Secret". *Communications of the ACM*, 22(11), 612–613. [Wikipedia Article](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)
*   **Finite Field GF(256):** [A Gentle Introduction to GF(256)](https://github.com/dsprenkels/sss) (Reference implementation and math overview).
*   **X25519 and AES-GCM Primitive Documentation:** [Python Cryptography Library Documentation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/) and [AEAD Ciphers](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM).
*   **mDNS / Zeroconf Implementation:** [python-zeroconf GitHub Repository](https://github.com/python-zeroconf/python-zeroconf) and reference implementation `plink` by Devlup Labs.
*   **TCP Socket Programming:** [Official Python Socket Programming HOWTO](https://docs.python.org/3/howto/sockets.html).