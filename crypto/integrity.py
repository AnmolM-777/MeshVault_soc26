"""
crypto/integrity.py

Cryptographic Integrity Checksums & Share Tamper Detection (Issue #17).

Problem
-------
Lagrange interpolation in crypto/sss.py has no way to know whether the
shares it was given are correct. If even ONE share is corrupted (bit
rot in transit, disk corruption, or a malicious peer substituting a
forged share), reconstruct_secret() will still return *a* value —
just the wrong secret — with no error, no exception, nothing. Silent
corruption is the worst failure mode for a secret-sharing tool.

Solution
--------
At split time, compute SHA-256(secret) once. That 32-byte digest is
embedded into EVERY share's payload before it goes out over the wire
(see pack_share_with_integrity). At recover time, every collected
share is unpacked to recover (x, share_bytes, embedded_hash). All
embedded hashes must agree with each other (if they don't, shares
came from different splits or were tampered with pre-emptively).
After Lagrange reconstruction, the secret is re-hashed and compared
against the embedded digest in constant time.

Why plain SHA-256 and not HMAC
-------------------------------
HMAC only adds value if you need to prove the *hash itself* wasn't
forged by an attacker without a shared key. Here, shares already
travel over channel.py's AES-GCM encrypted, authenticated channel —
so the transport layer already protects against a MITM forging
packets. The threat this issue actually targets is a corrupted or
maliciously-substituted SHARE causing bad reconstruction, which plain
SHA-256 catches identically to HMAC. An optional keyed HMAC variant is
included below in case the mentor prefers defense-in-depth.

Why embed the hash inside the share payload (design decision)
---------------------------------------------------------------
network/transfer.py and network/discovery.py (Contributor C's
already-verified modules) operate on (x: int, share_bytes: bytes)
tuples and know nothing about integrity metadata. Rather than
changing their signatures or the wire protocol, the 32-byte digest is
prepended to each share's byte payload before handing it to
send_shares(), and stripped back off after receive_encrypted_share().
This satisfies "distribute the hash alongside each share packet"
without touching the network layer at all.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import List, Tuple

HASH_LEN = 32  # SHA-256 digest length in bytes


class TamperDetectedError(Exception):
    """Raised when a reconstructed secret fails integrity verification,
    or when collected shares carry disagreeing integrity metadata."""


# --------------------------------------------------------------------------
# Core hashing
# --------------------------------------------------------------------------

def compute_integrity_hash(secret: bytes) -> bytes:
    """Compute the SHA-256 digest of the original secret at split time."""
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError("secret must be bytes")
    return hashlib.sha256(bytes(secret)).digest()


def verify_integrity(reconstructed_secret: bytes, expected_hash: bytes) -> None:
    """
    Verify a reconstructed secret against the expected SHA-256 digest.

    Raises TamperDetectedError on mismatch. Uses hmac.compare_digest
    for a constant-time comparison to avoid timing side channels.
    """
    actual_hash = hashlib.sha256(reconstructed_secret).digest()
    if not hmac.compare_digest(actual_hash, expected_hash):
        raise TamperDetectedError(
            "Reconstructed secret failed integrity check — one or more "
            "shares may be corrupted or tampered with."
        )


# --------------------------------------------------------------------------
# Optional keyed variant (HMAC) — not used by default, kept for mentor review
# --------------------------------------------------------------------------

def compute_integrity_hmac(secret: bytes, key: bytes) -> bytes:
    return hmac.new(key, secret, hashlib.sha256).digest()


def verify_integrity_hmac(reconstructed_secret: bytes, key: bytes, expected_mac: bytes) -> None:
    actual_mac = hmac.new(key, reconstructed_secret, hashlib.sha256).digest()
    if not hmac.compare_digest(actual_mac, expected_mac):
        raise TamperDetectedError("HMAC verification failed on reconstructed secret.")


# --------------------------------------------------------------------------
# Packet packing / unpacking — this is what lets the hash "ride along"
# with each share without changing transfer.py / discovery.py
# --------------------------------------------------------------------------

def pack_share_with_integrity(
    share: Tuple[int, bytes], secret_hash: bytes
) -> Tuple[int, bytes]:
    """
    Prepend the secret's integrity hash to a single share's byte payload.

    (x, share_bytes) + secret_hash  ->  (x, secret_hash || share_bytes)

    The result is still a plain (int, bytes) tuple, so it's transparent
    to network/transfer.py and network/discovery.py.
    """
    if len(secret_hash) != HASH_LEN:
        raise ValueError(f"secret_hash must be exactly {HASH_LEN} bytes")
    x, share_bytes = share
    return (x, secret_hash + share_bytes)


def pack_shares_with_integrity(
    shares: List[Tuple[int, bytes]], secret_hash: bytes
) -> List[Tuple[int, bytes]]:
    """Convenience wrapper: pack integrity metadata into every share."""
    return [pack_share_with_integrity(s, secret_hash) for s in shares]


def unpack_share_with_integrity(
    packet: Tuple[int, bytes]
) -> Tuple[Tuple[int, bytes], bytes]:
    """
    Reverse of pack_share_with_integrity.

    (x, secret_hash || share_bytes)  ->  ((x, share_bytes), secret_hash)

    Raises ValueError if the packet is too short to contain a valid
    embedded hash (defensive check against malformed/truncated data).
    """
    x, payload = packet
    if len(payload) < HASH_LEN:
        raise ValueError(
            f"Share packet too short ({len(payload)} bytes) to contain "
            f"a {HASH_LEN}-byte integrity hash — packet is malformed "
            "or was truncated in transit."
        )
    secret_hash = payload[:HASH_LEN]
    share_bytes = payload[HASH_LEN:]
    return (x, share_bytes), secret_hash


def unpack_shares_with_integrity(
    packets: List[Tuple[int, bytes]]
) -> Tuple[List[Tuple[int, bytes]], bytes]:
    """
    Unpack a list of received share packets and confirm they all agree
    on the same embedded secret hash.

    Returns (plain_shares, agreed_secret_hash).
    Raises TamperDetectedError if the packets disagree on the hash —
    this is a strong early signal that the shares are not all from the
    same legitimate split, or that one was tampered with before it even
    reached this function.
    """
    plain_shares: List[Tuple[int, bytes]] = []
    hashes = set()

    for packet in packets:
        share, secret_hash = unpack_share_with_integrity(packet)
        plain_shares.append(share)
        hashes.add(secret_hash)

    if len(hashes) != 1:
        raise TamperDetectedError(
            "Collected shares disagree on embedded integrity hash — "
            "shares may belong to different splits or have been tampered "
            "with."
        )

    return plain_shares, hashes.pop()