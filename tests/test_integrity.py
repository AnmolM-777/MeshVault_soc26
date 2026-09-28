"""
tests/test_integrity.py

Covers Issue #17 acceptance criteria:
  1. SHA-256 hash of the original secret is computed at split time.
  2. Hash metadata is distributed alongside each individual share packet.
  3. During recover, the reconstructed secret is verified against the
     hash before being returned.
  4. Corrupted share payloads are detected instead of producing silent
     wrong output.
"""

from __future__ import annotations

import hashlib

import pytest

from crypto.sss import split_secret, reconstruct_secret
from crypto.integrity import (
    HASH_LEN,
    TamperDetectedError,
    compute_integrity_hash,
    verify_integrity,
    pack_share_with_integrity,
    pack_shares_with_integrity,
    unpack_share_with_integrity,
    unpack_shares_with_integrity,
)


# --------------------------------------------------------------------------
# 1. Hash computation at split time
# --------------------------------------------------------------------------

def test_compute_integrity_hash_matches_sha256():
    secret = b"super-secret-api-key-12345"
    expected = hashlib.sha256(secret).digest()
    assert compute_integrity_hash(secret) == expected

def test_compute_integrity_hash_rejects_non_bytes():
    with pytest.raises(TypeError):
        compute_integrity_hash("not-bytes")  # type: ignore[arg-type]


def test_compute_integrity_hash_is_deterministic():
    secret = b"same-secret-every-time"
    assert compute_integrity_hash(secret) == compute_integrity_hash(secret)


def test_different_secrets_produce_different_hashes():
    assert compute_integrity_hash(b"secret-one") != compute_integrity_hash(b"secret-two")


# --------------------------------------------------------------------------
# 2. Hash metadata rides alongside each share packet
# --------------------------------------------------------------------------

def test_pack_share_prepends_hash_to_payload():
    secret_hash = b"\xaa" * HASH_LEN
    x, share_bytes = 3, b"share-payload-bytes"
    packed_x, packed_payload = pack_share_with_integrity((x, share_bytes), secret_hash)

    assert packed_x == x
    assert packed_payload[:HASH_LEN] == secret_hash
    assert packed_payload[HASH_LEN:] == share_bytes


def test_pack_shares_embeds_same_hash_in_every_share():
    secret = b"my-database-password"
    secret_hash = compute_integrity_hash(secret)
    raw_shares = split_secret(secret, n=5, k=3)

    packed = pack_shares_with_integrity(raw_shares, secret_hash)

    assert len(packed) == len(raw_shares)
    for x, payload in packed:
        assert payload[:HASH_LEN] == secret_hash


def test_pack_share_rejects_wrong_length_hash():
    with pytest.raises(ValueError):
        pack_share_with_integrity((1, b"payload"), b"too-short")


def test_unpack_share_reverses_pack_share():
    secret_hash = b"\xbb" * HASH_LEN
    original = (5, b"original-share-bytes")

    packed = pack_share_with_integrity(original, secret_hash)
    (x, share_bytes), recovered_hash = unpack_share_with_integrity(packed)

    assert (x, share_bytes) == original
    assert recovered_hash == secret_hash


def test_unpack_share_rejects_truncated_packet():
    # Payload shorter than HASH_LEN can't possibly contain a valid hash.
    truncated = (1, b"short")
    with pytest.raises(ValueError):
        unpack_share_with_integrity(truncated)


def test_unpack_shares_with_integrity_agrees_on_common_hash():
    secret = b"agreement-check-secret"
    secret_hash = compute_integrity_hash(secret)
    raw_shares = split_secret(secret, n=5, k=3)
    packed = pack_shares_with_integrity(raw_shares, secret_hash)

    plain_shares, agreed_hash = unpack_shares_with_integrity(packed[:3])

    assert agreed_hash == secret_hash
    assert sorted(plain_shares) == sorted(raw_shares[:3])


def test_unpack_shares_with_integrity_detects_disagreeing_hashes():
    secret_a = b"secret-a-data"
    secret_b = b"secret-b-data"
    hash_a = compute_integrity_hash(secret_a)
    hash_b = compute_integrity_hash(secret_b)

    shares_a = split_secret(secret_a, n=3, k=2)
    shares_b = split_secret(secret_b, n=3, k=2)

    # Mix a share from split A with a share from split B — a share
    # substitution / mixed-batch attack.
    mixed_packets = [
        pack_share_with_integrity(shares_a[0], hash_a),
        pack_share_with_integrity(shares_b[1], hash_b),
    ]

    with pytest.raises(TamperDetectedError):
        unpack_shares_with_integrity(mixed_packets)


# --------------------------------------------------------------------------
# 3. Verification of reconstructed secret against the hash
# --------------------------------------------------------------------------

def test_verify_integrity_passes_for_correct_secret():
    secret = b"correct-secret-value"
    secret_hash = compute_integrity_hash(secret)
    verify_integrity(secret, secret_hash)  # should not raise


def test_verify_integrity_raises_for_wrong_secret():
    secret_hash = compute_integrity_hash(b"expected-secret")
    with pytest.raises(TamperDetectedError):
        verify_integrity(b"wrong-secret-value", secret_hash)


# --------------------------------------------------------------------------
# 4. Full split -> corrupt -> recover pipeline: corrupted share is caught
#    instead of silently producing wrong output
# --------------------------------------------------------------------------

def test_end_to_end_valid_reconstruction_passes_integrity():
    secret = b"end-to-end-valid-secret"
    secret_hash = compute_integrity_hash(secret)

    raw_shares = split_secret(secret, n=5, k=3)
    packets = pack_shares_with_integrity(raw_shares, secret_hash)

    # Simulate recover.py: collect K packets, unpack, reconstruct, verify.
    collected = packets[:3]
    shares, agreed_hash = unpack_shares_with_integrity(collected)
    reconstructed = reconstruct_secret(shares)

    verify_integrity(reconstructed, agreed_hash)  # should not raise
    assert reconstructed == secret


def test_end_to_end_corrupted_share_byte_is_detected():
    secret = b"end-to-end-secret-that-will-be-tampered"
    secret_hash = compute_integrity_hash(secret)

    raw_shares = split_secret(secret, n=5, k=3)
    packets = pack_shares_with_integrity(raw_shares, secret_hash)

    collected = list(packets[:3])

    # Corrupt one share's payload bytes (flip a bit deep in the share
    # data, past the embedded hash) — simulates bit rot or a malicious
    # peer substituting a bad share, while keeping the packet structurally
    # valid (same length, hash prefix intact) so it isn't caught by the
    # truncation check.
    x, payload = collected[0]
    corrupted_payload = bytearray(payload)
    corrupted_payload[HASH_LEN] ^= 0xFF  # flip first byte of share data
    collected[0] = (x, bytes(corrupted_payload))

    shares, agreed_hash = unpack_shares_with_integrity(collected)
    reconstructed = reconstruct_secret(shares)

    with pytest.raises(TamperDetectedError):
        verify_integrity(reconstructed, agreed_hash)

    # Confirm the tool does NOT silently return the wrong secret as if
    # it were valid.
    assert reconstructed != secret


def test_end_to_end_corrupted_share_x_coordinate_is_detected():
    """A tampered x-coordinate changes which Lagrange basis point is
    used, which should also throw off reconstruction and fail the
    integrity check (rather than silently succeeding)."""
    secret = b"secret-with-tampered-x-coordinate"
    secret_hash = compute_integrity_hash(secret)

    raw_shares = split_secret(secret, n=5, k=3)
    packets = pack_shares_with_integrity(raw_shares, secret_hash)
    collected = list(packets[:3])

    x, payload = collected[0]
    # Swap in a different valid-range x that no other collected share uses.
    used_xs = {p[0] for p in collected}
    new_x = next(v for v in range(1, 256) if v not in used_xs)
    collected[0] = (new_x, payload)

    shares, agreed_hash = unpack_shares_with_integrity(collected)
    reconstructed = reconstruct_secret(shares)

    with pytest.raises(TamperDetectedError):
        verify_integrity(reconstructed, agreed_hash)


def test_end_to_end_insufficient_shares_below_threshold_fails_integrity():
    """Reconstructing with fewer than K shares should produce garbage
    that also fails the integrity check — the checksum catches this
    failure mode too, not just malicious tampering."""
    secret = b"needs-at-least-three-shares"
    secret_hash = compute_integrity_hash(secret)

    raw_shares = split_secret(secret, n=5, k=3)
    packets = pack_shares_with_integrity(raw_shares, secret_hash)

    # Only provide 2 of the required 3 shares.
    collected = packets[:2]
    shares, agreed_hash = unpack_shares_with_integrity(collected)
    reconstructed = reconstruct_secret(shares)

    with pytest.raises(TamperDetectedError):
        verify_integrity(reconstructed, agreed_hash)


def test_end_to_end_truncated_packet_raises_before_reconstruction():
    """A packet too short to even contain a hash should fail fast at
    unpack time, before wasting effort on interpolation."""
    secret = b"secret-for-truncation-test"
    secret_hash = compute_integrity_hash(secret)
    raw_shares = split_secret(secret, n=3, k=2)
    packets = pack_shares_with_integrity(raw_shares, secret_hash)

    collected = list(packets[:2])
    x, _ = collected[0]
    collected[0] = (x, b"\x00" * 5)  # way shorter than HASH_LEN

    with pytest.raises(ValueError):
        unpack_shares_with_integrity(collected)