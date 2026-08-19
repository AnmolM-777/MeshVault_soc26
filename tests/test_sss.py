"""
tests/test_sss.py — Issue #42 acceptance criteria:
"Add unit tests validating correct roundtrips for multi-byte secrets,
binary data, and empty secrets."
"""

import itertools
import secrets as pysecrets

import pytest

from crypto.sss import split_secret, reconstruct_secret


def roundtrip(secret: bytes, n: int, k: int) -> None:
    """Split, take a random k-subset of shares, reconstruct, compare."""
    shares = split_secret(secret, n, k)
    assert len(shares) == n

    subset = pysecrets.SystemRandom().sample(shares, k)
    recovered = reconstruct_secret(subset)
    assert recovered == secret


class TestMultiByteRoundtrip:
    def test_short_ascii_secret(self):
        roundtrip(b"hunter2-api-key", n=5, k=3)

    def test_long_multibyte_secret(self):
        # simulate a private key / credential file
        secret = pysecrets.token_bytes(256)
        roundtrip(secret, n=5, k=3)

    def test_binary_data_all_byte_values(self):
        # every possible byte value 0-255, exercises full field range
        secret = bytes(range(256))
        roundtrip(secret, n=5, k=3)

    def test_empty_secret(self):
        shares = split_secret(b"", n=5, k=3)
        assert len(shares) == 5
        assert all(y == b"" for _, y in shares)
        recovered = reconstruct_secret(shares[:3])
        assert recovered == b""

    def test_single_byte_secret(self):
        roundtrip(b"\x00", n=3, k=2)
        roundtrip(b"\xff", n=3, k=2)


class TestThresholdEdgeCases:
    def test_k_equals_n(self):
        # every single share is required
        secret = b"all-shares-required"
        roundtrip(secret, n=4, k=4)

    def test_k_equals_1(self):
        # any single share alone reconstructs the secret
        secret = b"any-one-share-works"
        shares = split_secret(secret, n=4, k=1)
        for share in shares:
            assert reconstruct_secret([share]) == secret

    def test_fewer_than_k_shares_does_not_reconstruct(self):
        # not a formal security proof, just a sanity check that
        # under-threshold reconstruction does NOT silently return
        # the right answer
        secret = b"threshold-secret-value"
        shares = split_secret(secret, n=5, k=3)
        wrong = reconstruct_secret(shares[:2])
        assert wrong != secret

    def test_more_than_k_shares_still_works(self):
        secret = b"extra-shares-ok"
        shares = split_secret(secret, n=5, k=3)
        recovered = reconstruct_secret(shares)  # pass all 5
        assert recovered == secret


class TestValidation:
    def test_rejects_k_greater_than_n(self):
        with pytest.raises(ValueError):
            split_secret(b"secret", n=3, k=5)

    def test_rejects_k_less_than_1(self):
        with pytest.raises(ValueError):
            split_secret(b"secret", n=3, k=0)

    def test_rejects_n_greater_than_255(self):
        # GF(256) only has 255 nonzero elements to use as x-coordinates
        with pytest.raises(ValueError):
            split_secret(b"secret", n=256, k=2)

    def test_accepts_n_equal_255(self):
        shares = split_secret(b"x", n=255, k=2)
        assert len(shares) == 255
        assert reconstruct_secret(shares[:2]) == b"x"

    def test_rejects_n_zero(self):
        with pytest.raises(ValueError):
            split_secret(b"secret", n=0, k=1)

    def test_rejects_non_bytes_secret(self):
        with pytest.raises(TypeError):
            split_secret("not-bytes", n=3, k=2)  # type: ignore[arg-type]

    def test_reconstruct_rejects_mismatched_share_lengths(self):
        with pytest.raises(ValueError):
            reconstruct_secret([(1, b"ab"), (2, b"a")])

    def test_reconstruct_rejects_duplicate_x_coordinates(self):
        with pytest.raises(ValueError):
            reconstruct_secret([(1, b"ab"), (1, b"cd")])

    def test_reconstruct_rejects_empty_share_list(self):
        with pytest.raises(ValueError):
            reconstruct_secret([])


class TestAllKSubsets:
    """
    Exhaustively check that every k-subset of shares (not just one
    random sample) reconstructs correctly -- catches bugs where only
    some x-coordinate combinations happen to work.
    """

    def test_every_k_subset_reconstructs(self):
        secret = b"exhaustive-check"
        n, k = 5, 3
        shares = split_secret(secret, n, k)
        for subset in itertools.combinations(shares, k):
            assert reconstruct_secret(list(subset)) == secret