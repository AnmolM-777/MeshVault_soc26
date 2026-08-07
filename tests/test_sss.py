<<<<<<< HEAD
import itertools
import pytest
from crypto.sss import split_secret, reconstruct_secret


def test_reconstruct_with_exact_k():
    secret = b"hello secret"
    shares = split_secret(secret, n=5, k=3)
    assert reconstruct_secret(shares[:3]) == secret


def test_reconstruct_with_all_n_shares():
    secret = b"another secret!"
    shares = split_secret(secret, n=6, k=4)
    assert reconstruct_secret(shares) == secret


def test_k_equals_1():
    secret = b"trivial"
    shares = split_secret(secret, n=4, k=1)
    assert reconstruct_secret(shares[:1]) == secret


def test_k_equals_n():
    secret = b"tight threshold"
    shares = split_secret(secret, n=5, k=5)
    assert reconstruct_secret(shares) == secret


def test_any_k_subset_agrees():
    secret = b"consistency check"
    shares = split_secret(secret, n=7, k=4)
    for subset in itertools.combinations(shares, 4):
        assert reconstruct_secret(list(subset)) == secret


def test_fewer_than_k_shares_gives_wrong_secret():
    secret = b"insufficient shares here"
    shares = split_secret(secret, n=5, k=4)
    assert reconstruct_secret(shares[:3]) != secret


def test_duplicate_x_raises():
    with pytest.raises(ValueError):
        reconstruct_secret([(1, b"a"), (1, b"b")])


def test_empty_shares_raises():
    with pytest.raises(ValueError):
        reconstruct_secret([])


def test_mismatched_lengths_raises():
    with pytest.raises(ValueError):
        reconstruct_secret([(1, b"ab"), (2, b"abc")])
=======
"""
Unit tests for Shamir's Secret Sharing core (crypto/sss.py).
"""

import pytest
from crypto.sss import split_secret, reconstruct_secret, gf256_add, gf256_multiply


def test_sss_import():
    """
    Ensure the functions are correctly defined and can be imported.
    """
    assert split_secret is not None
    assert reconstruct_secret is not None
    assert gf256_add is not None
    assert gf256_multiply is not None


def test_sss_raises_not_implemented():
    """
    Ensure the functions raise NotImplementedError for placeholder code.
    """
    with pytest.raises(NotImplementedError):
        gf256_add(1, 2)

    with pytest.raises(NotImplementedError):
        gf256_multiply(1, 2)

    with pytest.raises(NotImplementedError):
        split_secret(b"test_secret", 2, 3)

    with pytest.raises(NotImplementedError):
        reconstruct_secret([])
>>>>>>> 30c7fee7ab3dec7e252f0d92a24fcce382a46ce7
