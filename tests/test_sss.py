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