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
