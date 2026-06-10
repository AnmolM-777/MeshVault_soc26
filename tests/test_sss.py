"""
Unit tests for Shamir's Secret Sharing core (sss.py).
"""

import pytest
from meshvault.sss import split_secret, reconstruct_secret

def test_sss_import():
    """
    Ensure the functions are correctly defined and can be imported.
    """
    assert split_secret is not None
    assert reconstruct_secret is not None

def test_sss_raises_not_implemented():
    """
    Ensure the functions raise NotImplementedError for placeholder code.
    """
    with pytest.raises(NotImplementedError):
        split_secret(b"test_secret", 2, 3)

    with pytest.raises(NotImplementedError):
        reconstruct_secret([])
