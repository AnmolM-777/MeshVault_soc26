"""
Unit tests for Secure Channel module (crypto/channel.py).
"""

import pytest
from crypto.channel import SecureChannel

def test_channel_import():
    """
    Ensure the SecureChannel class is defined and can be instantiated.
    """
    channel = SecureChannel()
    assert channel is not None

def test_channel_raises_not_implemented():
    """
    Ensure the methods raise NotImplementedError for placeholder code.
    """
    channel = SecureChannel()
    with pytest.raises(NotImplementedError):
        channel.generate_key_pair()
        
    with pytest.raises(NotImplementedError):
        channel.compute_shared_secret(b"dummy_public_key")
        
    with pytest.raises(NotImplementedError):
        channel.encrypt_message(b"hello")
        
    with pytest.raises(NotImplementedError):
        channel.decrypt_message(b"ciphertext")
