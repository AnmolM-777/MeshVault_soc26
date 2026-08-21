"""
Unit and cryptographic tests for Secure Channel module (crypto/channel.py).
Issues #16, #17, #18, #19.
"""

import pytest
from crypto.channel import SecureChannel


def test_channel_key_pair_generation():
    channel = SecureChannel()
    pubkey = channel.generate_key_pair()
    assert isinstance(pubkey, bytes)
    assert len(pubkey) == 32
    assert channel.private_key is not None
    assert channel.public_key is not None


def test_ecdh_key_exchange_roundtrip():
    peer_a = SecureChannel()
    peer_b = SecureChannel()

    pub_a = peer_a.generate_key_pair()
    pub_b = peer_b.generate_key_pair()

    key_a = peer_a.compute_shared_secret(pub_b)
    key_b = peer_b.compute_shared_secret(pub_a)

    assert key_a == key_b
    assert len(key_a) == 32


def test_encryption_decryption_roundtrip():
    peer_a = SecureChannel()
    peer_b = SecureChannel()

    pub_a = peer_a.generate_key_pair()
    pub_b = peer_b.generate_key_pair()

    peer_a.compute_shared_secret(pub_b)
    peer_b.compute_shared_secret(pub_a)

    message = b"Secret payload to be encrypted over the peer channel"
    ciphertext = peer_a.encrypt_message(message)

    assert ciphertext != message
    assert len(ciphertext) >= len(message) + 12 + 16

    plaintext = peer_b.decrypt_message(ciphertext)
    assert plaintext == message


def test_empty_message_encryption():
    peer_a = SecureChannel()
    peer_b = SecureChannel()

    pub_a = peer_a.generate_key_pair()
    pub_b = peer_b.generate_key_pair()

    peer_a.compute_shared_secret(pub_b)
    peer_b.compute_shared_secret(pub_a)

    empty_msg = b""
    ciphertext = peer_a.encrypt_message(empty_msg)
    assert peer_b.decrypt_message(ciphertext) == empty_msg


def test_corrupted_ciphertext_fails_authentication():
    peer_a = SecureChannel()
    peer_b = SecureChannel()

    pub_a = peer_a.generate_key_pair()
    pub_b = peer_b.generate_key_pair()

    peer_a.compute_shared_secret(pub_b)
    peer_b.compute_shared_secret(pub_a)

    message = b"Tamper-proof payload"
    ciphertext = bytearray(peer_a.encrypt_message(message))

    # Tamper with the ciphertext byte
    ciphertext[-1] ^= 0x01

    with pytest.raises(Exception):
        peer_b.decrypt_message(bytes(ciphertext))


def test_invalid_key_length_raises():
    channel = SecureChannel()
    channel.generate_key_pair()

    with pytest.raises(ValueError, match="32 bytes"):
        channel.compute_shared_secret(b"short_key")


def test_encrypt_without_key_raises():
    channel = SecureChannel()
    with pytest.raises(
        ValueError, match="Shared symmetric key has not been established"
    ):
        channel.encrypt_message(b"test")


def test_decrypt_without_key_raises():
    channel = SecureChannel()
    with pytest.raises(
        ValueError, match="Shared symmetric key has not been established"
    ):
        channel.decrypt_message(b"test" * 10)


def test_decrypt_too_short_ciphertext_raises():
    peer_a = SecureChannel()
    peer_b = SecureChannel()
    pub_b = peer_b.generate_key_pair()
    peer_a.generate_key_pair()
    peer_a.compute_shared_secret(pub_b)

    with pytest.raises(ValueError, match="too short"):
        peer_a.decrypt_message(b"short")
