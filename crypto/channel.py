from __future__ import annotations

import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SecureChannel:
    """
    Handles ephemeral X25519 ECDH key exchange and AES-256-GCM authenticated
    encryption/decryption between peers.
    """

    def __init__(self):
        self.private_key: x25519.X25519PrivateKey | None = None
        self.public_key: x25519.X25519PublicKey | None = None
        self.shared_key: bytes | None = None

    def generate_key_pair(self) -> bytes:
        """
        Generates an X25519 private/public key pair and returns the public key
        as raw 32-byte bytes.
        """
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def compute_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Computes the Diffie-Hellman shared secret with the peer's public key
        and derives a 32-byte symmetric AES session key using HKDF-SHA256.
        """
        if self.private_key is None:
            raise ValueError(
                "Local key pair must be generated before computing shared secret."
            )

        if (
            not isinstance(peer_public_key_bytes, (bytes, bytearray))
            or len(peer_public_key_bytes) != 32
        ):
            raise ValueError("Peer public key must be exactly 32 bytes.")

        peer_public_key = x25519.X25519PublicKey.from_public_bytes(
            bytes(peer_public_key_bytes)
        )
        raw_secret = self.private_key.exchange(peer_public_key)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"meshvault-v1-session-key",
        )
        self.shared_key = hkdf.derive(raw_secret)
        return self.shared_key

    def encrypt_message(self, plaintext: bytes) -> bytes:
        """
        Encrypts a message using AES-256-GCM with a fresh 12-byte nonce.
        Returns nonce (12 bytes) + ciphertext + tag (16 bytes).
        """
        if self.shared_key is None:
            raise ValueError("Shared symmetric key has not been established.")

        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("Plaintext must be bytes.")

        nonce = os.urandom(12)
        aesgcm = AESGCM(self.shared_key)
        ciphertext = aesgcm.encrypt(nonce, bytes(plaintext), None)
        return nonce + ciphertext

    def decrypt_message(self, ciphertext: bytes) -> bytes:
        """
        Decrypts an AES-256-GCM encrypted message.
        Expects nonce (12 bytes) + ciphertext + tag (16 bytes).
        """
        if self.shared_key is None:
            raise ValueError("Shared symmetric key has not been established.")

        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("Ciphertext must be bytes.")

        if len(ciphertext) < 28:  # 12-byte nonce + 16-byte minimum tag
            raise ValueError("Ciphertext too short to be valid AES-GCM frame.")

        nonce = ciphertext[:12]
        payload = ciphertext[12:]
        aesgcm = AESGCM(self.shared_key)
        return aesgcm.decrypt(nonce, payload, None)
