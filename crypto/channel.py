"""
Secure Channel Encryption Module.
Responsible for X25519 ECDH key exchange and AES-256-GCM symmetric encryption.

Mentee B Deliverables:
- Weeks 1-2: Write working X25519 key exchange between two processes, derive and print shared secret.
- Weeks 3-4: Implement full ECDH handshake and AES-GCM encryption/decryption wrapper.
"""


class SecureChannel:
    """
    Handles key exchange and secure message packaging between peers.
    """

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.shared_key = None

    def generate_key_pair(self) -> bytes:
        """
        Generates an X25519 private/public key pair.

        Mentee B Weeks 1-2 Deliverable.
        """
        # TODO: Generate X25519 key pair and return public key bytes
        raise NotImplementedError("generate_key_pair has not been implemented yet.")

    def compute_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Computes the shared symmetric key using peer's public key.

        Mentee B Weeks 1-2 Deliverable.
        """
        # TODO: Compute Diffie-Hellman shared secret and derive session key (HKDF)
        raise NotImplementedError("compute_shared_secret has not been implemented yet.")

    def encrypt_message(self, plaintext: bytes) -> bytes:
        """
        Encrypts a message using the derived shared key with AES-256-GCM.

        Mentee B Weeks 3-4 Deliverable.
        """
        # TODO: Encrypt using AES-GCM
        raise NotImplementedError("encrypt_message has not been implemented yet.")

    def decrypt_message(self, ciphertext: bytes) -> bytes:
        """
        Decrypts an AES-256-GCM encrypted message.

        Mentee B Weeks 3-4 Deliverable.
        """
        # TODO: Decrypt using AES-GCM
        raise NotImplementedError("decrypt_message has not been implemented yet.")
