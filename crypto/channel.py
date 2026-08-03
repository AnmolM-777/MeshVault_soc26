"""
Secure Channel Encryption Module.
Responsible for X25519 ECDH key exchange and AES-256-GCM symmetric encryption.

Mentee B Deliverables:
- Weeks 1-2: Write working X25519 key exchange between two processes, derive and print shared secret.
- Weeks 3-4: Implement full ECDH handshake and AES-GCM encryption/decryption wrapper.
"""

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
 



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
        
        self.private_key = X25519PrivateKey.generate()
        # Derive the corresponding public key from the private key.
        self.public_key = self.private_key.public_key()
 
        # Serialize the public key to raw bytes so it can be sent to a peer.
        return self.public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )

        # TODO: Generate X25519 key pair and return public key bytes
        raise NotImplementedError("generate_key_pair has not been implemented yet.")



    def compute_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Computes the shared symmetric key using peer's public key.

        Mentee B Weeks 1-2 Deliverable.
        """


        peer_public_key = X25519PublicKey.from_public_bytes(
            peer_public_key_bytes
        )
 
        shared_secret = self.private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"SecureChannel X25519 session key",
        ).derive(shared_secret)
 
        self.shared_key = derived_key
        return self.shared_key
    

        # TODO: Compute Diffie-Hellman shared secret and derive session key (HKDF)
        raise NotImplementedError("compute_shared_secret has not been implemented yet.")




    def encrypt_message(self, plaintext: bytes) -> bytes:
        """
        Encrypts a message using the derived shared key with AES-256-GCM.

        Mentee B Weeks 3-4 Deliverable.
        """
        
        if self.shared_key is None:
            raise ValueError(
                "Shared key has not been established. "
                "Call compute_shared_secret() first."
            )
 
        nonce = os.urandom(12)
 
        aesgcm = AESGCM(self.shared_key)

        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext



        # TODO: Encrypt using AES-GCM
        raise NotImplementedError("encrypt_message has not been implemented yet.")

    def decrypt_message(self, ciphertext: bytes) -> bytes:
        """
        Decrypts an AES-256-GCM encrypted message.

        Mentee B Weeks 3-4 Deliverable.
        """


        if self.shared_key is None:
            raise ValueError(
                "Shared key has not been established. "
                "Call compute_shared_secret() first."
            )
 
        if len(ciphertext) < 12 + 16:
            raise ValueError("Encrypted message is too short to be valid.")
 
       
        nonce = ciphertext[:12]
        actual_ciphertext = ciphertext[12:]
 
        aesgcm = AESGCM(self.shared_key)
        try:
            # Decrypt and verify the authentication tag in one step.
            plaintext = aesgcm.decrypt(nonce, actual_ciphertext, None)
        except Exception as exc:
            raise ValueError(
                "Failed to decrypt message: authentication failed."
            ) from exc
 
        return plaintext


        # TODO: Decrypt using AES-GCM
        raise NotImplementedError("decrypt_message has not been implemented yet.")
