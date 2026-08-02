from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey , X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

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
        # private key generate kari
        self.private_key = X25519PrivateKey.generate()
        # private key se public key banayi
        self.public_key = self.private_key.public_key()
        # public key bytes mein return kari
        return self.public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )
        
    def compute_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Computes the shared symmetric key using peer's public key.

        Mentee B Weeks 1-2 Deliverable.
        """
        #bytes ko public key object mein convert kara
        peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    
        #raw shared secret nikala
        raw_shared = self.private_key.exchange(peer_public_key)
    
        #HKDF se clean 32-byte key banai
        self.shared_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"meshvault"
        ).derive(raw_shared)
    
        return self.shared_key

    def encrypt_message(self, plaintext: bytes) -> bytes:
        """
        Encrypts a message using the derived shared key with AES-256-GCM.

        Mentee B Weeks 3-4 Deliverable.
        """
        if self.shared_key is None:
            raise ValueError("Shared key not found — call compute_shared_secret() first")
        
        nonce = os.urandom(12)                                #cretaing 12 byte random number nonce
        aesgcm = AESGCM(self.shared_key)                      #creating object in class AESGCM
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)   #ciphertext is basically ciphertext + 16 bytes tag
        return nonce + ciphertext
        #return value structure[ 12 bytes nonce ][ ciphertext ][ 16 bytes tag ]

    def decrypt_message(self, ciphertext: bytes) -> bytes:
        """
        Decrypts an AES-256-GCM encrypted message.

        Mentee B Weeks 3-4 Deliverable.
        """
        if self.shared_key is None:
            raise ValueError("Shared key not found — call compute_shared_secret() first")
        
        nonce = ciphertext[:12]                                     #first 12 bytes = nonce
        actual_ciphertext = ciphertext[12:]                         #rest = ciphertext + tag
        aesgcm = AESGCM(self.shared_key)
        plaintext = aesgcm.decrypt(nonce, actual_ciphertext, None)    
        return plaintext
    

