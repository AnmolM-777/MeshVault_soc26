"""
Shamir's Secret Sharing (SSS) Module.
Responsible for finite field arithmetic, polynomial evaluation, and Lagrange interpolation.

Mentee A Deliverables:
- Weeks 1-2: Implement GF(256) addition and multiplication from scratch (without libraries)
- Weeks 3-4: Implement full SSS split and reconstruct over GF(256) or a prime field.
"""

from typing import List, Tuple

def gf256_add(a: int, b: int) -> int:
    """
    Adds two numbers in GF(256).
    
    Mentee A Weeks 1-2 Deliverable.
    """
    # TODO: Implement GF(256) addition
    raise NotImplementedError("gf256_add has not been implemented yet.")

def gf256_multiply(a: int, b: int) -> int:
    """
    Multiplies two numbers in GF(256).
    
    Mentee A Weeks 1-2 Deliverable.
    """
    # TODO: Implement GF(256) multiplication
    raise NotImplementedError("gf256_multiply has not been implemented yet.")

def split_secret(secret: bytes, threshold_k: int, shares_n: int) -> List[Tuple[int, bytes]]:
    """
    Splits the secret into N shares, such that any K shares can reconstruct it.
    
    Mentee A Weeks 3-4 Deliverable.
    """
    # TODO: Implement polynomial generation and evaluation over GF(256)
    raise NotImplementedError("split_secret has not been implemented yet.")

def reconstruct_secret(shares: List[Tuple[int, bytes]]) -> bytes:
    """
    Reconstructs the original secret from a list of K or more shares.
    
    Mentee A Weeks 3-4 Deliverable.
    """
    # TODO: Implement Lagrange interpolation to recover the secret
    raise NotImplementedError("reconstruct_secret has not been implemented yet.")
