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
    return a^b


def gf256_multiply(a: int, b: int) -> int:
    """
    Multiplies two numbers in GF(256).

    Mentee A Weeks 1-2 Deliverable.
    """
    #Based on Russian Peasant Multiplication idea
    result= 0
    while b:                
        if b&1:
            result^=a
        a<<=1
        if a&256:
            a^=283
        b>>=1
    return a&255    
         
def poly_eval(coeffs: List[int], x: int)
    result = 0
    for coeff in reversed(coeffs):
        result = (result gf256_multiply x) gf256_add coeff
    return result


def split_secret(
    secret: bytes, threshold_k: int, shares_n: int
) -> List[Tuple[int, bytes]]:
    """
    Splits the secret into N shares, such that any K shares can reconstruct it.

    Mentee A Weeks 3-4 Deliverable.
    """
    #Validation of inputs
    if threshold_k>shares_n:
        raise ValueError("Threshold k cannot be greater than total shares n")
    
    if not(1<=threshold_k<=255 and 1<=shares_n<=255 ):
        raise ValueError("Threshold k and Shares n must be between 1 and 255")
    
    import os
    #creating an empty list for storing shares
    shares=[bytearray() for _ in range(shares_n)]
    
    for byte in secret:
        #generating coefficients for polynomial
        coeffs=[byte]+list(os.urandom(threshold_k - 1))
        for i in range(shares_n):
            x=i+1
            result= poly_eval(coeff,x)
            shares[i].append(result)

    return [(i+1,s) for i,s in enumerate(shares)]  
   


def reconstruct_secret(shares: List[Tuple[int, bytes]]) -> bytes:
    """
    Reconstructs the original secret from a list of K or more shares.

    Mentee A Weeks 3-4 Deliverable.
    """
    # TODO: Implement Lagrange interpolation to recover the secret
    raise NotImplementedError("reconstruct_secret has not been implemented yet.")
