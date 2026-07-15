"""
Shamir's Secret Sharing (SSS) Module.
Responsible for finite field arithmetic, polynomial evaluation, and Lagrange interpolation.

Mentee A Deliverables:
- Weeks 1-2: Implement GF(256) addition and multiplication from scratch (without libraries)
- Weeks 3-4: Implement full SSS split and reconstruct over GF(256) or a prime field.
"""

from typing import List, Tuple
import secrets

def gf256_add(a: int, b: int) -> int:
    """
    Adds two numbers in GF(256).

    Mentee A Weeks 1-2 Deliverable.
    """
    return a ^ b
   


def gf256_multiply(a: int, b: int) -> int:
    """
    Multiplies two numbers in GF(256).

    Mentee A Weeks 1-2 Deliverable.
    """
    

    # Convert integer to polynomial (list of exponents)
    def int_to_poly(num):
        poly = []
        power = 0

        while num > 0:
            if num % 2 == 1:
                poly.append(power)
            num //= 2
            power += 1

        return poly

    # Multiply two polynomials
    def multiply_poly(p1, p2):
        result = []

        for x in p1:
            for y in p2:
                degree = x + y

                # XOR rule:
                # If the term already exists, remove it.
                # Otherwise, add it.
                if degree in result:
                    result.remove(degree)
                else:
                    result.append(degree)

        return result

    # Reduce using x^8 + x^4 + x^3 + x + 1
    def reduce_poly(poly):
        while max(poly, default=0) >= 8:
            highest = max(poly)
            poly.remove(highest)

            shift = highest - 8

            for term in [4, 3, 1, 0]:
                value = term + shift

                if value in poly:
                    poly.remove(value)
                else:
                    poly.append(value)

        return poly

    # Convert polynomial back to integer
    def poly_to_int(poly):
        value = 0

        for power in poly:
            value += 2 ** power

        return value 

    p1 = int_to_poly(a)
    p2 = int_to_poly(b)

    product = multiply_poly(p1, p2)
    reduced = reduce_poly(product)

    return poly_to_int(reduced)


def generate_polynomial(secret_byte: int, degree: int):
        """
        Generates a random polynomial whose constant term is the secret.
        """
        
        polynomial = [secret_byte]

        for i in range(degree):
            random_coefficient = secrets.randbelow(256)
            polynomial.append(random_coefficient)

        return polynomial


def split_secret(secret: bytes, threshold_k: int, shares_n: int) -> List[Tuple[int, bytes]]:
    """
    Splits the secret into N shares, such that any K shares can reconstruct it.

    Mentee A Weeks 3-4 Deliverable.
    """
    raise NotImplementedError("split_secret has not been implemented yet.")
    



def reconstruct_secret(shares: List[Tuple[int, bytes]]) -> bytes:
    """
    Reconstructs the original secret from a list of K or more shares.

    Mentee A Weeks 3-4 Deliverable.
    """
    # TODO: Implement Lagrange interpolation to recover the secret
    raise NotImplementedError("reconstruct_secret has not been implemented yet.")
