"""
Shamir's Secret Sharing (SSS) Module.
Responsible for finite field arithmetic, polynomial evaluation, and Lagrange interpolation.

Mentee A Deliverables:
- Weeks 1-2: Implement GF(256) addition and multiplication from scratch (without libraries)
- Weeks 3-4: Implement full SSS split and reconstruct over GF(256) or a prime field.
"""


import secrets
from typing import List, Tuple

_AES_MODULUS = 0x11B
_GF_SIZE = 256


def _validate_gf256_element(value: int, name: str) -> None:
  
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if not (0 <= value <= 255):
        raise ValueError(f"{name} must be between 0 and 255")
    

def _generate_polynomial_coefficients(
    constant_term: int, threshold_k: int
) -> List[int]:
   
    coefficients = [constant_term]
    for _ in range(threshold_k - 1):
        # secrets.randbelow(256) yields a cryptographically secure
        # random integer in [0, 255].
        coefficients.append(secrets.randbelow(_GF_SIZE))
    return coefficients
 

def _evaluate_polynomial(coefficients: List[int], x: int) -> int:
    result = 0
    for coefficient in reversed(coefficients):
        result = gf256_add(gf256_multiply(result, x), coefficient)
    return result


def _gf256_inverse(a: int) -> int:
    _validate_gf256_element(a, "a")
    if a == 0:
        raise ValueError("zero has no multiplicative inverse in GF(256)")
    result = 1
    base = a
    exponent = 254
    while exponent > 0:
        if exponent & 1:
            result = gf256_multiply(result, base)
        base = gf256_multiply(base, base)
        exponent >>= 1
    return result
 
 
def _lagrange_interpolate_at_zero(
    x_values: List[int], y_values: List[int]
) -> int:
   
    secret_byte = 0
    n = len(x_values)
 
    for i in range(n):
        x_i = x_values[i]
        y_i = y_values[i]
        numerator = 1
        denominator = 1
 
        for j in range(n):
            if j == i:
                continue
            x_j = x_values[j]
 
            # (0 - x_j) reduces to x_j via XOR-based subtraction.
            numerator = gf256_multiply(numerator, x_j)
 
            # (x_i - x_j) reduces to (x_i ^ x_j).
            diff = gf256_add(x_i, x_j)
            if diff == 0:
                raise ValueError(
                    "duplicate x-coordinates found among shares"
                )
            denominator = gf256_multiply(denominator, diff)
 
        basis_value = gf256_multiply(numerator, _gf256_inverse(denominator))
        secret_byte = gf256_add(secret_byte, gf256_multiply(y_i, basis_value))
 
    return secret_byte




def gf256_add(a: int, b: int) -> int:
    """
    Adds two numbers in GF(256).

    Mentee A Weeks 1-2 Deliverable.
    """

    _validate_gf256_element(a, "a")
    _validate_gf256_element(b, "b")
 
    # Addition in GF(2^8) is simply bitwise XOR.
    return a ^ b


    # TODO: Implement GF(256) addition
    raise NotImplementedError("gf256_add has not been implemented yet.")



def gf256_multiply(a: int, b: int) -> int:
    """
    Multiplies two numbers in GF(256).

    Mentee A Weeks 1-2 Deliverable.
    """

    _validate_gf256_element(a, "a")
    _validate_gf256_element(b, "b")
 
    result = 0
    x = a
    y = b
 
    for _ in range(8):
        # If the lowest bit of y is set, add (XOR) the current value
        # of x into the result.
        if y & 1:
            result ^= x
        high_bit_set = x & 0x80
        x = (x << 1) & 0xFF
 
        if high_bit_set:
            x ^= _AES_MODULUS & 0xFF
 
        # Shift y right to process the next bit.
        y >>= 1
 
    return result



    # TODO: Implement GF(256) multiplication
    raise NotImplementedError("gf256_multiply has not been implemented yet.")


def split_secret(
    secret: bytes, threshold_k: int, shares_n: int
) -> List[Tuple[int, bytes]]:
    """
    Splits the secret into N shares, such that any K shares can reconstruct it.

    Mentee A Weeks 3-4 Deliverable.
    """
    
    if not isinstance(secret, (bytes, bytearray)):
        raise ValueError("secret must be a bytes object")
    if len(secret) == 0:
        raise ValueError("secret must not be empty")
    if not isinstance(threshold_k, int) or isinstance(threshold_k, bool):
        raise ValueError("threshold_k must be an integer")
    if not isinstance(shares_n, int) or isinstance(shares_n, bool):
        raise ValueError("shares_n must be an integer")
    if threshold_k < 2:
        raise ValueError("threshold_k must be >= 2")
    if shares_n > 255:
        raise ValueError("shares_n must be <= 255")
    if threshold_k > shares_n:
        raise ValueError("threshold_k must be <= shares_n")
 
    # x-coordinates for the shares: 1, 2, ..., shares_n.
    x_coordinates = list(range(1, shares_n + 1))
    share_bytes = [bytearray(len(secret)) for _ in range(shares_n)]
 
    for byte_index, secret_byte in enumerate(secret):
        coefficients = _generate_polynomial_coefficients(
            secret_byte, threshold_k
        )
 
        for share_index, x in enumerate(x_coordinates):
            y = _evaluate_polynomial(coefficients, x)
            share_bytes[share_index][byte_index] = y
 
    return [
        (x_coordinates[i], bytes(share_bytes[i])) for i in range(shares_n)
    ]
 
 



    # TODO: Implement polynomial generation and evaluation over GF(256)
    raise NotImplementedError("split_secret has not been implemented yet.")


def reconstruct_secret(shares: List[Tuple[int, bytes]]) -> bytes:
    """
    Reconstructs the original secret from a list of K or more shares.

    Mentee A Weeks 3-4 Deliverable.
    """

    if not isinstance(shares, (list, tuple)) or len(shares) < 2:
        raise ValueError("at least 2 shares are required to reconstruct")
 
    x_values = []
    y_arrays = []
    share_length = None
 
    for entry in shares:
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            raise ValueError(
                "each share must be a tuple of (x, share_bytes)"
            )
        x, data = entry
 
        if not isinstance(x, int) or isinstance(x, bool):
            raise ValueError("share x-coordinate must be an integer")
        if not (1 <= x <= 255):
            raise ValueError("share x-coordinate must be in range [1, 255]")
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("share data must be a bytes object")
        if len(data) == 0:
            raise ValueError("share data must not be empty")
 
        if share_length is None:
            share_length = len(data)
        elif len(data) != share_length:
            raise ValueError("all shares must have the same length")
 
        x_values.append(x)
        y_arrays.append(data)
 
    if len(set(x_values)) != len(x_values):
        raise ValueError("duplicate x-coordinates found among shares")
 
    secret = bytearray(share_length)
 
    for byte_index in range(share_length):
        y_values = [y_arrays[i][byte_index] for i in range(len(shares))]
        secret[byte_index] = _lagrange_interpolate_at_zero(
            x_values, y_values
        )
 
    return bytes(secret)


    # TODO: Implement Lagrange interpolation to recover the secret
    raise NotImplementedError("reconstruct_secret has not been implemented yet.")
