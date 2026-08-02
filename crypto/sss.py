import secrets


GF256_EXP = [0] * 512
GF256_LOG = [0] * 256


def _init_tables():
    x = 1
    for i in range(255):
        GF256_EXP[i] = x
        GF256_LOG[x] = i
        double = x << 1
        if double & 0x100:
            double ^= 0x11B
        x = double ^ x
    for i in range(255, 512):
        GF256_EXP[i] = GF256_EXP[i - 255]

_init_tables()


def gf_add(a: int, b: int) -> int:
    return a ^ b  


gf_sub = gf_add


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return GF256_EXP[GF256_LOG[a] + GF256_LOG[b]]


def gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return GF256_EXP[(GF256_LOG[a] - GF256_LOG[b]) % 255]


def _eval_polynomial(coeffs: list[int], x: int) -> int:
    result = 0
    for coeff in reversed(coeffs):
        result = gf_mul(result, x) ^ coeff
    return result


def split_secret(secret: bytes, n: int, k: int) -> list[tuple[int, bytes]]:
    if not (1 <= k <= n <= 255):
        raise ValueError("require 1 <= k <= n <= 255")
    shares = [(x, bytearray(len(secret))) for x in range(1, n + 1)]
    for byte_index, secret_byte in enumerate(secret):
        coeffs = [secret_byte] + [secrets.randbelow(256) for _ in range(k - 1)]
        for x, share_bytes in shares:
            share_bytes[byte_index] = _eval_polynomial(coeffs, x)
    return [(x, bytes(b)) for x, b in shares]





def _lagrange_interpolate_zero(points: list[tuple[int, int]]) -> int:
    """Lagrange interpolation of a set of (x, y) points, evaluated at x=0, in GF(256)."""
    result = 0
    for i, (x_i, y_i) in enumerate(points):
        numerator = 1
        denominator = 1
        for j, (x_j, _) in enumerate(points):
            if i == j:
                continue
            numerator = gf_mul(numerator, x_j)                    
            denominator = gf_mul(denominator, gf_add(x_i, x_j))   
        term = gf_mul(y_i, gf_div(numerator, denominator))
        result = gf_add(result, term)
    return result


def reconstruct_secret(shares: list[tuple[int, bytes]]) -> bytes:
    if not shares:
        raise ValueError("need at least one share")

    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share x-values")

    length = len(shares[0][1])
    if any(len(b) != length for _, b in shares):
        raise ValueError("share byte-lengths do not match")

    secret = bytearray(length)
    for byte_index in range(length):
        points = [(x, share_bytes[byte_index]) for x, share_bytes in shares]
        secret[byte_index] = _lagrange_interpolate_zero(points)
    return bytes(secret)