"""
crypto/sss.py — Shamir's Secret Sharing over GF(256)

Issue #42: Dynamic Multi-byte Secret Chunking & Reassembly
------------------------------------------------------------
Extends split_secret / reconstruct_secret to operate on secrets of
ARBITRARY length (bytes), not a single field element.

Scope note: This file assumes GF(256) field arithmetic (gf_add, gf_mul,
gf_div, gf_inv) may already exist elsewhere in the module from earlier
work (Contributor A's original single-byte SSS implementation). The
table-based versions below are self-contained so this file works
standalone -- if gf256 arithmetic already exists in your sss.py,
DELETE the "GF(256) FIELD ARITHMETIC" block below and import/reuse
the existing functions instead, to avoid two divergent implementations
of the same field living in one module.
"""

import secrets

# ============================================================
# GF(256) FIELD ARITHMETIC
# (delete this block if equivalent functions already exist)
# Field: x^8 + x^4 + x^3 + x + 1  (0x11B) -- same field AES uses.
# ============================================================

_GF256_EXP = [0] * 512
_GF256_LOG = [0] * 256


def _init_gf256_tables() -> None:
    # NOTE: generator must be 3, not 2. Doubling (mul by 2) is NOT a
    # primitive element for the 0x11B reduction polynomial -- it does
    # not cycle through all 255 nonzero field elements, which silently
    # corrupts the log/antilog tables. 3 is primitive for this field.
    poly = 0x11B
    x = 1
    for i in range(255):
        _GF256_EXP[i] = x
        _GF256_LOG[x] = i
        # x = x * 3  (in GF(256)) = (x * 2) XOR x
        doubled = x << 1
        if doubled & 0x100:
            doubled ^= poly
        x = doubled ^ x
    for i in range(255, 512):
        _GF256_EXP[i] = _GF256_EXP[i - 255]


_init_gf256_tables()


def gf_add(a: int, b: int) -> int:
    """Addition (and subtraction) in GF(256) is XOR."""
    return a ^ b


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF256_EXP[_GF256_LOG[a] + _GF256_LOG[b]]


def gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return _GF256_EXP[(_GF256_LOG[a] - _GF256_LOG[b]) % 255]


# ============================================================
# MULTI-BYTE SSS  (Issue #42 — the actual deliverable)
# ============================================================
#
# Optimization notes vs. a naive "call a single-byte helper L times":
#
# 1. Randomness is generated in one bulk secrets.token_bytes() call
#    instead of L*(k-1) separate secrets.randbelow() calls -- fewer
#    CSPRNG call-boundary costs.
#
# 2. split_secret fills n bytearrays directly (one Horner evaluation
#    pass over the secret, per peer) instead of building L*N throwaway
#    (x, y) tuples and reshaping them afterward.
#
# 3. reconstruct_secret's biggest win: Lagrange basis weights
#    w_i = prod_{j!=i} x_j / (x_i - x_j)  (evaluated at x=0) depend
#    ONLY on the x-coordinates of the shares used, which are the same
#    for every byte position in a multi-byte secret. The naive
#    per-byte approach recomputes these O(k^2) field operations L
#    times -- O(L * k^2) total. Precomputing them once up front and
#    reusing them for every byte drops this to O(k^2 + L*k).


def split_secret(secret: bytes, n: int, k: int) -> list[tuple[int, bytes]]:
    """
    Split an arbitrary-length secret into n shares such that any k of
    them reconstruct the original secret.

    Each byte of `secret` gets its own independently-random polynomial
    of degree (k-1); all polynomials are evaluated at the same n
    x-coordinates (1..n), so a given peer only needs to remember one
    x-coordinate to hold a share of the whole secret.

    Returns a list of n shares: (x_coordinate, share_bytes), where
    share_bytes has the same length as `secret`.
    """
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError("secret must be bytes")
    if not isinstance(n, int) or not isinstance(k, int):
        raise TypeError("n and k must be int")
    if not (1 <= n <= 255):
        raise ValueError(
            "n must be between 1 and 255 (GF(256) has only 255 nonzero "
            "elements to use as x-coordinates)"
        )
    if k < 1 or k > n:
        raise ValueError("require 1 <= k <= n")

    length = len(secret)
    xs = range(1, n + 1)

    if length == 0:
        # Empty secret round-trips to empty; x-coordinates are still
        # assigned in case surrounding peer/session metadata cares.
        return [(x, b"") for x in xs]

    # One bulk CSPRNG draw for every random coefficient needed across
    # every byte's polynomial: (k-1) random coefficients per byte,
    # laid out as length contiguous chunks of (k-1) bytes each.
    degree = k - 1
    random_coeffs = secrets.token_bytes(length * degree)

    shares = [bytearray(length) for _ in xs]
    exp, log = _GF256_EXP, _GF256_LOG  # local refs: skip attribute lookups in the hot loop

    for byte_index in range(length):
        constant = secret[byte_index]
        base = byte_index * degree
        coeffs = random_coeffs[base : base + degree]  # high-degree -> low-degree term coefficients

        for peer_index, x in enumerate(xs):
            y = 0
            for coeff in coeffs:  # Horner's method for the random-degree terms
                y = (exp[log[y] + log[x]] if y else 0) ^ coeff
            # final Horner step folds in the constant term (the secret byte)
            y = (exp[log[y] + log[x]] if y else 0) ^ constant
            shares[peer_index][byte_index] = y

    return [(x, bytes(shares[peer_index])) for peer_index, x in enumerate(xs)]


def _lagrange_weights_at_zero(xs: list[int]) -> list[int]:
    """
    Precompute Lagrange basis weights w_i = prod_{j!=i} x_j / (x_i - x_j)
    at evaluation point x=0, for a fixed set of x-coordinates.

    Because these weights don't depend on the y-values (the actual
    share data), they're identical for every byte position of a
    multi-byte secret -- computed once here and reused for all L bytes
    by reconstruct_secret, instead of being recomputed per byte.
    """
    weights = []
    for i, x_i in enumerate(xs):
        numerator = 1
        denominator = 1
        for j, x_j in enumerate(xs):
            if i == j:
                continue
            numerator = gf_mul(numerator, x_j)  # (0 - x_j) == x_j in GF(256)
            denominator = gf_mul(denominator, gf_add(x_i, x_j))  # (x_i - x_j) == x_i ^ x_j
        weights.append(gf_div(numerator, denominator))
    return weights


def reconstruct_secret(shares: list[tuple[int, bytes]]) -> bytes:
    """
    Reconstruct the original secret from >= k shares produced by
    split_secret. Any k of the original n shares work; passing more
    than k is also fine (extra points are used but not required).
    """
    if not shares:
        raise ValueError("no shares provided")

    share_len = len(shares[0][1])
    for _, y_bytes in shares:
        if len(y_bytes) != share_len:
            raise ValueError("all shares must have equal length")

    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate x-coordinates among shares")

    if share_len == 0:
        return b""

    weights = _lagrange_weights_at_zero(xs)  # computed once, reused for every byte below
    y_arrays = [y for _, y in shares]

    secret_bytes = bytearray(share_len)
    for byte_index in range(share_len):
        acc = 0
        for weight, y_bytes in zip(weights, y_arrays):
            acc = gf_add(acc, gf_mul(weight, y_bytes[byte_index]))
        secret_bytes[byte_index] = acc
    return bytes(secret_bytes)