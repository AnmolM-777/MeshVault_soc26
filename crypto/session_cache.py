from __future__ import annotations

"""
Session key caching & reuse — issue #15.

Caches negotiated AES-256-GCM symmetric keys per-peer so a full ECDH
handshake doesn't need to be repeated on every reconnection. In-memory
only (no disk persistence), so cached key material doesn't outlive the
running process — a deliberate security choice, since writing symmetric
keys to disk would expand the attack surface for no real benefit in a
short-lived CLI tool.
"""
import hashlib
import time


def fingerprint_of(public_key: bytes) -> str:
    """
    Derive a short, stable identifier for a peer from their public key,
    used as part of the cache lookup key.
    """
    return hashlib.sha256(public_key).hexdigest()


class SessionCache:
    """
    In-memory store of (fingerprint, ip) -> (symmetric_key, expires_at).
    """

    def __init__(self, default_ttl_seconds: float = 300.0):
        self._store: dict[tuple[str, str], tuple[bytes, float]] = {}
        self._default_ttl = default_ttl_seconds

    def store(
        self,
        fingerprint: str,
        ip: str,
        symmetric_key: bytes,
        ttl_seconds: float | None = None,
    ) -> None:
        ttl = self._default_ttl if ttl_seconds is None else ttl_seconds
        expires_at = time.monotonic() + ttl
        self._store[(fingerprint, ip)] = (symmetric_key, expires_at)

    def lookup(self, fingerprint: str, ip: str) -> bytes | None:
        """
        Return the cached symmetric key for this peer, or None if there
        is no entry or the entry has expired (expired entries are also
        removed here, so they don't linger in memory).
        """
        entry = self._store.get((fingerprint, ip))
        if entry is None:
            return None
        symmetric_key, expires_at = entry
        if time.monotonic() >= expires_at:
            del self._store[(fingerprint, ip)]
            return None
        return symmetric_key

    def invalidate(self, fingerprint: str, ip: str) -> None:
        self._store.pop((fingerprint, ip), None)

    def clear(self) -> None:
        self._store.clear()
