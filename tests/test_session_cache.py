import time
from crypto.session_cache import SessionCache, fingerprint_of


def test_fingerprint_generation():
    key = b"\x01" * 32
    fp = fingerprint_of(key)
    assert isinstance(fp, str)
    assert len(fp) == 64
    # Deterministic
    assert fingerprint_of(key) == fp


def test_session_cache_store_lookup():
    cache = SessionCache(default_ttl_seconds=10.0)
    fp = "abc123"
    ip = "192.168.1.5"
    key = b"symmetric-key-32-bytes-long!!!!!"

    cache.store(fp, ip, key)
    assert cache.lookup(fp, ip) == key
    assert cache.lookup("nonexistent", ip) is None


def test_session_cache_expiry():
    cache = SessionCache(default_ttl_seconds=0.05)
    fp = "abc123"
    ip = "192.168.1.5"
    key = b"symmetric-key-32-bytes-long!!!!!"

    cache.store(fp, ip, key, ttl_seconds=0.05)
    assert cache.lookup(fp, ip) == key

    time.sleep(0.06)
    assert cache.lookup(fp, ip) is None


def test_session_cache_invalidate_and_clear():
    cache = SessionCache()
    cache.store("fp1", "10.0.0.1", b"key1")
    cache.store("fp2", "10.0.0.2", b"key2")

    cache.invalidate("fp1", "10.0.0.1")
    assert cache.lookup("fp1", "10.0.0.1") is None
    assert cache.lookup("fp2", "10.0.0.2") == b"key2"

    cache.clear()
    assert cache.lookup("fp2", "10.0.0.2") is None
