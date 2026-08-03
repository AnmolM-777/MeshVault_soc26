import time
from crypto.session_cache import SessionCache, fingerprint_of


def test_store_and_lookup_roundtrip():
    cache = SessionCache()
    fp = fingerprint_of(b"some-public-key-bytes")
    key = b"symmetric-key-bytes"
    cache.store(fp, "192.168.1.5", key)
    assert cache.lookup(fp, "192.168.1.5") == key


def test_lookup_miss_returns_none():
    cache = SessionCache()
    assert cache.lookup("nonexistent", "1.2.3.4") is None


def test_different_ip_is_a_cache_miss_even_with_same_fingerprint():
    cache = SessionCache()
    fp = fingerprint_of(b"key")
    cache.store(fp, "192.168.1.5", b"secret-key")
    assert cache.lookup(fp, "192.168.1.99") is None


def test_expired_entry_returns_none():
    cache = SessionCache()
    fp = fingerprint_of(b"key")
    cache.store(fp, "192.168.1.5", b"secret-key", ttl_seconds=0.05)
    assert cache.lookup(fp, "192.168.1.5") == b"secret-key"
    time.sleep(0.1)
    assert cache.lookup(fp, "192.168.1.5") is None


def test_invalidate_removes_entry():
    cache = SessionCache()
    fp = fingerprint_of(b"key")
    cache.store(fp, "192.168.1.5", b"secret-key")
    cache.invalidate(fp, "192.168.1.5")
    assert cache.lookup(fp, "192.168.1.5") is None


def test_fingerprint_is_deterministic_and_distinct():
    fp1 = fingerprint_of(b"key-one")
    fp2 = fingerprint_of(b"key-one")
    fp3 = fingerprint_of(b"key-two")
    assert fp1 == fp2
    assert fp1 != fp3


def test_clear_removes_all_entries():
    cache = SessionCache()
    fp = fingerprint_of(b"key")
    cache.store(fp, "192.168.1.5", b"secret-key")
    cache.clear()
    assert cache.lookup(fp, "192.168.1.5") is None