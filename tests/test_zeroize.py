import ctypes

import pytest

from crypto.zeroize import (
    SecureBuffer,
    buffer_to_int,
    int_to_buffer,
    secure_zero,
    to_bytearray,
    wipe_all,
    zeroize,
)


def raw_memory(buf: bytearray) -> bytes:
    """Read the actual memory behind the bytearray via ctypes."""
    arr = (ctypes.c_char * len(buf)).from_buffer(buf)
    try:
        return ctypes.string_at(ctypes.addressof(arr), len(buf))
    finally:
        del arr


# --- secure_zero -----------------------------------------------------------


def test_secure_zero_wipes_bytearray_in_place():
    secret = bytearray(b"super-secret-key-material")
    same_object = secret
    secure_zero(secret)
    assert secret is same_object
    assert raw_memory(secret) == bytes(len(secret))


def test_secure_zero_wipes_memoryview_underlying_buffer():
    secret = bytearray(b"\x01\x02\x03\x04")
    mv = memoryview(secret)
    secure_zero(mv)
    mv.release()
    assert secret == bytearray(4)


def test_secure_zero_empty_buffer_is_noop():
    secure_zero(bytearray())


def test_secure_zero_none_is_noop():
    secure_zero(None)


@pytest.mark.parametrize("immutable", [b"abc", "abc", 123])
def test_secure_zero_rejects_immutable(immutable):
    with pytest.raises(TypeError):
        secure_zero(immutable)


def test_secure_zero_rejects_readonly_view():
    with pytest.raises(TypeError):
        secure_zero(memoryview(b"abc"))


# --- context manager -------------------------------------------------------


def test_zeroize_wipes_on_success():
    a, b = bytearray(b"aaaa"), bytearray(b"bbbb")
    with zeroize(a, b):
        assert a == b"aaaa"
    assert a == bytearray(4) and b == bytearray(4)


def test_zeroize_wipes_on_exception():
    key = bytearray(b"topsecret")
    with pytest.raises(RuntimeError):
        with zeroize(key):
            raise RuntimeError("boom")
    assert key == bytearray(len(key))


# --- try / finally pattern -------------------------------------------------


def test_finally_pattern_wipes_even_when_error_raised():
    coeffs = [int_to_buffer(i + 1000, 8) for i in range(3)]
    with pytest.raises(ValueError):
        try:
            raise ValueError("computation failed")
        finally:
            wipe_all(coeffs)
    assert all(c == bytearray(8) for c in coeffs)


# --- SecureBuffer ----------------------------------------------------------


def test_secure_buffer_wipes_on_exit_and_redacts_repr():
    with SecureBuffer(b"hunter2") as sb:
        inner = sb.buffer
        assert "hunter2" not in repr(sb)
        assert bytes(inner) == b"hunter2"
    assert inner == bytearray(7)


def test_secure_buffer_size_constructor_is_zeroed():
    sb = SecureBuffer(16)
    assert len(sb) == 16
    assert sb.buffer == bytearray(16)


def test_secure_buffer_manual_wipe():
    sb = SecureBuffer(b"secret")
    inner = sb.buffer
    sb.wipe()
    assert inner == bytearray(6)


# --- wipe_all --------------------------------------------------------------


def test_wipe_all_handles_lists_of_buffers():
    bufs = [bytearray(b"x" * 8) for _ in range(5)]
    wipe_all(bufs)
    assert all(b == bytearray(8) for b in bufs)


def test_wipe_all_wipes_rest_then_raises_on_immutable():
    good = bytearray(b"secret")
    with pytest.raises(TypeError):
        wipe_all([b"immutable", good])
    assert good == bytearray(6)


# --- conversion helpers ----------------------------------------------------


def test_to_bytearray_returns_independent_mutable_copy():
    src = b"key-bytes"
    ba = to_bytearray(src)
    assert isinstance(ba, bytearray) and ba == src
    secure_zero(ba)
    assert src == b"key-bytes"  # original untouched
    assert ba == bytearray(len(src))


def test_int_buffer_roundtrip_and_wipe():
    buf = int_to_buffer(0xDEADBEEF, 8)
    assert buffer_to_int(buf) == 0xDEADBEEF
    secure_zero(buf)
    assert buffer_to_int(buf) == 0
