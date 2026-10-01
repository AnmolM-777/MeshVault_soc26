from __future__ import annotations

import ctypes
from contextlib import contextmanager
from typing import Iterable, Iterator, Tuple, Union

BufferLike = Union[bytearray, memoryview]


def secure_zero(buf: BufferLike) -> None:
    """Overwrite a mutable buffer with zeros, in place.

    Raises TypeError for immutable objects (bytes, str, int, ...) and for
    read-only buffers, because they cannot be wiped and silently ignoring
    them would give a false sense of security.
    """
    if buf is None:
        return
    if isinstance(buf, (bytes, str, int, float)):
        raise TypeError(
            f"Cannot zeroize immutable {type(buf).__name__}; "
            "store secrets in a bytearray instead."
        )

    view = memoryview(buf)
    flat = None
    try:
        if view.readonly:
            raise TypeError("Cannot zeroize a read-only buffer.")
        flat = view if (view.ndim == 1 and view.format == "B") else view.cast("B")
        n = flat.nbytes
        if n:
            arr = (ctypes.c_char * n).from_buffer(flat)
            try:
                ctypes.memset(ctypes.addressof(arr), 0, n)
            finally:
                del arr  # release the buffer export
    finally:
        if flat is not None and flat is not view:
            flat.release()
        view.release()


def wipe_all(buffers: Iterable[BufferLike]) -> None:
    """Zeroize every buffer in an iterable (e.g. a list of coefficients).

    Every buffer is attempted even if one fails; the first error is
    re-raised at the end.
    """
    first_error = None
    for b in buffers:
        try:
            secure_zero(b)
        except Exception as exc:  # noqa: BLE001
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise first_error


@contextmanager
def zeroize(*buffers: BufferLike) -> Iterator[Tuple[BufferLike, ...]]:
    """Context manager that wipes the given buffers on exit, always."""
    try:
        yield buffers
    finally:
        wipe_all(buffers)


class SecureBuffer:
    """A bytearray wrapper that wipes itself on exit and on deletion.

    SecureBuffer(32)         -> 32 zeroed bytes
    SecureBuffer(b"secret")  -> copies the data. The original bytes object
                                you passed in is NOT wiped; avoid keeping it.
    """

    __slots__ = ("_buf",)

    def __init__(self, data_or_size: Union[int, bytes, bytearray] = 0):
        # bytearray(int) -> zero-filled; bytearray(bytes) -> copy
        self._buf = bytearray(data_or_size)

    @property
    def buffer(self) -> bytearray:
        return self._buf

    def __len__(self) -> int:
        return len(self._buf)

    def wipe(self) -> None:
        secure_zero(self._buf)

    def __enter__(self) -> "SecureBuffer":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.wipe()

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception:  # noqa: BLE001 - never raise from __del__
            pass

    def __repr__(self) -> str:  # never leak contents in logs or tracebacks
        return f"<SecureBuffer len={len(self._buf)} [redacted]>"


def to_bytearray(data: Union[bytes, bytearray, memoryview]) -> bytearray:
    """Copy data into a wipeable bytearray.

    The source object is not touched. If it is an immutable bytes object,
    that original copy cannot be wiped, so avoid keeping it around.
    """
    return bytearray(data)


def int_to_buffer(value: int, length: int) -> bytearray:
    """Big-endian int -> wipeable bytearray of fixed length."""
    return bytearray(value.to_bytes(length, "big"))


def buffer_to_int(buf: BufferLike) -> int:
    """Wipeable buffer -> int. The int itself cannot be wiped, so use it
    only for the shortest possible computation."""
    return int.from_bytes(buf, "big")
