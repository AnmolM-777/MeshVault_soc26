from __future__ import annotations
import json
import socket
import struct
import base64

HEADER_SIZE = 4


class FramingError(Exception):
    """Raised when a socket frame is malformed or the connection drops mid-frame."""


def send_message(sock: socket.socket, payload: dict) -> None:
    """
    Serialize `payload` to JSON and send it over `sock`, framed with a
    4-byte big-endian length prefix, so the receiver knows exactly how
    many bytes make up this one message on a stream with no built-in
    message boundaries.
    """
    body = json.dumps(payload).encode("utf-8")
    header = struct.pack("!I", len(body))
    sock.sendall(header + body)


def _recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Read exactly num_bytes from sock, looping over recv() until satisfied."""
    chunks = []
    remaining = num_bytes
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise FramingError("connection closed before full frame was received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_message(sock: socket.socket) -> dict:
    """
    Read one complete length-prefixed JSON message from sock and return
    the decoded payload as a dict.
    """
    header = _recv_exact(sock, HEADER_SIZE)
    (length,) = struct.unpack("!I", header)
    body = _recv_exact(sock, length)
    return json.loads(body.decode("utf-8"))


DEFAULT_TIMEOUT = 5.0  # seconds to wait when connecting to a peer


# ---- Client-side share transmission — issue #26 ----


def _serialize_share(share: tuple[int, bytes]) -> dict:
    """
    Turn a (x, share_bytes) tuple from split_secret into a JSON-safe dict.
    JSON has no concept of raw binary data, so the share's bytes are
    Base64-encoded into plain ASCII text before being wrapped in the dict
    that send_message will serialize.
    """
    x, share_bytes = share
    return {
        "x": x,
        "data": base64.b64encode(share_bytes).decode("ascii"),
    }


def send_share(
    peer_host: str,
    peer_port: int,
    share: tuple[int, bytes],
    timeout: float = DEFAULT_TIMEOUT,
) -> None:
    """
    Open a TCP connection to a single peer and send them their one share,
    framed via send_message. The connection is closed automatically once
    the share has been sent.
    """
    payload = _serialize_share(share)
    with socket.create_connection((peer_host, peer_port), timeout=timeout) as sock:
        send_message(sock, payload)


def send_shares(
    shares: list[tuple[int, bytes]],
    peers: list[tuple[str, int]],
    timeout: float = DEFAULT_TIMEOUT,
) -> list[tuple[tuple[str, int], Exception | None]]:
    """
    Send each share to its corresponding peer address (shares[i] goes to
    peers[i]). Returns a list of (peer_address, error) pairs so the caller
    can see which sends failed without one bad peer aborting the rest.
    """
    if len(shares) != len(peers):
        raise ValueError("must have exactly one peer address per share")

    results = []
    for share, peer in zip(shares, peers):
        try:
            send_share(peer[0], peer[1], share, timeout=timeout)
            results.append((peer, None))
        except OSError as exc:
            results.append((peer, exc))
    return results
