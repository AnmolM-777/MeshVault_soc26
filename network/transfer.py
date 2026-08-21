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


def _deserialize_share(payload: dict) -> tuple[int, bytes]:
    """
    Parse a JSON dictionary containing 'x' and base64-encoded 'data' back into
    a (x, share_bytes) tuple.
    """
    if not isinstance(payload, dict) or "x" not in payload or "data" not in payload:
        raise ValueError("Invalid share payload structure")
    x = int(payload["x"])
    share_bytes = base64.b64decode(payload["data"])
    return (x, share_bytes)


def receive_share(sock: socket.socket) -> tuple[int, bytes]:
    """
    Read one framed share message from sock and return the (x, share_bytes) tuple.
    """
    payload = receive_message(sock)
    return _deserialize_share(payload)


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


def send_share_with_retry(
    peer_host: str,
    peer_port: int,
    share: tuple[int, bytes],
    retries: int = 3,
    delay: float = 0.2,
    timeout: float = DEFAULT_TIMEOUT,
) -> None:
    """
    Attempt to send a share to a peer with exponential backoff / retries.
    """
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            send_share(peer_host, peer_port, share, timeout=timeout)
            return
        except OSError as e:
            last_err = e
            import time

            time.sleep(delay * (attempt + 1))
    if last_err:
        raise last_err


def send_encrypted_share(
    peer_host: str,
    peer_port: int,
    share: tuple[int, bytes],
    timeout: float = DEFAULT_TIMEOUT,
) -> None:
    """
    Connect to a peer, perform X25519 key exchange, and send an AES-256-GCM
    encrypted SSS share.
    """
    from crypto.channel import SecureChannel

    channel = SecureChannel()
    my_pub = channel.generate_key_pair()

    with socket.create_connection((peer_host, peer_port), timeout=timeout) as sock:
        # Step 1: Send client public key
        send_message(
            sock,
            {
                "type": "KEY_EXCHANGE",
                "public_key": base64.b64encode(my_pub).decode("ascii"),
            },
        )

        # Step 2: Receive peer public key
        resp = receive_message(sock)
        if resp.get("type") != "KEY_EXCHANGE" or "public_key" not in resp:
            raise FramingError("Invalid key exchange response from peer")
        peer_pub = base64.b64decode(resp["public_key"])
        channel.compute_shared_secret(peer_pub)

        # Step 3: Encrypt and send share
        share_payload = _serialize_share(share)
        encrypted_bytes = channel.encrypt_message(
            json.dumps(share_payload).encode("utf-8")
        )
        send_message(
            sock,
            {
                "type": "SHARE",
                "payload": base64.b64encode(encrypted_bytes).decode("ascii"),
            },
        )


def receive_encrypted_share(conn: socket.socket) -> tuple[int, bytes]:
    """
    Perform X25519 handshake and receive an AES-256-GCM encrypted share over an established connection.
    Supports both encrypted handshake and fallback direct share payload.
    """
    from crypto.channel import SecureChannel

    msg = receive_message(conn)

    # Check if this is a direct plaintext share
    if "x" in msg and "data" in msg:
        return _deserialize_share(msg)

    if msg.get("type") == "KEY_EXCHANGE" and "public_key" in msg:
        peer_pub = base64.b64decode(msg["public_key"])
        channel = SecureChannel()
        my_pub = channel.generate_key_pair()

        # Reply with our public key
        send_message(
            conn,
            {
                "type": "KEY_EXCHANGE",
                "public_key": base64.b64encode(my_pub).decode("ascii"),
            },
        )

        channel.compute_shared_secret(peer_pub)

        # Receive encrypted share
        share_msg = receive_message(conn)
        if share_msg.get("type") != "SHARE" or "payload" not in share_msg:
            raise FramingError("Expected encrypted SHARE message")

        ciphertext = base64.b64decode(share_msg["payload"])
        decrypted_json = channel.decrypt_message(ciphertext)
        share_payload = json.loads(decrypted_json.decode("utf-8"))
        return _deserialize_share(share_payload)

    raise FramingError(f"Unknown message structure received: {msg}")


def send_shares(
    shares: list[tuple[int, bytes]],
    peers: list[tuple[str, int]],
    timeout: float = DEFAULT_TIMEOUT,
    encrypted: bool = False,
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
            if encrypted:
                send_encrypted_share(peer[0], peer[1], share, timeout=timeout)
            else:
                send_share(peer[0], peer[1], share, timeout=timeout)
            results.append((peer, None))
        except OSError as exc:
            results.append((peer, exc))
        except Exception as exc:
            results.append((peer, exc))
    return results
