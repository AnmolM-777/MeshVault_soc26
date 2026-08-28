"""
Network Transfer Layer.
Handles TCP connection management, message serialization, and framing.

Mentee D Deliverables:
- Weeks 1-2: Implement basic length-prefixed TCP socket framing to send and receive raw byte packets.
- Weeks 3-4: Complete TCP transmission wrapper, handling partial reads/writes and unexpected connection drops.
"""


import base64
import json
import socket
import struct
import time


HEADER_SIZE = 4  # 4-byte big-endian length prefix, per issue #25
DEFAULT_TIMEOUT = 5.0  # seconds to wait when connecting to a peer


class FramingError(Exception):
    """Raised when a socket frame is malformed or the connection drops mid-frame."""


# ---------------------------------------------------------------------------
# Framing — issue #25 (TEAMMATE'S CODE, exactly as given, unchanged)
# ---------------------------------------------------------------------------

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


def send_frame(sock: socket.socket, message_type: str, payload: bytes) -> None:
    """
    Prepends length headers and sends a framed message over a socket.
    Uses send_message to serialize and frame the message type and payload.
    """
    if isinstance(payload, bytes):
        payload_data = base64.b64encode(payload).decode("ascii")
        encoding = "base64"
    else:
        payload_data = payload
        encoding = "raw"

    msg = {
        "type": message_type,
        "payload": payload_data,
        "encoding": encoding,
    }
    send_message(sock, msg)


def recv_frame(sock: socket.socket) -> tuple:
    """
    Reads a length-prefixed framed message from a socket using receive_message.
    Returns tuple of (message_type, payload_bytes).
    """
    msg = receive_message(sock)
    msg_type = msg.get("type", "")
    payload_data = msg.get("payload", "")
    encoding = msg.get("encoding", "")

    if encoding == "base64" and isinstance(payload_data, str):
        payload_bytes = base64.b64decode(payload_data.encode("ascii"))
    elif isinstance(payload_data, str):
        try:
            payload_bytes = base64.b64decode(payload_data.encode("ascii"))
        except Exception:
            payload_bytes = payload_data.encode("utf-8")
    elif isinstance(payload_data, bytes):
        payload_bytes = payload_data
    else:
        payload_bytes = json.dumps(payload_data).encode("utf-8")

    return msg_type, payload_bytes




# ---------------------------------------------------------------------------
# Client-side share transmission — issue #26 (TEAMMATE'S CODE, unchanged)
# ---------------------------------------------------------------------------

def _serialize_share(share: tuple) -> dict:
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


def send_share(peer_host: str, peer_port: int, share: tuple,
               timeout: float = DEFAULT_TIMEOUT) -> None:
    """
    Open a TCP connection to a single peer and send them their one share,
    framed via send_message. The connection is closed automatically once
    the share has been sent.
    """
    payload = _serialize_share(share)
    with socket.create_connection((peer_host, peer_port), timeout=timeout) as sock:
        send_message(sock, payload)


def send_shares(shares: list, peers: list,
                 timeout: float = DEFAULT_TIMEOUT) -> list:
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

# ---------------------------------------------------------------------------
# Receiving shares — issue #27 (YOUR CODE)
# ---------------------------------------------------------------------------

def handle_client(conn, addr, share_buffer):
    """
    Handle one client connection: keep reading shares from it
    until it disconnects or sends something broken.
    """
    print(f"Connection from {addr}")
    try:
        while True:
            try:
                share = receive_message(conn)
            except FramingError:
                # client closed the connection normally
                print(f"Connection closed by {addr}")
                break
            except (struct.error, json.JSONDecodeError) as e:
                # client sent something broken — stop reading from them
                print(f"Bad data from {addr}: {e}")
                break

            if not isinstance(share, dict) or not share:
                print(f"Ignoring empty/invalid share from {addr}")
                continue

            print(f"Received share from {addr}: {share}")
            share_buffer.append(share)
    finally:
        conn.close()


def receive_shares(host='0.0.0.0', port=5000):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(5)
    print(f"Listening on {host}:{port}...")

    share_buffer = []

    while True:
        conn, addr = server_sock.accept()
        handle_client(conn, addr, share_buffer)

    return share_buffer


# ---------------------------------------------------------------------------
# Retry logic — issue #28 (YOUR CODE)
# ---------------------------------------------------------------------------

def send_share_with_retry(peer_host, peer_port, share, max_retries=3, delay=1,
                           timeout=DEFAULT_TIMEOUT):
    """
    Send one share to a peer using send_share(), retrying a few times if
    the peer is temporarily unreachable, instead of giving up on the
    first failure.

    peer_host, peer_port : where the peer is listening (who we connect to)
    share                : the (x, share_bytes) tuple, same as send_share expects
    max_retries          : how many attempts to make before giving up
    delay                : seconds to wait between attempts
    timeout              : seconds to wait for connect() before treating it as failed

    Returns True if the share was sent successfully, False if all
    attempts failed.
    """
    for attempt in range(1, max_retries + 1):
        try:
            send_share(peer_host, peer_port, share, timeout=timeout)
            print(f"Share sent successfully on attempt {attempt}")
            return True

        except OSError as e:
            # covers ConnectionRefusedError, socket.timeout, and other
            # connection-related failures — the "peer temporarily
            # unreachable" case issue #28 asks us to handle
            print(f"Attempt {attempt} failed: {e}")
            if attempt < max_retries:
                print(f"Retrying in {delay} second(s)...")
                time.sleep(delay)
            else:
                print("All retry attempts failed. Giving up.")
                return False

    return False


def send_shares_with_retry(shares: list, peers: list, max_retries=3, delay=1,
                            timeout=DEFAULT_TIMEOUT) -> list:
    """
    Same idea as send_shares(), but each individual peer send goes through
    send_share_with_retry() instead of a single bare attempt. One peer
    being temporarily unreachable no longer means that peer's share is
    lost immediately, and one failing peer doesn't stop the others from
    being sent.

    Returns a list of (peer_address, success: bool) pairs.
    """
    if len(shares) != len(peers):
        raise ValueError("must have exactly one peer address per share")

    results = []
    for share, peer in zip(shares, peers):
        success = send_share_with_retry(
            peer[0], peer[1], share,
            max_retries=max_retries, delay=delay, timeout=timeout,
        )
        results.append((peer, success))
    return results