# tests/test_transfer.py
import socket
import struct
import pytest
from network.transfer import send_message, receive_message, FramingError


def _make_connected_pair():
    """Spin up a real local TCP server/client pair connected to each other."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", port))

    conn, _ = server_sock.accept()
    server_sock.close()
    return conn, client_sock


def test_send_and_receive_simple_message():
    server_conn, client_conn = _make_connected_pair()
    try:
        send_message(client_conn, {"share_id": 1, "value": "abc"})
        result = receive_message(server_conn)
        assert result == {"share_id": 1, "value": "abc"}
    finally:
        server_conn.close()
        client_conn.close()


def test_send_and_receive_large_payload():
    server_conn, client_conn = _make_connected_pair()
    try:
        big_payload = {"data": "x" * 100000}
        send_message(client_conn, big_payload)
        result = receive_message(server_conn)
        assert result == big_payload
    finally:
        server_conn.close()
        client_conn.close()


def test_multiple_messages_in_sequence():
    server_conn, client_conn = _make_connected_pair()
    try:
        send_message(client_conn, {"n": 1})
        send_message(client_conn, {"n": 2})
        assert receive_message(server_conn) == {"n": 1}
        assert receive_message(server_conn) == {"n": 2}
    finally:
        server_conn.close()
        client_conn.close()


def test_connection_closed_mid_frame_raises():
    server_conn, client_conn = _make_connected_pair()
    try:
        client_conn.sendall(struct.pack("!I", 1000))
        client_conn.close()
        with pytest.raises(FramingError):
            receive_message(server_conn)
    finally:
        server_conn.close()



import base64
import threading
from network.transfer import send_share, send_shares, _serialize_share


def _run_one_shot_server(host, port_holder, received_holder, ready_event):
    """Accept exactly one connection, read one framed message, store it."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((host, 0))
    server_sock.listen(1)
    port_holder.append(server_sock.getsockname()[1])
    ready_event.set()
    conn, _ = server_sock.accept()
    try:
        received_holder.append(receive_message(conn))
    finally:
        conn.close()
        server_sock.close()


def test_send_share_reaches_real_peer():
    port_holder, received, ready = [], [], threading.Event()
    server_thread = threading.Thread(
        target=_run_one_shot_server, args=("127.0.0.1", port_holder, received, ready)
    )
    server_thread.start()
    ready.wait(timeout=2)

    share = (1, b"\x00\x01\xffshare-bytes")
    send_share("127.0.0.1", port_holder[0], share)
    server_thread.join(timeout=2)

    assert len(received) == 1
    assert received[0]["x"] == 1
    assert base64.b64decode(received[0]["data"]) == share[1]


def test_serialize_share_roundtrips_binary_data():
    share = (3, bytes(range(256)))  # every possible byte value
    payload = _serialize_share(share)
    assert payload["x"] == 3
    assert base64.b64decode(payload["data"]) == share[1]


def test_send_shares_reports_per_peer_results():
    port_holder, received, ready = [], [], threading.Event()
    server_thread = threading.Thread(
        target=_run_one_shot_server, args=("127.0.0.1", port_holder, received, ready)
    )
    server_thread.start()
    ready.wait(timeout=2)

    shares = [(1, b"share-one"), (2, b"share-two")]
    peers = [("127.0.0.1", port_holder[0]), ("127.0.0.1", 1)]  # port 1: nothing listens there
    results = send_shares(shares, peers, timeout=1.0)
    server_thread.join(timeout=2)

    assert results[0][1] is None               # first peer: success
    assert isinstance(results[1][1], OSError)   # second peer: failed, but didn't raise


def test_send_shares_requires_matching_lengths():
    with pytest.raises(ValueError):
        send_shares([(1, b"a")], [("127.0.0.1", 1), ("127.0.0.1", 2)])