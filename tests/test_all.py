"""
tests/test_all.py

Complete unified test suite for MeshVault containing all 64 test cases:
  - Part 1: Shamir's Secret Sharing (SSS) & GF(256) Arithmetic
  - Part 2: Secure Channel (X25519 ECDH & AES-256-GCM)
  - Part 3: Cryptographic Integrity Checksums & Share Tamper Detection
  - Part 4: Session Key Caching (SessionCache)
  - Part 5: Network Transfer Layer & TCP Socket Framing
  - Part 6: Peer Discovery (Zeroconf / mDNS)
  - Part 7: CLI Subcommands (split & recover)
  - Part 8: End-to-End Multi-Peer Integration Workflows
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import socket
import struct
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

# MeshVault Component Imports
from cli.__main__ import build_parser, _parse_peer, main
from cli.recover import execute_recover
from cli.split import execute_split
from crypto.channel import SecureChannel
from crypto.integrity import (
    HASH_LEN,
    TamperDetectedError,
    compute_integrity_hash,
    verify_integrity,
    pack_share_with_integrity,
    pack_shares_with_integrity,
    unpack_share_with_integrity,
    unpack_shares_with_integrity,
)
from crypto.session_cache import SessionCache, fingerprint_of
from crypto.sss import (
    split_secret,
    reconstruct_secret,
    gf256_add,
    gf256_multiply,
)
from network.discovery import PeerDiscovery, _get_local_ip
from network.transfer import (
    send_message,
    receive_message,
    FramingError,
    send_share,
    send_shares,
    _serialize_share,
    _deserialize_share,
    receive_share,
    send_share_with_retry,
    send_encrypted_share,
    receive_encrypted_share,
)

# ==============================================================================
# Helper functions for networking & integration tests
# ==============================================================================


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


def _peer_listener(port_holder, received_shares, ready_event, stop_event):
    """Mock peer listener node that accepts one connection, performs handshake, and receives encrypted share."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    port_holder.append(port)
    ready_event.set()

    sock.settimeout(3.0)
    try:
        conn, addr = sock.accept()
        try:
            share = receive_encrypted_share(conn)
            received_shares.append(share)
        finally:
            conn.close()
    except Exception:
        pass
    finally:
        sock.close()


# ==============================================================================
# PART 1: Shamir's Secret Sharing (SSS) & GF(256) Finite Field
# ==============================================================================


def test_sss_import():
    """Ensure the SSS functions are correctly defined and can be imported."""
    assert split_secret is not None
    assert reconstruct_secret is not None
    assert gf256_add is not None
    assert gf256_multiply is not None


def test_reconstruct_with_exact_k():
    secret = b"hello secret"
    shares = split_secret(secret, n=5, k=3)
    assert reconstruct_secret(shares[:3]) == secret


def test_reconstruct_with_all_n_shares():
    secret = b"another secret!"
    shares = split_secret(secret, n=6, k=4)
    assert reconstruct_secret(shares) == secret


def test_k_equals_1():
    secret = b"trivial"
    shares = split_secret(secret, n=4, k=1)
    assert reconstruct_secret(shares[:1]) == secret


def test_k_equals_n():
    secret = b"tight threshold"
    shares = split_secret(secret, n=5, k=5)
    assert reconstruct_secret(shares) == secret


def test_any_k_subset_agrees():
    secret = b"consistency check"
    shares = split_secret(secret, n=7, k=4)
    for subset in itertools.combinations(shares, 4):
        assert reconstruct_secret(list(subset)) == secret


def test_fewer_than_k_shares_gives_wrong_secret():
    secret = b"insufficient shares here"
    shares = split_secret(secret, n=5, k=4)
    assert reconstruct_secret(shares[:3]) != secret


def test_duplicate_x_raises():
    with pytest.raises(ValueError):
        reconstruct_secret([(1, b"a"), (1, b"b")])


def test_empty_shares_raises():
    with pytest.raises(ValueError):
        reconstruct_secret([])


def test_mismatched_lengths_raises():
    with pytest.raises(ValueError):
        reconstruct_secret([(1, b"ab"), (2, b"abc")])


# ==============================================================================
# PART 2: Cryptographic Channel Security (X25519 ECDH & AES-256-GCM)
# ==============================================================================


def test_channel_key_pair_generation():
    channel = SecureChannel()
    pubkey = channel.generate_key_pair()
    assert isinstance(pubkey, bytes)
    assert len(pubkey) == 32
    assert channel.private_key is not None
    assert channel.public_key is not None


def test_ecdh_key_exchange_roundtrip():
    peer_a = SecureChannel()
    peer_b = SecureChannel()

    pub_a = peer_a.generate_key_pair()
    pub_b = peer_b.generate_key_pair()

    key_a = peer_a.compute_shared_secret(pub_b)
    key_b = peer_b.compute_shared_secret(pub_a)

    assert key_a == key_b
    assert len(key_a) == 32


def test_encryption_decryption_roundtrip():
    peer_a = SecureChannel()
    peer_b = SecureChannel()

    pub_a = peer_a.generate_key_pair()
    pub_b = peer_b.generate_key_pair()

    peer_a.compute_shared_secret(pub_b)
    peer_b.compute_shared_secret(pub_a)

    message = b"Secret payload to be encrypted over the peer channel"
    ciphertext = peer_a.encrypt_message(message)

    assert ciphertext != message
    assert len(ciphertext) >= len(message) + 12 + 16

    plaintext = peer_b.decrypt_message(ciphertext)
    assert plaintext == message


def test_empty_message_encryption():
    peer_a = SecureChannel()
    peer_b = SecureChannel()

    pub_a = peer_a.generate_key_pair()
    pub_b = peer_b.generate_key_pair()

    peer_a.compute_shared_secret(pub_b)
    peer_b.compute_shared_secret(pub_a)

    empty_msg = b""
    ciphertext = peer_a.encrypt_message(empty_msg)
    assert peer_b.decrypt_message(ciphertext) == empty_msg


def test_corrupted_ciphertext_fails_authentication():
    peer_a = SecureChannel()
    peer_b = SecureChannel()

    pub_a = peer_a.generate_key_pair()
    pub_b = peer_b.generate_key_pair()

    peer_a.compute_shared_secret(pub_b)
    peer_b.compute_shared_secret(pub_a)

    message = b"Tamper-proof payload"
    ciphertext = bytearray(peer_a.encrypt_message(message))

    # Tamper with the ciphertext byte
    ciphertext[-1] ^= 0x01

    with pytest.raises(Exception):
        peer_b.decrypt_message(bytes(ciphertext))


def test_invalid_key_length_raises():
    channel = SecureChannel()
    channel.generate_key_pair()

    with pytest.raises(ValueError, match="32 bytes"):
        channel.compute_shared_secret(b"short_key")


def test_encrypt_without_key_raises():
    channel = SecureChannel()
    with pytest.raises(
        ValueError, match="Shared symmetric key has not been established"
    ):
        channel.encrypt_message(b"test")


def test_decrypt_without_key_raises():
    channel = SecureChannel()
    with pytest.raises(
        ValueError, match="Shared symmetric key has not been established"
    ):
        channel.decrypt_message(b"test" * 10)


def test_decrypt_too_short_ciphertext_raises():
    peer_a = SecureChannel()
    peer_b = SecureChannel()
    pub_b = peer_b.generate_key_pair()
    peer_a.generate_key_pair()
    peer_a.compute_shared_secret(pub_b)

    with pytest.raises(ValueError, match="too short"):
        peer_a.decrypt_message(b"short")


# ==============================================================================
# PART 3: Cryptographic Integrity Checksums & Share Tamper Detection
# ==============================================================================


def test_compute_integrity_hash_matches_sha256():
    secret = b"super-secret-api-key-12345"
    expected = hashlib.sha256(secret).digest()
    assert compute_integrity_hash(secret) == expected


def test_compute_integrity_hash_rejects_non_bytes():
    with pytest.raises(TypeError):
        compute_integrity_hash("not-bytes")  # type: ignore[arg-type]


def test_compute_integrity_hash_is_deterministic():
    secret = b"same-secret-every-time"
    assert compute_integrity_hash(secret) == compute_integrity_hash(secret)


def test_different_secrets_produce_different_hashes():
    assert compute_integrity_hash(b"secret-one") != compute_integrity_hash(
        b"secret-two"
    )


def test_pack_share_prepends_hash_to_payload():
    secret_hash = b"\xaa" * HASH_LEN
    x, share_bytes = 3, b"share-payload-bytes"
    packed_x, packed_payload = pack_share_with_integrity((x, share_bytes), secret_hash)

    assert packed_x == x
    assert packed_payload[:HASH_LEN] == secret_hash
    assert packed_payload[HASH_LEN:] == share_bytes


def test_pack_shares_embeds_same_hash_in_every_share():
    secret = b"my-database-password"
    secret_hash = compute_integrity_hash(secret)
    raw_shares = split_secret(secret, n=5, k=3)

    packed = pack_shares_with_integrity(raw_shares, secret_hash)

    assert len(packed) == len(raw_shares)
    for x, payload in packed:
        assert payload[:HASH_LEN] == secret_hash


def test_pack_share_rejects_wrong_length_hash():
    with pytest.raises(ValueError):
        pack_share_with_integrity((1, b"payload"), b"too-short")


def test_unpack_share_reverses_pack_share():
    secret_hash = b"\xbb" * HASH_LEN
    original = (5, b"original-share-bytes")

    packed = pack_share_with_integrity(original, secret_hash)
    (x, share_bytes), recovered_hash = unpack_share_with_integrity(packed)

    assert (x, share_bytes) == original
    assert recovered_hash == secret_hash


def test_unpack_share_rejects_truncated_packet():
    truncated = (1, b"short")
    with pytest.raises(ValueError):
        unpack_share_with_integrity(truncated)


def test_unpack_shares_with_integrity_agrees_on_common_hash():
    secret = b"agreement-check-secret"
    secret_hash = compute_integrity_hash(secret)
    raw_shares = split_secret(secret, n=5, k=3)
    packed = pack_shares_with_integrity(raw_shares, secret_hash)

    plain_shares, agreed_hash = unpack_shares_with_integrity(packed[:3])

    assert agreed_hash == secret_hash
    assert sorted(plain_shares) == sorted(raw_shares[:3])


def test_unpack_shares_with_integrity_detects_disagreeing_hashes():
    secret_a = b"secret-a-data"
    secret_b = b"secret-b-data"
    hash_a = compute_integrity_hash(secret_a)
    hash_b = compute_integrity_hash(secret_b)

    shares_a = split_secret(secret_a, n=3, k=2)
    shares_b = split_secret(secret_b, n=3, k=2)

    mixed_packets = [
        pack_share_with_integrity(shares_a[0], hash_a),
        pack_share_with_integrity(shares_b[1], hash_b),
    ]

    with pytest.raises(TamperDetectedError):
        unpack_shares_with_integrity(mixed_packets)


def test_verify_integrity_passes_for_correct_secret():
    secret = b"correct-secret-value"
    secret_hash = compute_integrity_hash(secret)
    verify_integrity(secret, secret_hash)


def test_verify_integrity_raises_for_wrong_secret():
    secret_hash = compute_integrity_hash(b"expected-secret")
    with pytest.raises(TamperDetectedError):
        verify_integrity(b"wrong-secret-value", secret_hash)


def test_end_to_end_valid_reconstruction_passes_integrity():
    secret = b"end-to-end-valid-secret"
    secret_hash = compute_integrity_hash(secret)

    raw_shares = split_secret(secret, n=5, k=3)
    packets = pack_shares_with_integrity(raw_shares, secret_hash)

    collected = packets[:3]
    shares, agreed_hash = unpack_shares_with_integrity(collected)
    reconstructed = reconstruct_secret(shares)

    verify_integrity(reconstructed, agreed_hash)
    assert reconstructed == secret


def test_end_to_end_corrupted_share_byte_is_detected():
    secret = b"end-to-end-secret-that-will-be-tampered"
    secret_hash = compute_integrity_hash(secret)

    raw_shares = split_secret(secret, n=5, k=3)
    packets = pack_shares_with_integrity(raw_shares, secret_hash)

    collected = list(packets[:3])

    x, payload = collected[0]
    corrupted_payload = bytearray(payload)
    corrupted_payload[HASH_LEN] ^= 0xFF
    collected[0] = (x, bytes(corrupted_payload))

    shares, agreed_hash = unpack_shares_with_integrity(collected)
    reconstructed = reconstruct_secret(shares)

    with pytest.raises(TamperDetectedError):
        verify_integrity(reconstructed, agreed_hash)

    assert reconstructed != secret


def test_end_to_end_corrupted_share_x_coordinate_is_detected():
    secret = b"secret-with-tampered-x-coordinate"
    secret_hash = compute_integrity_hash(secret)

    raw_shares = split_secret(secret, n=5, k=3)
    packets = pack_shares_with_integrity(raw_shares, secret_hash)
    collected = list(packets[:3])

    x, payload = collected[0]
    used_xs = {p[0] for p in collected}
    new_x = next(v for v in range(1, 256) if v not in used_xs)
    collected[0] = (new_x, payload)

    shares, agreed_hash = unpack_shares_with_integrity(collected)
    reconstructed = reconstruct_secret(shares)

    with pytest.raises(TamperDetectedError):
        verify_integrity(reconstructed, agreed_hash)


def test_end_to_end_insufficient_shares_below_threshold_fails_integrity():
    secret = b"needs-at-least-three-shares"
    secret_hash = compute_integrity_hash(secret)

    raw_shares = split_secret(secret, n=5, k=3)
    packets = pack_shares_with_integrity(raw_shares, secret_hash)

    collected = packets[:2]
    shares, agreed_hash = unpack_shares_with_integrity(collected)
    reconstructed = reconstruct_secret(shares)

    with pytest.raises(TamperDetectedError):
        verify_integrity(reconstructed, agreed_hash)


def test_end_to_end_truncated_packet_raises_before_reconstruction():
    secret = b"secret-for-truncation-test"
    secret_hash = compute_integrity_hash(secret)
    raw_shares = split_secret(secret, n=3, k=2)
    packets = pack_shares_with_integrity(raw_shares, secret_hash)

    collected = list(packets[:2])
    x, _ = collected[0]
    collected[0] = (x, b"\x00" * 5)

    with pytest.raises(ValueError):
        unpack_shares_with_integrity(collected)


# ==============================================================================
# PART 4: Session Key Caching (SessionCache)
# ==============================================================================


def test_fingerprint_generation():
    key = b"\x01" * 32
    fp = fingerprint_of(key)
    assert isinstance(fp, str)
    assert len(fp) == 64
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


# ==============================================================================
# PART 5: Network Transfer Layer & TCP Socket Framing
# ==============================================================================


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


def test_send_share_reaches_real_peer():
    port_holder, received, ready = [], [], threading.Event()
    server_thread = threading.Thread(
        target=_run_one_shot_server,
        args=("127.0.0.1", port_holder, received, ready),
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
    share = (3, bytes(range(256)))
    payload = _serialize_share(share)
    assert payload["x"] == 3
    assert base64.b64decode(payload["data"]) == share[1]


def test_send_shares_reports_per_peer_results():
    port_holder, received, ready = [], [], threading.Event()
    server_thread = threading.Thread(
        target=_run_one_shot_server,
        args=("127.0.0.1", port_holder, received, ready),
    )
    server_thread.start()
    ready.wait(timeout=2)

    shares = [(1, b"share-one"), (2, b"share-two")]
    peers = [
        ("127.0.0.1", port_holder[0]),
        ("127.0.0.1", 1),
    ]
    results = send_shares(shares, peers, timeout=1.0)
    server_thread.join(timeout=2)

    assert results[0][1] is None
    assert isinstance(results[1][1], OSError)


def test_send_shares_requires_matching_lengths():
    with pytest.raises(ValueError):
        send_shares([(1, b"a")], [("127.0.0.1", 1), ("127.0.0.1", 2)])


def test_deserialize_share_valid_and_invalid():
    valid = {"x": 2, "data": base64.b64encode(b"test-share-bytes").decode("ascii")}
    assert _deserialize_share(valid) == (2, b"test-share-bytes")

    with pytest.raises(ValueError):
        _deserialize_share({"invalid": "payload"})


def test_receive_share_from_connected_socket():
    server_conn, client_conn = _make_connected_pair()
    try:
        share = (4, b"test-secret-share-payload")
        send_message(client_conn, _serialize_share(share))
        recovered_share = receive_share(server_conn)
        assert recovered_share == share
    finally:
        server_conn.close()
        client_conn.close()


def test_send_share_with_retry_failure():
    with pytest.raises(OSError):
        send_share_with_retry(
            "127.0.0.1", 1, (1, b"data"), retries=2, delay=0.01, timeout=0.5
        )


# ==============================================================================
# PART 6: Peer Discovery (Zeroconf / mDNS)
# ==============================================================================


def test_get_local_ip_returns_valid_string():
    ip = _get_local_ip()
    assert isinstance(ip, str)
    assert len(ip.split(".")) == 4


def test_peer_discovery_initialization():
    pd = PeerDiscovery()
    assert pd.service_type == "_meshvault._tcp.local."
    assert pd.zeroconf is None
    assert pd.service_info is None


@patch("network.discovery.Zeroconf")
def test_advertise_service_mocked(mock_zc_class):
    mock_zc = MagicMock()
    mock_zc_class.return_value = mock_zc

    pd = PeerDiscovery()
    pd.advertise_service(
        name="node1",
        port=5000,
        metadata={"k": "3", "n": "5"},
        host_ip="192.168.1.10",
    )

    assert pd.service_info is not None
    assert pd.service_info.port == 5000
    assert mock_zc.register_service.called

    pd.stop()
    assert mock_zc.unregister_service.called
    assert mock_zc.close.called


@patch("network.discovery.ServiceBrowser")
@patch("network.discovery.Zeroconf")
def test_find_peers_mocked(mock_zc_class, mock_browser_class):
    mock_zc = MagicMock()
    mock_zc_class.return_value = mock_zc

    pd = PeerDiscovery()

    def simulate_browse(zc, type_, listener):
        mock_info = MagicMock()
        mock_info.name = "node2._meshvault._tcp.local."
        mock_info.addresses = [b"\xc0\xa8\x01\x14"]
        mock_info.port = 6000
        mock_info.properties = {b"k": b"2", b"n": b"3"}
        mock_info.parsed_addresses.return_value = ["192.168.1.20"]
        listener.discovered_infos.append(mock_info)
        return MagicMock()

    mock_browser_class.side_effect = simulate_browse

    peers = pd.find_peers(timeout_seconds=0.01)
    assert len(peers) == 1
    assert peers[0]["host"] == "192.168.1.20"
    assert peers[0]["port"] == 6000
    assert peers[0]["properties"] == {"k": "2", "n": "3"}

    pd.stop()


# ==============================================================================
# PART 7: Command-Line Interface (CLI split & recover)
# ==============================================================================


def test_parse_peer_valid():
    host, port = _parse_peer("192.168.1.100:5005")
    assert host == "192.168.1.100"
    assert port == 5005

    host, port = _parse_peer("localhost:8080")
    assert host == "localhost"
    assert port == 8080


def test_parse_peer_invalid():
    with pytest.raises(Exception):
        _parse_peer("invalid_peer_without_port")

    with pytest.raises(Exception):
        _parse_peer("127.0.0.1:99999")


def test_cli_split_parser():
    parser = build_parser()
    args = parser.parse_args(
        [
            "split",
            "-k",
            "3",
            "-n",
            "5",
            "-s",
            "mysecret",
            "-p",
            "127.0.0.1:5001",
            "-p",
            "127.0.0.1:5002",
        ]
    )
    assert args.command == "split"
    assert args.threshold == 3
    assert args.shares == 5
    assert args.secret == "mysecret"
    assert len(args.peers) == 2
    assert args.peers[0] == ("127.0.0.1", 5001)


def test_cli_recover_parser():
    parser = build_parser()
    args = parser.parse_args(
        ["recover", "-k", "3", "-p", "6000", "--host", "127.0.0.1", "-o", "out.txt"]
    )
    assert args.command == "recover"
    assert args.threshold == 3
    assert args.port == 6000
    assert args.host == "127.0.0.1"
    assert args.output == "out.txt"


def test_cli_split_main_execution(tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("classified-top-secret")

    ret = main(
        ["split", "-k", "2", "-n", "3", "-f", str(secret_file), "--timeout", "0.1"]
    )
    assert ret == 0


def test_cli_split_invalid_k_n():
    ret = main(["split", "-k", "5", "-n", "3", "-s", "invalid"])
    assert ret == 1


# ==============================================================================
# PART 8: End-to-End Multi-Peer Integration Workflows
# ==============================================================================


def test_e2e_split_to_multiple_peers():
    """Test splitting a secret and securely sending shares to 3 distinct mock peer nodes."""
    secret = b"Antigravity-MeshVault-E2E-Secret-Key-2026!"
    threshold_k = 2
    shares_n = 3

    peer_threads = []
    ports = []
    shares_received = [[] for _ in range(shares_n)]
    ready_events = [threading.Event() for _ in range(shares_n)]
    stop_event = threading.Event()

    for i in range(shares_n):
        t = threading.Thread(
            target=_peer_listener,
            args=(ports, shares_received[i], ready_events[i], stop_event),
        )
        t.daemon = True
        t.start()
        peer_threads.append(t)
        ready_events[i].wait(timeout=2.0)

    peer_addresses = [("127.0.0.1", p) for p in ports]

    generated_shares = execute_split(
        secret=secret,
        threshold_k=threshold_k,
        shares_n=shares_n,
        peers=peer_addresses,
        transfer_timeout=2.0,
        encrypted=True,
    )

    for t in peer_threads:
        t.join(timeout=3.0)

    # Verify all 3 peers received their distinct shares
    assert len(generated_shares) == 3
    collected = []
    for peer_shares in shares_received:
        if peer_shares:
            collected.append(peer_shares[0])

    assert len(collected) == 3

    # Reconstruct from any threshold subset (K=2)
    assert reconstruct_secret(collected[:2]) == secret
    assert reconstruct_secret(collected[1:3]) == secret


def test_e2e_recover_flow():
    """Test execute_recover listening and receiving encrypted shares from client peers."""
    secret = b"Classified-Data-Recovery-Vector-99"
    threshold_k = 3
    shares_n = 4

    shares = split_secret(secret, n=shares_n, k=threshold_k)

    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_sock.bind(("127.0.0.1", 0))
    free_port = temp_sock.getsockname()[1]
    temp_sock.close()

    recovered_holder = []

    def run_recover():
        result = execute_recover(
            threshold_k=threshold_k,
            listen_port=free_port,
            listen_host="127.0.0.1",
            timeout=5.0,
            advertise=False,
        )
        recovered_holder.append(result)

    recover_thread = threading.Thread(target=run_recover)
    recover_thread.daemon = True
    recover_thread.start()

    time.sleep(0.3)

    for i in range(threshold_k):
        send_encrypted_share("127.0.0.1", free_port, shares[i], timeout=2.0)
        time.sleep(0.05)

    recover_thread.join(timeout=5.0)

    assert len(recovered_holder) == 1
    assert recovered_holder[0] == secret
