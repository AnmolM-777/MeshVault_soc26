import socket
import threading
import time
import pytest
from cli.split import execute_split
from cli.recover import execute_recover
from crypto.sss import reconstruct_secret
from network.transfer import receive_encrypted_share, send_encrypted_share


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

    from crypto.sss import split_secret

    shares = split_secret(secret, n=shares_n, k=threshold_k)

    # Find a free port
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

    time.sleep(0.3)  # Wait for recover listener to start

    # Send K shares from client peers
    for i in range(threshold_k):
        send_encrypted_share("127.0.0.1", free_port, shares[i], timeout=2.0)
        time.sleep(0.05)

    recover_thread.join(timeout=5.0)

    assert len(recovered_holder) == 1
    assert recovered_holder[0] == secret


def test_e2e_split_invalid_threshold_zero():
    """
    Simulates: Calling execute_split with threshold_k = 0.
    Why fail: A threshold of 0 is mathematically invalid for Shamir's Secret Sharing.
    Expected: Should raise ValueError from execute_split validation.
    """
    secret = b"Test-Secret"
    with pytest.raises(ValueError, match="Invalid threshold/shares configuration"):
        execute_split(secret, threshold_k=0, shares_n=3, peers=[])


def test_e2e_split_threshold_greater_than_shares():
    """
    Simulates: Calling execute_split with k > n.
    Why fail: Cannot require more shares for recovery than the total number of shares generated.
    Expected: Should raise ValueError from execute_split validation.
    """
    secret = b"Test-Secret"
    with pytest.raises(ValueError, match="Invalid threshold/shares configuration"):
        execute_split(secret, threshold_k=4, shares_n=3, peers=[])


def test_e2e_recover_insufficient_shares():
    """
    Simulates: Providing fewer than the required threshold_k shares to recovery.
    Why fail: execute_recover waits for k shares. If timeout occurs before k shares, it raises socket.timeout.
    Expected: Raises socket.timeout exception.
    """
    from crypto.sss import split_secret

    threshold_k = 3
    shares_n = 4
    secret = b"Not-Enough-Shares-Test"
    shares = split_secret(secret, n=shares_n, k=threshold_k)

    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_sock.bind(("127.0.0.1", 0))
    free_port = temp_sock.getsockname()[1]
    temp_sock.close()

    error_holder = []

    def run_recover():
        try:
            execute_recover(
                threshold_k=threshold_k,
                listen_port=free_port,
                listen_host="127.0.0.1",
                timeout=1.0,
                advertise=False,
            )
        except Exception as e:
            error_holder.append(e)

    t = threading.Thread(target=run_recover)
    t.daemon = True
    t.start()
    time.sleep(0.3)

    # Send only 2 shares (needs 3)
    for i in range(2):
        send_encrypted_share("127.0.0.1", free_port, shares[i], timeout=2.0)
        time.sleep(0.05)

    t.join(timeout=3.0)

    assert len(error_holder) == 1
    assert isinstance(error_holder[0], socket.timeout)


def test_e2e_recover_corrupted_share():
    """
    Simulates: Modifying the share data before sending it to the recovery process.
    Why fail: The current SSS implementation does not embed integrity checks (hashes/MACs) for the reconstructed secret.
              Therefore, it reconstructs a garbage secret rather than explicitly failing.
    Expected: This test exposes that a corrupted share leads to a silently corrupted reconstructed secret.
    """
    from crypto.sss import split_secret

    threshold_k = 3
    secret = b"Corrupted-Share-Test"
    shares = split_secret(secret, n=4, k=threshold_k)

    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_sock.bind(("127.0.0.1", 0))
    free_port = temp_sock.getsockname()[1]
    temp_sock.close()

    recovered_holder = []

    def run_recover():
        try:
            res = execute_recover(
                threshold_k=threshold_k,
                listen_port=free_port,
                listen_host="127.0.0.1",
                timeout=5.0,
                advertise=False,
            )
            recovered_holder.append(res)
        except Exception as e:
            recovered_holder.append(e)

    t = threading.Thread(target=run_recover)
    t.daemon = True
    t.start()
    time.sleep(0.3)

    # Send K shares, but corrupt the first one
    corrupted_share_data = bytearray(shares[0][1])
    corrupted_share_data[0] ^= 0xFF  # Flip bits
    corrupted_share = (shares[0][0], bytes(corrupted_share_data))

    send_encrypted_share("127.0.0.1", free_port, corrupted_share, timeout=2.0)
    time.sleep(0.05)

    for i in range(1, threshold_k):
        send_encrypted_share("127.0.0.1", free_port, shares[i], timeout=2.0)
        time.sleep(0.05)

    t.join(timeout=5.0)

    # Assert it recovered something, but it's NOT the original secret.
    assert len(recovered_holder) == 1
    recovered_data = recovered_holder[0]
    assert isinstance(recovered_data, bytes)
    assert recovered_data != secret


def test_e2e_split_unreachable_peer():
    """
    Simulates: split operation where one specified peer is unreachable.
    Why fail: Connection attempts should fail for that peer.
    Expected: execute_split should continue and attempt to send to available peers. It will not raise,
              but handles the unreachable peer according to existing error-handling (prints error).
    """
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_sock.bind(("127.0.0.1", 0))
    dead_port = temp_sock.getsockname()[1]
    temp_sock.close()

    ports = []
    shares_received = [[] for _ in range(2)]
    ready_events = [threading.Event() for _ in range(2)]
    stop_event = threading.Event()
    peer_threads = []
    for i in range(2):
        t = threading.Thread(
            target=_peer_listener,
            args=(ports, shares_received[i], ready_events[i], stop_event),
        )
        t.daemon = True
        t.start()
        peer_threads.append(t)
        ready_events[i].wait(timeout=2.0)

    peers = [("127.0.0.1", ports[0]), ("127.0.0.1", ports[1]), ("127.0.0.1", dead_port)]

    secret = b"Unreachable-Peer-Test"
    shares = execute_split(
        secret, threshold_k=2, shares_n=3, peers=peers, transfer_timeout=1.0
    )

    for t in peer_threads:
        t.join(timeout=3.0)

    assert len(shares) == 3
    assert len(shares_received[0]) == 1
    assert len(shares_received[1]) == 1


def test_e2e_recover_peer_disconnect():
    """
    Simulates: A peer connecting to the recovery listener but disconnecting before sending data.
    Why fail: The listener expects an encrypted share structure. A sudden close raises an error.
    Expected: The listener catches the exception, prints it, and continues waiting. Eventually times out.
    """
    threshold_k = 2
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_sock.bind(("127.0.0.1", 0))
    free_port = temp_sock.getsockname()[1]
    temp_sock.close()

    error_holder = []

    def run_recover():
        try:
            execute_recover(
                threshold_k=threshold_k,
                listen_port=free_port,
                listen_host="127.0.0.1",
                timeout=1.0,
                advertise=False,
            )
        except Exception as e:
            error_holder.append(e)

    t = threading.Thread(target=run_recover)
    t.daemon = True
    t.start()
    time.sleep(0.3)

    # Simulate partial connection then drop
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", free_port))
    s.close()

    t.join(timeout=3.0)

    assert len(error_holder) == 1
    assert isinstance(error_holder[0], socket.timeout)


def test_e2e_recover_mismatched_shares():
    """
    Simulates: Trying to recover a secret using shares from two different secrets.
    Why fail: The polynomials won't align, so the reconstructed secret will be garbage.
    Expected: Reconstructs an incorrect secret since no integrity checks exist at this layer.
    """
    from crypto.sss import split_secret, reconstruct_secret

    shares_a = split_secret(b"SecretA", n=3, k=2)
    shares_b = split_secret(b"SecretB", n=3, k=2)

    mixed_shares = [shares_a[0], shares_b[1]]
    recovered = reconstruct_secret(mixed_shares)

    assert recovered != b"SecretA"
    assert recovered != b"SecretB"


def test_e2e_split_invalid_peer_address(capsys):
    """
    Simulates: Calling execute_split with a syntactically invalid peer address.
    Why fail: socket.create_connection cannot resolve the address.
    Expected: execute_split catches the socket.gaierror, prints the failure, and returns the generated shares.
    """
    secret = b"Invalid-Address-Test"
    peers = [("invalid.nonexistent.local", 12345)]

    shares = execute_split(
        secret, threshold_k=1, shares_n=1, peers=peers, transfer_timeout=1.0
    )
    assert len(shares) == 1

    captured = capsys.readouterr()
    assert "Failed to send share to" in captured.out


def test_e2e_tampered_encrypted_share():
    """
    Simulates: Intercepting and modifying the ciphertext of an encrypted share during transit.
    Why fail: AES-GCM tag validation will fail during decrypt_message.
    Expected: InvalidTag is caught during decryption, causing framing error. Listener loops and times out.
    """
    from crypto.channel import SecureChannel
    from network.transfer import send_message, receive_message
    import base64
    import json

    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_sock.bind(("127.0.0.1", 0))
    free_port = temp_sock.getsockname()[1]
    temp_sock.close()

    error_holder = []

    def run_recover():
        try:
            execute_recover(
                threshold_k=1,
                listen_port=free_port,
                listen_host="127.0.0.1",
                timeout=2.0,
                advertise=False,
            )
        except Exception as e:
            error_holder.append(e)

    t = threading.Thread(target=run_recover)
    t.daemon = True
    t.start()
    time.sleep(0.3)

    client_channel = SecureChannel()
    client_pub = client_channel.generate_key_pair()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", free_port))

    send_message(
        s,
        {
            "type": "KEY_EXCHANGE",
            "public_key": base64.b64encode(client_pub).decode("ascii"),
        },
    )

    resp = receive_message(s)
    peer_pub = base64.b64decode(resp["public_key"])
    client_channel.compute_shared_secret(peer_pub)

    share_payload = {"x": 1, "data": base64.b64encode(b"secret").decode("ascii")}
    encrypted_bytes = client_channel.encrypt_message(
        json.dumps(share_payload).encode("utf-8")
    )

    tampered = bytearray(encrypted_bytes)
    tampered[-1] ^= 0xFF

    send_message(
        s,
        {
            "type": "SHARE",
            "payload": base64.b64encode(tampered).decode("ascii"),
        },
    )

    s.close()
    t.join(timeout=3.0)

    assert len(error_holder) == 1
    assert isinstance(error_holder[0], socket.timeout)


def test_e2e_recover_no_peers():
    """
    Simulates: Calling execute_recover with threshold_k = 0.
    Why fail: Threshold of 0 is mathematically invalid.
    Expected: Raises ValueError immediately from validation checks.
    """
    with pytest.raises(ValueError, match="Threshold K must be between 1 and 255"):
        execute_recover(threshold_k=0, listen_port=5000, advertise=False)
