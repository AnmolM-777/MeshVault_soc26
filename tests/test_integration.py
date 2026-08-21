import socket
import threading
import time
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
