
import itertools
import socket
import threading

import pytest

from crypto.sss import reconstruct_secret, split_secret
from crypto.channel import SecureChannel
from network.transfer import recv_frame, send_frame

import cli.split as cli_split_module
import cli.recover as cli_recover_module
from cli.split import ShareDeliveryError, execute_split
from cli.recover import RecoverError, _collect_share, execute_recover

THRESHOLD_K = 3
SHARES_N = 5


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

# in real we are using mDns 
# we are doing a fake discovery just storing a list and returning it again
# Create some mock peers.
class _FakeDiscovery:

    #store the data given in form of list
    def __init__(self, peers):    
        self._peers = peers
    

    #returns the data stored in list
    def find_peers(self, timeout_seconds=5):
        return self._peers

    #stop the discovery
    def stop(self):
        pass



def test_fake_discovery():
    # Manually creating peer data 
    peers = [
        {"name": "Peer1", "ip": "127.0.0.1", "port": 5001},
        {"name": "Peer2", "ip": "127.0.0.1", "port": 5002},
    ]

    #creating a object
    discovery = _FakeDiscovery(peers)


    #calling the function
    result=discovery.find_peers();
    print(result)

    discovery.stop()
    print("discovery stop")

    assert discovery.find_peers() == peers


# when secret is split we share it to real peer nodes but here we are making fake peer for that
# it functions like a mini server
# its work it to start the server,wait for client, receive and send data
class _MockPeer:
  
    #create a fake peer 
    def __init__(self, handler, name="mock-peer"):
        self.name = name
        self._handler = handler
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # when socket is stop and immediately started os will float that address already in use
        # cannot reuse the address immediately
        # so it changes the socket property
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))           #socket created but no ip address and port number so it add it
        self._sock.listen(1)                        #now it starts listening for 1 pending conn
        self.ip, self.port = self._sock.getsockname()   # returns ip and port no so that client may know where to connect


        # make a background thread for server running ,will wait for clinet to connect
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    
    # executed inside the background thread
    def _serve(self):

        # client connects 
        # accept() returns address and new socket used for talking
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        
        # client is connected
        # peer = _MockPeer(_split_delivery_handler)  so _split_delivery_handler is same as _split_delivery_handler(conn)
        # this cals does not know which protocol to run, so it executes the simply the function given.
        try:
            self._handler(conn)
        except Exception:
            pass
        finally:
            conn.close()

    
    # peer discovery doe not need each attributes of the object so it returns only name,ip,port
    def as_peer_record(self):
        return {"name": self.name, "ip": self.ip, "port": self.port}

    def close(self):
        try:
            self._sock.close()


        #if the background thread is never executed due to some reasons then main waits for 2 sec then continues
        finally:
            self._thread.join(timeout=2)



# mock receiver (peer) used during integration testing
# simulates what another computer would do when it receives a share from the sender.
# Receives the sender's public key.
# Exchanges public keys.
# Creates the shared secret.
# Receives the encrypted share.
# Decrypts it.
# Stores it for verification.
# Sends an acknowledgement.

# store={}
# receiver=_split_delivery_handler()
def _split_delivery_handler(store: dict):
    
    def handler(conn):

        # obj is created containing private key, public key
        channel = SecureChannel()
        msg_type, client_public_key = recv_frame(conn)
        print("Received message type:", msg_type)
        print("Client public key:", client_public_key)
        assert msg_type == "KEY"

        my_public_key = channel.generate_key_pair()
        print("My public key:", my_public_key)
        send_frame(conn, "KEY", my_public_key)

        #generates aes key
        channel.compute_shared_secret(client_public_key)
        print("Shared key:", channel.shared_key)

        # encrypted message is shared over sockets in frame 
        # payload=nonce+tag+msg
        msg_type, payload = recv_frame(conn)
        print("Received message type:", msg_type)
        print("Encrypted payload:", payload)
        assert msg_type == "SHARE"
        decrypted= channel.decrypt_message(payload)

        print("Decrypted share:", decrypted)
        print("\n")
        store["share_value"] = decrypted


        send_frame(conn, "ACK", b"")

    return handler


def _recover_serving_handler(index: int, value: bytes):
    """
    Mimics the peer side of cli.recover._collect_share: perform the
    SecureChannel handshake, wait for a REQUEST_SHARE frame, and reply
    with an encrypted SHARE frame whose plaintext is the 1-byte share
    index followed by the share value -- the wire format expected by
    cli.recover._parse_share_bytes.
    """

    def handler(conn):
        channel = SecureChannel()
        msg_type, client_public_key = recv_frame(conn)
        assert msg_type == "KEY"

        my_public_key = channel.generate_key_pair()
        send_frame(conn, "KEY", my_public_key)
        channel.compute_shared_secret(client_public_key)

        msg_type, _ = recv_frame(conn)
        assert msg_type == "REQUEST_SHARE"

        plaintext = bytes([index]) + value
        encrypted = channel.encrypt_message(plaintext)
        send_frame(conn, "SHARE", encrypted)

    return handler


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_peers():
    """Factory for _MockPeer instances, closed automatically at teardown."""
    created = []

    def _make(handler, name="mock-peer"):
        peer = _MockPeer(handler, name=name)
        created.append(peer)
        return peer

    yield _make

    for peer in created:
        peer.close()


@pytest.fixture
def deliver_via_network(monkeypatch, mock_peers):
    """
    Returns a helper that runs the real cli.split.execute_split
    coordinator against a set of local mock peers and returns the list
    of (x, share_value) pairs each peer actually received -- exercising
    crypto.sss.split_secret, crypto.channel.SecureChannel, and
    network.transfer end-to-end.
    """

    def _deliver(secret: bytes, threshold_k: int, shares_n: int):
        stores = [dict() for _ in range(shares_n)]
        peers = [
            mock_peers(_split_delivery_handler(stores[i]), name=f"peer-{i}")
            for i in range(shares_n)
        ]
        peer_records = [peer.as_peer_record() for peer in peers]

        monkeypatch.setattr(
            cli_split_module,
            "PeerDiscovery",
            lambda: _FakeDiscovery(peer_records),
        )

        results = execute_split(secret, threshold_k, shares_n)
        assert all(result.success for result in results)

        # Peer i (0-indexed) was handed share x = i + 1, matching the
        # x-coordinate ordering produced by crypto.sss.split_secret.
        return [(i + 1, stores[i]["share_value"]) for i in range(shares_n)]

    return _deliver


# ---------------------------------------------------------------------------
# 1. Happy path
# ---------------------------------------------------------------------------


def test_split_and_recover_happy_path(deliver_via_network):
    """
    Full network happy path: split a secret, distribute it to mock
    peers over the real crypto/network stack via execute_split, then
    reconstruct it from exactly threshold_k of the delivered shares.
    """
    secret = b"MeshVault integration test secret"

    shares = deliver_via_network(secret, THRESHOLD_K, SHARES_N)

    recovered = reconstruct_secret(shares[:THRESHOLD_K])
    assert recovered == secret


# ---------------------------------------------------------------------------
# 2. Different share combinations
# ---------------------------------------------------------------------------


def test_recovery_succeeds_with_various_share_combinations(deliver_via_network):
    """
    Any threshold_k-sized subset of the delivered shares must
    reconstruct the same original secret.
    """
    secret = b"combo-test-secret"
    shares = deliver_via_network(secret, THRESHOLD_K, SHARES_N)
    share_by_x = dict(shares)

    # Explicit combinations called out in the project's acceptance
    # criteria (share indexes are 1-based).
    named_combinations = [(1, 2, 3), (2, 3, 5), (1, 4, 5)]
    for combo in named_combinations:
        subset = [(x, share_by_x[x]) for x in combo]
        assert reconstruct_secret(subset) == secret

    # Exhaustively check every threshold_k-sized subset for good measure.
    for combo in itertools.combinations(shares, THRESHOLD_K):
        assert reconstruct_secret(list(combo)) == secret


# ---------------------------------------------------------------------------
# 3. Insufficient shares
# ---------------------------------------------------------------------------


def test_reconstruct_secret_rejects_fewer_than_two_shares(deliver_via_network):
    """crypto.sss.reconstruct_secret requires at least 2 shares."""
    secret = b"insufficient-shares-secret"
    shares = deliver_via_network(secret, THRESHOLD_K, SHARES_N)

    with pytest.raises(ValueError):
        reconstruct_secret(shares[:1])


def test_reconstruct_secret_below_threshold_yields_wrong_secret(deliver_via_network):
    """
    With fewer than threshold_k points, Shamir's scheme provides no
    detection mechanism -- crypto.sss has no way to know what the
    original threshold was, so it interpolates through too few points
    and silently returns the wrong answer instead of raising.
    """
    secret = b"below-threshold-secret"
    shares = deliver_via_network(secret, THRESHOLD_K, SHARES_N)

    below_threshold = shares[: THRESHOLD_K - 1]
    assert reconstruct_secret(below_threshold) != secret


def test_execute_recover_rejects_insufficient_discovered_peers(monkeypatch):
    """
    cli.recover.execute_recover checks the discovered peer *count*
    against threshold_k before attempting any network I/O or
    reconstruction, so this path can be exercised cleanly without
    touching the reconstruct_secret signature bug documented below.
    """
    monkeypatch.setattr(
        cli_recover_module,
        "PeerDiscovery",
        lambda: _FakeDiscovery(
            [{"name": "only-one", "ip": "127.0.0.1", "port": 1}]
        ),
    )

    with pytest.raises(RecoverError):
        execute_recover(THRESHOLD_K)


def test_execute_split_raises_when_not_enough_peers_discovered(monkeypatch):
    """Mirrors the insufficient-peers check on the split/distribution side."""
    monkeypatch.setattr(
        cli_split_module,
        "PeerDiscovery",
        lambda: _FakeDiscovery(
            [{"name": "only-one", "ip": "127.0.0.1", "port": 1}]
        ),
    )

    with pytest.raises(ShareDeliveryError):
        execute_split(b"not-enough-peers", THRESHOLD_K, SHARES_N)


# ---------------------------------------------------------------------------
# 4. Corrupted share
# ---------------------------------------------------------------------------


def test_corrupted_share_produces_incorrect_secret(deliver_via_network):
    """
    crypto.sss provides no authentication of share contents, so a
    single-bit corruption in one share is not detected -- reconstruction
    succeeds but yields the wrong secret rather than raising.
    """
    secret = b"tamper-detection-secret"
    shares = deliver_via_network(secret, THRESHOLD_K, SHARES_N)
    subset = list(shares[:THRESHOLD_K])

    x, value = subset[0]
    tampered_value = bytearray(value)
    tampered_value[0] ^= 0xFF
    subset[0] = (x, bytes(tampered_value))

    assert reconstruct_secret(subset) != secret


# ---------------------------------------------------------------------------
# 5. Large secret
# ---------------------------------------------------------------------------


def test_large_secret_round_trip(deliver_via_network):
    """Split/reconstruct a several-kilobyte secret and verify integrity."""
    # A deterministic, non-repeating 4 KB byte pattern.
    secret = bytes((i * 37 + 11) % 256 for i in range(4096))

    shares = deliver_via_network(secret, THRESHOLD_K, SHARES_N)
    assert reconstruct_secret(shares[:THRESHOLD_K]) == secret


# ---------------------------------------------------------------------------
# 6. Multiple independent runs
# ---------------------------------------------------------------------------


def test_multiple_independent_secrets_reconstruct_correctly(deliver_via_network):
    """Each independently split secret must reconstruct to itself, with
    no state leaking between runs."""
    secrets_to_test = [
        b"first-secret-value",
        b"second-secret-value-longer",
        b"3",
        bytes(range(64)),
    ]

    for secret in secrets_to_test:
        shares = deliver_via_network(secret, THRESHOLD_K, SHARES_N)
        assert reconstruct_secret(shares[:THRESHOLD_K]) == secret


# ---------------------------------------------------------------------------
# Recover-side network protocol (see module docstring for why this does
# not go through execute_recover's final reconstruction call)
# ---------------------------------------------------------------------------


def test_recover_side_collects_and_reconstructs_shares(mock_peers):
    """
    Exercises the client half of cli.recover's network protocol
    (_collect_share: peer validation, handshake, REQUEST_SHARE, decrypt,
    parse) against mock peers seeded with real crypto.sss shares, then
    reconstructs with crypto.sss.reconstruct_secret directly.
    """
    secret = b"recover-side-network-secret"
    shares = split_secret(secret, THRESHOLD_K, SHARES_N)

    peer_records = []
    for x, value in shares[:THRESHOLD_K]:
        peer = mock_peers(_recover_serving_handler(x, value), name=f"peer-{x}")
        peer_records.append(peer.as_peer_record())

    collected = [_collect_share(peer) for peer in peer_records]
    assert len(collected) == THRESHOLD_K

    reconstructed_pairs = [
        (share.share_index, share.share_bytes) for share in collected
    ]
    assert reconstruct_secret(reconstructed_pairs) == secret


def test_execute_recover_reconstruction_signature_bug(monkeypatch, mock_peers):
    """
    Regression/documentation test for a real defect found while writing
    these tests: cli.recover.execute_recover calls

        reconstruct_secret(share_tuples, threshold_k)

    but crypto.sss.reconstruct_secret only accepts a single `shares`
    argument. As a result, execute_recover currently raises a
    RecoverError (wrapping the underlying TypeError) even when enough
    valid shares are available.

    This test sets up a fully valid scenario -- enough correct peers,
    each serving a genuine share -- and asserts on the *actual* current
    behavior, so that fixing cli.recover's call site turns this into a
    (welcome) failing test the team can then update.
    """
    secret = b"execute-recover-bug-secret"
    shares = split_secret(secret, THRESHOLD_K, SHARES_N)

    peer_records = []
    for x, value in shares[:THRESHOLD_K]:
        peer = mock_peers(_recover_serving_handler(x, value), name=f"peer-{x}")
        peer_records.append(peer.as_peer_record())

    monkeypatch.setattr(
        cli_recover_module,
        "PeerDiscovery",
        lambda: _FakeDiscovery(peer_records),
    )

    with pytest.raises(RecoverError, match="Failed to reconstruct secret"):
        execute_recover(THRESHOLD_K)