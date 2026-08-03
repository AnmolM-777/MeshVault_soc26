"""
Split Operation Coordinator.
Coordinates CLI input, SSS splitting, mDNS discovery, and key-exchange/delivery of shares.

Mentee E Deliverables:
- Weeks 1-2: Set up repo, pre-commit hooks, pytest structure, and write skeleton test files.
- Weeks 3-4: Build integration test harness.
- Weeks 7-8: Build full CLI command coordination for 'split'.
"""


import logging
import socket
from dataclasses import dataclass
from typing import List, Tuple
 
from crypto.sss import split_secret
from crypto.channel import SecureChannel
from network.discovery import PeerDiscovery
from network.transfer import send_frame, recv_frame

logger = logging.getLogger(__name__)
 
CONNECT_TIMEOUT_SECONDS = 10
RECV_TIMEOUT_SECONDS = 10
 
 
class ShareDeliveryError(RuntimeError):
    """Raised when one or more shares could not be delivered to peers."""
 
 
@dataclass
class DeliveryResult:
    share_index: int
    peer_name: str
    peer_ip: str
    peer_port: int
    success: bool
    error: str = ""
 
 
def _dedupe_peers(peers: List[dict]) -> List[dict]:
    """Remove duplicate peer entries (same ip:port) returned by discovery."""
    seen = set()
    unique = []
    for peer in peers:
        key = (peer["ip"], peer["port"])
        if key in seen:
            logger.warning("Ignoring duplicate peer entry: %s:%s", *key)
            continue
        seen.add(key)
        unique.append(peer)
    return unique
 
 
def _deliver_share(peer: dict, x: int, share_bytes: bytes) -> None:
    """
    Deliver a single share to a single peer over an authenticated, encrypted
    channel. Raises on any failure; caller is responsible for aggregating
    results and cleanup.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT_SECONDS)
    try:
        sock.connect((peer["ip"], peer["port"]))
        sock.settimeout(RECV_TIMEOUT_SECONDS)
 
        channel = SecureChannel()
        my_public_key = channel.generate_key_pair()
 
        send_frame(sock, "KEY", my_public_key)
        msg_type, peer_public_key = recv_frame(sock)
        if msg_type != "KEY":
            raise ShareDeliveryError(
                f"Expected KEY frame from peer, got '{msg_type}'"
            )
 
        channel.compute_shared_secret(peer_public_key)
 
        encrypted_share = channel.encrypt_message(share_bytes)
        send_frame(sock, "SHARE", encrypted_share)
 
        # Require an explicit ack so we know the peer actually stored the
        # share rather than assuming success once bytes hit the wire.
        ack_type, ack_payload = recv_frame(sock)
        if ack_type != "ACK":
            raise ShareDeliveryError(
                f"Peer did not acknowledge share (got '{ack_type}')"
            )
 
        logger.info(
            "Share %s delivered to peer %s (%s:%s)",
            x, peer["name"], peer["ip"], peer["port"],
        )
    except socket.timeout as exc:
        raise ShareDeliveryError(f"Timed out communicating with peer: {exc}") from exc
    except OSError as exc:
        raise ShareDeliveryError(f"Network error communicating with peer: {exc}") from exc
    finally:
        sock.close()
 




def execute_split(secret: bytes, threshold_k: int, shares_n: int) -> None:
    """
    Executes the secret split operation.

    Mentee E Weeks 7-8 Deliverable.
    """

    if threshold_k < 1 or shares_n < 1:
        raise ValueError("threshold_k and shares_n must be positive integers")
    if threshold_k > shares_n:
        raise ValueError("threshold_k cannot exceed shares_n")
 
    # Step 1 — split the secret into N shares
    shares: List[Tuple[int, bytes]] = split_secret(secret, threshold_k, shares_n)
    logger.info("Secret split into %s shares with threshold %s", shares_n, threshold_k)
 
    # Step 2 — discover peers on the LAN
    discovery = PeerDiscovery()
    try:
        peers = discovery.find_peers(timeout_seconds=5)
    finally:
        discovery.stop()
 
    peers = _dedupe_peers(peers)
 
    # Step 3 — confirm enough distinct peers are available
    if len(peers) < shares_n:
        raise ShareDeliveryError(
            f"Need {shares_n} distinct peers but found {len(peers)}"
        )
 
    # Step 4 — deliver one share per peer, tracking results so partial
    # failures are reported rather than silently abandoned.
    results: List[DeliveryResult] = []
    for i, (x, share_bytes) in enumerate(shares):
        peer = peers[i]
        try:
            _deliver_share(peer, x, share_bytes)
            results.append(
                DeliveryResult(
                    share_index=x,
                    peer_name=peer["name"],
                    peer_ip=peer["ip"],
                    peer_port=peer["port"],
                    success=True,
                )
            )
        except ShareDeliveryError as exc:
            logger.error(
                "Failed to deliver share %s to peer %s (%s:%s): %s",
                x, peer["name"], peer["ip"], peer["port"], exc,
            )
            results.append(
                DeliveryResult(
                    share_index=x,
                    peer_name=peer["name"],
                    peer_ip=peer["ip"],
                    peer_port=peer["port"],
                    success=False,
                    error=str(exc),
                )
            )
 
    failed = [r for r in results if not r.success]
    if failed:
        raise ShareDeliveryError(
            f"{len(failed)}/{len(results)} shares failed to deliver: "
            + "; ".join(f"share {r.share_index}->{r.peer_name}: {r.error}" for r in failed)
        )
 
    return results





    # TODO: Implement split orchestration
    raise NotImplementedError("execute_split has not been implemented yet.")
