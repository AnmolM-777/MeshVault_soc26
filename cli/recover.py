"""
Recover Operation Coordinator.
Coordinates CLI input, local socket listening, key-exchange/collection of shares, and SSS reconstruction.

Mentee E Deliverables:
- Weeks 1-2: Set up repo, pre-commit hooks, pytest structure, and write skeleton test files.
- Weeks 3-4: Build integration test harness.
- Weeks 7-8: Build full CLI command coordination for 'recover'.
"""


import logging
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
 
from crypto.sss import reconstruct_secret
from crypto.channel import SecureChannel
from network.discovery import PeerDiscovery
from network.transfer import send_frame, recv_frame



 
logger = logging.getLogger(__name__)
 
CONNECT_TIMEOUT_SECONDS = 10
RECV_TIMEOUT_SECONDS = 10
 
# Frame type constants — centralized so protocol changes only need to
# happen in one place.
FRAME_KEY = "KEY"
FRAME_REQUEST_SHARE = "REQUEST_SHARE"
FRAME_SHARE = "SHARE"
 
 
class RecoverError(RuntimeError):
    """Raised when the secret cannot be reconstructed from available peers."""
 
 
class PeerShareError(RuntimeError):
    """Raised when a single peer fails to provide a usable share.
 
    This is intentionally distinct from RecoverError: a PeerShareError
    for one peer should not, by itself, abort the overall recovery —
    the caller aggregates these and only raises RecoverError once it's
    clear the threshold cannot be met.
    """
 
 
@dataclass
class CollectedShare:
    """A validated, decrypted share collected from a peer."""
    share_index: int
    share_bytes: bytes
    peer_name: str
    peer_ip: str
    peer_port: int
 
 
@dataclass
class CollectionFailure:
    """Details about a peer that failed to yield a usable share."""
    peer_name: str
    peer_ip: str
    peer_port: int
    error: str
 
 
@dataclass
class RecoveryOutcome:
    """Aggregate result of a recovery attempt, success or failure."""
    secret: Optional[bytes] = None
    shares_used: List[CollectedShare] = field(default_factory=list)
    failures: List[CollectionFailure] = field(default_factory=list)
 
 
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
 
 
def _validate_peer(peer: dict) -> None:
    """
    Validate that a peer discovery record has the fields we need before
    attempting a connection. Raises PeerShareError on malformed records
    rather than letting a KeyError bubble up mid-recovery.
    """
    required_fields = ("ip", "port", "name")
    missing = [f for f in required_fields if f not in peer]
    if missing:
        raise PeerShareError(
            f"Peer discovery record missing fields {missing}: {peer!r}"
        )
    if not isinstance(peer["port"], int) or not (0 < peer["port"] < 65536):
        raise PeerShareError(f"Peer has invalid port: {peer.get('port')!r}")
 
 
def _handshake(sock: socket.socket) -> SecureChannel:
    """
    Perform the SecureChannel key exchange over an already-connected
    socket, mirroring the handshake in cli/split.py. Returns a
    SecureChannel ready for encrypt/decrypt use.
    """
    channel = SecureChannel()
    my_public_key = channel.generate_key_pair()
 
    send_frame(sock, FRAME_KEY, my_public_key)
    msg_type, peer_public_key = recv_frame(sock)
    if msg_type != FRAME_KEY:
        raise PeerShareError(
            f"Expected '{FRAME_KEY}' frame during handshake, got '{msg_type}'"
        )
 
    channel.compute_shared_secret(peer_public_key)
    return channel
 
 
def _request_share(sock: socket.socket) -> Tuple[str, bytes]:
    """
    Ask the connected peer for its share and return the raw
    (frame_type, payload) response. Does not validate or decrypt —
    that's the caller's job, so this stays a thin network operation.
    """
    send_frame(sock, FRAME_REQUEST_SHARE, b"")
    return recv_frame(sock)
 
 
def _decrypt_share(channel: SecureChannel, frame_type: str, payload: bytes) -> bytes:
    """
    Validate the frame type and decrypt the share payload.
    Raises PeerShareError on an unexpected frame type or decryption failure.
    """
    if frame_type != FRAME_SHARE:
        raise PeerShareError(
            f"Expected '{FRAME_SHARE}' frame, got '{frame_type}'"
        )
    try:
        return channel.decrypt_message(payload)
    except Exception as exc:  # decryption failures may raise various types
        # depending on the crypto backend; normalize to PeerShareError so
        # callers have one exception type to handle.
        raise PeerShareError(f"Failed to decrypt share: {exc}") from exc
 
 
def _parse_share_bytes(decrypted: bytes) -> Tuple[int, bytes]:
    """
    Parse decrypted share bytes into (share_index, share_value).
 
    Assumes the wire format matches what split_secret/reconstruct_secret
    expect elsewhere in the project: the first byte is the share index
    (1-255, per standard SSS x-coordinates) and the remainder is the
    share value. Adjust this if crypto.sss uses a different encoding.
    """
    if len(decrypted) < 2:
        raise PeerShareError(
            f"Decrypted share too short to contain an index and value "
            f"({len(decrypted)} bytes)"
        )
    share_index = decrypted[0]
    share_value = decrypted[1:]
    if share_index == 0:
        raise PeerShareError("Share index 0 is invalid for Shamir Secret Sharing")
    return share_index, share_value
 
 
def _collect_share(peer: dict) -> CollectedShare:
    """
    Connect to a single peer, perform the handshake, request and decrypt
    its share, and return a validated CollectedShare.
 
    Raises PeerShareError on any failure. Always closes its socket.
    """
    _validate_peer(peer)
 
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT_SECONDS)
    try:
        try:
            sock.connect((peer["ip"], peer["port"]))
        except ConnectionRefusedError as exc:
            raise PeerShareError(f"Connection refused by peer: {exc}") from exc
        except socket.timeout as exc:
            raise PeerShareError(f"Timed out connecting to peer: {exc}") from exc
        except OSError as exc:
            raise PeerShareError(f"Network error connecting to peer: {exc}") from exc
 
        sock.settimeout(RECV_TIMEOUT_SECONDS)
 
        try:
            channel = _handshake(sock)
            frame_type, payload = _request_share(sock)
        except socket.timeout as exc:
            raise PeerShareError(f"Timed out communicating with peer: {exc}") from exc
        except OSError as exc:
            raise PeerShareError(f"Network error communicating with peer: {exc}") from exc
 
        decrypted = _decrypt_share(channel, frame_type, payload)
        share_index, share_value = _parse_share_bytes(decrypted)
 
        logger.info(
            "Collected share %s from peer %s (%s:%s)",
            share_index, peer["name"], peer["ip"], peer["port"],
        )
 
        return CollectedShare(
            share_index=share_index,
            share_bytes=share_value,
            peer_name=peer["name"],
            peer_ip=peer["ip"],
            peer_port=peer["port"],
        )
    finally:
        sock.close()
 
 
def _write_secret_to_file(secret: bytes, output_path: Path) -> None:
    """
    Write the recovered secret to disk. Kept separate from
    execute_recover so callers that only want the bytes in memory
    (e.g. tests) don't need to touch the filesystem.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Write with restrictive permissions where the platform supports it,
    # since this file contains recovered secret material.
    with open(output_path, "wb") as f:
        f.write(secret)
    try:
        output_path.chmod(0o600)
    except OSError:
        logger.warning("Could not set restrictive permissions on %s", output_path)
    logger.info("Recovered secret written to %s", output_path)




def execute_recover(threshold_k: int, output_path: Optional[Path] = None,
) -> RecoveryOutcome:
    """
    Executes the secret recovery operation.

    Mentee E Weeks 7-8 Deliverable.
    """

    if threshold_k < 1:
        raise ValueError("threshold_k must be a positive integer")
 
    # Step 1 — discover peers on the LAN
    discovery = PeerDiscovery()
    try:
        peers = discovery.find_peers(timeout_seconds=5)
    finally:
        discovery.stop()
 
    peers = _dedupe_peers(peers)
 
    # Step 2 — confirm enough peers are even present to *attempt* recovery.
    # Note this is optimistic: some peers may still fail later, so we keep
    # trying peers beyond this point rather than stopping at exactly
    # threshold_k discovered peers.
    if len(peers) < threshold_k:
        raise RecoverError(
            f"Need at least {threshold_k} peers but only found {len(peers)}"
        )
 
    outcome = RecoveryOutcome()
    seen_indexes: Dict[int, CollectedShare] = {}
 
    # Step 3 — contact peers one at a time, collecting shares until the
    # threshold is satisfied. Continue past individual peer failures.
    for peer in peers:
        if len(seen_indexes) >= threshold_k:
            break
 
        try:
            collected = _collect_share(peer)
        except PeerShareError as exc:
            logger.error(
                "Failed to collect share from peer %s (%s:%s): %s",
                peer.get("name"), peer.get("ip"), peer.get("port"), exc,
            )
            outcome.failures.append(
                CollectionFailure(
                    peer_name=peer.get("name", "?"),
                    peer_ip=peer.get("ip", "?"),
                    peer_port=peer.get("port", 0),
                    error=str(exc),
                )
            )
            continue
 
        # Step 4 — reject duplicate share indexes (e.g. a misconfigured
        # peer re-serving another peer's share).
        if collected.share_index in seen_indexes:
            logger.warning(
                "Duplicate share index %s from peer %s ignored "
                "(already have it from %s)",
                collected.share_index,
                collected.peer_name,
                seen_indexes[collected.share_index].peer_name,
            )
            continue
 
        seen_indexes[collected.share_index] = collected
        outcome.shares_used.append(collected)
 
    # Step 5 — verify the threshold was actually met after attempting all
    # peers, aggregating failure details for a clean error report.
    if len(seen_indexes) < threshold_k:
        failure_summary = "; ".join(
            f"{f.peer_name} ({f.peer_ip}:{f.peer_port}): {f.error}"
            for f in outcome.failures
        ) or "no additional failure details available"
        raise RecoverError(
            f"Only collected {len(seen_indexes)}/{threshold_k} required "
            f"shares. Failures: {failure_summary}"
        )
 
    # Step 6 — reconstruct the secret from the collected shares.
    share_tuples: List[Tuple[int, bytes]] = [
        (s.share_index, s.share_bytes) for s in outcome.shares_used
    ]
    try:
        secret = reconstruct_secret(share_tuples, threshold_k)
    except Exception as exc:
        raise RecoverError(f"Failed to reconstruct secret: {exc}") from exc
 
    outcome.secret = secret
    logger.info(
        "Secret successfully reconstructed from %s shares", len(share_tuples)
    )
 
    # Step 7 — optionally persist to disk.
    if output_path is not None:
        _write_secret_to_file(secret, output_path)
 
    return outcome
 





    # TODO: Implement recover orchestration
    raise NotImplementedError("execute_recover has not been implemented yet.")
