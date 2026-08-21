from __future__ import annotations

from typing import List, Tuple
from crypto.sss import split_secret
from network.discovery import PeerDiscovery
from network.transfer import send_shares


def _find_target_peers(discovery_timeout: float) -> List[Tuple[str, int]]:
    """Discover available peer addresses via mDNS."""
    print(f"Searching for active peers on LAN (timeout: {discovery_timeout}s)...")
    target_peers: List[Tuple[str, int]] = []
    pd = PeerDiscovery()
    try:
        discovered = pd.find_peers(timeout_seconds=discovery_timeout)
        for p in discovered:
            target_peers.append((p["host"], p["port"]))
    finally:
        pd.stop()
    return target_peers


def _distribute_shares(
    shares: List[Tuple[int, bytes]],
    target_peers: List[Tuple[str, int]],
    transfer_timeout: float,
    encrypted: bool,
) -> None:
    """Distribute split shares to target peers."""
    if not target_peers:
        print("No active peers detected or specified. Shares generated locally.")
        return

    print(f"Found {len(target_peers)} peer(s). Distributing shares...")
    num_to_send = min(len(shares), len(target_peers))
    send_results = send_shares(
        shares[:num_to_send],
        target_peers[:num_to_send],
        timeout=transfer_timeout,
        encrypted=encrypted,
    )
    for (peer_host, peer_port), err in send_results:
        if err is None:
            print(f"  [+] Share successfully sent to {peer_host}:{peer_port}")
        else:
            print(f"  [-] Failed to send share to {peer_host}:{peer_port}: {err}")


def execute_split(
    secret: bytes | str,
    threshold_k: int,
    shares_n: int,
    peers: List[Tuple[str, int]] | None = None,
    discovery_timeout: float = 3.0,
    transfer_timeout: float = 5.0,
    encrypted: bool = True,
) -> List[Tuple[int, bytes]]:
    """
    Executes the secret split operation.
    Splits the secret into shares_n shares with threshold_k, discovers or connects
    to network peers, and securely transfers shares to peers.

    Returns the generated shares.
    """
    if isinstance(secret, str):
        secret_bytes = secret.encode("utf-8")
    elif isinstance(secret, (bytes, bytearray)):
        secret_bytes = bytes(secret)
    else:
        raise TypeError("Secret must be a string or bytes.")

    if not secret_bytes:
        raise ValueError("Secret cannot be empty.")

    if not (1 <= threshold_k <= shares_n <= 255):
        raise ValueError(
            f"Invalid threshold/shares configuration: require 1 <= threshold ({threshold_k}) <= shares ({shares_n}) <= 255"
        )

    print(
        f"Splitting secret ({len(secret_bytes)} bytes) into {shares_n} shares (Threshold: {threshold_k})..."
    )
    shares = split_secret(secret_bytes, n=shares_n, k=threshold_k)

    target_peers = (
        list(peers) if peers is not None else _find_target_peers(discovery_timeout)
    )
    _distribute_shares(shares, target_peers, transfer_timeout, encrypted)

    return shares
