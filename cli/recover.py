"""
Concurrent Multi-Peer Recover Operation Coordinator (v2).
Coordinates CLI input, mDNS advertisement, concurrent multi-peer socket listening (via transfer2),
and SSS secret reconstruction.
"""

from __future__ import annotations
from typing import List, Tuple, Optional
from crypto.sss import reconstruct_secret
from network.discovery import PeerDiscovery
from network.transfer2 import MultiPeerServer


def execute_recover(
    threshold_k: int,
    listen_port: int = 5000,
    listen_host: str = "0.0.0.0",
    timeout: float = 30.0,
    advertise: bool = True,
) -> bytes:
    """
    Executes the secret recovery operation using concurrent multi-peer listening:
    1. Starts MultiPeerServer from transfer2.py to handle multiple peer connections simultaneously.
    2. Advertises the recovery service over mDNS so peers on LAN can discover it.
    3. Concurrently receives and decrypts K shares from connecting peers.
    4. Reconstructs and returns the original secret bytes.

    Args:
        threshold_k: Minimum number of shares (K) required to reconstruct the secret.
        listen_port: Port to listen on (default: 5000).
        listen_host: Host IP to bind (default: "0.0.0.0").
        timeout: Maximum seconds to wait for shares before timing out (default: 30.0).
        advertise: Whether to broadcast this recovery node via mDNS (default: True).

    Returns:
        bytes: The reconstructed original secret.

    Raises:
        ValueError: If threshold_k is invalid.
        RuntimeError: If insufficient shares are collected within the timeout.
    """
    if threshold_k < 1 or threshold_k > 255:
        raise ValueError("Threshold K must be between 1 and 255.")

    print(
        f"[*] MeshVault Recovery Node active: Listening on {listen_host}:{listen_port} "
        f"(Waiting concurrently for {threshold_k} shares)..."
    )

    # Step 1: Start transfer2's Multi-Peer Concurrent Server
    server = MultiPeerServer(
        host=listen_host, port=listen_port, threshold_k=threshold_k
    )
    active_port = server.start()

    # Step 2: Advertise on LAN via mDNS so peers can auto-discover this node
    pd: Optional[PeerDiscovery] = None
    if advertise:
        try:
            pd = PeerDiscovery()
            pd.advertise_service(
                name="meshvault-recovery",
                port=active_port,
                metadata={"role": "recover", "k": str(threshold_k)},
            )
            print(
                f"[*] mDNS Service advertised: 'meshvault-recovery' on port {active_port}"
            )
        except Exception as e:
            print(
                f"[!] Warning: mDNS advertisement failed ({e}), continuing with TCP listener."
            )

    # Step 3: Concurrently collect K shares (transfer2 handles ECDH handshake + AES decrypt per peer)
    try:
        shares_dict = server.receive_shares(timeout_seconds=timeout)
    finally:
        # Step 4: Gracefully cleanup mDNS advertisement and socket server
        if pd is not None:
            pd.stop()
        server.stop()

    # Step 5: Check if enough distinct shares were received
    if len(shares_dict) < threshold_k:
        raise RuntimeError(
            f"Recovery failed: Received only {len(shares_dict)}/{threshold_k} shares "
            f"within {timeout}s timeout."
        )

    print(f"[+] Successfully collected {len(shares_dict)}/{threshold_k} unique shares.")
    print("[*] Reconstructing secret from collected shares...")

    # Step 6: Convert {x: share_bytes} dictionary to [(x, share_bytes), ...] format for SSS
    shares_list: List[Tuple[int, bytes]] = list(shares_dict.items())[:threshold_k]
    return reconstruct_secret(shares_list)
