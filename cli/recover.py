from __future__ import annotations

import socket
from typing import List, Tuple
from crypto.sss import reconstruct_secret
from network.discovery import PeerDiscovery
from network.transfer import receive_encrypted_share


def _collect_shares(
    server_sock: socket.socket,
    threshold_k: int,
) -> List[Tuple[int, bytes]]:
    """Accept incoming connections and collect threshold_k unique shares."""
    shares: List[Tuple[int, bytes]] = []
    seen_x: set[int] = set()

    while len(shares) < threshold_k:
        conn, addr = server_sock.accept()
        try:
            share = receive_encrypted_share(conn)
            x_val, share_bytes = share
            if x_val not in seen_x:
                seen_x.add(x_val)
                shares.append(share)
                count = len(shares)
                print(
                    f"  [+] Received share (x={x_val}, {len(share_bytes)} bytes) "
                    f"from {addr[0]}:{addr[1]} [{count}/{threshold_k}]"
                )
            else:
                print(
                    f"  [!] Duplicate share x={x_val} received from {addr[0]}:{addr[1]}, ignored."
                )

        except Exception as e:
            print(f"  [-] Error receiving share from {addr[0]}:{addr[1]}: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass
    return shares


def execute_recover(
    threshold_k: int,
    listen_port: int = 5000,
    listen_host: str = "0.0.0.0",
    timeout: float | None = None,
    advertise: bool = True,
) -> bytes:
    """
    Executes the secret recovery operation.
    Listens for threshold_k connections from peers, receives shares (encrypted or plain),
    validates unique x coordinates, and reconstructs the original secret.

    Returns the reconstructed secret bytes.
    """
    if threshold_k < 1 or threshold_k > 255:
        raise ValueError("Threshold K must be between 1 and 255.")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((listen_host, listen_port))
    server_sock.listen(threshold_k)
    if timeout:
        server_sock.settimeout(timeout)

    print(
        f"MeshVault Recovery Node active: Listening on {listen_host}:{listen_port} (Waiting for {threshold_k} shares)..."
    )

    pd: PeerDiscovery | None = None
    if advertise:
        try:
            pd = PeerDiscovery()
            pd.advertise_service(
                name="meshvault-recovery",
                port=listen_port,
                metadata={"role": "recover", "k": str(threshold_k)},
            )
        except Exception as e:
            print(
                f"Warning: mDNS advertisement failed ({e}), continuing with TCP listener."
            )

    try:
        shares = _collect_shares(server_sock, threshold_k)
    finally:
        if pd is not None:
            pd.stop()
        server_sock.close()

    print("Reconstructing secret from collected threshold shares...")
    return reconstruct_secret(shares[:threshold_k])
