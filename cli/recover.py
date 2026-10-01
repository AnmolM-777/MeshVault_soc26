"""
Concurrent Multi-Peer Recover Operation Coordinator.
Coordinates CLI input, mDNS advertisement, concurrent multi-peer
socket listening,
and SSS secret reconstruction.
"""

from __future__ import annotations
import socket
import threading
import time
from typing import List, Tuple, Optional
from crypto.sss import reconstruct_secret
from network.discovery import PeerDiscovery
from network.transfer import receive_encrypted_share


def _handle_client(
    conn: socket.socket,
    shares_dict: dict,
    lock: threading.Lock,
    stop_event: threading.Event,
    threshold_k: int,
) -> None:
    try:
        conn.settimeout(10.0)
        share = receive_encrypted_share(conn)
        with lock:
            shares_dict[share[0]] = share[1]
            if len(shares_dict) >= threshold_k:
                stop_event.set()
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _advertise_mdns(active_port: int, threshold_k: int) -> Optional[PeerDiscovery]:
    try:
        pd = PeerDiscovery()
        pd.advertise_service(
            name="meshvault-recovery",
            port=active_port,
            metadata={"role": "recover", "k": str(threshold_k)},
        )
        print(
            f"[*] mDNS Service advertised: 'meshvault-recovery' on "
            f"port {active_port}"
        )
        return pd
    except Exception as e:
        print(
            f"[!] Warning: mDNS advertisement failed ({e}), "
            "continuing with TCP listener."
        )
        return None


def execute_recover(
    threshold_k: int,
    listen_port: int = 5000,
    listen_host: str = "0.0.0.0",
    timeout: float = 30.0,
    advertise: bool = True,
) -> bytes:
    """
    Executes the secret recovery operation using concurrent multi-peer
    listening.
    """
    if threshold_k < 1 or threshold_k > 255:
        raise ValueError("Threshold K must be between 1 and 255.")

    print(
        f"[*] MeshVault Recovery Node active: Listening on "
        f"{listen_host}:{listen_port} "
        f"(Waiting concurrently for {threshold_k} shares)..."
    )

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((listen_host, listen_port))
    server_sock.listen(128)
    server_sock.settimeout(0.5)
    active_port = server_sock.getsockname()[1]

    pd = _advertise_mdns(active_port, threshold_k) if advertise else None

    shares_dict = {}
    lock = threading.Lock()
    stop_event = threading.Event()
    threads = []
    start_time = time.time()

    try:
        while not stop_event.is_set():
            if time.time() - start_time >= timeout:
                break
            try:
                conn, _ = server_sock.accept()
                t = threading.Thread(
                    target=_handle_client,
                    args=(conn, shares_dict, lock, stop_event, threshold_k),
                    daemon=True,
                )
                t.start()
                threads.append(t)
            except socket.timeout:
                continue
            except OSError:
                break
    finally:
        if pd is not None:
            pd.stop()
        server_sock.close()
        stop_event.set()

    if len(shares_dict) < threshold_k:
        raise socket.timeout(
            f"Recovery failed: Received only {len(shares_dict)}/"
            f"{threshold_k} shares within {timeout}s timeout."
        )

    print(
        f"[+] Successfully collected {len(shares_dict)}/{threshold_k} " "unique shares."
    )
    print("[*] Reconstructing secret from collected shares...")

    shares_list: List[Tuple[int, bytes]] = list(shares_dict.items())[:threshold_k]
    return reconstruct_secret(shares_list)
