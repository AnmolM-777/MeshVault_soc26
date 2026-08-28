"""
Concurrent Multi-Peer Socket Server.
Handles multi-peer concurrent non-blocking connections, isolated ECDH handshakes,
and thread-safe share aggregation.
"""

import socket
import struct
import threading
import time
from typing import Dict, Optional
from crypto.channel import SecureChannel
from network.transfer import send_frame, recv_frame


class MultiPeerServer:
    """
    Concurrent non-blocking multi-peer TCP server for receiving Shamir shares.
    Uses a thread-per-connection pattern to handle multiple peer connections simultaneously.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 0, threshold_k: int = 1):
        self.host = host
        self.port = port
        self.threshold_k = threshold_k
        self.server_sock: Optional[socket.socket] = None
        self.shares: Dict[int, bytes] = {}       # Saare received shares yahan save honge
        self.lock = threading.Lock()              # Thread safety ke liye Lock
        self.stop_event = threading.Event()       # K shares pure hone par switch ON hoga
        self.client_threads: list[threading.Thread] = []
        self._listener_thread: Optional[threading.Thread] = None

    def start(self) -> int:
        """
        Server socket bind karta hai, listen karta hai aur background listener thread start karta hai.
        Returns: Assigned Port number.
        """
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(128)
        self.server_sock.settimeout(0.5)  # 0.5s timeout taaki bar-bar stop_event check ho sake
        self.port = self.server_sock.getsockname()[1]

        # Background listener thread
        self._listener_thread = threading.Thread(target=self._listener_loop, daemon=True)
        self._listener_thread.start()
        return self.port

    def _listener_loop(self) -> None:
        """
        Main Gatekeeper Loop: Naye peers accept karta hai aur har peer ke liye worker thread spawn karta hai.
        """
        while not self.stop_event.is_set():
            try:
                conn, addr = self.server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            # Har incoming peer ke liye naya Thread
            t = threading.Thread(
                target=self._handle_peer,
                args=(conn, addr),
                daemon=True,
            )
            t.start()
            with self.lock:
                self.client_threads.append(t)

    def _handle_peer(self, conn: socket.socket, addr: tuple) -> None:
        """
        Worker Thread: Individual peer se handshake aur share receive karta hai.
        """
        try:
            conn.settimeout(10.0)

            # Step 1: Isolated SecureChannel instance
            channel = SecureChannel()
            my_public_key = channel.generate_key_pair()

            # Step 2: Peer ki public key receive karo
            msg_type, peer_public_key = recv_frame(conn)
            if msg_type != "KEY":
                print(f"Invalid message type from {addr}: {msg_type}")
                return

            # Step 3: Apni public key peer ko bhejo
            send_frame(conn, "KEY", my_public_key)

            # Step 4: Shared secret compute karo (ECDH)
            channel.compute_shared_secret(peer_public_key)

            # Step 5: Encrypted share receive karo
            msg_type, encrypted_share = recv_frame(conn)
            if msg_type != "SHARE":
                print(f"Invalid message type from {addr}: {msg_type}")
                return

            # Step 6: Decrypt share payload
            combined = channel.decrypt_message(encrypted_share)
            x = struct.unpack("B", combined[:1])[0]   # 1st byte = x coordinate
            share_bytes = combined[1:]                # Remaining bytes = share

            # Step 7: Thread-safe tareeqe se dictionary update karo
            with self.lock:
                self.shares[x] = share_bytes
                if len(self.shares) >= self.threshold_k:
                    self.stop_event.set()

        except Exception as e:
            # Individual peer disconnect/error handle karo
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def stop(self) -> None:
        """
        Server stop karta hai aur resources cleanup karta hai.
        """
        self.stop_event.set()
        if self.server_sock is not None:
            try:
                self.server_sock.close()
            except Exception:
                pass
        if self._listener_thread and self._listener_thread.is_alive():
            self._listener_thread.join(timeout=1.0)

    def receive_shares(self, timeout_seconds: float = 15.0) -> Dict[int, bytes]:
        """
        Jab tak K shares na mil jayein ya timeout na ho jaye, wait karta hai.
        Returns: {x: share_bytes, ...}
        """
        if self.server_sock is None:
            self.start()

        start_time = time.time()
        while not self.stop_event.is_set():
            if time.time() - start_time >= timeout_seconds:
                break
            time.sleep(0.05)

        self.stop()
        with self.lock:
            return dict(self.shares)


def receive_shares_concurrent(
    port: int,
    threshold_k: int,
    host: str = "0.0.0.0",
    timeout_seconds: float = 15.0,
) -> Dict[int, bytes]:
    """
    Convenience function: Concurrent multi-peer server chalata hai aur K shares collect karke deta hai.
    """
    server = MultiPeerServer(host=host, port=port, threshold_k=threshold_k)
    return server.receive_shares(timeout_seconds=timeout_seconds)
