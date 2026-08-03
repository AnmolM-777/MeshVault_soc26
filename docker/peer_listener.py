
# acts as a MeshVault peer inside a Docker container
# It waits for requests from other peers, stores a share during the split phase, and sends the share back during the recovery phase.

import logging
import os
import socket
import sys
import threading

# Reuse the project's existing, unmodified crypto and network layers.
from crypto.channel import SecureChannel
from network.transfer import send_frame, recv_frame

# Logging is simply a way of recording what your program is doing
# tells python to print data in this format when someonr logins

# there are some log levels like info,debug 
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(name)s %(levelname)s: %(message)s",
)

#  %(name)s =meshvault.docker.peer_listener

#each py file ha a logger, here one is created and named
logger = logging.getLogger("meshvault.docker.peer_listener")

# Frame type constants, mirrored from cli/split.py and cli/recover.py so
# this file stays in lockstep with the existing wire protocol.
FRAME_KEY = "KEY"
FRAME_SHARE = "SHARE"
FRAME_REQUEST_SHARE = "REQUEST_SHARE"
FRAME_ACK = "ACK"

RECV_TIMEOUT_SECONDS = 15
LISTEN_BACKLOG = 8


class PeerState:
    """
    Holds the single SSS share this peer is responsible for once it has
    been delivered during the split phase. Guarded by a lock because
    split-delivery and recover-serving arrive on independent connection
    threads.
    """

    def __init__(self, share_index: int):
        self.share_index = share_index
        self._lock = threading.Lock()
        self._share_value: bytes | None = None

    def store(self, value: bytes) -> None:
        with self._lock:
            self._share_value = value

    def read(self) -> bytes | None:
        with self._lock:
            return self._share_value


def _handle_connection(conn: socket.socket, addr, state: PeerState) -> None:
    """
    Services exactly one incoming TCP connection using the same
    handshake cli/split.py and cli/recover.py's clients perform, then
    branches into split-delivery or recover-serving depending on the
    frame the client sends after the handshake.
    """
    conn.settimeout(RECV_TIMEOUT_SECONDS)
    peer_desc = f"{addr[0]}:{addr[1]}"
    try:
        channel = SecureChannel()

        # Step 1-2: standard SecureChannel handshake, identical to the
        # handshake performed in cli/recover.py._handshake and inline
        # in cli/split.py._deliver_share.
        msg_type, client_public_key = recv_frame(conn)
        if msg_type != FRAME_KEY:
            logger.warning("Peer %s sent unexpected first frame %r", peer_desc, msg_type)
            return

        my_public_key = channel.generate_key_pair()
        send_frame(conn, FRAME_KEY, my_public_key)
        channel.compute_shared_secret(client_public_key)

        # Step 3: branch on what the caller wants.
        msg_type, payload = recv_frame(conn)

        if msg_type == FRAME_SHARE:
            # Split delivery: decrypt and store our share, then ACK —
            # exactly what tests/test_integration.py._split_delivery_handler
            # does for cli.split.execute_split.
            decrypted = channel.decrypt_message(payload)
            state.store(decrypted)
            send_frame(conn, FRAME_ACK, b"")
            logger.info(
                "Received and stored share from %s (%d bytes)",
                peer_desc, len(decrypted),
            )

        elif msg_type == FRAME_REQUEST_SHARE:
            # Recover request: reply with (index || value), encrypted —
            # exactly the wire format cli.recover._parse_share_bytes
            # expects, and exactly what
            # tests/test_integration.py._recover_serving_handler does.
            share_value = state.read()
            if share_value is None:
                logger.warning(
                    "Peer %s requested a share before one was delivered; "
                    "closing connection without replying",
                    peer_desc,
                )
                return

            plaintext = bytes([state.share_index]) + share_value
            encrypted = channel.encrypt_message(plaintext)
            send_frame(conn, FRAME_SHARE, encrypted)
            logger.info("Served share (index=%d) to %s", state.share_index, peer_desc)

        else:
            logger.warning("Peer %s sent unrecognized frame type %r", peer_desc, msg_type)

    except (OSError, socket.timeout) as exc:
        logger.error("Connection with %s failed: %s", peer_desc, exc)
    finally:
        conn.close()


def serve_forever(host: str, port: int, state: PeerState) -> None:
    """
    Binds a TCP listening socket and services connections on background
    threads until the process receives a termination signal (e.g. from
    `docker compose down`), at which point the accept() loop raises
    OSError on the closed socket and the process exits cleanly.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(LISTEN_BACKLOG)
    logger.info(
        "Peer '%s' (share index=%d) listening on %s:%d",
        os.environ.get("PEER_NAME", "unnamed-peer"), state.share_index, host, port,
    )

    try:
        while True:
            conn, addr = sock.accept()
            thread = threading.Thread(
                target=_handle_connection, args=(conn, addr, state), daemon=True,
            )
            thread.start()
    except OSError:
        logger.info("Listening socket closed; shutting down.")
    finally:
        sock.close()


def main() -> int:
    peer_name = os.environ.get("PEER_NAME", "peer")
    port = int(os.environ.get("PEER_PORT", "6000"))
    try:
        share_index = int(os.environ["PEER_INDEX"])
    except (KeyError, ValueError):
        logger.error(
            "PEER_INDEX environment variable must be set to this peer's "
            "1-based SSS share index (see docker-compose.yml)."
        )
        return 1

    if not (1 <= share_index <= 255):
        logger.error("PEER_INDEX must be between 1 and 255, got %s", share_index)
        return 1

    state = PeerState(share_index=share_index)
    serve_forever("0.0.0.0", port, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
