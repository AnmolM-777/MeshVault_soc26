import socket

from crypto.channel import SecureChannel
from crypto.sss import reconstruct_secret
from network.transfer import send_frame, recv_frame


def execute_recover(threshold_k: int, listen_port: int = 5000) -> bytes:
    """
    Executes the secret recovery operation.

    Mirrors execute_split's handshake: listens for threshold_k peers,
    exchanges public keys, decrypts each incoming share, and
    reconstructs the original secret.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", listen_port))
    server_sock.listen(threshold_k)
    print(f"Waiting for {threshold_k} peers on port {listen_port}...")

    shares = []
    while len(shares) < threshold_k:
        conn, addr = server_sock.accept()

        msg_type, peer_public_key = recv_frame(conn)

        channel = SecureChannel()
        my_public_key = channel.generate_key_pair()
        send_frame(conn, "KEY", my_public_key)

        channel.compute_shared_secret(peer_public_key)

        msg_type, encrypted_share = recv_frame(conn)
        share_bytes = channel.decrypt_message(encrypted_share)

        shares.append(share_bytes)
        print(f"Received share from {addr}")

        conn.close()

    server_sock.close()
    return reconstruct_secret(shares)
