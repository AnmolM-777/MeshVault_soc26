"""
Split Operation Coordinator.
Coordinates CLI input, SSS splitting, mDNS discovery, and key-exchange/delivery of shares.

Mentee E Deliverables:
- Weeks 1-2: Set up repo, pre-commit hooks, pytest structure, and write skeleton test files.
- Weeks 3-4: Build integration test harness.
- Weeks 7-8: Build full CLI command coordination for 'split'.
"""

import socket
import struct
from crypto.sss import split_secret
from crypto.channel import SecureChannel
from network.discovery import PeerDiscovery
from network.transfer import send_frame, recv_frame


def execute_split(secret: bytes, threshold_k: int, shares_n: int) -> None:
    """
    Executes the secret split operation.

    Mentee E Weeks 7-8 Deliverable.
    """

    # Step 1 — Secret ko N shares mein split karo
    shares = split_secret(secret, threshold_k, shares_n)
    print(f"Secret split into {shares_n} shares with threshold {threshold_k}")

    # Step 2 — LAN pe peers dhundho
    discovery = PeerDiscovery()
    peers = discovery.find_peers(timeout_seconds=5)

    # Step 3 — Enough peers hain?
    if len(peers) < shares_n:
        discovery.stop()
        raise RuntimeError(f"Need {shares_n} peers but found {len(peers)}")

    # Successfully bheje gaye shares ka count
    successful_shares = 0

    # Step 4 — Har peer ko ek share bhejo
    for i, (x, share_bytes) in enumerate(shares):
        peer = peers[i]
        sock = None  # pehle None — finally mein check ke liye

        try:
            # Step 4a — TCP connection banao
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # 10 sec mein connect nahi hua → skip
            sock.connect((peer["ip"], peer["port"]))

            # Step 4b — SecureChannel object banao
            channel = SecureChannel()

            # Step 4c — Apni public key generate karo
            my_public_key = channel.generate_key_pair()

            # Step 4d — Apni public key peer ko bhejo
            send_frame(sock, "KEY", my_public_key)

            # Step 4e — Peer ki public key lo
            msg_type, peer_public_key = recv_frame(sock)

            # Step 4f — Shared secret compute karo (ECDH)
            channel.compute_shared_secret(peer_public_key)

            # Step 4g — x aur share_bytes ek saath pack karo
            x_bytes = struct.pack("B", x)  # x → 1 byte
            combined = x_bytes + share_bytes

            # Step 4h — Encrypt karo
            encrypted_share = channel.encrypt_message(combined)

            # Step 4i — Encrypted share peer ko bhejo
            send_frame(sock, "SHARE", encrypted_share)

            print(f"✓ Share {x} sent to {peer['name']} ({peer['ip']}:{peer['port']})")
            successful_shares += 1

        except ConnectionRefusedError:
            # Peer offline ho gaya
            print(f"✗ Peer {peer['name']} offline ho gaya — skipping")

        except TimeoutError:
            # Peer ne 10 sec mein respond nahi kiya
            print(f"✗ Peer {peer['name']} timeout — skipping")

        except Exception as e:
            # Koi bhi aur unexpected error
            print(f"✗ Peer {peer['name']} error: {e} — skipping")

        finally:
            # Hamesha socket close karo — error aaye ya na aaye
            if sock is not None:
                sock.close()

    # Step 5 — mDNS cleanup karo
    discovery.stop()

    # Step 6 — Enough shares successfully bheje?
    if successful_shares < threshold_k:
        raise RuntimeError(
            f"Only {successful_shares} shares sent — need at least {threshold_k}!"
        )

    print(f"✓ {successful_shares}/{shares_n} shares successfully sent!")

def receive_share(port: int) -> tuple:
    """
    Peer side pe share receive karta hai.
    Alice se connect hone ka wait karta hai.
    
    Input:  port → kaunse port pe sunna hai
    Output: (x, share_bytes) → share ka x coordinate aur actual share
    """

    # Step 1 — Server socket banao
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Step 2 — Port reuse karo (agar pehle se bind tha)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Step 3 — Port pe bind karo
    server.bind(("0.0.0.0", port))

    # Step 4 — Connections ke liye tayar ho jao
    server.listen(1)
    print(f"Port {port} pe sun raha hoon...")

    conn = None  # pehle None — finally mein check ke liye

    try:
        # Step 5 — Alice ka wait karo
        conn, addr = server.accept()
        print(f"Connected: {addr[0]}:{addr[1]}")

        # Step 6 — Alice ki public key receive karo
        msg_type, alice_public_key = recv_frame(conn)

        # Step 7 — Apni key pair generate karo
        channel = SecureChannel()
        my_public_key = channel.generate_key_pair()

        # Step 8 — Apni public key Alice ko bhejo
        send_frame(conn, "KEY", my_public_key)

        # Step 9 — Shared secret compute karo (ECDH)
        channel.compute_shared_secret(alice_public_key)

        # Step 10 — Encrypted share receive karo
        msg_type, encrypted_share = recv_frame(conn)

        # Step 11 — Decrypt karo
        combined = channel.decrypt_message(encrypted_share)

        # Step 12 — x aur share_bytes alag karo
        x = struct.unpack("B", combined[:1])[0]   # pehla byte = x
        share_bytes = combined[1:]                  # baaki = share

        print(f"✓ Share {x} received successfully!")
        return (x, share_bytes)

    except Exception as e:
        print(f"✗ Error receiving share: {e}")
        raise

    finally:
        # Hamesha close karo
        if conn is not None:
            conn.close()
        server.close()    