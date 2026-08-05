import socket
import struct
from crypto.sss import split_secret
from crypto.channel import SecureChannel
from network.discovery import PeerDiscovery
from network.transfer import send_frame, recv_frame

def execute_split(secret: bytes, threshold_k: int, shares_n: int) -> None:
    """
    Executes the secret split operation.
    """

    # Step 1 — Secret ko N shares mein split karo
    shares = split_secret(secret, threshold_k, shares_n)
    print(f"Secret split into {shares_n} shares with threshold {threshold_k}")

    # Step 2 — mDNS discovery object
    discovery = PeerDiscovery()

    # Pending queue (jo shares abhi tak successfully send nahi hue)
    pending_shares = list(shares)

    # Jin peers ko already share mil chuka hai
    used_peers = set()

    #succesful shares ka count
    successful_shares = 0

    # Maximum number of peer rediscovery attempts
    MAX_DISCOVERY_ATTEMPTS = 5
    discovery_attempts = 0

    # Maximum retry cycles for the current share
    MAX_SHARE_RETRY_CYCLES = 5
    share_retry_cycles = 0

    try:
        # Jab tak saare shares successfully send na ho jaye
        while pending_shares:

            # Fresh discovery
            peers = discovery.find_peers(timeout_seconds=5)

            # Already used peers hata do
            available_peers = [
                peer for peer in peers
                if peer["name"] not in used_peers
            ]
            # Koi peer available nahi
            if not available_peers:
                discovery_attempts += 1

                print(
                    f"No unused peers available. "
                    f"Discovery attempt {discovery_attempts}/{MAX_DISCOVERY_ATTEMPTS}"
                )

                if discovery_attempts >= MAX_DISCOVERY_ATTEMPTS:
                    raise RuntimeError(
                        "No new peers became available after multiple discovery attempts."
                    )
                
                continue

            # Queue ka first share
            x, share_bytes = pending_shares[0]

            share_sent = False

            # Available peers ko ek-ek karke try karo
            for peer in available_peers:

                sock = None

                try:

                    # -----------------------------
                    # TCP Connection
                    # -----------------------------
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    sock.connect((peer["ip"], peer["port"]))

                    # -----------------------------
                    # Secure Channel
                    # -----------------------------
                    channel = SecureChannel()

                    my_public_key = channel.generate_key_pair()

                    send_frame(sock, "KEY", my_public_key)

                    msg_type, peer_public_key = recv_frame(sock)

                    if msg_type != "KEY":
                        raise RuntimeError("Expected KEY message from peer")

                    channel.compute_shared_secret(peer_public_key)

                    # -----------------------------
                    # Encrypt Share
                    # -----------------------------
                    x_bytes = struct.pack("B", x)

                    combined = x_bytes + share_bytes

                    encrypted_share = channel.encrypt_message(combined)

                    send_frame(sock, "SHARE", encrypted_share)

                    print(
                        f"✓ Share {x} sent to "
                        f"{peer['name']} ({peer['ip']}:{peer['port']})"
                    )

                    # Share successfully send ho gaya and discovery attempt bhi rest kardiya finally
                    successful_shares += 1
                    discovery_attempts = 0
                    share_retry_cycles = 0

                    # Queue se remove
                    pending_shares.pop(0)

                    # Peer ko used mark karo
                    used_peers.add(peer["name"])

                    share_sent = True

                    break

                except ConnectionRefusedError:
                    print(f"⚠ {peer['name']} refused the connection.")

                except ConnectionResetError:
                    print(f"⚠ Connection lost with {peer['name']}.")

                except socket.timeout:
                    print(f"⚠ Connection to {peer['name']} timed out.")

                except OSError as e:
                    print(f"⚠ Network error with {peer['name']}: {e}")

                except Exception as e:
                    print(f"⚠ Unexpected error: {e}")    

                finally:

                    if sock is not None:
                        sock.close()

            # Agar kisi peer ko bhi send nahi hua
            # To next discovery me fir try karenge
            if not share_sent:

                share_retry_cycles += 1

                print(
                    f"Current share could not be delivered. "
                    f"Retry cycle {share_retry_cycles}/{MAX_SHARE_RETRY_CYCLES}. "
                    "Rediscovering peers..."
                    )

                if share_retry_cycles >= MAX_SHARE_RETRY_CYCLES:
                    raise RuntimeError(
                        "Current share could not be delivered after multiple retry cycles."
                    )

    finally:

        discovery.stop()

    # Threshold check
    if successful_shares < threshold_k:

        raise RuntimeError(
            f"Only {successful_shares} shares sent "
            f"(need at least {threshold_k})"
        )

    print(
        f"✓ Successfully sent "
        f"{successful_shares}/{shares_n} shares."
    )

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
        if msg_type != "SHARE":
            raise RuntimeError("Expected SHARE message")

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