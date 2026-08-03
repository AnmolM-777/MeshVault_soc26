import socket
import threading


class _MockPeer:

    def __init__(self, handler, name="mock-peer"):
        self.name = name
        self._handler = handler

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)

        self.ip, self.port = self._sock.getsockname()

        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return

        try:
            self._handler(conn)
        finally:
            conn.close()

    def as_peer_record(self):
        return {
            "name": self.name,
            "ip": self.ip,
            "port": self.port
        }

    def close(self):
        self._sock.close()
        self._thread.join(timeout=2)


# -------------------------------
# Handler
# -------------------------------

# object will be   peer = _MockPeer(my_handler)
# self._handler=my_handler


def my_handler(conn):
    print("Client Connected!")

    # recv() receives data from connected client
    data = conn.recv(1024)

    print("Received:", data.decode())

    conn.send(b"Hello Client")

    print("reply sent")


# -------------------------------
# Create Peer
# -------------------------------

peer = _MockPeer(my_handler)

print("\npeer record")
print(peer.as_peer_record())

# -------------------------------
# Create Client
# -------------------------------

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

print("\nconnecting client")

client.connect((peer.ip, peer.port))

client.send(b"Hello Server")

print(client.recv(1024).decode())

client.close()

peer.close()