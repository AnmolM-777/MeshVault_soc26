import pytest
import struct
from network.transfer import _recv_exactly, recv_frame, send_frame



#a fake socket is created to test the functions
#used to test send_frame and recv_frame when the frame is ready and just to check recv
#internally the recv data is stored in one continuous memory
class FakeSocket:
    def __init__(self, recv_data: bytes = b""):
        self.sent = b""
        self._buffer = recv_data
 
    def sendall(self, data: bytes) -> None:
        self.sent += data
 
    def recv(self, n: int) -> bytes:
        chunk = self._buffer[:n]
        self._buffer = self._buffer[len(chunk):]
        return chunk


#used to test the recv_exactly 
#internally the recv data is stored in small packet like envelops 
class ChunkedSocket:

    def __init__(self, recv_chunks):
        self.sent = b""
        self._recv_chunks = list(recv_chunks)
 
    def sendall(self, data: bytes) -> None:
        self.sent += data
 
    def recv(self, n: int) -> bytes:
        if not self._recv_chunks:
            return b""
        chunk = self._recv_chunks.pop(0)
        return chunk[:n]



#used to test integration test means to test send_frame and recv_frame together
class LoopbackSocket:
 
    def __init__(self):
        self._buffer = b""
 
    def sendall(self, data: bytes) -> None:
        self._buffer += data
 
    def recv(self, n: int) -> bytes:
        chunk = self._buffer[:n]
        self._buffer = self._buffer[len(chunk):]
        return chunk



def test_send_frame():
    sock = FakeSocket()  # no recv data needed; this test only exercises sendall()
    message_type = "hello"
    payload = b"world"
 
    send_frame(sock, message_type, payload)
 
    type_bytes = message_type.encode("utf-8")
    header = struct.pack("!I", len(type_bytes))
    payload_header = struct.pack("!I", len(payload))
    frame = header + type_bytes + payload_header + payload
    
    expected = (
        struct.pack("!I", len(type_bytes))
        + type_bytes
        + struct.pack("!I", len(payload))
        + payload
    )
 
    assert sock.sent == expected
    print("Type Length Header:", header)
    print("Type Bytes:", type_bytes)
    
    print("Payload Length Header:", payload_header)
    print("Payload:", payload)
    print("Complete Frame:", frame)



#This test verifies that recv_frame() correctly reads a framed message from a socket and reconstructs the original message type and payload."
def test_recv_frame():
    message_type = "\0"
    payload = b"payload-data"
    type_bytes = message_type.encode("utf-8")
 
    frame = (
        struct.pack("!I", len(type_bytes))
        + type_bytes
        + struct.pack("!I", len(payload))
        + payload
    )
 
    sock = FakeSocket(recv_data=frame)
 
    recv_type, recv_payload = recv_frame(sock)
    print("Received Type:", recv_type)
    print("Received Payload:", recv_payload)
 
    assert recv_type == message_type
    print("sent Message Type:", message_type)
    print("sent Payload:", payload)
    print("Frame:", frame)
   



def test_recv_exactly():
    print("hello world 1")
    data = b"abcdefghij"

    print("hello world 2")
    
    sock = ChunkedSocket(recv_chunks=[b"ab", b"cde", b"fg", b"hij"])
 
    print("hello world 3")
    result = _recv_exactly(sock, len(data))
 
    print("hello world 4")
    assert result == data
 
 
def test_recv_exactly_connection_closed():
    sock = ChunkedSocket(recv_chunks=[b"ab", b""])
 
    with pytest.raises(ConnectionError):
        _recv_exactly(sock, 10)


def test_send_receive_integration():
    sock = LoopbackSocket()
    message_type = "greeting"
    payload = b"hello there, this is a test payload"

    print("Before sending:")
    print("Message Type:", message_type)
    print("Payload:", payload)
 
    send_frame(sock, message_type, payload)

    print("\nFrame sent successfully.\n")
    recv_type, recv_payload = recv_frame(sock)

    print("After receiving:")
    print("Received Type:", recv_type)
    print("Received Payload:", recv_payload)
 
    assert recv_type == message_type
    assert recv_payload == payload



