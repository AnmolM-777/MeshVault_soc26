import struct


def _recv_exactly(sock, n: int) -> bytes:
    chunks = []
    remaining = n

    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError(
                f"Socket closed while expecting {remaining} more byte(s)."
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_frame(sock, message_type: str, payload: bytes) -> None:
    type_bytes = message_type.encode("utf-8")

    header = struct.pack("!I", len(type_bytes))
    payload_header = struct.pack("!I", len(payload))

    frame = header + type_bytes + payload_header + payload
    sock.sendall(frame)

    # TODO: Package message_type and payload into a framed structure and send
    # raise NotImplementedError("send_frame has not been implemented yet.")


def recv_frame(sock) -> tuple:

    type_len_bytes = _recv_exactly(sock, 4)
    (type_len,) = struct.unpack("!I", type_len_bytes)
    message_type = _recv_exactly(sock, type_len).decode("utf-8")

    payload_len_bytes = _recv_exactly(sock, 4)
    (payload_len,) = struct.unpack("!I", payload_len_bytes)
    payload = _recv_exactly(sock, payload_len)

    return message_type, payload

    # TODO: Read size header and extract the message type and payload bytes
    # raise NotImplementedError("recv_frame has not been implemented yet.")
