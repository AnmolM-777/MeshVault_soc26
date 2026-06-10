"""
Network Transfer Layer.
Handles TCP connection management, message serialization, and framing.

Mentee D Deliverables:
- Weeks 1-2: Implement basic length-prefixed TCP socket framing to send and receive raw byte packets.
- Weeks 3-4: Complete TCP transmission wrapper, handling partial reads/writes and unexpected connection drops.
"""

def send_frame(sock, message_type: str, payload: bytes) -> None:
    """
    Prepends length headers and sends a framed message over a socket.
    
    Mentee D Weeks 1-2 Deliverable.
    """
    # TODO: Package message_type and payload into a framed structure and send
    raise NotImplementedError("send_frame has not been implemented yet.")

def recv_frame(sock) -> tuple:
    """
    Reads a length-prefixed framed message from a socket.
    
    Mentee D Weeks 1-2 Deliverable.
    """
    # TODO: Read size header and extract the message type and payload bytes
    raise NotImplementedError("recv_frame has not been implemented yet.")
