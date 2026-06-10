"""
Network Transfer Layer.
Handles TCP connection management, message serialization, and framing.
"""

def send_frame(sock, message_type: str, payload: bytes) -> None:
    """
    Prepends length headers and sends a framed message over a socket.
    
    Args:
        sock: The active socket object.
        message_type: Identifier for the type of message (e.g., 'KEY_EXCHANGE', 'SHARE').
        payload: Content body in bytes.
    """
    # TODO: Package message_type and payload into a framed structure and send
    raise NotImplementedError("send_frame has not been implemented yet.")

def recv_frame(sock) -> tuple[str, bytes]:
    """
    Reads a length-prefixed framed message from a socket.
    
    Args:
        sock: The active socket object.
        
    Returns:
        A tuple of (message_type, payload).
    """
    # TODO: Read size header and extract the message type and payload bytes
    raise NotImplementedError("recv_frame has not been implemented yet.")
