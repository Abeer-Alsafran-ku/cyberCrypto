"""
Wire protocol for the encrypted messaging application.

Every message sent over the TCP socket has the following structure:

    [ 4 bytes big-endian length ][ JSON payload (length bytes) ]

The JSON payload always contains a "type" field.  All binary fields are
base64-encoded so they survive JSON serialisation.

Message types
-------------
HELLO        – sent by both sides at the start of a session; carries the
               sender's RSA public key.
SESSION_KEY  – sent by the client after receiving the server's HELLO;
               carries the AES session key encrypted with the server's
               RSA public key.
MSG          – an encrypted, signed application message.
ERROR        – fatal error notice.
"""

import json
import struct
import base64
import socket

# Message type constants
T_HELLO       = "HELLO"
T_SESSION_KEY = "SESSION_KEY"
T_MSG         = "MSG"
T_ERROR       = "ERROR"

_HEADER_FMT  = "!I"          # 4-byte big-endian unsigned int
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)


# ---------------------------------------------------------------------------
# Low-level framing
# ---------------------------------------------------------------------------

def _send_raw(sock: socket.socket, data: bytes) -> None:
    """Send a length-prefixed frame."""
    header = struct.pack(_HEADER_FMT, len(data))
    sock.sendall(header + data)


def _recv_raw(sock: socket.socket) -> bytes:
    """Receive a length-prefixed frame, blocking until complete."""
    header = _recv_exactly(sock, _HEADER_SIZE)
    (length,) = struct.unpack(_HEADER_FMT, header)
    if length > 10 * 1024 * 1024:   # 10 MB sanity cap
        raise ValueError(f"Frame too large: {length} bytes")
    return _recv_exactly(sock, length)


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*, raising on connection close."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading")
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# High-level send helpers
# ---------------------------------------------------------------------------

def send_hello(sock: socket.socket, public_key_pem: bytes) -> None:
    """Send our RSA public key to the peer."""
    payload = {
        "type": T_HELLO,
        "public_key": base64.b64encode(public_key_pem).decode(),
    }
    _send_raw(sock, json.dumps(payload).encode())


def send_session_key(sock: socket.socket, encrypted_key: bytes) -> None:
    """Send the AES session key (RSA-encrypted) to the server."""
    payload = {
        "type": T_SESSION_KEY,
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
    }
    _send_raw(sock, json.dumps(payload).encode())


def send_message(
    sock: socket.socket,
    nonce: bytes,
    ciphertext: bytes,
    signature: bytes,
) -> None:
    """Send an encrypted, signed message."""
    payload = {
        "type": T_MSG,
        "nonce":      base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "signature":  base64.b64encode(signature).decode(),
    }
    _send_raw(sock, json.dumps(payload).encode())


def send_error(sock: socket.socket, reason: str) -> None:
    """Send a fatal error message."""
    payload = {"type": T_ERROR, "reason": reason}
    _send_raw(sock, json.dumps(payload).encode())


# ---------------------------------------------------------------------------
# High-level receive helper
# ---------------------------------------------------------------------------

def receive(sock: socket.socket) -> dict:
    """
    Receive the next message from *sock*.

    Returns a plain dict with a guaranteed "type" key.  Binary fields are
    already decoded back to *bytes*.
    """
    raw = _recv_raw(sock)
    msg = json.loads(raw.decode())

    # Decode base64 binary fields in-place
    for field in ("public_key", "encrypted_key", "nonce", "ciphertext", "signature"):
        if field in msg:
            msg[field] = base64.b64decode(msg[field])

    return msg
