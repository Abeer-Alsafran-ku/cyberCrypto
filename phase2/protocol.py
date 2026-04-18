"""Wire protocol helpers for the encrypted messaging application."""

import json
import struct
import base64
import socket

# Message type constants
T_HELLO = "SALAM"
T_MSG = "ABEER"
T_ERROR = "ERROR"

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
    """Send a generic public key to the peer."""
    payload = {
        "type": T_HELLO,
        "public_key": base64.b64encode(public_key_pem).decode(),
    }
    _send_raw(sock, json.dumps(payload).encode())

def send_server_params(sock: socket.socket, p: int, g: int, server_public_bytes: bytes) -> None:
    """Send DH parameters and the server public key to the client."""
    payload = {
        "type": T_HELLO,
        "p": p,
        "g": g,
        "server_public_bytes": base64.b64encode(server_public_bytes).decode(),
    }
    _send_raw(sock, json.dumps(payload).encode())

def send_client_params(sock: socket.socket, client_public_bytes: bytes) -> None:
    """Send the client DH public key to the server."""
    payload = {
        "type": T_HELLO,
        "client_public_bytes": base64.b64encode(client_public_bytes).decode(),
    }
    _send_raw(sock, json.dumps(payload).encode())


def recieve_dh(sock: socket.socket) -> dict:
    """Receive a DH handshake message."""
    raw = _recv_raw(sock)
    msg = json.loads(raw.decode())

    for field in ("server_public_bytes", "client_public_bytes"):
        if field in msg:
            msg[field] = base64.b64decode(msg[field])

    return msg

def send_message(
    sock: socket.socket,
    nonce: bytes,
    ciphertext: bytes,
) -> None:
    """Send an encrypted message."""
    payload = {
        "type": T_MSG,
        "nonce":      base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
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

    Returns a plain dict with a guaranteed "type" key.
    """
    raw = _recv_raw(sock)
    msg = json.loads(raw.decode())

    for field in ("public_key", "nonce", "ciphertext"):
        if field in msg:
            msg[field] = base64.b64decode(msg[field])

    return msg
