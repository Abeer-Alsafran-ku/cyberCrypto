"""Wire protocol helpers for the encrypted messaging application."""

import json
import struct
import base64
import socket

# Message type constants
T_HELLO = "SALAM"
T_MSG = "ABEER"
T_ERROR = "ERROR"
T_KEY_METHOD = "KEY_METHOD"  # Indicates which key exchange method to use
T_RANDOM_PRIME = "RANDOM_PRIME"  # For random prime key exchange
T_TEST_CASE = "TEST_CASE"

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
    if length > 100 * 1024 * 1024:   # 100 MB sanity cap
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

def send_key_method(sock: socket.socket, method: str) -> None:
    """Send the key exchange method to the peer (DH or RANDOM_PRIME)."""
    payload = {
        "type": T_KEY_METHOD,
        "method": method,
    }
    _send_raw(sock, json.dumps(payload).encode())


def send_test_case(sock: socket.socket, case_id: int, name: str) -> None:
    """Send the selected test-case metadata to the peer."""
    payload = {
        "type": T_TEST_CASE,
        "case_id": case_id,
        "name": name,
    }
    _send_raw(sock, json.dumps(payload).encode())


def send_random_prime_value(sock: socket.socket, prime_bytes: bytes, bit_length: int) -> None:
    """Send a random prime number as bytes to the client."""
    payload = {
        "type": T_RANDOM_PRIME,
        "prime_bytes": base64.b64encode(prime_bytes).decode(),
        "bit_length": bit_length,
    }
    _send_raw(sock, json.dumps(payload).encode())


def send_random_prime(sock: socket.socket, encrypted_prime: bytes) -> None:
    """Send a random prime (encrypted) to establish session key."""
    payload = {
        "type": T_RANDOM_PRIME,
        "encrypted_prime": base64.b64encode(encrypted_prime).decode(),
    }
    _send_raw(sock, json.dumps(payload).encode())

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

def send_client_params(sock: socket.socket, client_public_bytes: bytes, rsa:bool) -> None:
    """Send the client DH public key to the server."""
    if rsa:
        payload = {
        "type": T_HELLO,
        "rsa_client_public_key_pem": base64.b64encode(client_public_bytes).decode(),
    }
    else:            
        payload = {
            "type": T_HELLO,
            "client_public_bytes": base64.b64encode(client_public_bytes).decode(),
        }
        
    _send_raw(sock, json.dumps(payload).encode())


def recieve_dh(sock: socket.socket) -> dict:
    """Receive a DH handshake message."""
    raw = _recv_raw(sock)
    msg = json.loads(raw.decode())

    for field in ("server_public_bytes", "client_public_bytes","rsa_client_public_key_pem"):
        if field in msg:
            msg[field] = base64.b64decode(msg[field])

    return msg

def send_message(
    sock: socket.socket,
    nonce: bytes,
    ciphertext: bytes,
    sig: bytes | None,
    hmac_msg: bytes | None,
) -> None:
    """Send an encrypted message."""
    payload = {
        "type": T_MSG,
        "nonce":      base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    if sig is not None:
        payload["sig"] = base64.b64encode(sig).decode()
    if hmac_msg is not None:
        payload["hmac_msg"] = base64.b64encode(hmac_msg).decode()
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

    for field in ("public_key", "nonce", "ciphertext", "sig", "encrypted_prime", "hmac_msg", "prime_bytes"):
        if field in msg:
            msg[field] = base64.b64decode(msg[field])

    return msg
