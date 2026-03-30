"""
Encrypted messaging client.

Handshake
---------
1. Receive server HELLO (server RSA public key).
2. Send own HELLO (client RSA public key).
3. Generate AES-256 session key, encrypt with server's public key, send SESSION_KEY.
4. Exchange encrypted, signed messages interactively.

Run:
    python client.py [--host HOST] [--port PORT]
"""

import argparse
import socket
import threading

import crypto_utils as cu
import protocol as proto


def receive_loop(
    sock: socket.socket,
    session_key: bytes,
    server_public_key,
    stop_event: threading.Event,
) -> None:
    """Background thread: print incoming messages from the server."""
    while not stop_event.is_set():
        try:
            msg = proto.receive(sock)
        except ConnectionError:
            if not stop_event.is_set():
                print("\n[!] Server closed the connection.")
            stop_event.set()
            break
        except Exception as exc:
            if not stop_event.is_set():
                print(f"\n[!] Receive error: {exc}")
            stop_event.set()
            break

        if msg["type"] == proto.T_ERROR:
            print(f"\n[Server error] {msg.get('reason', '?')}")
            stop_event.set()
            break

        if msg["type"] != proto.T_MSG:
            continue

        # Decrypt
        plaintext = cu.aes_decrypt(session_key, msg["nonce"], msg["ciphertext"])

        # Verify signature
        valid = cu.verify(server_public_key, msg["ciphertext"], msg["signature"])
        sig_status = "valid" if valid else "INVALID ⚠"

        print(f"\n[Server | sig:{sig_status}] {plaintext.decode()}")
        print("You: ", end="", flush=True)


def run_client(host: str, port: int) -> None:
    print("Generating RSA-2048 key pair for client…")
    client_private_key, client_public_key = cu.generate_rsa_keypair()
    client_public_key_pem = cu.serialize_public_key(client_public_key)
    print("Key pair ready.\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print(f"Connecting to {host}:{port}…")
        sock.connect((host, port))
        print("Connected.\n")

        # -------------------------------------------------------------- #
        # Handshake                                                        #
        # -------------------------------------------------------------- #

        # Step 1 – receive server's public key
        msg = proto.receive(sock)
        if msg["type"] != proto.T_HELLO:
            print(f"[!] Expected HELLO from server, got {msg['type']}")
            return
        server_public_key = cu.deserialize_public_key(msg["public_key"])
        print("Received server public key.")

        # Step 2 – send our public key
        proto.send_hello(sock, client_public_key_pem)

        # Step 3 – generate session key, encrypt with server's public key, send
        session_key = cu.generate_aes_key()
        encrypted_session_key = cu.rsa_encrypt(server_public_key, session_key)
        proto.send_session_key(sock, encrypted_session_key)
        print("Session key sent (encrypted with server's RSA public key).")
        print("Handshake complete — all messages are AES-256-GCM encrypted & RSA-PSS signed.\n")
        print("Type a message and press Enter to send.  Type 'quit' to exit.\n")

        # -------------------------------------------------------------- #
        # Start background receiver thread                                #
        # -------------------------------------------------------------- #
        stop_event = threading.Event()
        receiver = threading.Thread(
            target=receive_loop,
            args=(sock, session_key, server_public_key, stop_event),
            daemon=True,
        )
        receiver.start()

        # -------------------------------------------------------------- #
        # Interactive send loop                                           #
        # -------------------------------------------------------------- #
        try:
            while not stop_event.is_set():
                print("You: ", end="", flush=True)
                line = input()

                if stop_event.is_set():
                    break

                if line.strip().lower() == "quit":
                    proto.send_error(sock, "Client disconnecting")
                    break

                if not line.strip():
                    continue

                # Encrypt
                nonce, ciphertext = cu.aes_encrypt(session_key, line.encode())
                # Sign the raw ciphertext
                signature = cu.sign(client_private_key, ciphertext)
                proto.send_message(sock, nonce, ciphertext, signature)

        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting…")
        finally:
            stop_event.set()

    print("Disconnected.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted messaging client")
    parser.add_argument("--host", default="127.0.0.1", help="Server address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9000, help="Server port (default: 9000)")
    args = parser.parse_args()
    run_client(args.host, args.port)


if __name__ == "__main__":
    main()
