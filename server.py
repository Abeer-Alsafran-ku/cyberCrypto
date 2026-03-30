"""
Encrypted messaging server.

Handshake (per client connection)
----------------------------------
1. Server  → HELLO  (server RSA public key)
2. Client  → HELLO  (client RSA public key)
3. Client  → SESSION_KEY  (AES-256 key encrypted with server's RSA public key)
4. Both sides are now ready to exchange AES-256-GCM + RSA-PSS signed messages.

Run:
    python server.py [--host HOST] [--port PORT]
"""

import argparse
import socket
import threading

import crypto_utils as cu
import protocol as proto


def handle_client(conn: socket.socket, addr: tuple, server_private_key, server_public_key_pem: bytes) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    print(f"[+] New connection from {peer}")

    try:
        # ------------------------------------------------------------------ #
        # Handshake                                                            #
        # ------------------------------------------------------------------ #

        # Step 1 – send our public key
        proto.send_hello(conn, server_public_key_pem)

        # Step 2 – receive client's public key
        msg = proto.receive(conn)
        if msg["type"] != proto.T_HELLO:
            proto.send_error(conn, "Expected HELLO")
            return
        client_public_key = cu.deserialize_public_key(msg["public_key"])
        print(f"[{peer}] Received client public key.")

        # Step 3 – receive AES session key (encrypted with our RSA public key)
        msg = proto.receive(conn)
        if msg["type"] != proto.T_SESSION_KEY:
            proto.send_error(conn, "Expected SESSION_KEY")
            return
        session_key = cu.rsa_decrypt(server_private_key, msg["encrypted_key"])
        print(f"[{peer}] Session key established (AES-256-GCM). Handshake complete.")

        # ------------------------------------------------------------------ #
        # Messaging loop                                                       #
        # ------------------------------------------------------------------ #
        print(f"[{peer}] Waiting for messages (type Ctrl-C to stop the server)…\n")

        while True:
            msg = proto.receive(conn)

            if msg["type"] == proto.T_ERROR:
                print(f"[{peer}] Client sent error: {msg.get('reason', '?')}")
                break

            if msg["type"] != proto.T_MSG:
                print(f"[{peer}] Unexpected message type: {msg['type']}")
                continue

            # Decrypt
            plaintext = cu.aes_decrypt(session_key, msg["nonce"], msg["ciphertext"])

            # Verify signature (signed over the raw ciphertext bytes)
            valid = cu.verify(client_public_key, msg["ciphertext"], msg["signature"])
            sig_status = "VALID" if valid else "INVALID ⚠"

            print(f"[{peer}] Message received | signature: {sig_status}")
            print(f"    {plaintext.decode()}")

            # Echo back an encrypted, signed reply
            reply_text = f"[Server echo] {plaintext.decode()}"
            nonce, ciphertext = cu.aes_encrypt(session_key, reply_text.encode())
            # Sign the raw ciphertext so the client can verify authenticity
            server_priv = server_private_key          # already in scope
            signature = cu.sign(server_priv, ciphertext)
            proto.send_message(conn, nonce, ciphertext, signature)

    except ConnectionError as exc:
        print(f"[{peer}] Connection closed: {exc}")
    except Exception as exc:
        print(f"[{peer}] Error: {exc}")
    finally:
        conn.close()
        print(f"[-] Disconnected: {peer}")


def run_server(host: str, port: int) -> None:
    print("Generating RSA-2048 key pair for server…")
    server_private_key, server_public_key = cu.generate_rsa_keypair()
    server_public_key_pem = cu.serialize_public_key(server_public_key)
    print("Key pair ready.\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        print(f"Server listening on {host}:{port}")
        print("Press Ctrl-C to stop.\n")

        try:
            while True:
                conn, addr = srv.accept()
                t = threading.Thread(
                    target=handle_client,
                    args=(conn, addr, server_private_key, server_public_key_pem),
                    daemon=True,
                )
                t.start()
        except KeyboardInterrupt:
            print("\nServer shutting down.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted messaging server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9000, help="Port (default: 9000)")
    args = parser.parse_args()
    run_server(args.host, args.port)


if __name__ == "__main__":
    main()
