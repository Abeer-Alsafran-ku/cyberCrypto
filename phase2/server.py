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

import crypto_utils as cu # helpful functions for encryption and decryprion algorithms.
import protocol as proto  # wire protocol for the message over the internet.
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh


#def handle_client(conn: socket.socket, addr: tuple, server_private_key, server_public_key_pem: bytes) -> None:
def handle_client(conn: socket.socket, addr: tuple) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    print(f"[+] New connection from {peer}")
    
    # once the client has been connected over the socket the process begins.

    try:
        # ------------------------------------------------------------------ #
        # Handshake                                                          #
        # ------------------------------------------------------------------ #

        parameters = dh.generate_parameters(generator=2, key_size=2048)
        server_private_key = parameters.generate_private_key()
        server_public_key = server_private_key.public_key()
        parameters_numbers = parameters.parameter_numbers()
        p = parameters_numbers.p
        g = parameters_numbers.g
        
        # Step 1 – send our public key
        server_public_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        proto.send_server_params(conn, p, g, server_public_bytes)
        

        # Step 2 – receive client's public key
        msg = proto.recieve_dh(conn)
        if msg["type"] != proto.T_HELLO:
            proto.send_error(conn, "Expected SALAM")
            return
        
        loaded_client_public_key = serialization.load_pem_public_key(msg["client_public_bytes"])
        
        print(f"[{peer}] Received client public key.")

        server_shared_key = server_private_key.exchange(loaded_client_public_key)
        session_key = cu.generate_dh_keypair(server_shared_key)

        print(f"[{peer}] Session key established (Diffie Hellman). Handshake complete.")

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

            plaintext = cu.aes_decrypt(session_key, msg["nonce"], msg["ciphertext"])
            print(f"[{peer}] Message received")
            print(f"    {plaintext.decode()}")

            # Echo back an encrypted, signed reply
            reply_text = f"[Server echo] {plaintext.decode()}"
            nonce, ciphertext = cu.aes_encrypt(session_key, reply_text.encode())
            proto.send_message(conn, nonce, ciphertext)

    except ConnectionError as exc:
        print(f"[{peer}] Connection closed: {exc}")
    except Exception as exc:
        print(f"[{peer}] Error: {exc}")
    finally:
        conn.close()
        print(f"[-] Disconnected: {peer}")


def run_server(host: str, port: int) -> None:
  #  print("Generating RSA-2048 key pair for server…")
#    server_private_key, server_public_key = cu.generate_rsa_keypair() # generating the public and private key of server
 #   server_public_key_pem = cu.serialize_public_key(server_public_key) # serialize the public key
   # print("Key pair ready.\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv: # create the socket so client can listen to the server
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        srv.bind((host, port)) # set the port and host for the socket
        srv.listen(5) 
        print(f"Server listening on {host}:{port}")
        print("Press Ctrl-C to stop.\n")

        try:
            while True:
                conn, addr = srv.accept()
                t = threading.Thread(       # threading for handling multiple clients simoultancly.
                    target=handle_client,   # handle_client() for establishing the key (over a secure channel) and receiving messages. 
                    #args=(conn, addr, server_private_key, server_public_key_pem), # args of handle_client()
                    args=(conn, addr), # args of handle_client()
                    daemon=True, # spawn child
                )
                t.start() # start thread
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
