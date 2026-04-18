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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh

import crypto_utils as cu
import protocol as proto


def receive_loop(
    sock: socket.socket,
    session_key: bytes,
    stop_event: threading.Event,
) -> None:
    """Background thread: print incoming messages from the server."""
    while not stop_event.is_set():
        try:
            msg = proto.receive(sock) # acknowledge 
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

        if msg["type"] == proto.T_ERROR: # handling error from server
            print(f"\n[Server error] {msg.get('reason', '?')}")
            stop_event.set()
            break

        if msg["type"] != proto.T_MSG: # no error
            continue

        plaintext = cu.aes_decrypt(session_key, msg["nonce"], msg["ciphertext"])
        print(f"\n[Server] {plaintext.decode()}")
        print("You: ", end="", flush=True)


def run_client(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print(f"Connecting to {host}:{port}…")
        sock.connect((host, port)) # connect to the socket
        print("Connected.\n")

        # -------------------------------------------------------------- #
        # Handshake                                                        #
        # -------------------------------------------------------------- #
        
        # Step 1 – receive server's public key
        msg = proto.recieve_dh(sock)
        if msg["type"] != proto.T_HELLO:
            print(f"[!] Expected SALAM from server, got {msg['type']}")
            return

        loaded_server_public_key = serialization.load_pem_public_key(msg["server_public_bytes"])
        print("Received server public key.")

        pn = dh.DHParameterNumbers(msg["p"], msg["g"])
        client_parameters = pn.parameters()
        print("Generating DH key pair for client…")
        client_private_key = client_parameters.generate_private_key()
        client_public_key = client_private_key.public_key()
        print("Key pair ready.\n")

        client_public_bytes = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        client_shared_key = client_private_key.exchange(loaded_server_public_key)
        session_key = cu.generate_dh_keypair(client_shared_key)

        proto.send_client_params(sock, client_public_bytes)
        print("Session key established with Diffie-Hellman.")
        
        print("Handshake complete.\n")
        print("Type a message and press Enter to send.  Type 'quit' to exit.\n")


        

        # -------------------------------------------------------------- #
        # Start background receiver thread                                #
        # -------------------------------------------------------------- #
        stop_event = threading.Event() # create thread
        receiver = threading.Thread(  
            target=receive_loop, # thread function - loop (key-msg-sig-verify)
            args=(sock, session_key, stop_event), # loop args
            daemon=True, 
        )
        receiver.start() # start deamon

        # -------------------------------------------------------------- #
        # Interactive send loop                                          #
        # -------------------------------------------------------------- #
        try:
            while not stop_event.is_set():
                print("You: ", end="", flush=True) # user input
                line = input()

                if stop_event.is_set(): # check if server stops
                    break

                if line.strip().lower() == "quit": # client closed the connection
                    proto.send_error(sock, "Client disconnecting")
                    break

                if not line.strip(): # no input
                    continue

                nonce, ciphertext = cu.aes_encrypt(session_key, line.encode())
                proto.send_message(sock, nonce, ciphertext)

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
