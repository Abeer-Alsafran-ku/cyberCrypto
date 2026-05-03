import argparse
import socket
import threading
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh

import crypto_utils as cu
import protocol as proto


TEST_CASES = {
    1: {
        "name": "No Diffie-Hellman key exchange (Random Prime) | Attack: Brute force",
        "use_dh": False,
        "use_signature": True,
        "use_hmac": True,
        "attack": "brute_force",
    },
    2: {
        "name": "HMAC Verification | Attack: Message tampering",
        "use_dh": True,
        "use_signature": True,
        "use_hmac": True,
        "attack": "tamper_hmac",
    },
    3: {
        "name": "DS Verification | Attack: MITM",
        "use_dh": True,
        "use_signature": True,
        "use_hmac": True,
        "attack": "tamper_signature",
    },
    4: {
        "name": "No DS and No HMAC",
        "use_dh": True,
        "use_signature": False,
        "use_hmac": False,
        "attack": "none",
    },
}


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
        handshake_start = time.perf_counter()

        # -------------------------------------------------------------- #
        # Receive key exchange method from server                         #
        # -------------------------------------------------------------- #
        msg = proto.receive(sock)
        if msg["type"] != proto.T_KEY_METHOD:
            print(f"[!] Expected KEY_METHOD from server, got {msg['type']}")
            return

        case_msg = proto.receive(sock)
        if case_msg["type"] != proto.T_TEST_CASE:
            print(f"[!] Expected TEST_CASE from server, got {case_msg['type']}")
            return

        case_id = case_msg["case_id"]
        scenario = TEST_CASES.get(case_id)
        if scenario is None:
            print(f"[!] Unsupported test case from server: {case_id}")
            return
        
        use_dh = msg.get("method") == "DH"
        print(f"Server selected: {msg.get('method')} key exchange\n")
        print(f"Test case {case_id}: {scenario['name']}\n")

        if use_dh:
            # ------------------------------------------------------------------ #
            # Handshake By DH                                                    #
            # ------------------------------------------------------------------ #
            
            # \\ Step 1 – receive server's public key \\
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

            proto.send_client_params(sock, client_public_bytes, rsa= False)
            print("Session key established with Diffie-Hellman.")

        else:
            # ------------------------------------------------------------------ #
            # Handshake using Random Prime                                       #
            # ------------------------------------------------------------------ #
            print("Server is using Random Prime key exchange")
            print("Waiting to receive session key from server…")
            
            # Receive the random prime from server
            msg = proto.receive(sock)
            if msg["type"] != proto.T_RANDOM_PRIME:
                print(f"[!] Expected RANDOM_PRIME from server, got {msg['type']}")
                return
            
            random_prime_bytes = msg.get("prime_bytes")
            if random_prime_bytes is None:
                print("[!] Server did not send a valid prime number")
                return
                
            prime_bits = msg.get("bit_length", len(random_prime_bytes) * 8)
            random_prime = int.from_bytes(random_prime_bytes, byteorder="big")
            print(f"Received random prime from server ({prime_bits} bits).")
            session_key = cu.derive_session_key_from_prime(random_prime)
            print("Session key established with Random Prime.")
        
        print("Handshake complete.\n")
        handshake_elapsed = time.perf_counter() - handshake_start
        print(f"Handshake time: {handshake_elapsed:.6f} seconds\n")


        # ------------------------------------------------------------------ #
        # RSA KEY FOR SIG                                                    #
        # ------------------------------------------------------------------ #
        
        # \\ Send to the server the client public key so that he can verify the signiture \\
        print("Generating RSA-2048 key pair for client…")
        rsa_client_private_key, rsa_client_public_key = cu.generate_rsa_keypair() # create keys
        rsa_client_public_key_pem = cu.serialize_public_key(rsa_client_public_key) # serialize them
        # \\ send to server rsa public key for verification \\
        proto.send_client_params(sock, rsa_client_public_key_pem,rsa=True)

        

        print("Type a message and press Enter to send.  Type 'quit' to exit.\n")
        print("For multi-line input, type '/multi', enter your text, then '/send' on its own line.\n")
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
                print("You: ", end="", flush=True)
                line = input()

                if stop_event.is_set():
                    break

                command = line.strip().lower()
                if command == "quit":
                    proto.send_error(sock, "Client disconnecting")
                    return

                if command == "/send":
                    print("[!] '/send' is only valid after '/multi'.")
                    continue

                if command == "/multi":
                    print("Enter multi-line message. Type '/send' on its own line when finished.")
                    lines: list[str] = []

                    while not stop_event.is_set():
                        line = input()

                        if stop_event.is_set():
                            break

                        if line.strip() == "/send":
                            break

                        lines.append(line)

                    if stop_event.is_set():
                        break

                    if not lines:
                        print("[!] Empty multi-line message discarded.")
                        continue

                    message_text = "\n".join(lines)
                else:
                    if not line.strip():
                        continue
                    message_text = line


                # \\ Encrypt the MSG : Using AES Cipher Algorithm \\
                message_start = time.perf_counter()
                plaintext_bytes = message_text.encode()
                nonce, ciphertext = cu.aes_encrypt(session_key, plaintext_bytes)
                
                hmac_msg = None
                if scenario["use_hmac"]:
                    hmac_msg = cu.generate_hmac(session_key, plaintext_bytes)

                sig = None
                if scenario["use_signature"]:
                    sig = cu.sign(rsa_client_private_key, ciphertext)

                if scenario["attack"] == "tamper_signature" and sig is not None:
                    sig = sig + b"!"
                    print("[Attack] MITM simulation: altered digital signature bytes.")
                elif scenario["attack"] == "tamper_hmac" and hmac_msg is not None:
                    hmac_msg = hmac_msg + b"!"
                    print("[Attack] Message tampering simulation: altered HMAC bytes.")
                
                # \\ Send the MSG with Digital Sig \\
                proto.send_message(sock, nonce,ciphertext, sig, hmac_msg)
                elapsed = time.perf_counter() - message_start
                print(f"[Timing] Message packaging and attack simulation: {elapsed:.6f} seconds")

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
