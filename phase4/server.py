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
import sys
import time

import crypto_utils as cu # helpful functions for encryption and decryprion algorithms.
import protocol as proto  # wire protocol for the message over the internet.
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh


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


def handle_client(conn: socket.socket, addr: tuple, test_case_id: int, prime_bits: int) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    print(f"[+] New connection from {peer}")
    scenario = TEST_CASES[test_case_id]
    use_dh = scenario["use_dh"]
    
    # \\ once the client has been connected over the socket the process begins. \\

    try:
        handshake_start = time.perf_counter()
        # ------------------------------------------------------------------ #
        # Inform client of key exchange method                              #
        # ------------------------------------------------------------------ #
        method = "DH" if use_dh else "RANDOM_PRIME"
        proto.send_key_method(conn, method)
        proto.send_test_case(conn, test_case_id, scenario["name"])
        print(f"[{peer}] Using {method} key exchange")
        print(f"[{peer}] Test case {test_case_id}: {scenario['name']}")

        if use_dh:
            # ------------------------------------------------------------------ #
            # Handshake by Diffie Hellman                                        #
            # ------------------------------------------------------------------ #

            parameters = dh.generate_parameters(generator=2, key_size=2048)
            server_private_key = parameters.generate_private_key()
            server_public_key = server_private_key.public_key()
            parameters_numbers = parameters.parameter_numbers()
            p = parameters_numbers.p
            g = parameters_numbers.g
            
            # \\ Step 1 – send our public key \\
            server_public_bytes = server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            proto.send_server_params(conn, p, g, server_public_bytes)
            

            # \\ Step 2 – receive client's public key \\
            msg = proto.recieve_dh(conn)
            if msg["type"] != proto.T_HELLO:
                proto.send_error(conn, "Expected SALAM")
                return
            
            loaded_client_public_key = serialization.load_pem_public_key(msg["client_public_bytes"])
            
            print(f"[{peer}] Received client public key.")

            server_shared_key = server_private_key.exchange(loaded_client_public_key)
            session_key = cu.generate_dh_keypair(server_shared_key)

            print(f"[{peer}] Session key established (Diffie Hellman). Handshake complete.")

        else:
            # ------------------------------------------------------------------ #
            # Handshake using Random Prime                                       #
            # ------------------------------------------------------------------ #
            # Generate a random prime and send it to client
            print(f"[{peer}] Generating random prime for session key...")
            random_prime = cu.generate_random_prime(prime_bits)
            prime_bytes = cu.int_to_bytes(random_prime)
            
            # Send the prime to client
            proto.send_random_prime_value(conn, prime_bytes, random_prime.bit_length())
            print(f"[{peer}] Sent random prime to client ({random_prime.bit_length()} bits).")
            
            session_key = cu.derive_session_key_from_prime(random_prime)
            
            print(f"[{peer}] Session key established (Random Prime). Handshake complete.")

            if scenario["attack"] == "brute_force":
                attack_result = cu.brute_force_demo(session_key)
                print(
                    f"[{peer}] Brute-force demo recovered the first {attack_result['bits']} bits "
                    f"in {attack_result['elapsed']:.6f} seconds after {attack_result['attempts']} attempts."
                )
                print(
                    f"[{peer}] Estimated time for full 256-bit brute force: "
                    f"{attack_result['estimated_full_seconds']:.3e} seconds."
                )

        handshake_elapsed = time.perf_counter() - handshake_start
        print(f"[{peer}] Handshake time: {handshake_elapsed:.6f} seconds")

        # ------------------------------------------------------------------ #
        # Receive Client RSA pub for verification                            #
        # ------------------------------------------------------------------ #
        msg = proto.recieve_dh(conn)
        if msg["type"] != proto.T_HELLO:
            proto.send_error(conn, "Expected SALAM")
            return
        
        rsa_client_public_key = serialization.load_pem_public_key(msg["rsa_client_public_key_pem"])
        

        # ------------------------------------------------------------------ #
        # Messaging loop                                                     #
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

            message_start = time.perf_counter()

            if scenario["use_signature"]:
                signature = msg.get("sig")
                if signature is None:
                    print(f"[{peer}] Missing digital signature.")
                    continue
                received_from_client = cu.verify(rsa_client_public_key, msg["ciphertext"], signature)
                if not received_from_client:
                    print("Sender is not verified : Probability of Identity Theft / MITM!\n")
                    print(f"[{peer}] Verification time: {time.perf_counter() - message_start:.6f} seconds")
                    continue

            plaintext = cu.aes_decrypt(session_key, msg["nonce"], msg["ciphertext"])

            if scenario["use_hmac"]:
                hmac_msg = msg.get("hmac_msg")
                if hmac_msg is None:
                    print(f"[{peer}] Missing HMAC.")
                    continue
                hmac_auth = cu.verify_hmac(session_key, plaintext, hmac_msg)
                if not hmac_auth:
                    print("Message is not verified : Probability of message tampering!\n")
                    print(f"[{peer}] Verification time: {time.perf_counter() - message_start:.6f} seconds")
                    continue

            print(f"[{peer}] Message received and verified")
            print(f"    {plaintext.decode()}")
            print(f"[{peer}] Verification time: {time.perf_counter() - message_start:.6f} seconds")

    except ConnectionError as exc:
        print(f"[{peer}] Connection closed: {exc}")
    except Exception as exc:
        print(f"[{peer}] Error: {exc}")
    finally:
        conn.close()
        print(f"[-] Disconnected: {peer}")


def run_server(host: str, port: int, test_case_id: int, prime_bits: int) -> None:

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:  
        #// create the socket so client can listen to the server //
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
                    args=(conn, addr, test_case_id, prime_bits), # args of handle_client()
                    daemon=True, # spawn child
                )
                t.start() # start thread
        except KeyboardInterrupt:
            print("\nServer shutting down.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted messaging server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9000, help="Port (default: 9000)")
    parser.add_argument("--test-case", type=int, choices=sorted(TEST_CASES), help="Select a predefined test case")
    parser.add_argument("--prime-bits", type=int, default=2048, help="Prime size for test case 1 (default: 2048)")
    args = parser.parse_args()

    if args.test_case:
        test_case_id = args.test_case
    else:
        print("\n" + "="*60)
        print("SELECT TEST CASE")
        print("="*60)
        for case_id, scenario in TEST_CASES.items():
            print(f"{case_id}. {scenario['name']}")
        print("="*60)
        
        while True:
            choice = input("Enter test case number [default: 1]: ").strip()
            if choice == "":
                test_case_id = 1
                break
            if choice.isdigit() and int(choice) in TEST_CASES:
                test_case_id = int(choice)
                break
            print("Invalid choice. Please enter 1, 2, 3, or 4.")

    selected = TEST_CASES[test_case_id]
    print(f"→ Using test case {test_case_id}: {selected['name']}\n")
    if test_case_id == 1:
        if args.prime_bits < 256:
            raise ValueError("--prime-bits must be at least 256")
        print(f"→ Random-prime size: {args.prime_bits} bits\n")

    run_server(args.host, args.port, test_case_id, args.prime_bits)


if __name__ == "__main__":
    main()
