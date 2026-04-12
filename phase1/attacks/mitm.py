"""
Attack simulation: Man-in-the-Middle (MITM) key substitution
=============================================================

Scenario
--------
Alice wants to establish an encrypted session with Bob.
Mallory (the attacker) sits between them on the network and intercepts
the HELLO messages, replacing each party's public key with her own.

    Alice ──(thinks she talks to Bob)──► Mallory ──(impersonates Alice)──► Bob

Result without defence
----------------------
- Alice encrypts the session key with Mallory's public key (not Bob's).
- Mallory decrypts it, reads/modifies all messages in both directions.
- Bob never knows he is not talking directly to Alice.

Defence demonstrated
--------------------
Comparing a public-key fingerprint (SHA-256 hash of the PEM) out-of-band
(e.g. by phone, QR code, or a PKI certificate) exposes the substitution
immediately — the fingerprint Alice sees does not match what Bob published.

Run:
    python -m attacks.mitm
    # or from the project root:
    python attacks/mitm.py
"""

import hashlib
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import crypto_utils as cu

RESET  = "\033[0m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"

def fingerprint(pem: bytes) -> str:
    """Return a short hex fingerprint of a PEM public key."""
    digest = hashlib.sha256(pem).hexdigest()
    # Format as colon-separated pairs like SSH does
    pairs = [digest[i:i+2] for i in range(0, 16, 2)]
    return ":".join(pairs) + "…"

def section(title: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*60}{RESET}\n")

def log(actor: str, msg: str, color: str = RESET) -> None:
    print(f"  {BOLD}{color}[{actor:^8}]{RESET}  {msg}")


def main() -> None:
    print(f"\n{BOLD}MITM Key-Substitution Attack Simulation{RESET}")
    print("=" * 60)

    # ------------------------------------------------------------------ #
    # Key generation for all three parties                                #
    # ------------------------------------------------------------------ #
    section("1 · Key Generation")

    alice_priv, alice_pub   = cu.generate_rsa_keypair()
    bob_priv,   bob_pub     = cu.generate_rsa_keypair()
    mallory_priv, mallory_pub = cu.generate_rsa_keypair()

    alice_pem   = cu.serialize_public_key(alice_pub)
    bob_pem     = cu.serialize_public_key(bob_pub)
    mallory_pem = cu.serialize_public_key(mallory_pub)

    log("Alice",   f"generated RSA-2048 key pair  fingerprint: {fingerprint(alice_pem)}",   GREEN)
    log("Bob",     f"generated RSA-2048 key pair  fingerprint: {fingerprint(bob_pem)}",     GREEN)
    log("Mallory", f"generated RSA-2048 key pair  fingerprint: {fingerprint(mallory_pem)}", RED)

    # ------------------------------------------------------------------ #
    # MITM intercepts HELLO messages and swaps public keys               #
    # ------------------------------------------------------------------ #
    section("2 · Handshake — Mallory intercepts and substitutes keys")

    log("Bob",     f"sends HELLO with real key    fingerprint: {fingerprint(bob_pem)}", GREEN)
    log("Mallory", f"intercepts Bob's HELLO …",                                         RED)
    log("Mallory", f"forwards HER key to Alice    fingerprint: {fingerprint(mallory_pem)}", RED)

    # Alice receives Mallory's key, believing it is Bob's
    alice_believes_is_bob_pem = mallory_pem
    alice_believes_is_bob_pub = cu.deserialize_public_key(alice_believes_is_bob_pem)

    log("Alice",   f"receives 'Bob' key           fingerprint: {fingerprint(alice_believes_is_bob_pem)}", YELLOW)

    # ------------------------------------------------------------------ #
    # Alice establishes a session key — but with Mallory                 #
    # ------------------------------------------------------------------ #
    section("3 · Session Key Exchange — Alice unknowingly trusts Mallory")

    session_key = cu.generate_aes_key()
    log("Alice", f"generated AES-256 session key: {session_key.hex()[:24]}…", GREEN)

    # Alice encrypts session key with what she thinks is Bob's key
    encrypted_for_mallory = cu.rsa_encrypt(alice_believes_is_bob_pub, session_key)
    log("Alice",   "encrypts session key with 'Bob' public key and sends it …", GREEN)

    # Mallory decrypts it with her own private key
    stolen_session_key = cu.rsa_decrypt(mallory_priv, encrypted_for_mallory)
    log("Mallory", f"decrypts session key!        {stolen_session_key.hex()[:24]}…", RED)

    keys_match = session_key == stolen_session_key
    print(f"\n  {BOLD}{RED}  ✗  Mallory recovered Alice's session key: {keys_match}{RESET}")

    # ------------------------------------------------------------------ #
    # Mallory can now read and forge every message                       #
    # ------------------------------------------------------------------ #
    section("4 · Message Interception — Mallory reads and modifies messages")

    original_message = "Transfer $500 to account 1234"
    nonce, ciphertext = cu.aes_encrypt(session_key, original_message.encode())
    signature = cu.sign(alice_priv, ciphertext)

    log("Alice",   f"sends encrypted message: '{original_message}'", GREEN)
    log("Mallory", "intercepts the ciphertext …",                     RED)

    decrypted_by_mallory = cu.aes_decrypt(stolen_session_key, nonce, ciphertext)
    log("Mallory", f"decrypts it: '{decrypted_by_mallory.decode()}'", RED)

    # Mallory forges a replacement message and re-encrypts
    forged_message = "Transfer $500 to account 9999"
    forged_nonce, forged_ct = cu.aes_encrypt(stolen_session_key, forged_message.encode())
    forged_sig = cu.sign(mallory_priv, forged_ct)   # signed with Mallory's key

    log("Mallory", f"forges message:  '{forged_message}'", RED)
    log("Bob",     f"receives:        '{cu.aes_decrypt(stolen_session_key, forged_nonce, forged_ct).decode()}'", YELLOW)

    # Bob verifies signature — but against whom?
    # Bob has received Alice's real key (Mallory forwarded it unmodified from Alice's HELLO)
    bob_verifies_with_alice_pub = cu.verify(alice_pub, forged_ct, forged_sig)
    log("Bob", f"signature check (Alice's key): {bob_verifies_with_alice_pub}  ← forged sig fails", YELLOW)

    # ------------------------------------------------------------------ #
    # Defence: fingerprint comparison                                     #
    # ------------------------------------------------------------------ #
    section("5 · Defence — Out-of-band fingerprint verification")

    print(f"  Alice compares the key fingerprint she received for 'Bob'")
    print(f"  against Bob's published fingerprint:\n")
    print(f"    Alice received:   {YELLOW}{fingerprint(alice_believes_is_bob_pem)}{RESET}")
    print(f"    Bob's real key:   {GREEN}{fingerprint(bob_pem)}{RESET}")

    attack_detected = alice_believes_is_bob_pem != bob_pem
    if attack_detected:
        print(f"\n  {BOLD}{GREEN}  ✓  MITM DETECTED — fingerprints do not match!{RESET}")
        print(f"     Alice aborts the session.")
    else:
        print(f"\n  {BOLD}{RED}  ✗  No substitution detected (fingerprints matched).{RESET}")

    section("Summary")
    print("  The RSA handshake alone does NOT prevent MITM if you blindly")
    print("  accept the peer's public key.  Authentication requires either:")
    print("    • Out-of-band fingerprint comparison (shown above)")
    print("    • A Certificate Authority (CA) signing the public key")
    print("    • A pre-shared key or Trust-On-First-Use (TOFU) model\n")


if __name__ == "__main__":
    main()
