"""
Attack simulation: Replay attack
=================================

Scenario
--------
Alice sends Bob a legitimate encrypted, signed message.
Mallory records the raw bytes off the wire.
Later, Mallory re-sends the exact same bytes to Bob.

Phase 1 — No defence
---------------------
Because AES-256-GCM only guarantees confidentiality and integrity for the
*content*, it does not prevent the same valid ciphertext from being accepted
twice.  The signature also stays valid (it was legitimately produced by Alice).
Bob receives the replayed message and cannot tell it is not fresh.

Phase 2 — Defence: sequence numbers
------------------------------------
Alice includes a monotonically increasing sequence number *inside* the
plaintext before encrypting.  Bob tracks the last seen sequence number and
rejects any message whose number is not strictly greater than the previous one.
Because the sequence number is inside the AES-GCM envelope, Mallory cannot
change it without breaking the authentication tag.

Run:
    python -m attacks.replay
    # or from the project root:
    python attacks/replay.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import crypto_utils as cu

RESET = "\033[0m"
RED   = "\033[31m"
GREEN = "\033[32m"
YELLOW= "\033[33m"
CYAN  = "\033[36m"
BOLD  = "\033[1m"

def section(title: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*60}{RESET}\n")

def log(actor: str, msg: str, color: str = RESET) -> None:
    print(f"  {BOLD}{color}[{actor:^8}]{RESET}  {msg}")


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def make_message(session_key: bytes, private_key, text: str):
    """Encrypt and sign a plaintext message. Returns (nonce, ciphertext, sig)."""
    nonce, ciphertext = cu.aes_encrypt(session_key, text.encode())
    signature = cu.sign(private_key, ciphertext)
    return nonce, ciphertext, signature


def receive_message(
    session_key: bytes,
    public_key,
    nonce: bytes,
    ciphertext: bytes,
    signature: bytes,
) -> tuple[str, bool]:
    """
    Decrypt and verify a message (no replay protection).

    Returns (plaintext, sig_valid).
    """
    plaintext = cu.aes_decrypt(session_key, nonce, ciphertext)
    sig_valid = cu.verify(public_key, ciphertext, signature)
    return plaintext.decode(), sig_valid


def receive_message_with_seqnum(
    session_key: bytes,
    public_key,
    nonce: bytes,
    ciphertext: bytes,
    signature: bytes,
    last_seq: int,
) -> tuple[str | None, bool, int]:
    """
    Decrypt, verify, and enforce sequence-number ordering.

    Returns (plaintext_or_None, sig_valid, new_last_seq).
    Replay is detected when seq <= last_seq.
    """
    plaintext_bytes = cu.aes_decrypt(session_key, nonce, ciphertext)
    sig_valid = cu.verify(public_key, ciphertext, signature)

    # Plaintext format: "<seq>:<message>"
    raw = plaintext_bytes.decode()
    seq_str, _, text = raw.partition(":")
    seq = int(seq_str)

    if seq <= last_seq:
        return None, sig_valid, last_seq   # REPLAY detected

    return text, sig_valid, seq


def main() -> None:
    print(f"\n{BOLD}Replay Attack Simulation{RESET}")
    print("=" * 60)

    # ------------------------------------------------------------------ #
    # Setup                                                               #
    # ------------------------------------------------------------------ #
    section("1 · Setup — honest session established")

    alice_priv, alice_pub = cu.generate_rsa_keypair()
    _bob_priv,  bob_pub   = cu.generate_rsa_keypair()
    session_key = cu.generate_aes_key()

    log("Alice", "RSA-2048 key pair generated", GREEN)
    log("Bob",   "RSA-2048 key pair generated", GREEN)
    log("",      f"Shared AES-256 session key: {session_key.hex()[:24]}…", GREEN)

    # ------------------------------------------------------------------ #
    # Phase 1: No replay defence                                          #
    # ------------------------------------------------------------------ #
    section("2 · Phase 1: Replay with no defence")

    message_text = "Approve payment of $1,000"
    nonce, ciphertext, signature = make_message(session_key, alice_priv, message_text)

    log("Alice",   f"sends:    '{message_text}'", GREEN)
    log("Mallory", "records the encrypted frame (nonce + ciphertext + signature)…", RED)

    # Bob receives the legitimate message
    pt, valid = receive_message(session_key, alice_pub, nonce, ciphertext, signature)
    log("Bob",     f"receives: '{pt}'  |  sig valid: {valid}", GREEN)

    # Mallory replays the exact same bytes 2 more times
    print()
    for attempt in range(1, 3):
        pt, valid = receive_message(session_key, alice_pub, nonce, ciphertext, signature)
        log("Mallory", f"replays message (attempt {attempt})", RED)
        log("Bob",     f"receives: '{pt}'  |  sig valid: {valid}  ← accepted again!", YELLOW)

    print(f"\n  {BOLD}{RED}  ✗  Bob accepted the replayed message — no defence!{RESET}")

    # ------------------------------------------------------------------ #
    # Phase 2: With sequence numbers                                      #
    # ------------------------------------------------------------------ #
    section("3 · Phase 2: Replay defeated by sequence numbers")

    print("  Alice now prepends a sequence number inside the encrypted envelope:\n")
    print(f"    plaintext format: \"<seq>:<message>\"\n")

    last_seq = 0   # Bob's counter

    # Alice sends two legitimate messages
    for seq, text in [(1, "Approve payment of $1,000"), (2, "Logout")]:
        payload = f"{seq}:{text}"
        n, ct, sig = make_message(session_key, alice_priv, payload)

        if seq == 1:
            # Save first message for Mallory to replay later
            replay_n, replay_ct, replay_sig = n, ct, sig

        result, valid, last_seq = receive_message_with_seqnum(
            session_key, alice_pub, n, ct, sig, last_seq
        )
        log("Alice", f"sends seq={seq}: '{text}'", GREEN)
        log("Bob",   f"accepts seq={seq}: '{result}'  |  sig valid: {valid}", GREEN)

    # Mallory replays message seq=1 (already processed)
    print()
    log("Mallory", "replays captured message (seq=1)…", RED)
    result, valid, last_seq = receive_message_with_seqnum(
        session_key, alice_pub, replay_n, replay_ct, replay_sig, last_seq
    )
    if result is None:
        log("Bob", f"REPLAY DETECTED — seq ≤ last_seq ({last_seq})  → message dropped", GREEN)
        print(f"\n  {BOLD}{GREEN}  ✓  Replay blocked — sequence number out of order!{RESET}")
    else:
        log("Bob", f"accepted: '{result}'  ← NOT blocked!", RED)

    section("Summary")
    print("  AES-256-GCM + RSA-PSS guarantee that a replayed message:")
    print("    • Cannot be decrypted by anyone without the session key")
    print("    • Cannot be modified without breaking the auth tag / signature")
    print("  BUT they do NOT prevent the same valid frame being re-delivered.")
    print()
    print("  Defence: embed a strictly increasing sequence number (or a")
    print("  timestamp with a tight acceptance window) inside the encrypted")
    print("  payload.  The receiver rejects anything out of order.\n")


if __name__ == "__main__":
    main()
