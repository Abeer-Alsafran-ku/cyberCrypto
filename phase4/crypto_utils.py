"""
Cryptographic utilities for the encrypted messaging application.

Provides:
  - RSA-2048 key pair generation and serialization
  - RSA-OAEP encryption/decryption (for key exchange)
  - RSA-PSS digital signatures and verification
  - AES-256-GCM authenticated encryption/decryption
  - Random prime number generation for session keys
"""

import os
import time
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
import random


# ---------------------------------------------------------------------------
# RSA key management
# ---------------------------------------------------------------------------

def generate_rsa_keypair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate a fresh RSA-2048 key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


def serialize_public_key(public_key: RSAPublicKey) -> bytes:
    """Serialize a public key to PEM bytes for transmission."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_bytes: bytes) -> RSAPublicKey:
    """Deserialize a PEM-encoded public key received from a peer."""
    return serialization.load_pem_public_key(pem_bytes)


# ---------------------------------------------------------------------------
# Prime number generation for alternative key exchange
# ---------------------------------------------------------------------------

def is_prime(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin primality test.
    Returns True if n is probably prime (with error probability < 2^-k).
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_random_prime(bit_length: int = 256) -> int:
    """
    Generate a random prime number of specified bit length.
    Default is 256 bits (32 bytes) to match AES-256 key size.
    """
    while True:
        # Generate a random odd number with the specified bit length
        candidate = random.getrandbits(bit_length)
        candidate |= (1 << bit_length - 1)  # Ensure top bit is set
        candidate |= 1  # Ensure it's odd

        if is_prime(candidate):
            return candidate


def int_to_bytes(value: int) -> bytes:
    """Convert an integer to its minimal big-endian byte representation."""
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, byteorder="big")


def derive_session_key_from_prime(prime: int) -> bytes:
    """
    Derive a 256-bit AES session key from a prime of arbitrary size.

    This allows the random-prime path to accept primes larger than 256 bits
    while still producing a valid AES-256 key.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"random-prime-session-key",
    ).derive(int_to_bytes(prime))


# ---------------------------------------------------------------------------
# DH key management
# ---------------------------------------------------------------------------
def generate_dh_keypair(shared_key: bytes) -> bytes:
    """Generate a fresh RSA-2048 key pair."""
    #private_key = rsa.generate_private_key(
     #   public_exponent=65537,
      #  key_size=2048,
    #)

    return HKDF(
            algorithm = hashes.SHA256(),
            length=32,
            salt = None,
            info = b"handshake data",
            ).derive(shared_key)

    """Diffie Hellman """
    #parameters = dh.generate_parameters(generator = 2, key_size=2048)
    #private_key = parameters.generate_private_key()

    #return private_key, parameters.generate_private_key().public_key()


#def serialize_public_key(public_key: DHPublicKey) -> bytes:
    """Serialize a public key to PEM bytes for transmission."""
   # return public_key.public_bytes(
  #      encoding=serialization.Encoding.PEM,
 #       format=serialization.PublicFormat.SubjectPublicKeyInfo,
#    )


def deserialize_public_key(pem_bytes: bytes) -> RSAPublicKey:
    """Deserialize a PEM-encoded public key received from a peer."""
    return serialization.load_pem_public_key(pem_bytes)


# ---------------------------------------------------------------------------
# RSA-OAEP key encapsulation  (used during handshake)
# ---------------------------------------------------------------------------

def rsa_encrypt(public_key: RSAPublicKey, plaintext: bytes) -> bytes:
    """Encrypt *plaintext* with an RSA public key (OAEP/SHA-256)."""
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key: RSAPrivateKey, ciphertext: bytes) -> bytes:
    """Decrypt *ciphertext* with an RSA private key (OAEP/SHA-256)."""
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ---------------------------------------------------------------------------
# RSA-PSS digital signatures  (used per message)
# ---------------------------------------------------------------------------

def sign(private_key:RSAPrivateKey, message: bytes) -> bytes:
    """Create a PSS signature over *message* with the caller's private key."""
    return private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify(public_key:RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """
    Verify that *signature* was produced by the owner of *public_key*.

    Returns True on success, False if the signature is invalid.
    """
    try:
        public_key.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception as exc:
        print(f"Signature verification failed: {exc}")
        return False


# ---------------------------------------------------------------------------
# AES-256-GCM authenticated encryption  (used per message)
# ---------------------------------------------------------------------------

AES_KEY_SIZE = 32   # 256-bit key
NONCE_SIZE   = 12   # 96-bit nonce (GCM standard)


def generate_aes_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return os.urandom(AES_KEY_SIZE)


def aes_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Returns (nonce, ciphertext+tag).  The tag is appended to the ciphertext
    by the AESGCM implementation automatically.
    """
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt *ciphertext* (with appended GCM tag) using *key* and *nonce*.

    Raises cryptography.exceptions.InvalidTag if authentication fails.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ---------------------------------------------------------------------------
# HMAC for Message Integrity 
# ---------------------------------------------------------------------------

def generate_hmac(key: bytes, msg: bytes) -> bytes:
    """Generates a HMAC signature for a message."""
    return hmac.new(key, msg, hashlib.sha256).digest()

def verify_hmac(key: bytes, msg: bytes, received_signature: bytes) -> bool:
    """Verifies a message's integrity against a received signature."""
    expected_signature = generate_hmac(key, msg)
    return hmac.compare_digest(expected_signature, received_signature)


def brute_force_demo(secret_key: bytes, bits: int = 20) -> dict:
    """
    Demonstrate brute force against a truncated prefix of the session key.

    The full 256-bit key is intentionally not brute-forced. This function
    measures the time to recover the first *bits* of the key and extrapolates
    the average time per attempt.
    """
    if bits <= 0 or bits > 24:
        raise ValueError("bits must be between 1 and 24 for the brute-force demo")

    target = int.from_bytes(secret_key, byteorder="big") >> (len(secret_key) * 8 - bits)
    max_attempts = 1 << bits

    start = time.perf_counter()
    found = None
    for guess in range(max_attempts):
        if guess == target:
            found = guess
            break
    elapsed = time.perf_counter() - start

    attempts = (found + 1) if found is not None else max_attempts
    avg_per_attempt = elapsed / attempts if attempts else 0.0
    estimated_full_seconds = avg_per_attempt * (2 ** (len(secret_key) * 8 - 1))

    return {
        "bits": bits,
        "found": found,
        "attempts": attempts,
        "elapsed": elapsed,
        "estimated_full_seconds": estimated_full_seconds,
    }
