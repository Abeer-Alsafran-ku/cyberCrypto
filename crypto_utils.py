"""
Cryptographic utilities for the encrypted messaging application.

Provides:
  - RSA-2048 key pair generation and serialization
  - RSA-OAEP encryption/decryption (for key exchange)
  - RSA-PSS digital signatures and verification
  - AES-256-GCM authenticated encryption/decryption
"""

import os
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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

def sign(private_key: RSAPrivateKey, message: bytes) -> bytes:
    """Create a PSS signature over *message* with the caller's private key."""
    return private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify(public_key: RSAPublicKey, message: bytes, signature: bytes) -> bool:
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
    except Exception:
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
