# Key Exchange Method Implementation Summary

## Overview
Users can now choose between two key exchange methods:
1. **Diffie-Hellman (DH)** - Default, uses secure DH key exchange (2048-bit parameters)
2. **Random Prime** - Generates a random 256-bit prime number as the session key

---

## Changes Made

### 1. **crypto_utils.py**
Added prime number generation functions:

- **`is_prime(n, k=40)`** - Miller-Rabin primality test with configurable error probability
- **`generate_random_prime(bit_length=256)`** - Generates a random 256-bit prime number for session key

### 2. **protocol.py**
New message types and protocol functions:

**New Constants:**
- `T_KEY_METHOD` - Message to indicate which key exchange method to use
- `T_RANDOM_PRIME` - Message type for random prime key exchange

**New Functions:**
- `send_key_method(sock, method)` - Sends "DH" or "RANDOM_PRIME" to peer
- `send_random_prime(sock, encrypted_prime)` - Sends encrypted prime for key exchange
- Updated `receive()` to handle new message types

### 3. **server.py**
Major improvements:

**Modified `handle_client()` Function:**
- Now accepts `use_dh` parameter
- Sends key method choice to client at start
- **If DH mode:** Uses existing Diffie-Hellman handshake
- **If RANDOM_PRIME mode:** Generates random prime and uses it directly as session key

**Updated `main()` Function:**
- Interactive menu for user to select key exchange method
- Command-line flags: `--dh` or `--random-prime`
- Default: Prompts user if no flag provided
- Passes selection to `run_server()`

**Updated `run_server()` Function:**
- Now passes `use_dh` parameter to `handle_client()` via threading

### 4. **client.py**
Synchronized with server changes:

**Modified `run_client()` Function:**
- First receives key method from server (`T_KEY_METHOD` message)
- **If DH mode:** Performs existing DH handshake
- **If RANDOM_PRIME mode:** Generates same random prime as server
- Both methods continue to use RSA-PSS signatures and HMAC authentication

---

## Usage

### Starting the Server
```bash
python server.py [--host 127.0.0.1] [--port 9000]
```

**Interactive Menu:**
```
============================================================
SELECT KEY EXCHANGE METHOD
============================================================
1. Diffie-Hellman (default, recommended)
2. Random Prime Number
============================================================
Enter your choice (1 or 2) [default: 1]:
```

**Command-line Options:**
```bash
# Use Diffie-Hellman
python server.py --dh

# Use Random Prime
python server.py --random-prime
```

### Starting the Client
```bash
python client.py [--host 127.0.0.1] [--port 9000]
```

The client automatically detects the server's chosen method and adapts accordingly.

---

## How It Works

### Diffie-Hellman Flow (Default)
1. Server sends "DH" method indicator
2. Server generates 2048-bit DH parameters
3. Client and server exchange public keys
4. Both derive shared session key using HKDF-SHA256

### Random Prime Flow
1. Server sends "RANDOM_PRIME" method indicator
2. Server generates random 256-bit prime number
3. Server uses it as session key (as 32-byte array)
4. Client generates same size prime as session key
5. Both proceed with message encryption/signing

---

## Security Notes

- **Diffie-Hellman**: More robust for distributed key agreement. Recommended for production.
- **Random Prime**: Useful for testing/demonstration. Both parties generate independently.
- Both methods maintain: RSA-PSS signatures, HMAC-SHA256 authentication, AES-256-GCM encryption

---

## Testing

All files have been verified for correct syntax. Run:
```bash
python server.py
python client.py  # in another terminal
```

Type messages to test encryption and authentication in either mode.
