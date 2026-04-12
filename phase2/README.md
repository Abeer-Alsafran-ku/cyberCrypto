# CyberCrypto — Encrypted Messaging App

A client-server messaging application that simulates secure communication over the internet using real cryptographic techniques: public-key encryption, authenticated symmetric encryption, and digital signatures.

---

## How It Works

### Handshake (Key Exchange)

Before any message is sent, the client and server perform a handshake to establish a shared secret session key:

```
Client                                  Server
  |                                       |
  | <------- HELLO (RSA public key) ----- |   1. Server sends its RSA public key
  |                                       |
  | ------- HELLO (RSA public key) -----> |   2. Client sends its RSA public key
  |                                       |
  | --- SESSION_KEY (AES key, RSA enc) -> |   3. Client generates AES-256 session key,
  |                                       |      encrypts it with server's RSA public key,
  |                                       |      sends it
  |                                       |
  |   === Secure channel established ===  |   4. Server decrypts session key with its
  |                                       |      private key — both sides now share it
```

### Encrypted Messaging

Every message sent in either direction is:

1. **Encrypted** with AES-256-GCM using the shared session key
2. **Signed** with the sender's RSA private key (PSS scheme)
3. **Verified** on receipt — the receiver checks the signature using the sender's public key

---

## Cryptographic Techniques

| Technique | Algorithm | Purpose |
|---|---|---|
| Key exchange | RSA-2048 OAEP/SHA-256 | Securely deliver the AES session key |
| Message encryption | AES-256-GCM | Confidentiality + integrity of messages |
| Digital signature | RSA-PSS/SHA-256 | Authenticity and non-repudiation |
| Wire protocol | JSON + base64 + 4-byte length prefix | Safe binary transport over TCP |

---

## Project Structure

```
cyberCrypto/
├── crypto_utils.py   # RSA & AES primitives (key gen, encrypt, sign, verify)
├── protocol.py       # Wire protocol: framing, serialization, message types
├── server.py         # Multi-client TCP server
├── client.py         # Interactive TCP client
└── requirements.txt  # Python dependencies
```

---

## Installation

```bash
pip install -r requirements.txt
```

**Requires:** Python 3.11+ and the [`cryptography`](https://cryptography.io) library.

---

## Usage

### Start the server

```bash
python server.py
```

Options:

```
--host HOST   Bind address (default: 127.0.0.1)
--port PORT   Port number  (default: 9000)
```

### Connect a client

```bash
python client.py
```

Options:

```
--host HOST   Server address (default: 127.0.0.1)
--port PORT   Server port   (default: 9000)
```

Type a message and press **Enter** to send. The server echoes it back. Type `quit` to disconnect.

---

## Example Session

**Server terminal:**

```
Generating RSA-2048 key pair for server…
Key pair ready.

Server listening on 127.0.0.1:9000
Press Ctrl-C to stop.

[+] New connection from 127.0.0.1:54321
[127.0.0.1:54321] Received client public key.
[127.0.0.1:54321] Session key established (AES-256-GCM). Handshake complete.
[127.0.0.1:54321] Waiting for messages…

[127.0.0.1:54321] Message received | signature: VALID
    Hello, secure world!
```

**Client terminal:**

```
Generating RSA-2048 key pair for client…
Key pair ready.

Connecting to 127.0.0.1:9000…
Connected.

Received server public key.
Session key sent (encrypted with server's RSA public key).
Handshake complete — all messages are AES-256-GCM encrypted & RSA-PSS signed.

Type a message and press Enter to send.  Type 'quit' to exit.

You: Hello, secure world!

[Server | sig:valid] [Server echo] Hello, secure world!
You:
```

---

## Security Properties

| Property | Provided by |
|---|---|
| **Confidentiality** | AES-256-GCM encrypts every message; only the holder of the session key can read it |
| **Integrity** | GCM authentication tag detects any ciphertext tampering |
| **Authenticity** | RSA-PSS signature proves the message came from the expected party |
| **Non-repudiation** | Each message is signed with the sender's private key |
| **Forward secrecy** | A fresh AES session key is generated per connection |
