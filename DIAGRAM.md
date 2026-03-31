# Protocol Flow Diagram

## Full Session Sequence

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    Note over C,S: ── SETUP ──────────────────────────────────────────
    C->>C: Generate RSA-2048 key pair<br/>(client_priv, client_pub)
    S->>S: Generate RSA-2048 key pair<br/>(server_priv, server_pub)

    Note over C,S: ── HANDSHAKE ──────────────────────────────────────

    S-->>C: HELLO { public_key: server_pub (PEM, base64) }
    C-->>S: HELLO { public_key: client_pub (PEM, base64) }

    C->>C: Generate random AES-256 session key
    C->>C: Encrypt session key with server_pub<br/>(RSA-OAEP / SHA-256)
    C-->>S: SESSION_KEY { encrypted_key: RSA_enc(session_key) }

    S->>S: Decrypt encrypted_key with server_priv<br/>→ recovers session_key

    Note over C,S: Both sides now share session_key (AES-256)

    Note over C,S: ── MESSAGING ──────────────────────────────────────

    C->>C: nonce ← random 96-bit value
    C->>C: ciphertext ← AES-256-GCM(session_key, nonce, plaintext)
    C->>C: signature  ← RSA-PSS(client_priv, ciphertext)
    C-->>S: MSG { nonce, ciphertext, signature }

    S->>S: plaintext ← AES-256-GCM-Decrypt(session_key, nonce, ciphertext)
    S->>S: valid ← RSA-PSS-Verify(client_pub, ciphertext, signature)

    S->>S: nonce' ← random 96-bit value
    S->>S: ciphertext' ← AES-256-GCM(session_key, nonce', reply)
    S->>S: signature'  ← RSA-PSS(server_priv, ciphertext')
    S-->>C: MSG { nonce', ciphertext', signature' }

    C->>C: reply ← AES-256-GCM-Decrypt(session_key, nonce', ciphertext')
    C->>C: valid ← RSA-PSS-Verify(server_pub, ciphertext', signature')

    Note over C,S: MSG exchange repeats for every message

    Note over C,S: ── TEARDOWN ───────────────────────────────────────
    C-->>S: ERROR { reason: "Client disconnecting" }
    Note over C,S: Both sides close the TCP socket
```

---

## Wire Protocol Frame

Every message is a **length-prefixed JSON frame**:

```
┌─────────────────────────────────────────────────────────────┐
│  TCP Stream                                                  │
│                                                             │
│  ┌──────────────┬──────────────────────────────────────┐   │
│  │  4 bytes     │  N bytes                             │   │
│  │  (big-endian │  JSON payload                        │   │
│  │   uint32)    │                                      │   │
│  │    length N  │  { "type": "...", ... }               │   │
│  └──────────────┴──────────────────────────────────────┘   │
│                                                             │
│  Frames are sent back-to-back with no separator             │
└─────────────────────────────────────────────────────────────┘
```

---

## Message Payloads

### `HELLO`
```json
{
  "type": "HELLO",
  "public_key": "<base64-encoded PEM>"
}
```

### `SESSION_KEY`
```json
{
  "type": "SESSION_KEY",
  "encrypted_key": "<base64-encoded RSA-OAEP ciphertext>"
}
```

### `MSG`
```json
{
  "type": "MSG",
  "nonce":      "<base64  — 12 random bytes>",
  "ciphertext": "<base64  — AES-256-GCM encrypted payload + 16-byte auth tag>",
  "signature":  "<base64  — RSA-PSS signature over ciphertext bytes>"
}
```

### `ERROR`
```json
{
  "type": "ERROR",
  "reason": "<human-readable string>"
}
```

---

## Cryptographic Layers

```
┌─────────────────────────────────────────────────────────────┐
│  Application message  (plaintext string)                    │
├─────────────────────────────────────────────────────────────┤
│  AES-256-GCM encryption                                     │
│  key    = session_key  (32 bytes, exchanged at handshake)   │
│  nonce  = random 12-byte value (new for every message)      │
│  output = ciphertext ∥ 16-byte authentication tag           │
├─────────────────────────────────────────────────────────────┤
│  RSA-PSS digital signature                                  │
│  input  = ciphertext (not plaintext — sign after encrypt)   │
│  key    = sender's RSA-2048 private key                     │
│  hash   = SHA-256,  salt = maximum length                   │
├─────────────────────────────────────────────────────────────┤
│  JSON serialisation  (binary fields → base64 strings)       │
├─────────────────────────────────────────────────────────────┤
│  4-byte big-endian length prefix                            │
├─────────────────────────────────────────────────────────────┤
│  TCP socket                                                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Exchange Detail

```
Client                                          Server
  │                                               │
  │  server_pub  ←────────────────────────────── │  (HELLO)
  │                                               │
  │ ──────────────────────────────→  client_pub  │  (HELLO)
  │                                               │
  │  session_key = random 32 bytes                │
  │  enc = RSA-OAEP(server_pub, session_key)      │
  │ ─────────────── enc ──────────────────────→  │  (SESSION_KEY)
  │                                               │
  │                     session_key = RSA-OAEP-  │
  │                     Decrypt(server_priv, enc) │
  │                                               │
  │    session_key  ══════════════  session_key   │
  │         (known only to client and server)     │
```
