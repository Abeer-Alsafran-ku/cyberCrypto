import hmac
import hashlib
import base64

# 1. Configuration: Secret key and message must be bytes
# In a real app, use a strong random key stored securely
secret_key = b'shared-secret-key'
message = b'This is a sensitive message.'

def generate_hmac(key, msg):
    """Generates a HMAC signature for a message."""
    # hmac.new(key, msg, digestmod) returns an HMAC object
    # return hmac.new(key, msg, hashlib.sha256).hexdigest()
    return base64.b64encode(hmac.new(key, msg, hashlib.sha256)).decode()

def verify_hmac(key, msg, received_signature):
    """Verifies a message's integrity against a received signature."""
    # Re-calculate the HMAC for the message we just received
    sig = base64.b64decode(received_signature)
    expected_signature = generate_hmac(key, msg)
    
    # ALWAYS use compare_digest to prevent timing attacks
    return hmac.compare_digest(expected_signature, received_signature)

# --- Usage Example ---

# Alice signs a message
signature = generate_hmac(secret_key, message)
print(f"Message: {message.decode()}")
print(f"Signature: {signature}")

# Bob verifies the message (Success)
is_valid = verify_hmac(secret_key, message, signature)
print(f"Verification Successful? {is_valid}")

# Simulation: An attacker alters the message
tampered_message = b'This is a sensitive message.!' # Added a '!'
is_valid_tampered = verify_hmac(secret_key, tampered_message, signature)
print(f"Tampered Message Valid? {is_valid_tampered}")
