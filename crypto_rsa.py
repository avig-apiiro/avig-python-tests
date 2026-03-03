from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from base64 import b64encode

# Key size: 1024 bits
KEY_SIZE = 1024


def generate_key_pair():
    """Generate a 1024-bit RSA key pair."""
    private_key = RSA.generate(KEY_SIZE)
    public_key = private_key.publickey()
    print(f"[keygen] Generated RSA key pair, key_size={KEY_SIZE}-bit")
    print(f"[keygen] public key (PEM):\n{public_key.export_key().decode()}\n")
    return private_key, public_key


def example_encrypt_decrypt(private_key, public_key):
    """RSA-OAEP encryption and decryption."""
    message = b"ALIENS DO EXIST!!!!"

    # Encrypt with public key using OAEP padding (recommended over PKCS1v1.5)
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message)
    print(f"[encrypt] plaintext:  {message.decode()}")
    print(f"[encrypt] ciphertext: {b64encode(ciphertext).decode()}")

    # Decrypt with private key
    decipher = PKCS1_OAEP.new(private_key)
    plaintext = decipher.decrypt(ciphertext)
    print(f"[decrypt] decrypted:  {plaintext.decode()}")
    assert plaintext == message, "Decryption mismatch!"


def example_sign_verify(private_key, public_key):
    """RSA-PSS signing and verification."""
    message = b"ALIENS DO EXIST!!!!"
    message_hash = SHA256.new(message)

    # Sign with private key using PSS padding
    signature = pss.new(private_key).sign(message_hash)
    print(f"[sign]   message:   {message.decode()}")
    print(f"[sign]   signature: {b64encode(signature).decode()}")

    # Verify with public key
    verifier = pss.new(public_key)
    try:
        verifier.verify(SHA256.new(message), signature)
        print("[verify] Signature is VALID")
    except (ValueError, TypeError):
        print("[verify] Signature is INVALID")


if __name__ == "__main__":
    print(f"=== RSA Examples ({KEY_SIZE}-bit key) ===\n")

    private_key, public_key = generate_key_pair()

    print("--- Encryption / Decryption (OAEP) ---")
    example_encrypt_decrypt(private_key, public_key)
    print()

    print("--- Signing / Verification (PSS + SHA-256) ---")
    example_sign_verify(private_key, public_key)
