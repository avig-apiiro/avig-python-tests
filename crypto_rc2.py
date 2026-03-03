from Crypto.Cipher import ARC2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode

# Key size: 128 bits = 16 bytes (valid range: 1–128 bytes; effective key bits
# controlled separately via effective_keylen, max 1024 bits)
KEY_SIZE = 128


def example_cbc():
    """RC2-CBC with PKCS7 padding — encrypt and decrypt."""
    plaintext = b"ALIENS DO EXIST!!!!"
    key = get_random_bytes(KEY_SIZE // 8)

    # Mode: CBC | Padding: PKCS7 | Effective key length: 128 bits
    cipher = ARC2.new(key, ARC2.MODE_CBC, effective_keylen=KEY_SIZE)
    ciphertext = cipher.encrypt(pad(plaintext, ARC2.block_size))

    print(f"[CBC encrypt] mode=CBC, padding=PKCS7, key_size={KEY_SIZE }-bit, effective_keylen=128-bit")
    print(f"[CBC encrypt] iv:         {b64encode(cipher.iv).decode()}")
    print(f"[CBC encrypt] ciphertext: {b64encode(ciphertext).decode()}")

    # Decrypt
    decipher = ARC2.new(key, ARC2.MODE_CBC, iv=cipher.iv, effective_keylen=KEY_SIZE)
    decrypted = unpad(decipher.decrypt(ciphertext), ARC2.block_size)
    print(f"[CBC decrypt] decrypted:  {decrypted.decode()}")
    assert decrypted == plaintext


def example_ecb():
    """RC2-ECB with PKCS7 padding — encrypt and decrypt.

    NOTE: ECB mode is deterministic and leaks patterns; shown here for
    completeness only. Prefer CBC or an AEAD mode in production.
    """
    plaintext = b"ALIENS DO EXIST!!!!"
    key = get_random_bytes(KEY_SIZE)

    # Mode: ECB | Padding: PKCS7 | Effective key length: 128 bits
    cipher = ARC2.new(key, ARC2.MODE_ECB, effective_keylen=KEY_SIZE)
    ciphertext = cipher.encrypt(pad(plaintext, ARC2.block_size))

    print(f"[ECB encrypt] mode=ECB, padding=PKCS7, key_size={KEY_SIZE * 8}-bit, effective_keylen=128-bit")
    print(f"[ECB encrypt] ciphertext: {b64encode(ciphertext).decode()}")

    decipher = ARC2.new(key, ARC2.MODE_ECB, effective_keylen=KEY_SIZE)
    decrypted = unpad(decipher.decrypt(ciphertext), ARC2.block_size)
    print(f"[ECB decrypt] decrypted:  {decrypted.decode()}")
    assert decrypted == plaintext


if __name__ == "__main__":
    print(f"=== RC2 Examples ({KEY_SIZE * 8}-bit key) ===\n")

    print("--- CBC ---")
    example_cbc()
    print()

    print("--- ECB (insecure — demo only) ---")
    example_ecb()
