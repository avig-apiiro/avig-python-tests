from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode

# Key size: 64 bits = 8 bytes (56 bits effective — 8 bits are parity)
KEY_SIZE = 8


def example_cbc():
    """DES-CBC with PKCS7 padding — encrypt and decrypt."""
    plaintext = b"ALIENS DO EXIST!!!!"
    key = get_random_bytes(KEY_SIZE)

    # Mode: CBC | Padding: PKCS7
    cipher = DES.new(key, DES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))

    print(f"[CBC encrypt] mode=CBC, padding=PKCS7, key_size={KEY_SIZE * 8}-bit")
    print(f"[CBC encrypt] iv:         {b64encode(cipher.iv).decode()}")
    print(f"[CBC encrypt] ciphertext: {b64encode(ciphertext).decode()}")

    # Decrypt
    decipher = DES.new(key, DES.MODE_CBC, iv=cipher.iv)
    decrypted = unpad(decipher.decrypt(ciphertext), DES.block_size)
    print(f"[CBC decrypt] decrypted:  {decrypted.decode()}")
    assert decrypted == plaintext


def example_ecb():
    """DES-ECB with PKCS7 padding — encrypt and decrypt.

    NOTE: ECB mode is deterministic and leaks patterns; shown here for
    completeness only. Prefer CBC or an AEAD mode in production.
    """
    plaintext = b"ALIENS!!"  # 8 bytes — exact block, no padding needed
    key = get_random_bytes(KEY_SIZE)

    # Mode: ECB | Padding: PKCS7
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))

    print(f"[ECB encrypt] mode=ECB, padding=PKCS7, key_size={KEY_SIZE * 8}-bit")
    print(f"[ECB encrypt] ciphertext: {b64encode(ciphertext).decode()}")

    decipher = DES.new(key, DES.MODE_ECB)
    decrypted = unpad(decipher.decrypt(ciphertext), DES.block_size)
    print(f"[ECB decrypt] decrypted:  {decrypted.decode()}")
    assert decrypted == plaintext


if __name__ == "__main__":
    print(f"=== DES Examples ({KEY_SIZE * 8}-bit key) ===\n")

    print("--- CBC ---")
    example_cbc()
    print()

    print("--- ECB (insecure — demo only) ---")
    example_ecb()
