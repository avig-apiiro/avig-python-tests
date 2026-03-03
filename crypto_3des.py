from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode

# Key size: 168 bits effective = 24 bytes (3 independent 56-bit keys)
# 16-byte key is also valid (112-bit effective — key1 == key3), but 24 is stronger.
KEY_SIZE = 24


def example_cbc():
    """3DES-CBC with PKCS7 padding — encrypt and decrypt."""
    plaintext = b"ALIENS DO EXIST!!!!"
    key = DES3.adjust_key_parity(get_random_bytes(KEY_SIZE))

    # Mode: CBC | Padding: PKCS7
    cipher = DES3.new(key, DES3.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))

    print(f"[CBC encrypt] mode=CBC, padding=PKCS7, key_size={KEY_SIZE * 8}-bit")
    print(f"[CBC encrypt] iv:         {b64encode(cipher.iv).decode()}")
    print(f"[CBC encrypt] ciphertext: {b64encode(ciphertext).decode()}")

    # Decrypt
    decipher = DES3.new(key, DES3.MODE_CBC, iv=cipher.iv)
    decrypted = unpad(decipher.decrypt(ciphertext), DES3.block_size)
    print(f"[CBC decrypt] decrypted:  {decrypted.decode()}")
    assert decrypted == plaintext


def example_cfb():
    """3DES-CFB (8-bit segment size) — stream-like mode, no padding required."""
    plaintext = b"ALIENS DO EXIST!!!!"
    key = DES3.adjust_key_parity(get_random_bytes(KEY_SIZE))

    # Mode: CFB | Padding: none (stream-like)
    cipher = DES3.new(key, DES3.MODE_CFB)
    ciphertext = cipher.encrypt(plaintext)

    print(f"[CFB encrypt] mode=CFB, padding=none, key_size={KEY_SIZE * 8}-bit")
    print(f"[CFB encrypt] iv:         {b64encode(cipher.iv).decode()}")
    print(f"[CFB encrypt] ciphertext: {b64encode(ciphertext).decode()}")

    decipher = DES3.new(key, DES3.MODE_CFB, iv=cipher.iv)
    decrypted = decipher.decrypt(ciphertext)
    print(f"[CFB decrypt] decrypted:  {decrypted.decode()}")
    assert decrypted == plaintext


if __name__ == "__main__":
    print(f"=== 3DES Examples ({KEY_SIZE * 8}-bit key) ===\n")

    print("--- CBC ---")
    example_cbc()
    print()

    print("--- CFB ---")
    example_cfb()
