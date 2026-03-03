from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode

# Key size: 128 bits = 16 bytes (valid range: 4–56 bytes / 32–448 bits)
KEY_SIZE = 16


def example_cbc():
    """Blowfish-CBC with PKCS7 padding — encrypt and decrypt."""
    plaintext = b"ALIENS DO EXIST!!!!"
    key = get_random_bytes(KEY_SIZE)

    # Mode: CBC | Padding: PKCS7
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, Blowfish.block_size))

    print(f"[CBC encrypt] mode=CBC, padding=PKCS7, key_size={KEY_SIZE * 8}-bit")
    print(f"[CBC encrypt] iv:         {b64encode(cipher.iv).decode()}")
    print(f"[CBC encrypt] ciphertext: {b64encode(ciphertext).decode()}")

    # Decrypt
    decipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=cipher.iv)
    decrypted = unpad(decipher.decrypt(ciphertext), Blowfish.block_size)
    print(f"[CBC decrypt] decrypted:  {decrypted.decode()}")
    assert decrypted == plaintext


def example_ctr():
    """Blowfish-CTR — stream-like mode, no padding required."""
    plaintext = b"ALIENS DO EXIST!!!!"
    key = get_random_bytes(KEY_SIZE)

    # Mode: CTR | Padding: none (counter mode is stream-like)
    # nonce is half the block size (4 bytes for Blowfish's 8-byte block)
    nonce = get_random_bytes(Blowfish.block_size // 2)
    cipher = Blowfish.new(key, Blowfish.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)

    print(f"[CTR encrypt] mode=CTR, padding=none, key_size={KEY_SIZE * 8}-bit")
    print(f"[CTR encrypt] nonce:      {b64encode(nonce).decode()}")
    print(f"[CTR encrypt] ciphertext: {b64encode(ciphertext).decode()}")

    decipher = Blowfish.new(key, Blowfish.MODE_CTR, nonce=nonce)
    decrypted = decipher.decrypt(ciphertext)
    print(f"[CTR decrypt] decrypted:  {decrypted.decode()}")
    assert decrypted == plaintext


if __name__ == "__main__":
    print(f"=== Blowfish Examples ({KEY_SIZE * 8}-bit key) ===\n")

    print("--- CBC ---")
    example_cbc()
    print()

    print("--- CTR ---")
    example_ctr()
