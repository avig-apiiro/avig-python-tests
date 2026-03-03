from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.Hash import HMAC, SHA256

# Key size: 128 bits = 16 bytes
KEY_SIZE = 16


def example1():
    # AES-CBC with PKCS7 padding, no MAC — unauthenticated encryption (insecure example)
    sensitive_data = b"ALIENS DO EXIST!!!!"
    key = get_random_bytes(KEY_SIZE)

    # Mode: CBC | Padding: PKCS7 (via pad with AES.block_size=16)
    # ruleid: crypto-mode-without-authentication
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(sensitive_data, AES.block_size))
    print(f"[example1] mode=CBC, padding=PKCS7, key_size={KEY_SIZE * 8}-bit")
    print(f"[example1] ciphertext: {b64encode(ciphertext).decode()}")


def example2():
    # AES-CBC with PKCS7 padding + HMAC-SHA256 for authentication
    key = get_random_bytes(KEY_SIZE)
    hmac_key = get_random_bytes(KEY_SIZE)
    sensitive_data = b"ALIENS DO EXIST!!!!"

    # Mode: CBC | Padding: PKCS7
    # ok: crypto-mode-without-authentication
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_bytes = cipher.encrypt(pad(sensitive_data, AES.block_size))

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(iv + encrypted_bytes)
    mac_bytes = hmac.digest()

    print(f"[example2] mode=CBC, padding=PKCS7, key_size={KEY_SIZE * 8}-bit, auth=HMAC-SHA256")
    print(f"[example2] iv:         {b64encode(iv).decode()}")
    print(f"[example2] ciphertext: {b64encode(encrypted_bytes).decode()}")
    print(f"[example2] hmac:       {b64encode(mac_bytes).decode()}")


def example3():
    # AES-GCM — authenticated encryption (mode provides built-in authentication, no padding needed)
    sensitive_data = b"ALIENS DO EXIST!!!!"
    key = get_random_bytes(KEY_SIZE)

    # Mode: GCM | Padding: none (stream-like mode, no block padding required)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(sensitive_data)

    print(f"[example3] mode=GCM, padding=none, key_size={KEY_SIZE * 8}-bit, auth=built-in tag")
    print(f"[example3] nonce:      {b64encode(cipher.nonce).decode()}")
    print(f"[example3] ciphertext: {b64encode(ciphertext).decode()}")
    print(f"[example3] auth tag:   {b64encode(tag).decode()}")

    # Decrypt and verify
    decipher = AES.new(key, AES.MODE_GCM, nonce=cipher.nonce)
    plaintext = decipher.decrypt_and_verify(ciphertext, tag)
    print(f"[example3] decrypted:  {plaintext.decode()}")


if __name__ == "__main__":
    print("=== AES Examples (128-bit key) ===\n")
    example1()
    print()
    example2()
    print()
    example3()
