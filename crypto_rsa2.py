import crypto_rsa
from Crypto.PublicKey import RSA

def generate_key_pair():
    """Generate a 1024-bit RSA key pair."""
    private_key = RSA.generate(crypto_rsa.KEY_SIZE)
    public_key = private_key.publickey()

    return private_key, public_key
