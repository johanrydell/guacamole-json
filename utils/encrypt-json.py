import base64
import hashlib
import hmac
import sys

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

# Constants
NULL_IV = bytes.fromhex("00000000000000000000000000000000")


# Function to sign the file using HMAC/SHA-256
def sign(secret_key, json_filename):
    with open(json_filename, "rb") as f:
        file_contents = f.read()

    # Create HMAC signature using the provided key
    key_bytes = bytes.fromhex(secret_key)
    hmac_signature = hmac.new(key_bytes, file_contents, hashlib.sha256).digest()

    # Return signature followed by file contents
    return hmac_signature + file_contents


# Function to encrypt data using AES-128-CBC with a null IV
def encrypt(secret_key, data):
    key_bytes = bytes.fromhex(secret_key)
    cipher = AES.new(key_bytes, AES.MODE_CBC, NULL_IV)

    # Pad data to be a multiple of AES block size
    padded_data = pad(data, AES.block_size)

    # Encrypt data and encode it to base64
    encrypted_data = cipher.encrypt(padded_data)
    base64_encoded = base64.b64encode(encrypted_data).decode("utf-8")

    # Break base64-encoded data into lines of 64 characters
    # return '\n'.join(base64_encoded[i:i+64] for i in \
    # range(0, len(base64_encoded), 64))
    return base64_encoded


if __name__ == "__main__":
    # Ensure both secret key and filename are provided as arguments
    if len(sys.argv) != 3:
        print("Usage: python encrypt_json.py <SECRET_KEY> <JSON_FILENAME>")
        sys.exit(1)

    secret_key = sys.argv[1]
    json_filename = sys.argv[2]

    # Sign and encrypt the file
    signed_data = sign(secret_key, json_filename)
    encrypted_data = encrypt(secret_key, signed_data)

    # Output the encrypted, base64-encoded data
    print(encrypted_data)
