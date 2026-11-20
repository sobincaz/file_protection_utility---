
import os
import argparse
import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# Encryption settings
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 600000

MAGIC = b"FP01"


def derive_key(password, salt):
    """Generate a 256-bit key using PBKDF2."""

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS
    )

    return kdf.derive(password.encode("utf-8"))


def encrypt_file(input_file, output_file, password):
    """Encrypt a file using AES-256-GCM."""

    if not os.path.isfile(input_file):
        print("Error: Input file not found.")
        return

    if os.path.exists(output_file):
        print("Error: Output file already exists.")
        return

    try:
        with open(input_file, "rb") as file:
            data = file.read()

        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)

        key = derive_key(password, salt)

        aes = AESGCM(key)

        ciphertext = aes.encrypt(nonce, data, None)

        with open(output_file, "xb") as file:
            file.write(MAGIC + salt + nonce + ciphertext)

        print("\nEncryption successful!")
        print("Encrypted file:", output_file)
        print("Algorithm: AES-256-GCM")
        print("Key derivation: PBKDF2-HMAC-SHA256")

    except Exception as error:
        print("Encryption failed:", error)


def decrypt_file(input_file, output_file, password):
    """Decrypt a file and verify authentication."""

    if not os.path.isfile(input_file):
        print("Error: Encrypted file not found.")
        return

    if os.path.exists(output_file):
        print("Error: Output file already exists.")
        return

    try:
        with open(input_file, "rb") as file:
            encrypted_data = file.read()

        minimum_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE + 16

        if len(encrypted_data) < minimum_size:
            print("Error: Invalid or damaged encrypted file.")
            return

        if encrypted_data[:4] != MAGIC:
            print("Error: Invalid encrypted file format.")
            return

        position = len(MAGIC)

        salt = encrypted_data[position:position + SALT_SIZE]
        position += SALT_SIZE

        nonce = encrypted_data[position:position + NONCE_SIZE]
        position += NONCE_SIZE

        ciphertext = encrypted_data[position:]

        key = derive_key(password, salt)

        aes = AESGCM(key)

        # AES-GCM verifies the authentication tag (MAC)
        plaintext = aes.decrypt(nonce, ciphertext, None)

        with open(output_file, "xb") as file:
            file.write(plaintext)

        print("\nDecryption successful!")
        print("Decrypted file:", output_file)
        print("MAC integrity verification: PASSED")

    except Exception:
        print("\nDecryption failed!")
        print("Wrong password or file has been modified.")
        print("Integrity verification: FAILED")


def main():
    parser = argparse.ArgumentParser(
        description="AES-256 File Protection Utility"
    )

    parser.add_argument(
        "action",
        choices=["encrypt", "decrypt"],
        help="Choose encryption or decryption"
    )

    parser.add_argument(
        "input",
        help="Input file path"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file path"
    )

    args = parser.parse_args()

    password = getpass.getpass("Enter password: ")

    if not password:
        print("Error: Password cannot be empty.")
        return

    if args.action == "encrypt":
        confirm = getpass.getpass("Confirm password: ")

        if password != confirm:
            print("Passwords do not match.")
            return

        output = args.output or args.input + ".enc"

        encrypt_file(args.input, output, password)

    else:
        if args.output:
            output = args.output
        elif args.input.endswith(".enc"):
            output = args.input[:-4] + ".dec"
        else:
            output = args.input + ".dec"

        decrypt_file(args.input, output, password)


if __name__ == "__main__":
    main()
