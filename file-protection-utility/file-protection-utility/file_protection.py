import os
import sys
import getpass
import argparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 600_000


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(input_file, output_file, password):
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    aes = AESGCM(key)

    with open(input_file, "rb") as f:
        plaintext = f.read()

    ciphertext = aes.encrypt(nonce, plaintext, None)

    with open(output_file, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

    print("\n[+] File encrypted successfully.")
    print(f"[+] Output: {output_file}")
    print("[+] Encryption: AES-256-GCM")
    print("[+] Key Derivation: PBKDF2-HMAC-SHA256")


def decrypt_file(input_file, output_file, password):
    with open(input_file, "rb") as f:
        data = f.read()

    minimum_size = SALT_SIZE + NONCE_SIZE + 16
    if len(data) < minimum_size:
        raise ValueError("Invalid or corrupted encrypted file.")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aes = AESGCM(key)

    try:
        plaintext = aes.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError(
            "Authentication failed. Wrong password or file was modified."
        )

    with open(output_file, "wb") as f:
        f.write(plaintext)

    print("\n[+] File decrypted successfully.")
    print(f"[+] Output: {output_file}")
    print("[+] Integrity/MAC verification: PASSED")


def main():
    parser = argparse.ArgumentParser(
        description="AES-256 File Protection Utility"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    enc = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("input", help="Input file")
    enc.add_argument("output", help="Encrypted output file (.enc)")

    dec = subparsers.add_parser("decrypt", help="Decrypt an encrypted file")
    dec.add_argument("input", help="Encrypted .enc file")
    dec.add_argument("output", help="Decrypted output file")

    args = parser.parse_args()
    password = getpass.getpass("Enter password: ")

    if not password:
        print("[-] Password cannot be empty.")
        sys.exit(1)

    try:
        if args.command == "encrypt":
            encrypt_file(args.input, args.output, password)
        else:
            decrypt_file(args.input, args.output, password)
    except FileNotFoundError:
        print("[-] Error: File not found.")
        sys.exit(1)
    except PermissionError:
        print("[-] Error: Permission denied.")
        sys.exit(1)
    except ValueError as error:
        print(f"[-] Error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
