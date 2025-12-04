#!/usr/bin/env python3

import os
import base64
import hashlib
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ========= Utility functions =========

BLOCK_SIZE = AES.block_size  # 16 bytes


def pad(data: bytes) -> bytes:
    """Apply PKCS7 padding."""
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len]) * padding_len


def unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding."""
    if not data:
        raise ValueError("Invalid padded data (empty).")
    padding_len = data[-1]
    if padding_len < 1 or padding_len > BLOCK_SIZE:
        raise ValueError("Invalid padding.")
    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Invalid padding.")
    return data[:-padding_len]


def derive_key(password: str) -> bytes:
    """
    Derive a 256-bit key from a password using SHA-256.
    For real-world apps, use PBKDF2/argon2 with salt.
    """
    return hashlib.sha256(password.encode("utf-8")).digest()


# ========= Core AES-CBC encryption / decryption =========

def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    key = derive_key(password)
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))
    # Store iv + ciphertext together
    return iv + ciphertext


def decrypt_bytes(data: bytes, password: str) -> bytes:
    if len(data) <= BLOCK_SIZE:
        raise ValueError("Data too short to contain IV + ciphertext.")
    key = derive_key(password)
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    return unpad(plaintext_padded)


# ========= Text helpers (Base64 for readability) =========

def encrypt_text(plaintext: str, password: str) -> str:
    raw = encrypt_bytes(plaintext.encode("utf-8"), password)
    # Base64 encode for safe printing / copying
    return base64.b64encode(raw).decode("utf-8")


def decrypt_text(cipher_b64: str, password: str) -> str:
    raw = base64.b64decode(cipher_b64.encode("utf-8"))
    decrypted = decrypt_bytes(raw, password)
    return decrypted.decode("utf-8")


# ========= File helpers =========

def encrypt_file(input_path: str, output_path: str, password: str):
    with open(input_path, "rb") as f:
        data = f.read()

    encrypted = encrypt_bytes(data, password)

    with open(output_path, "wb") as f:
        f.write(encrypted)


def decrypt_file(input_path: str, output_path: str, password: str):
    with open(input_path, "rb") as f:
        data = f.read()

    decrypted = decrypt_bytes(data, password)

    with open(output_path, "wb") as f:
        f.write(decrypted)


# ========= Simple CLI =========

def menu():
    print("\n=== AES-256-CBC Encryption Tool ===")
    print("1) Encrypt text")
    print("2) Decrypt text")
    print("3) Encrypt file")
    print("4) Decrypt file")
    print("5) Exit")


def main():
    while True:
        menu()
        choice = input("Choose an option (1-5): ").strip()

        if choice == "1":
            text = input("Enter plaintext: ")
            password = getpass("Enter password: ")
            enc = encrypt_text(text, password)
            print("\n--- Encrypted (Base64) ---")
            print(enc)
            print("--------------------------")

        elif choice == "2":
            cipher_b64 = input("Enter Base64 ciphertext: ")
            password = getpass("Enter password: ")
            try:
                dec = decrypt_text(cipher_b64, password)
                print("\n--- Decrypted Text ---")
                print(dec)
                print("----------------------")
            except Exception as e:
                print(f"[!] Decryption failed: {e}")

        elif choice == "3":
            in_path = input("Input file path: ").strip()
            if not os.path.isfile(in_path):
                print("[!] File not found.")
                continue
            out_path = input("Output (encrypted) file path: ").strip()
            password = getpass("Enter password: ")
            try:
                encrypt_file(in_path, out_path, password)
                print(f"[+] Encrypted file saved to: {out_path}")
            except Exception as e:
                print(f"[!] Encryption failed: {e}")

        elif choice == "4":
            in_path = input("Input (encrypted) file path: ").strip()
            if not os.path.isfile(in_path):
                print("[!] File not found.")
                continue
            out_path = input("Output (decrypted) file path: ").strip()
            password = getpass("Enter password: ")
            try:
                decrypt_file(in_path, out_path, password)
                print(f"[+] Decrypted file saved to: {out_path}")
            except Exception as e:
                print(f"[!] Decryption failed: {e}")

        elif choice == "5":
            print("Exiting.")
            break
        else:
            print("[!] Invalid choice, try again.")


if __name__ == "__main__":
    main()
