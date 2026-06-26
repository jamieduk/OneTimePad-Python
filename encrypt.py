"""Encryption module for the OTP Toolkit.

Supports encrypting text entered directly or files using XOR with an OTP key.
Streams large files to avoid loading them entirely into RAM.
"""

from pathlib import Path

from config import OTP_WARNING
from fileio import pick_file, read_file_bytes, save_file, write_file_bytes
from utils import (
    confirm,
    file_size,
    format_size,
    format_time,
    print_progress,
    sha256_file,
    xor_stream,
)


def encrypt_text() -> None:
    """Encrypt user-entered text with an OTP key file."""
    print("\n--- Encrypt Text ---\n")
    plaintext=input("Enter text to encrypt: ")
    if not plaintext:
        print("  No text entered.")
        return

    plaintext_bytes=plaintext.encode("utf-8")
    print(f"  Plaintext size: {format_size(len(plaintext_bytes))}")

    key_path=pick_file("Select OTP Key File")
    if key_path is None:
        print("  Cancelled.")
        return

    key_bytes=read_file_bytes(key_path)
    if len(key_bytes) < len(plaintext_bytes):
        print(f"  WARNING: Key ({format_size(len(key_bytes))}) is shorter than plaintext ({format_size(len(plaintext_bytes))}).")
        print(OTP_WARNING)
        if not confirm("  Continue anyway?"):
            return

    key_bytes=key_bytes[: len(plaintext_bytes)]
    ciphertext=bytes(p ^ k for p, k in zip(plaintext_bytes, key_bytes))

    output_path=save_file("Save Ciphertext")
    if output_path is None:
        print("  Cancelled.")
        return

    write_file_bytes(output_path, ciphertext)
    print(f"  Ciphertext saved to: {output_path}")
    print(f"  Size: {format_size(len(ciphertext))}")
    print(f"  SHA-256: {sha256_file(output_path)}")


def encrypt_file() -> None:
    """Encrypt a file with an OTP key file using streaming XOR."""
    print("\n--- Encrypt File ---\n")

    input_path=pick_file("Select Plaintext File")
    if input_path is None:
        print("  Cancelled.")
        return

    key_path=pick_file("Select OTP Key File")
    if key_path is None:
        print("  Cancelled.")
        return

    input_size=file_size(input_path)
    key_size=file_size(key_path)

    print(f"  Plaintext: {format_size(input_size)}")
    print(f"  Key:       {format_size(key_size)}")

    if key_size < input_size:
        print(f"  WARNING: Key is shorter than plaintext!")
        print(OTP_WARNING)
        if not confirm("  Continue anyway?"):
            return

    output_path=save_file("Save Ciphertext")
    if output_path is None:
        print("  Cancelled.")
        return

    print("  Encrypting...")
    try:
        processed, elapsed=xor_stream(input_path, key_path, output_path, print_progress)
    except ValueError as e:
        print(f"\n  Error: {e}")
        return

    print(f"\n  Ciphertext saved to: {output_path}")
    print(f"  Processed: {format_size(processed)}")
    print(f"  Time: {format_time(elapsed)}")
    if elapsed > 0:
        print(f"  Speed: {format_size(int(processed / elapsed))}/s")
    print(f"  SHA-256: {sha256_file(output_path)}")


def encrypt_menu() -> None:
    """Encryption sub-menu."""
    while True:
        print("\n--- Encrypt ---\n")
        print("  1. Encrypt Text")
        print("  2. Encrypt File")
        print("  3. Back")
        choice=input("Choose (1-3): ").strip()
        if choice == "1":
            encrypt_text()
        elif choice == "2":
            encrypt_file()
        elif choice == "3":
            break
        else:
            print("  Invalid choice.")
