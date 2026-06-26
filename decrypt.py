"""Decryption module for the OTP Toolkit.

Supports decrypting ciphertext entered manually or from files using XOR with an OTP key.
Streams large files to avoid loading them entirely into RAM.
"""

from pathlib import Path

from fileio import pick_file, read_file_bytes, save_file, write_file_bytes
from utils import (
    file_size,
    format_size,
    format_time,
    print_progress,
    sha256_file,
    xor_stream,
)


def decrypt_text() -> None:
    """Decrypt user-entered hex ciphertext with an OTP key file."""
    print("\n--- Decrypt Text ---\n")
    print("Enter ciphertext as hex (e.g. 'a1b2c3'):")
    hex_input=input("> ").strip()
    if not hex_input:
        print("  No ciphertext entered.")
        return

    try:
        ciphertext=bytes.fromhex(hex_input)
    except ValueError:
        print("  Invalid hex string.")
        return

    print(f"  Ciphertext size: {format_size(len(ciphertext))}")

    key_path=pick_file("Select OTP Key File")
    if key_path is None:
        print("  Cancelled.")
        return

    key_bytes=read_file_bytes(key_path)
    if len(key_bytes) < len(ciphertext):
        print(f"  WARNING: Key ({format_size(len(key_bytes))}) is shorter than ciphertext ({format_size(len(ciphertext))}).")
        return

    key_bytes=key_bytes[: len(ciphertext)]
    plaintext_bytes=bytes(c ^ k for c, k in zip(ciphertext, key_bytes))

    try:
        plaintext=plaintext_bytes.decode("utf-8")
        print(f"\n  Decrypted text: {plaintext}")
    except UnicodeDecodeError:
        print("\n  Result is not valid UTF-8 text. Saving as binary file.")
        output_path=save_file("Save Decrypted Data")
        if output_path is None:
            print("  Cancelled.")
            return
        write_file_bytes(output_path, plaintext_bytes)
        print(f"  Saved to: {output_path}")
        return

    save_choice=input("  Save to file? (y/n): ").strip().lower()
    if save_choice in ("y", "yes"):
        output_path=save_file("Save Decrypted Text")
        if output_path:
            write_file_bytes(output_path, plaintext_bytes)
            print(f"  Saved to: {output_path}")


def decrypt_file() -> None:
    """Decrypt a ciphertext file with an OTP key file using streaming XOR."""
    print("\n--- Decrypt File ---\n")

    input_path=pick_file("Select Ciphertext File")
    if input_path is None:
        print("  Cancelled.")
        return

    key_path=pick_file("Select OTP Key File")
    if key_path is None:
        print("  Cancelled.")
        return

    input_size=file_size(input_path)
    key_size=file_size(key_path)

    print(f"  Ciphertext: {format_size(input_size)}")
    print(f"  Key:        {format_size(key_size)}")

    if key_size < input_size:
        print(f"  WARNING: Key is shorter than ciphertext!")
        return

    output_path=save_file("Save Decrypted Output")
    if output_path is None:
        print("  Cancelled.")
        return

    print("  Decrypting...")
    try:
        processed, elapsed=xor_stream(input_path, key_path, output_path, print_progress)
    except ValueError as e:
        print(f"\n  Error: {e}")
        return

    print(f"\n  Output saved to: {output_path}")
    print(f"  Processed: {format_size(processed)}")
    print(f"  Time: {format_time(elapsed)}")
    if elapsed > 0:
        print(f"  Speed: {format_size(int(processed / elapsed))}/s")
    print(f"  SHA-256: {sha256_file(output_path)}")


def decrypt_menu() -> None:
    """Decryption sub-menu."""
    while True:
        print("\n--- Decrypt ---\n")
        print("  1. Decrypt Text (hex)")
        print("  2. Decrypt File")
        print("  3. Back")
        choice=input("Choose (1-3): ").strip()
        if choice == "1":
            decrypt_text()
        elif choice == "2":
            decrypt_file()
        elif choice == "3":
            break
        else:
            print("  Invalid choice.")
