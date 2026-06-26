"""Key generation module for the OTP Toolkit.

Generates cryptographically secure random keys using Python's secrets module.
Supports hex, base64, and raw binary output formats with configurable sizes.
"""

import base64
import secrets
import time
from pathlib import Path

from config import CHUNK_SIZE, KEY_FORMATS, SIZE_MULTIPLIERS, SIZE_UNITS
from fileio import save_file
from utils import format_size, format_time, sha256_file


def generate_key(size: int, fmt: str="binary") -> bytes:
    """Generate a cryptographically secure random key of the given size in bytes.

    Args:
        size: Number of bytes to generate.
        fmt: Output format - 'binary', 'hex', or 'base64'.

    Returns:
        The generated key as bytes.
    """
    raw=secrets.token_bytes(size)
    if fmt == "hex":
        return raw.hex().encode("ascii")
    elif fmt == "base64":
        return base64.b64encode(raw)
    else:
        return raw


def generate_key_streaming(
    path: Path, size: int, fmt: str="binary"
) -> tuple[int, float]:
    """Generate a key and write it to a file in chunks (for large keys).

    Args:
        path: Output file path.
        size: Number of raw bytes to generate.
        fmt: Output format - 'binary', 'hex', or 'base64'.

    Returns:
        Tuple of (bytes_written, elapsed_seconds).
    """
    start=time.perf_counter()
    written=0
    with open(path, "wb") as f:
        remaining=size
        while remaining > 0:
            chunk_raw=min(CHUNK_SIZE, remaining)
            raw=secrets.token_bytes(chunk_raw)
            if fmt == "hex":
                data=raw.hex().encode("ascii")
            elif fmt == "base64":
                data=base64.b64encode(raw)
            else:
                data=raw
            f.write(data)
            written += len(data)
            remaining -= chunk_raw
    elapsed=time.perf_counter() - start
    return written, elapsed


def keygen_menu() -> None:
    """Interactive menu for key generation."""
    print("\n--- Generate OTP Key ---\n")

    print("Format:")
    for i, f in enumerate(KEY_FORMATS, 1):
        print(f"  {i}. {f.capitalize()}")
    fmt_choice=input("Choose format (1-3): ").strip()
    try:
        fmt_idx=int(fmt_choice) - 1
        if fmt_idx < 0 or fmt_idx >= len(KEY_FORMATS):
            print("  Invalid choice, defaulting to binary.")
            fmt_idx=2
    except ValueError:
        print("  Invalid input, defaulting to binary.")
        fmt_idx=2
    fmt=KEY_FORMATS[fmt_idx]

    print("\nSize unit:")
    for i, u in enumerate(SIZE_UNITS, 1):
        print(f"  {i}. {u}")
    unit_choice=input("Choose unit (1-4): ").strip()
    try:
        unit_idx=int(unit_choice) - 1
        if unit_idx < 0 or unit_idx >= len(SIZE_UNITS):
            print("  Invalid choice, defaulting to bytes.")
            unit_idx=0
    except ValueError:
        print("  Invalid input, defaulting to bytes.")
        unit_idx=0
    unit=SIZE_UNITS[unit_idx]

    amount_str=input(f"Enter size in {unit}: ").strip()
    try:
        amount=int(amount_str)
        if amount <= 0:
            raise ValueError
    except ValueError:
        print("  Invalid size, using 256.")
        amount=256

    raw_bytes=amount * SIZE_MULTIPLIERS[unit]

    print(f"\n  Generating {format_size(raw_bytes)} of random data...")

    output_path=save_file("Save OTP Key")
    if output_path is None:
        print("  Cancelled.")
        return

    written, elapsed=generate_key_streaming(output_path, raw_bytes, fmt)

    print(f"\n  Key saved to: {output_path}")
    print(f"  Size on disk: {format_size(written)}")
    print(f"  SHA-256: {sha256_file(output_path)}")
    print(f"  Generation time: {format_time(elapsed)}")
    print(f"  Speed: {format_size(int(written / elapsed))}/s")
