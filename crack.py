"""Crack / Security Tests module for the OTP Toolkit.

Educational analysis tools demonstrating OTP security properties:
brute-force infeasibility, frequency analysis, entropy, key reuse detection,
ciphertext XOR, and statistical randomness tests.
"""

import math
import time
from collections import Counter
from pathlib import Path

from config import (
    BRUTE_FORCE_MAX_BITS,
    BRUTE_FORCE_STEP_BITS,
    ENTROPY_THRESHOLD_HIGH,
    ENTROPY_THRESHOLD_LOW,
    RANDOMNESS_TEST_SAMPLE_SIZE,
)
from fileio import pick_file, read_file_bytes
from utils import (
    CpuThrottle,
    file_size,
    format_size,
    format_time,
    shannon_entropy,
    shannon_entropy_file,
    xor_bytes,
)

_throttle=CpuThrottle()


def _xor_bytes_throttled(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings with CPU throttling."""
    result=bytearray(len(a))
    for i in range(len(a)):
        result[i]=a[i] ^ b[i]
        _throttle.check()
    return bytes(result)


def _count_ones_throttled(data: bytes) -> int:
    """Count set bits across all bytes with CPU throttling."""
    total=0
    for b in data:
        total += b.bit_count()
        _throttle.check()
    return total


def _build_counter_throttled(data: bytes) -> Counter[int]:
    """Build a byte frequency counter with CPU throttling."""
    counts: Counter[int]=Counter()
    for b in data:
        counts[b] += 1
        _throttle.check()
    return counts


def brute_force_demo() -> None:
    """Demonstrate why brute-forcing OTP is infeasible as key size grows."""
    print("\n--- Brute Force Demonstration ---\n")
    print("This shows why OTP becomes impossible to brute force as key length increases.\n")
    print(f"{'Bits':>6}  {'Keyspace':>30}  {'Time (1B tries/s)':>25}")
    print("-" * 65)

    for bits in range(BRUTE_FORCE_STEP_BITS, BRUTE_FORCE_MAX_BITS + 1, BRUTE_FORCE_STEP_BITS):
        keyspace=2 ** bits
        tries_per_sec=1_000_000_000
        seconds=keyspace / tries_per_sec

        if keyspace < 1_000_000:
            ks_str=f"{keyspace:,}"
        elif keyspace < 1_000_000_000:
            ks_str=f"{keyspace / 1_000_000:.1f} million"
        elif keyspace < 1_000_000_000_000:
            ks_str=f"{keyspace / 1_000_000_000:.1f} billion"
        else:
            ks_str=f"2^{bits}"

        if seconds < 60:
            time_str=f"{seconds:.2f} seconds"
        elif seconds < 3600:
            time_str=f"{seconds / 60:.2f} minutes"
        elif seconds < 86400:
            time_str=f"{seconds / 3600:.2f} hours"
        elif seconds < 86400 * 365.25:
            time_str=f"{seconds / 86400:.2f} days"
        elif seconds < 86400 * 365.25 * 1_000_000:
            time_str=f"{seconds / (86400 * 365.25):.2f} years"
        else:
            time_str=f"{seconds / (86400 * 365.25 * 1_000_000):.2f} million years"

        print(f"  {bits:>4}  {ks_str:>30}  {time_str:>25}")

    print("\n  For a 256-bit key, brute force is computationally impossible.")
    print("  The OTP is information-theoretically secure when used correctly.")


def frequency_analysis() -> None:
    """Perform frequency analysis on a file and display a text-based chart."""
    print("\n--- Frequency Analysis ---\n")

    path=pick_file("Select File to Analyze")
    if path is None:
        print("  Cancelled.")
        return

    data=read_file_bytes(path)
    if not data:
        print("  File is empty.")
        return

    total=len(data)
    counts=_build_counter_throttled(data)
    print(f"  File size: {format_size(total)}")
    print(f"  Unique byte values: {len(counts)}")
    print(f"  Shannon entropy: {shannon_entropy(data):.4f} bits/byte\n")

    if shannon_entropy(data) > ENTROPY_THRESHOLD_HIGH:
        print("  This data appears highly random (like proper OTP ciphertext).")
        print("  Frequency analysis reveals no patterns.\n")
    elif shannon_entropy(data) < ENTROPY_THRESHOLD_LOW:
        print("  This data has low entropy (likely plaintext or structured data).\n")
    else:
        print("  This data has moderate entropy.\n")

    print("  Byte Frequency Chart (top 20 values):\n")
    print(f"  {'Byte':>6}  {'Count':>10}  {'Freq %':>8}  Chart")
    print("  " + "-" * 55)

    max_count=counts.most_common(1)[0][1] if counts else 1
    for byte_val, count in counts.most_common(20):
        pct=(count / total) * 100
        bar_len=int((count / max_count) * 30)
        bar="#" * bar_len
        char_repr=chr(byte_val) if 32 <= byte_val < 127 else "."
        print(f"  0x{byte_val:02x} ({char_repr})  {count:>10}  {pct:>7.2f}%  {bar}")

    print("\n  Proper OTP ciphertext should show a flat, uniform distribution.")
    print("  Any visible patterns suggest the data is NOT OTP-encrypted.")


def entropy_analysis() -> None:
    """Calculate and compare Shannon entropy of plaintext and ciphertext."""
    print("\n--- Entropy Analysis ---\n")

    print("Select plaintext file:")
    pt_path=pick_file("Select Plaintext File")
    if pt_path is None:
        print("  Cancelled.")
        return

    print("Select ciphertext file:")
    ct_path=pick_file("Select Ciphertext File")
    if ct_path is None:
        print("  Cancelled.")
        return

    pt_entropy=shannon_entropy_file(pt_path, RANDOMNESS_TEST_SAMPLE_SIZE)
    ct_entropy=shannon_entropy_file(ct_path, RANDOMNESS_TEST_SAMPLE_SIZE)

    print(f"\n  Plaintext entropy:  {pt_entropy:.4f} bits/byte")
    print(f"  Ciphertext entropy: {ct_entropy:.4f} bits/byte")
    print(f"  Maximum possible:   8.0000 bits/byte\n")

    if ct_entropy > ENTROPY_THRESHOLD_HIGH:
        print("  Ciphertext entropy is very high — consistent with proper OTP encryption.")
    elif ct_entropy > ENTROPY_THRESHOLD_LOW:
        print("  Ciphertext entropy is moderate — may not be OTP-encrypted.")
    else:
        print("  Ciphertext entropy is low — likely not encrypted at all.")

    print("\n  Proper OTP ciphertext should have entropy close to 8.0 bits/byte,")
    print("  meaning each byte is nearly uniformly random.")


def key_reuse_detection() -> None:
    """Detect possible OTP key reuse by XORing two ciphertexts."""
    print("\n--- Key Reuse Detection ---\n")
    print("If the same OTP key was used to encrypt two messages,")
    print("XORing the ciphertexts reveals the XOR of the plaintexts.\n")

    print("Select first ciphertext:")
    ct1_path=pick_file("Select First Ciphertext")
    if ct1_path is None:
        print("  Cancelled.")
        return

    print("Select second ciphertext:")
    ct2_path=pick_file("Select Second Ciphertext")
    if ct2_path is None:
        print("  Cancelled.")
        return

    ct1=read_file_bytes(ct1_path)
    ct2=read_file_bytes(ct2_path)

    min_len=min(len(ct1), len(ct2))
    ct1=ct1[:min_len]
    ct2=ct2[:min_len]

    result=_xor_bytes_throttled(ct1, ct2)

    printable="".join(chr(b) if 32 <= b < 127 else "." for b in result[:256])

    print(f"\n  Ciphertext 1 size: {format_size(len(ct1))}")
    print(f"  Ciphertext 2 size: {format_size(len(ct2))}")
    print(f"  XOR result size:   {format_size(len(result))}")
    print(f"  XOR entropy:       {shannon_entropy(result):.4f} bits/byte\n")

    if shannon_entropy(result) < ENTROPY_THRESHOLD_LOW:
        print("  LOW ENTROPY DETECTED — likely key reuse!")
        print("  The XOR result shows structure, meaning the same key was used.\n")
    else:
        print("  XOR result appears random — keys are likely different.\n")

    print(f"  First 256 bytes of XOR result (printable chars shown):\n")
    for i in range(0, min(256, len(printable)), 64):
        print(f"  {printable[i:i+64]}")

    print("\n  Why key reuse breaks OTP:")
    print("    C1 XOR C2=(P1 XOR K) XOR (P2 XOR K)=P1 XOR P2")
    print("  The key cancels out, revealing the XOR of the two plaintexts.")
    print("  An attacker can then use linguistic analysis to recover both messages.")


def ciphertext_xor_demo() -> None:
    """Load two ciphertexts, show their XOR, and explain key reuse risks."""
    print("\n--- Ciphertext XOR Demonstration ---\n")
    print("This demonstrates what happens when two ciphertexts encrypted")
    print("with the same OTP key are XORed together.\n")

    print("Select first ciphertext:")
    ct1_path=pick_file("Select First Ciphertext")
    if ct1_path is None:
        print("  Cancelled.")
        return

    print("Select second ciphertext:")
    ct2_path=pick_file("Select Second Ciphertext")
    if ct2_path is None:
        print("  Cancelled.")
        return

    ct1=read_file_bytes(ct1_path)
    ct2=read_file_bytes(ct2_path)

    min_len=min(len(ct1), len(ct2))
    ct1=ct1[:min_len]
    ct2=ct2[:min_len]

    result=_xor_bytes_throttled(ct1, ct2)

    print(f"\n  C1 XOR C2 result (first 512 bytes as hex):\n")
    hex_str=result[:512].hex()
    for i in range(0, len(hex_str), 64):
        print(f"  {hex_str[i:i+64]}")

    print(f"\n  Result entropy: {shannon_entropy(result):.4f} bits/byte")

    if shannon_entropy(result) < ENTROPY_THRESHOLD_LOW:
        print("\n  WARNING: Low entropy indicates key reuse!")
        print("  The XOR of two ciphertexts encrypted with the same key")
        print("  equals the XOR of the two original plaintexts.")
        print("  This completely breaks OTP security.")
    else:
        print("\n  Result appears random — keys are likely different.")

    print("\n  Remember: NEVER reuse an OTP key. Each key must be used exactly once.")


def randomness_tests() -> None:
    """Run statistical randomness tests on a file."""
    print("\n--- Randomness Tests ---\n")

    path=pick_file("Select File to Test")
    if path is None:
        print("  Cancelled.")
        return

    fsize=file_size(path)
    sample_size=min(fsize, RANDOMNESS_TEST_SAMPLE_SIZE)
    data=read_file_bytes(path)
    if len(data) > sample_size:
        data=data[:sample_size]

    if not data:
        print("  File is empty.")
        return

    n=len(data)
    print(f"  Sample size: {format_size(n)} bytes\n")

    # Bit distribution
    ones=_count_ones_throttled(data)
    total_bits=n * 8
    zeros=total_bits - ones
    bit_ratio=ones / total_bits if total_bits > 0 else 0
    print(f"  Bit Distribution:")
    print(f"    Ones:  {ones} ({bit_ratio * 100:.2f}%)")
    print(f"    Zeros: {zeros} ({(1 - bit_ratio) * 100:.2f}%)")
    bit_score=1.0 - abs(bit_ratio - 0.5) * 2
    print(f"    Score: {bit_score:.4f} (1.0=perfect)\n")

    # Byte frequency
    counts=_build_counter_throttled(data)
    expected=n / 256
    chi_sq=sum((c - expected) ** 2 / expected for c in counts.values())
    print(f"  Chi-Square Test:")
    print(f"    Chi-square: {chi_sq:.2f}")
    print(f"    Expected range (95%): 205-310 for 256 df")
    chi_ok=205 <= chi_sq <= 310
    print(f"    Pass: {'Yes' if chi_ok else 'No'}\n")

    # Runs test
    median=sorted(data)[n // 2]
    above: list[int]=[]
    for b in data:
        above.append(1 if b > median else 0)
        _throttle.check()
    runs=1 + sum(1 for i in range(1, len(above)) if above[i] != above[i - 1])
    n1=sum(above)
    n2=n - n1
    if n1 > 0 and n2 > 0:
        expected_runs=1 + (2 * n1 * n2) / n
        std_runs=math.sqrt(
            (2 * n1 * n2 * (2 * n1 * n2 - n)) / (n * n * (n - 1))
        )
        z_runs=(runs - expected_runs) / std_runs if std_runs > 0 else 0
    else:
        expected_runs=0
        z_runs=0

    print(f"  Runs Test (median-based):")
    print(f"    Runs: {runs}")
    print(f"    Expected: {expected_runs:.1f}")
    print(f"    Z-score: {z_runs:.4f}")
    runs_ok=abs(z_runs) < 1.96
    print(f"    Pass (|Z| < 1.96): {'Yes' if runs_ok else 'No'}\n")

    # Entropy
    entropy=shannon_entropy(data)
    entropy_pct=(entropy / 8.0) * 100
    print(f"  Shannon Entropy:")
    print(f"    Entropy: {entropy:.4f} bits/byte")
    print(f"    Percentage of max: {entropy_pct:.2f}%")
    entropy_ok=entropy > ENTROPY_THRESHOLD_HIGH
    print(f"    Pass (> {ENTROPY_THRESHOLD_HIGH}): {'Yes' if entropy_ok else 'No'}\n")

    # Overall score
    tests_passed=sum([bit_score > 0.95, chi_ok, runs_ok, entropy_ok])
    print(f"  Overall Randomness Score: {tests_passed}/4 tests passed")
    if tests_passed == 4:
        print("  The data appears highly random — consistent with proper OTP output.")
    elif tests_passed >= 2:
        print("  The data shows some randomness but may not be ideal OTP output.")
    else:
        print("  The data does NOT appear random — not consistent with OTP output.")


def crack_menu() -> None:
    """Crack / Security Tests sub-menu."""
    while True:
        print("\n--- Crack / Security Tests ---\n")
        print("  1. Brute Force Demonstration")
        print("  2. Frequency Analysis")
        print("  3. Entropy Analysis")
        print("  4. Key Reuse Detection")
        print("  5. Ciphertext XOR Demonstration")
        print("  6. Randomness Tests")
        print("  7. Back")
        choice=input("Choose (1-7): ").strip()
        if choice == "1":
            brute_force_demo()
        elif choice == "2":
            frequency_analysis()
        elif choice == "3":
            entropy_analysis()
        elif choice == "4":
            key_reuse_detection()
        elif choice == "5":
            ciphertext_xor_demo()
        elif choice == "6":
            randomness_tests()
        elif choice == "7":
            break
        else:
            print("  Invalid choice.")
