"""Utility functions for the OTP Toolkit."""

import hashlib
import math
import os
import time
from collections import Counter
from pathlib import Path
from typing import Callable

from config import (
    CHUNK_SIZE,
    CPU_THROTTLE_CHECK_INTERVAL,
    CPU_THROTTLE_ENABLED,
    CPU_THROTTLE_SLEEP,
    CPU_THROTTLE_TARGET,
)


class CpuThrottle:
    """Auto-throttle CPU usage by monitoring /proc/stat and sleeping when load exceeds target.

    Usage:
        throttle=CpuThrottle()
        for chunk in large_data:
            process(chunk)
            throttle.check()  # sleeps if CPU is too hot
    """

    def __init__(
        self,
        enabled: bool=CPU_THROTTLE_ENABLED,
        target_pct: float=CPU_THROTTLE_TARGET,
        check_interval: int=CPU_THROTTLE_CHECK_INTERVAL,
        sleep_sec: float=CPU_THROTTLE_SLEEP,
    ) -> None:
        self._enabled=enabled and os.path.exists("/proc/stat")
        self._target=target_pct
        self._interval=check_interval
        self._sleep=sleep_sec
        self._counter=0
        self._prev_idle: int=0
        self._prev_total: int=0

    def _read_cpu(self) -> tuple[int, int]:
        """Read /proc/stat and return (idle, total) from the first cpu line."""
        with open("/proc/stat", "r") as f:
            for line in f:
                if line.startswith("cpu "):
                    parts=line.split()
                    vals=[int(x) for x in parts[1:]]
                    total=sum(vals)
                    idle=vals[3] + (vals[4] if len(vals) > 4 else 0)
                    return idle, total
        return 0, 0

    def _cpu_pct(self) -> float:
        """Return current CPU usage percentage (0-100)."""
        idle, total=self._read_cpu()
        if self._prev_total == 0:
            self._prev_idle, self._prev_total=idle, total
            return 0.0
        delta_idle=idle - self._prev_idle
        delta_total=total - self._prev_total
        self._prev_idle, self._prev_total=idle, total
        if delta_total == 0:
            return 0.0
        return 100.0 * (1.0 - delta_idle / delta_total)

    def check(self) -> None:
        """Call periodically during heavy loops. Sleeps if CPU exceeds target."""
        if not self._enabled:
            return
        self._counter += 1
        if self._counter % self._interval != 0:
            return
        usage=self._cpu_pct()
        if usage > self._target:
            time.sleep(self._sleep)

    def status(self) -> str:
        """Return a human-readable status string."""
        if not self._enabled:
            return "CPU throttle: disabled"
        return f"CPU throttle: target={self._target}%  sleep={self._sleep}s  interval={self._interval}"


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of the given bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a file (streamed)."""
    h=hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk=f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def file_size(path: Path) -> int:
    """Return the size of a file in bytes."""
    return path.stat().st_size


def format_size(size_bytes: int) -> str:
    """Return a human-readable file size string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def format_time(seconds: float) -> str:
    """Return a human-readable time duration string."""
    if seconds < 0.001:
        return f"{seconds * 1_000_000:.2f} µs"
    elif seconds < 1:
        return f"{seconds * 1000:.2f} ms"
    elif seconds < 60:
        return f"{seconds:.2f} s"
    else:
        m, s=divmod(seconds, 60)
        return f"{int(m)}m {s:.2f}s"


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0.0 to 8.0)."""
    if not data:
        return 0.0
    total=len(data)
    counts=Counter(data)
    entropy=0.0
    for count in counts.values():
        p=count / total
        entropy -= p * math.log2(p)
    return entropy


def shannon_entropy_file(path: Path, sample_size: int | None=None) -> float:
    """Calculate Shannon entropy of a file (streamed, optionally sampled)."""
    h=hashlib.sha256()
    total=0
    counts: Counter[int]=Counter()
    with open(path, "rb") as f:
        while True:
            chunk=f.read(CHUNK_SIZE)
            if not chunk:
                break
            if sample_size is not None and total >= sample_size:
                break
            if sample_size is not None:
                remaining=sample_size - total
                if len(chunk) > remaining:
                    chunk=chunk[:remaining]
            h.update(chunk)
            counts.update(chunk)
            total += len(chunk)
    if total == 0:
        return 0.0
    entropy=0.0
    for count in counts.values():
        p=count / total
        entropy -= p * math.log2(p)
    return entropy


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def xor_stream(
    input_path: Path,
    key_path: Path,
    output_path: Path,
    progress_callback: Callable[[int, int], None] | None=None,
) -> tuple[int, float]:
    """Stream-XOR input with key, writing to output. Returns (bytes_processed, elapsed)."""
    start=time.perf_counter()
    total=file_size(input_path)
    processed=0
    with open(input_path, "rb") as fin, open(key_path, "rb") as fkey, open(
        output_path, "wb"
    ) as fout:
        while True:
            data_chunk=fin.read(CHUNK_SIZE)
            if not data_chunk:
                break
            key_chunk=fkey.read(len(data_chunk))
            if len(key_chunk) < len(data_chunk):
                raise ValueError("Key is shorter than input data")
            fout.write(xor_bytes(data_chunk, key_chunk))
            processed += len(data_chunk)
            if progress_callback:
                progress_callback(processed, total)
    elapsed=time.perf_counter() - start
    return processed, elapsed


def progress_bar(current: int, total: int, width: int=40) -> str:
    """Return a text progress bar string."""
    if total == 0:
        return "[%-40s] 100.0%%" % ("=" * width)
    pct=current / total
    filled=int(width * pct)
    bar="=" * filled + "-" * (width - filled)
    return f"[{bar}] {pct * 100:5.1f}%"


def print_progress(current: int, total: int) -> None:
    """Print a progress bar to stdout (overwrites current line)."""
    bar=progress_bar(current, total)
    print(f"\r  {bar}", end="", flush=True)
    if current >= total:
        print()


def get_positive_int(prompt: str) -> int:
    """Prompt the user for a positive integer."""
    while True:
        try:
            val=int(input(prompt).strip())
            if val > 0:
                return val
            print("  Value must be positive.")
        except ValueError:
            print("  Invalid integer. Try again.")


def get_menu_choice(prompt: str, min_val: int, max_val: int) -> int:
    """Prompt the user for a menu choice within a range."""
    while True:
        try:
            val=int(input(prompt).strip())
            if min_val <= val <= max_val:
                return val
            print(f"  Enter a number between {min_val} and {max_val}.")
        except ValueError:
            print("  Invalid input. Enter a number.")


def confirm(prompt: str) -> bool:
    """Ask a yes/no question, return True for yes."""
    while True:
        ans=input(f"{prompt} (y/n): ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("  Please answer y or n.")
