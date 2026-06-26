"""Configuration constants for the OTP Toolkit."""

from pathlib import Path

PROJECT_NAME: str="One-Time Pad Toolkit"
PROJECT_DIR: Path=Path(__file__).resolve().parent

CHUNK_SIZE: int=1024 * 1024  # 1 MB streaming buffer

KEY_FORMATS: list[str]=["hex", "base64", "binary"]
SIZE_UNITS: list[str]=["bytes", "KB", "MB", "GB"]

SIZE_MULTIPLIERS: dict[str, int]={
    "bytes": 1,
    "KB": 1024,
    "MB": 1024 * 1024,
    "GB": 1024 * 1024 * 1024,
}

ENTROPY_THRESHOLD_HIGH: float=7.5
ENTROPY_THRESHOLD_LOW: float=4.0

BRUTE_FORCE_MAX_BITS: int=64
BRUTE_FORCE_STEP_BITS: int=8

RANDOMNESS_TEST_SAMPLE_SIZE: int=1_000_000

CPU_THROTTLE_ENABLED: bool=True
CPU_THROTTLE_TARGET: float=70.0
CPU_THROTTLE_CHECK_INTERVAL: int=100_000
CPU_THROTTLE_SLEEP: float=0.05

OTP_WARNING: str=(
    "A One-Time Pad is only theoretically unbreakable if:\n"
    "  - the key is truly random,\n"
    "  - at least as long as the plaintext,\n"
    "  - never reused,\n"
    "  - kept completely secret."
)
