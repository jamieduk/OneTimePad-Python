"""File I/O operations for the OTP Toolkit.

Provides cross-platform file selection and save dialogs using tkinter,
with fallback to manual path entry when no GUI is available.
"""

import tkinter as tk
from pathlib import Path
from tkinter import filedialog
from typing import Any


def _tk_root() -> tk.Tk:
    """Create and return a hidden tkinter root window."""
    root=tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    return root


def pick_file(title: str="Select file") -> Path | None:
    """Open a file picker dialog and return the selected path, or None."""
    try:
        root=_tk_root()
        path_str: str=filedialog.askopenfilename(title=title)
        root.destroy()
        if path_str:
            return Path(path_str)
        return None
    except Exception:
        return _manual_path_entry(f"Enter path ({title}): ")


def save_file(title: str="Save file") -> Path | None:
    """Open a save-file dialog and return the chosen path, or None."""
    try:
        root=_tk_root()
        path_str: str=filedialog.asksaveasfilename(title=title)
        root.destroy()
        if path_str:
            return Path(path_str)
        return None
    except Exception:
        return _manual_path_entry(f"Enter save path ({title}): ")


def _manual_path_entry(prompt: str) -> Path | None:
    """Fallback: prompt the user to type a file path."""
    raw=input(prompt).strip()
    if not raw:
        return None
    p=Path(raw).expanduser().resolve()
    return p


def read_file_bytes(path: Path) -> bytes:
    """Read an entire file into bytes (for small files only)."""
    with open(path, "rb") as f:
        return f.read()


def write_file_bytes(path: Path, data: bytes) -> None:
    """Write bytes to a file, creating parent directories if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def read_text(path: Path) -> str:
    """Read a text file as a string."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_text(path: Path, text: str) -> None:
    """Write a string to a text file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
