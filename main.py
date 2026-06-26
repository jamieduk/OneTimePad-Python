"""One-Time Pad Cryptography Toolkit — Main Entry Point.

Provides a menu-driven interface to all toolkit functionality.
Each menu option delegates to the appropriate module.
"""

import sys

from config import OTP_WARNING, PROJECT_NAME
from keygen import keygen_menu
from encrypt import encrypt_menu
from decrypt import decrypt_menu
from crack import crack_menu


def show_banner() -> None:
    """Display the main menu banner."""
    print()
    print("=" * 30)
    print(f" {PROJECT_NAME}")
    print("=" * 30)


def show_main_menu() -> None:
    """Display the main menu options."""
    print()
    print("1. Generate OTP Key")
    print("2. Encrypt Text / File")
    print("3. Decrypt Text / File")
    print("4. Crack / Security Tests")
    print("5. Exit")


def show_warning() -> None:
    """Display the OTP security warning."""
    print()
    print("  SECURITY NOTICE:")
    print(f"  {OTP_WARNING}")
    print()


def main() -> None:
    """Run the main menu loop."""
    show_banner()
    show_warning()

    while True:
        show_main_menu()
        choice=input("\nChoose (1-5): ").strip()

        if choice == "1":
            keygen_menu()
        elif choice == "2":
            encrypt_menu()
        elif choice == "3":
            decrypt_menu()
        elif choice == "4":
            crack_menu()
        elif choice == "5":
            print("\n  Goodbye.")
            sys.exit(0)
        else:
            print("  Invalid choice. Enter a number between 1 and 5.")


if __name__ == "__main__":
    main()
