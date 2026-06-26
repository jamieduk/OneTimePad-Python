# One Time Pad for Python

**One Time Pad for Python** is a complete Python implementation of the **One-Time Pad (OTP)** cipher with an easy-to-use menu-driven interface for generating keys, encrypting and decrypting text or files, and testing the security of the cipher.

> **Copyright (c) J~Net 2026**

## GitHub

https://github.com/jamieduk/OneTimePad-Python

---

## Features

* Generate cryptographically secure One-Time Pad keys
* Encrypt text
* Decrypt text
* Encrypt files
* Decrypt files
* Crack/Test options for evaluating OTP security
* Simple menu-driven interface
* Pure Python
* Cross-platform (Linux, Windows, macOS)

---

## Requirements

* Python 3.10 or newer

No third-party Python packages are required.

---

## Starting the Program

### Linux

```bash
./start.sh
```

### Manual Start

```bash
python3 main.py
```

---

## Menu

```
1. Generate Key
2. Encrypt
3. Decrypt
4. Crack Options
5. Exit
```

---

## One-Time Pad Security

A correctly implemented One-Time Pad is mathematically proven to be unbreakable.

For this to remain true, **all** of the following conditions must be met:

* The key must be truly random.
* The key must be at least as long as the message.
* Every key must only ever be used once.
* The key must remain completely secret.

If any of these rules are broken, the security of the One-Time Pad is reduced.

---

## Cipher Comparison

| Rank | Cipher                         | Status                              | Approx. Security |
| ---: | ------------------------------ | ----------------------------------- | ---------------- |
|    1 | **One-Time Pad**               | **Unbreakable (if used correctly)** | ★★★★★            |
|    2 | AES-256                        | Industry Standard                   | ★★★★★            |
|    3 | ChaCha20                       | Modern                              | ★★★★★            |
|    4 | AES-128                        | Modern                              | ★★★★★            |
|    5 | Serpent                        | Modern                              | ★★★★★            |
|    6 | Twofish                        | Modern                              | ★★★★★            |
|    7 | Camellia                       | Modern                              | ★★★★★            |
|    8 | Blowfish                       | Older but still respectable         | ★★★★☆            |
|    9 | Enigma Machine (late versions) | Historical                          | ★★☆☆☆            |
|   10 | Lorenz Cipher                  | Historical military cipher          | ★★★☆☆            |
|   11 | DES                            | Broken by brute force               | ★★☆☆☆            |
|   12 | Vigenère Cipher                | Classical                           | ★☆☆☆☆            |
|   13 | Playfair Cipher                | Classical                           | ★☆☆☆☆            |
|   14 | Hill Cipher                    | Educational                         | ★☆☆☆☆            |
|   15 | Affine Cipher                  | Weak                                | ☆☆☆☆☆            |
|   16 | Caesar Cipher                  | Trivial                             | ☆☆☆☆☆            |

---

## Example Files

An example encrypted file is included with the project:

```
enc-text-file01
```

Use it to test the decryption and cracking features.

---

## Educational Purpose

This project is intended for:

* Learning about classical and modern cryptography
* Demonstrating why One-Time Pads are theoretically perfect
* Experimenting with encryption techniques
* Comparing cipher strength

---

## License

Copyright (c) J~Net 2026

This project is provided for educational and research purposes.

