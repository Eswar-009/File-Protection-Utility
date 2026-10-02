# File Protection Utility

A command-line Python utility for encrypting and decrypting local files using AES-256-GCM and PBKDF2-HMAC-SHA256 password-based key derivation.

## Features

- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA256 key derivation
- Random salt and nonce for every encryption
- Authentication/MAC integrity verification
- Command-line encrypt/decrypt operations
- No external service or network connection required

## Requirements

Python 3.x and the `cryptography` package.

```bash
pip install cryptography
```

## Usage

Encrypt:

```bash
python file_protection.py encrypt secret.txt secret.txt.enc
```

Decrypt:

```bash
python file_protection.py decrypt secret.txt.enc recovered.txt
```

Verify the recovered file on Windows:

```bash
fc /b secret.txt recovered.txt
```

Expected:

```text
FC: no differences encountered
```

## Security Note

Use dummy/test files for demonstrations. Protect passwords carefully. This utility is intended for authorized local file protection and educational use.
