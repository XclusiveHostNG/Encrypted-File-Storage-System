# Encrypted File Storage System

A Python-based command-line utility for encrypting and decrypting files and folders using AES-256 in CBC mode with PBKDF2-derived keys and integrity protection via HMAC-SHA256.

## Features

- **AES-256 encryption** with PKCS7 padding and random IVs for every file.
- **Password-based key derivation** using PBKDF2-HMAC-SHA256 with a configurable iteration count.
- **Integrity verification** by authenticating encrypted payloads with HMAC-SHA256.
- **Secure metadata handling** that preserves relative file paths inside the encrypted container.
- **Batch processing** of multiple files or entire directory trees.
- **Cross-platform CLI** built with `argparse`.

## Installation

1. Create a virtual environment (recommended):

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows use `.venv\\Scripts\\activate`
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

   If you do not have a `requirements.txt`, install the `cryptography` package directly:

   ```bash
   pip install cryptography
   ```

## Usage

The CLI exposes two commands: `encrypt` and `decrypt`. Run `python -m efs.cli --help` for the full reference.

### Encrypting files or folders

```bash
python -m efs.cli --iterations 200000 encrypt -o encrypted/ path/to/file.txt path/to/folder
```

- You will be prompted for a password (with confirmation). Provide `--password` only when automation outweighs the security risk of exposing the secret in process lists.
- Encrypted files are written beneath the specified output directory, preserving the source structure and appending `.enc` to each filename.

### Decrypting files

```bash
python -m efs.cli decrypt -o decrypted/ encrypted/path/to/file.txt.enc
```

- The tool restores the original relative paths beneath the output directory.
- Integrity is verified before decryption. If verification fails the process stops and exits with code `2`.

## Cryptographic Design

- **Key Derivation:** PBKDF2-HMAC-SHA256 derives 64 bytes of keying material from the supplied password and a 16-byte random salt. The material is split into a 32-byte AES key and a 32-byte HMAC key. The default iteration count is 200,000 and can be overridden with `--iterations`.
- **Encryption:** Data is padded with PKCS7 and encrypted using AES-256 in CBC mode with a randomly generated 16-byte IV per file.
- **Integrity:** An HMAC-SHA256 tag covers the file header and ciphertext. Verification happens prior to decryption to protect against tampering.
- **File Format:** Each encrypted file stores a header containing a magic value, version, PBKDF2 iteration count, salt, IV, original relative path, and ciphertext length. This metadata ensures the original layout can be reconstructed during decryption.
- **Key Handling:** Derived keys live only in memory for the duration of the cryptographic operation and are explicitly deleted afterwards to reduce exposure time.

## Development

- `efs/crypto.py` implements the cryptographic primitives, metadata handling, and helpers for expanding directories into file lists.
- `efs/cli.py` provides the command-line interface and orchestrates encryption/decryption workflows.

Contributions and security reviews are welcome. Please open an issue or pull request with suggestions and improvements.
