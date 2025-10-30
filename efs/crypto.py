"""Core cryptographic utilities for the Encrypted File Storage System."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import struct
from typing import Iterable, List, Tuple

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"EFS1"
VERSION = 1
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32
HMAC_KEY_SIZE = 32
HMAC_SIZE = 32
PBKDF2_ITERATIONS = 200_000

_HEADER_STRUCT = struct.Struct(
    ">4sB I 16s 16s I"
)  # magic, version, iterations, salt, iv, path length


@dataclass(frozen=True)
class EncryptionParameters:
    """Parameters captured when encrypting a file."""

    salt: bytes
    iv: bytes
    iterations: int = PBKDF2_ITERATIONS


def generate_salt() -> bytes:
    """Return a cryptographically secure random salt."""

    return os.urandom(SALT_SIZE)


def derive_keys(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> Tuple[bytes, bytes]:
    """Derive independent AES and HMAC keys from *password* and *salt*.

    The PBKDF2 output is split into two 32 byte keys.
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE + HMAC_KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    material = kdf.derive(password.encode("utf-8"))
    enc_key = material[:KEY_SIZE]
    mac_key = material[KEY_SIZE:]
    # Best-effort scrubbing of intermediate material
    del material
    return enc_key, mac_key


def _build_header(path_bytes: bytes, params: EncryptionParameters, ciphertext: bytes) -> bytes:
    header = _HEADER_STRUCT.pack(
        MAGIC,
        VERSION,
        params.iterations,
        params.salt,
        params.iv,
        len(path_bytes),
    )
    header += path_bytes
    header += struct.pack(">Q", len(ciphertext))
    return header


def _parse_header(buffer: bytes) -> Tuple[str, EncryptionParameters, int, int]:
    """Parse the header from *buffer*.

    Returns
    -------
    tuple
        (relative_path, parameters, header_length, ciphertext_length)
    """

    if len(buffer) < _HEADER_STRUCT.size + 8:  # requires room for header and cipher length
        raise ValueError("Encrypted payload truncated before header")

    magic, version, iterations, salt, iv, path_len = _HEADER_STRUCT.unpack_from(buffer, 0)
    if magic != MAGIC:
        raise ValueError("Unrecognized encrypted file format")
    if version != VERSION:
        raise ValueError(f"Unsupported file version: {version}")
    if path_len < 0:
        raise ValueError("Invalid path length")

    offset = _HEADER_STRUCT.size
    path_bytes = buffer[offset : offset + path_len]
    if len(path_bytes) != path_len:
        raise ValueError("Encrypted payload truncated in path metadata")
    offset += path_len

    cipher_len = struct.unpack_from(">Q", buffer, offset)[0]
    offset += 8

    params = EncryptionParameters(salt=salt, iv=iv, iterations=iterations)
    relative_path = path_bytes.decode("utf-8")
    return relative_path, params, offset, cipher_len


def encrypt_file(
    input_path: Path,
    relative_path: Path,
    password: str,
    output_path: Path,
    iterations: int = PBKDF2_ITERATIONS,
) -> Path:
    """Encrypt *input_path* to *output_path*.

    The produced file stores metadata allowing the original relative path
    to be reconstructed during decryption.
    """

    data = input_path.read_bytes()
    params = EncryptionParameters(salt=generate_salt(), iv=os.urandom(IV_SIZE), iterations=iterations)
    enc_key, mac_key = derive_keys(password, params.salt, params.iterations)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(params.iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    path_bytes = relative_path.as_posix().encode("utf-8")
    header = _build_header(path_bytes, params, ciphertext)

    mac = hmac.HMAC(mac_key, hashes.SHA256())
    mac.update(header)
    mac.update(ciphertext)
    tag = mac.finalize()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(header + ciphertext + tag)

    # Attempt to scrub keys from memory
    del enc_key
    del mac_key

    return output_path


def decrypt_file(enc_path: Path, password: str, output_root: Path) -> Path:
    """Decrypt *enc_path* and write the plaintext under *output_root*.

    Returns the path to the decrypted file.
    """

    payload = enc_path.read_bytes()
    if len(payload) <= HMAC_SIZE:
        raise ValueError("Encrypted payload is too small")

    body = payload[:-HMAC_SIZE]
    tag = payload[-HMAC_SIZE:]

    relative_path, params, header_len, cipher_len = _parse_header(body)
    ciphertext = body[header_len:]
    if len(ciphertext) != cipher_len:
        raise ValueError("Encrypted payload truncated in ciphertext")

    enc_key, mac_key = derive_keys(password, params.salt, params.iterations)

    verifier = hmac.HMAC(mac_key, hashes.SHA256())
    verifier.update(body)
    verifier.verify(tag)

    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(params.iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()

    output_path = output_root.joinpath(Path(relative_path))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(data)

    del enc_key
    del mac_key

    return output_path


def collect_input_files(paths: Iterable[Path]) -> List[Tuple[Path, Path]]:
    """Expand *paths* into a list of files with their relative paths."""

    files: List[Tuple[Path, Path]] = []
    for path in paths:
        if path.is_file():
            files.append((path, Path(path.name)))
        elif path.is_dir():
            for file_path in path.rglob("*"):
                if file_path.is_file():
                    rel = file_path.relative_to(path)
                    files.append((file_path, Path(path.name) / rel))
        else:
            raise FileNotFoundError(f"Path does not exist: {path}")
    return files
