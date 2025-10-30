"""Command-line interface for the Encrypted File Storage System."""

from __future__ import annotations

import argparse
import getpass
import importlib
import sys
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Sequence, Tuple


DEFAULT_PBKDF2_ITERATIONS = 200_000


def _validate_iterations(value: str) -> int:
    try:
        ivalue = int(value)
    except ValueError as exc:  # pragma: no cover - defensive programming
        raise argparse.ArgumentTypeError("Iterations must be an integer") from exc
    if ivalue <= 0:
        raise argparse.ArgumentTypeError("Iterations must be positive")
    return ivalue


def _obtain_password(provided: str | None, confirm: bool) -> str:
    if provided:
        return provided

    password = getpass.getpass("Password: ")
    if confirm:
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise ValueError("Passwords do not match")
    if not password:
        raise ValueError("Password must not be empty")
    return password


def _iter_paths(raw_paths: Sequence[str]) -> Iterable[Path]:
    for item in raw_paths:
        yield Path(item).expanduser().resolve()


@lru_cache(maxsize=1)
def _get_crypto_deps() -> Tuple[object, type]:
    """Import heavy crypto dependencies on demand.

    Returns a tuple of the ``efs.crypto`` module and the
    :class:`cryptography.exceptions.InvalidSignature` exception type.
    Raises ``RuntimeError`` with an actionable message when the optional
    dependency is missing.
    """

    try:
        crypto_mod = importlib.import_module("efs.crypto")
        from cryptography.exceptions import InvalidSignature  # type: ignore
    except ModuleNotFoundError as exc:  # pragma: no cover - import guard
        missing_root = exc.name.split(".")[0]
        if missing_root == "cryptography":
            raise RuntimeError(
                "The 'cryptography' package is required. Install dependencies via "
                "`pip install -r requirements.txt`."
            ) from exc
        raise

    return crypto_mod, InvalidSignature


def _resolve_iterations_default() -> int:
    """Best-effort fetch of the crypto default iterations.

    Falls back to :data:`DEFAULT_PBKDF2_ITERATIONS` when the optional
    dependency is unavailable so that ``--help`` remains functional without
    cryptography installed.
    """

    try:
        crypto_mod = importlib.import_module("efs.crypto")
    except ModuleNotFoundError as exc:  # pragma: no cover - import guard
        missing_root = exc.name.split(".")[0]
        if missing_root == "cryptography":
            return DEFAULT_PBKDF2_ITERATIONS
        raise

    return getattr(crypto_mod, "PBKDF2_ITERATIONS", DEFAULT_PBKDF2_ITERATIONS)


def encrypt_command(args: argparse.Namespace) -> int:
    try:
        crypto, _ = _get_crypto_deps()
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1

    password = _obtain_password(args.password, confirm=not args.password)

    inputs = list(_iter_paths(args.inputs))
    files = crypto.collect_input_files(inputs)
    output_root = Path(args.output).expanduser().resolve()

    for input_path, rel_path in files:
        encrypted_rel = Path(f"{rel_path}.enc")
        output_path = output_root / encrypted_rel
        crypto.encrypt_file(
            input_path,
            rel_path,
            password,
            output_path,
            iterations=args.iterations,
        )
        print(f"Encrypted {input_path} -> {output_path}")

    return 0


def decrypt_command(args: argparse.Namespace) -> int:
    try:
        crypto, InvalidSignature = _get_crypto_deps()
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1

    password = _obtain_password(args.password, confirm=False)
    output_root = Path(args.output).expanduser().resolve()

    for enc in _iter_paths(args.inputs):
        try:
            decrypted = crypto.decrypt_file(enc, password, output_root)
        except FileNotFoundError as exc:
            print(exc, file=sys.stderr)
            return 1
        except InvalidSignature:
            print(f"Integrity verification failed for {enc}", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"Failed to decrypt {enc}: {exc}", file=sys.stderr)
            return 1
        else:
            print(f"Decrypted {enc} -> {decrypted}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="efs",
        description="Encrypt and decrypt files using AES-256 with PBKDF2 and HMAC",
    )
    parser.add_argument(
        "--iterations",
        type=_validate_iterations,
        default=_resolve_iterations_default(),
        help="PBKDF2 iterations (default: %(default)s)",
    )
    parser.add_argument(
        "--password",
        help="Password to use for encryption/decryption (discouraged on shared systems)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt files and folders")
    encrypt_parser.add_argument(
        "inputs",
        nargs="+",
        help="Files or directories to encrypt",
    )
    encrypt_parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Directory to store encrypted files",
    )
    encrypt_parser.set_defaults(func=encrypt_command)

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt previously encrypted files")
    decrypt_parser.add_argument(
        "inputs",
        nargs="+",
        help="Encrypted .enc files to decrypt",
    )
    decrypt_parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Directory where decrypted files will be written",
    )
    decrypt_parser.set_defaults(func=decrypt_command)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
