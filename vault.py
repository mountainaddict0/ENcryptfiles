#!/usr/bin/env python3
"""Secure file and folder locker for Kali Linux."""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import struct
import sys
import tarfile
import tempfile
from getpass import getpass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"VAULT1"
SALT_LEN = 16
NONCE_LEN = 12
PBKDF2_ITERS = 600_000
# OWASP guidance (2023+) recommends ~600k+ PBKDF2-HMAC-SHA256 iterations.
KEY_LEN = 32


class VaultError(Exception):
    """Handled vault operation failure."""


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte encryption key from a user password."""
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=KEY_LEN, salt=salt, iterations=PBKDF2_ITERS)
    return kdf.derive(password.encode("utf-8"))


def secure_delete_file(path: Path) -> None:
    """Best-effort secure delete by overwriting with zeros then removing."""
    if not path.exists():
        return
    if path.is_symlink():
        path.unlink()
        return
    length = path.stat().st_size
    chunk = b"\x00" * 1024 * 1024
    try:
        handle = path.open("r+b", buffering=0)
    except ValueError:
        # Some file types/filesystems reject unbuffered binary access; fall back safely.
        handle = path.open("r+b")
    with handle:
        remaining = length
        while remaining > 0:
            to_write = min(len(chunk), remaining)
            handle.write(chunk[:to_write])
            remaining -= to_write
        handle.flush()
        os.fsync(handle.fileno())
    path.unlink()


def secure_delete_directory(path: Path) -> None:
    """Secure-delete directory contents (files) then remove directories."""
    for root, dirs, files in os.walk(path, topdown=False):
        root_path = Path(root)
        for filename in files:
            secure_delete_file(root_path / filename)
        for dirname in dirs:
            dir_path = root_path / dirname
            if dir_path.is_symlink():
                dir_path.unlink()
            else:
                dir_path.rmdir()
    path.rmdir()


def secure_delete_path(path: Path) -> None:
    """Route secure deletion to file or directory handlers."""
    if path.is_file() or path.is_symlink():
        secure_delete_file(path)
    elif path.is_dir():
        secure_delete_directory(path)


def archive_directory_to_bytes(directory: Path) -> bytes:
    """Archive directory recursively into a .tar.gz byte stream."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        tar.add(directory, arcname=directory.name)
    return buffer.getvalue()


def safe_extract_tar_gz(tar_bytes: bytes, destination: Path) -> None:
    """Safely extract tar.gz bytes to destination."""
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        dest_root = destination.resolve()
        for member in tar.getmembers():
            target = (destination / member.name).resolve()
            try:
                is_safe = os.path.commonpath([str(dest_root), str(target)]) == str(dest_root)
            except ValueError:
                is_safe = False
            if not is_safe:
                raise VaultError("Unsafe archive path detected.")
        tar.extractall(path=destination)


def normalize_name(path: Path) -> str:
    """Return basename used for metadata and default restore target."""
    return path.name


def read_input_payload(input_path: Path) -> tuple[str, str, bytes]:
    """Return tuple: (payload_type, original_name, payload_bytes)."""
    if input_path.is_file():
        return "file", normalize_name(input_path), input_path.read_bytes()
    if input_path.is_dir():
        return "folder", normalize_name(input_path), archive_directory_to_bytes(input_path)
    raise VaultError(f"Input path is neither file nor directory: {input_path}")


def default_vault_output(input_path: Path) -> Path:
    return input_path.with_name(f"{input_path.name}.vault")


def encrypt_path(input_path: Path, output_path: Path, force: bool) -> None:
    if not input_path.exists():
        raise VaultError(f"Input does not exist: {input_path}")
    if output_path.exists() and not force:
        raise VaultError(f"Output already exists: {output_path} (use --force)")

    password = getpass("Enter password: ")
    confirm = getpass("Confirm password: ")
    if not password:
        raise VaultError("Password cannot be empty.")
    if password != confirm:
        raise VaultError("Passwords do not match.")

    payload_type, original_name, payload = read_input_payload(input_path)
    metadata = json.dumps({"type": payload_type, "name": original_name}, separators=(",", ":")).encode("utf-8")
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, payload, metadata)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as out:
        out.write(MAGIC)
        out.write(salt)
        out.write(nonce)
        out.write(struct.pack(">I", len(metadata)))
        out.write(metadata)
        out.write(ciphertext)

    read_vault(output_path)
    secure_delete_path(input_path)
    print(f"Locked successfully: {output_path}")


def read_vault(vault_path: Path) -> tuple[bytes, bytes, bytes, bytes]:
    """Read vault and return tuple: (salt, nonce, metadata_bytes, ciphertext)."""
    with vault_path.open("rb") as source:
        magic = source.read(len(MAGIC))
        if magic != MAGIC:
            raise VaultError("Invalid vault format.")
        salt = source.read(SALT_LEN)
        nonce = source.read(NONCE_LEN)
        if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN:
            raise VaultError("Corrupted vault metadata.")
        raw_meta_len = source.read(4)
        if len(raw_meta_len) != 4:
            raise VaultError("Corrupted vault metadata.")
        (meta_len,) = struct.unpack(">I", raw_meta_len)
        metadata = source.read(meta_len)
        if len(metadata) != meta_len:
            raise VaultError("Corrupted vault metadata.")
        ciphertext = source.read()
    if not ciphertext:
        raise VaultError("Vault has no encrypted payload.")
    return salt, nonce, metadata, ciphertext


def parse_vault_metadata(metadata_bytes: bytes) -> dict[str, str]:
    try:
        metadata = json.loads(metadata_bytes.decode("utf-8"))
        payload_type = metadata["type"]
        name = metadata["name"]
        if payload_type not in {"file", "folder"} or not isinstance(name, str) or not name:
            raise KeyError
        return metadata
    except (ValueError, KeyError, TypeError):
        raise VaultError("Vault metadata is invalid.") from None


def pick_decrypt_target(vault_path: Path, metadata: dict, output_override: Path | None) -> Path:
    """Choose decrypt output path using override, else stored original name."""
    if output_override is not None:
        return output_override
    return vault_path.with_name(metadata["name"])


def decrypt_vault(
    vault_path: Path,
    output_path: Path,
    force: bool,
    vault_parts: tuple[bytes, bytes, bytes, bytes] | None = None,
    metadata: dict[str, str] | None = None,
) -> None:
    if not vault_path.is_file():
        raise VaultError(f"Vault file does not exist: {vault_path}")
    if output_path.exists() and not force:
        raise VaultError(f"Output already exists: {output_path} (use --force)")

    salt, nonce, metadata_bytes, ciphertext = vault_parts if vault_parts else read_vault(vault_path)
    parsed_metadata = metadata if metadata is not None else parse_vault_metadata(metadata_bytes)
    payload_type = parsed_metadata["type"]

    password = getpass("Enter password: ")
    key = derive_key(password, salt)
    try:
        payload = AESGCM(key).decrypt(nonce, ciphertext, metadata_bytes)
    except InvalidTag:
        print("Security Alert: Incorrect Key")
        raise SystemExit(1) from None

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if payload_type == "file":
        output_path.write_bytes(payload)
    else:
        with tempfile.TemporaryDirectory(dir=str(output_path.parent)) as temp_dir:
            temp_root = Path(temp_dir)
            safe_extract_tar_gz(payload, temp_root)
            children = list(temp_root.iterdir())
            if len(children) != 1 or not children[0].is_dir():
                raise VaultError(f"Invalid archive: expected one root directory, found {len(children)} items.")
            extracted_root = children[0]
            if output_path.exists():
                if output_path.is_dir():
                    shutil.rmtree(output_path)
                else:
                    output_path.unlink()
            shutil.move(str(extracted_root), str(output_path))
    print(f"Unlocked successfully: {output_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Securely lock and unlock files/folders into .vault containers.")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--lock", metavar="PATH", help="Encrypt a file or folder into a .vault file.")
    action.add_argument("--unlock", metavar="VAULT", help="Decrypt a .vault file.")
    parser.add_argument("-o", "--output", metavar="PATH", help="Output file/folder path.")
    parser.add_argument("--force", action="store_true", help="Overwrite output path if it already exists.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.lock:
            input_path = Path(args.lock).expanduser().resolve()
            output_path = Path(args.output).expanduser().resolve() if args.output else default_vault_output(input_path)
            encrypt_path(input_path, output_path, args.force)
        else:
            vault_path = Path(args.unlock).expanduser().resolve()
            override = Path(args.output).expanduser().resolve() if args.output else None
            vault_parts = read_vault(vault_path)
            metadata = parse_vault_metadata(vault_parts[2])
            output_path = pick_decrypt_target(vault_path, metadata, override)
            decrypt_vault(vault_path, output_path, args.force, vault_parts=vault_parts, metadata=metadata)
    except VaultError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
