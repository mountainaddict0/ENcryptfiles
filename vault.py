#!/usr/bin/env python3
import argparse
import io
import os
import struct
import sys
import tarfile
from getpass import getpass
from pathlib import Path, PurePosixPath
from typing import List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
except Exception:  # pragma: no cover
    class _DummyColors:
        RED = ""
        GREEN = ""
        CYAN = ""
        YELLOW = ""
        RESET_ALL = ""

    Fore = _DummyColors()
    Style = _DummyColors()


MAGIC = b"EVLT1"
VAULT_EXTENSION = ".vault"
FLAG_DIR = 1
FLAG_FILE = 0
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
PBKDF2_ITERATIONS = 600000


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=KEY_LEN, salt=salt, iterations=PBKDF2_ITERATIONS)
    return kdf.derive(password.encode("utf-8"))


def _secure_delete_file(path: Path) -> None:
    if path.is_symlink():
        path.unlink()
        return
    if not path.is_file():
        return
    size = path.stat().st_size
    block_size = 64 * 1024
    with path.open("r+b", buffering=0) as fh:
        fh.seek(0)
        remaining = size
        zero_block = b"\x00" * block_size
        while remaining > 0:
            chunk = zero_block[: min(block_size, remaining)]
            fh.write(chunk)
            remaining -= len(chunk)
        fh.flush()
        os.fsync(fh.fileno())
    path.unlink()


def _secure_delete_folder(path: Path) -> None:
    for root, dirs, files in os.walk(path, topdown=False):
        root_path = Path(root)
        for name in files:
            _secure_delete_file(root_path / name)
        for name in dirs:
            d = root_path / name
            if d.is_symlink():
                d.unlink()
            elif d.exists():
                d.rmdir()
    path.rmdir()


def _build_encrypted_blob(payload: bytes, password: str, flag: int) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, payload, None)
    header = MAGIC + struct.pack(">B", flag) + salt + nonce + struct.pack(">I", PBKDF2_ITERATIONS)
    return header + ciphertext


def _parse_header(blob: bytes) -> Tuple[int, bytes, bytes, int, bytes]:
    header_len = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN + 4
    if len(blob) <= header_len:
        raise ValueError("Invalid vault file format.")
    if blob[: len(MAGIC)] != MAGIC:
        raise ValueError("Invalid vault file magic.")
    offset = len(MAGIC)
    flag = blob[offset]
    offset += 1
    salt = blob[offset : offset + SALT_LEN]
    offset += SALT_LEN
    nonce = blob[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    iterations = struct.unpack(">I", blob[offset : offset + 4])[0]
    ciphertext = blob[offset + 4 :]
    return flag, salt, nonce, iterations, ciphertext


def _safe_extract_tar(archive_bytes: bytes, destination: Path) -> None:
    destination_resolved = destination.resolve()
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
        for member in tar.getmembers():
            target = destination / member.name
            if not target.resolve().is_relative_to(destination_resolved):
                raise ValueError("Unsafe archive content detected.")
        top_names = set()
        for member in tar.getmembers():
            cleaned_name = member.name.lstrip("/")
            if not cleaned_name:
                continue
            top_names.add(PurePosixPath(cleaned_name).parts[0])
        for top_name in top_names:
            if (destination / top_name).exists():
                raise FileExistsError(f"Refusing to overwrite existing path: {top_name}")
        tar.extractall(destination, filter="data")


def lock_path(path_text: str, password: str) -> Path:
    src = Path(path_text).resolve()
    if not src.exists():
        raise FileNotFoundError(f"Path not found: {src}")
    out_path = src.with_name(src.name.rstrip("/\\") + VAULT_EXTENSION)
    if out_path.exists():
        raise FileExistsError(f"Vault already exists: {out_path}")

    if src.is_file():
        payload = src.read_bytes()
        blob = _build_encrypted_blob(payload, password, FLAG_FILE)
        out_path.write_bytes(blob)
        _secure_delete_file(src)
        return out_path

    if src.is_dir():
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(src, arcname=src.name)
        blob = _build_encrypted_blob(buf.getvalue(), password, FLAG_DIR)
        out_path.write_bytes(blob)
        _secure_delete_folder(src)
        return out_path

    raise ValueError(f"Unsupported path type: {src}")


def unlock_path(path_text: str, password: str) -> Path:
    vault_path = Path(path_text).resolve()
    if not vault_path.is_file():
        raise FileNotFoundError(f"Vault file not found: {vault_path}")
    blob = vault_path.read_bytes()
    flag, salt, nonce, iterations, ciphertext = _parse_header(blob)
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=KEY_LEN, salt=salt, iterations=iterations)
    key = kdf.derive(password.encode("utf-8"))

    try:
        payload = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise PermissionError("Security Alert: Incorrect Key") from exc

    if flag == FLAG_FILE:
        out_path = _file_unlock_output_path(vault_path)
        if out_path.exists():
            raise FileExistsError(f"Refusing to overwrite existing file: {out_path}")
        out_path.write_bytes(payload)
        return out_path
    if flag == FLAG_DIR:
        _safe_extract_tar(payload, vault_path.parent)
        return vault_path.parent
    raise ValueError("Unknown vault payload type.")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Professional AES-256 vault for files and folders.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--lock", metavar="PATH", help="Encrypt file/folder into a .vault archive.")
    group.add_argument("--unlock", metavar="PATH", help="Decrypt a .vault file.")
    return parser


def _file_unlock_output_path(vault_path: Path) -> Path:
    if vault_path.name.endswith(VAULT_EXTENSION):
        return vault_path.with_name(vault_path.name[: -len(VAULT_EXTENSION)])
    return vault_path.with_suffix(".decrypted")


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.lock:
            password = getpass("Enter encryption password: ")
            confirm = getpass("Confirm encryption password: ")
            if password != confirm:
                print(f"{Fore.RED}Error: Passwords do not match.{Style.RESET_ALL}")
                return 2
            out_file = lock_path(args.lock, password)
            print(f"{Fore.GREEN}Locked successfully:{Style.RESET_ALL} {Fore.CYAN}{out_file}{Style.RESET_ALL}")
            return 0

        password = getpass("Enter decryption password: ")
        out_path = unlock_path(args.unlock, password)
        print(f"{Fore.GREEN}Unlocked successfully:{Style.RESET_ALL} {Fore.CYAN}{out_path}{Style.RESET_ALL}")
        return 0
    except PermissionError as exc:
        print(f"{Fore.RED}{exc}{Style.RESET_ALL}")
        return 3
    except (FileNotFoundError, FileExistsError, ValueError, OSError) as exc:
        print(f"{Fore.YELLOW}Operation failed:{Style.RESET_ALL} {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
