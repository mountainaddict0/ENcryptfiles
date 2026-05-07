# ENcryptfiles

Standalone CLI vault tool for secure file/folder encryption and decryption on Kali Linux.

## Features
- AES-256-GCM encryption via `cryptography.hazmat`
- PBKDF2-HMAC-SHA256 key derivation (32-byte key, random 16-byte salt per encryption)
- Hidden password prompt (`getpass`)
- File support (`<file>.vault`)
- Folder support (recursive `.tar.gz` archive in memory, encrypted to one `.vault`)
- Gatekeeper logic: wrong password shows `Security Alert: Incorrect Key`
- Metadata (salt + IV/nonce + encrypted payload metadata) stored in each vault file
- Secure deletion of original unencrypted source after successful encryption

## Install
```bash
python3 -m pip install cryptography
```

## Usage
```bash
# Encrypt file or folder
python3 vault.py --lock /path/to/data

# Encrypt with explicit output path
python3 vault.py --lock /path/to/data -o /path/to/output.vault

# Decrypt vault
python3 vault.py --unlock /path/to/data.vault

# Force overwrite output
python3 vault.py --unlock /path/to/data.vault --force
```

## Notes
- Decryption asks for password using hidden input.
- On invalid password/MAC mismatch, tool exits safely without touching source vault data.
- Default decrypt output uses the original stored base name.
