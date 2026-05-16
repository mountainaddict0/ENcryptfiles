# ENcryptfiles

`vault.py` is a standalone CLI tool to encrypt and decrypt files/folders.

## CipherNode foundation assets

The `ciphernode/` directory contains foundational, security-focused code artifacts for the CipherNode
secure messaging application (SQLite schema/handlers, responsive desktop UI, cryptographic file
processors, and disappearing-message workers). These files are reference implementations intended to
be integrated into mobile or desktop builds.

## What it does

- AES-256-GCM encryption (`cryptography.hazmat`)
- PBKDF2-HMAC-SHA256 key derivation (password is never stored)
- Random salt + nonce for every encryption
- Hidden password prompts via `getpass`
- Secure deletion of plaintext after successful `--lock`
- File output format: `.vault`

## Install on Kali Linux

1. Install Python tooling (if missing):

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
```

2. Clone the repo and enter it:

```bash
git clone https://github.com/mountainaddict0/ENcryptfiles.git
cd ENcryptfiles
```

3. (Recommended) Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

4. Install dependencies:

```bash
pip install -r requirements.txt
```

## Run the tool

From the repository root:

```bash
python3 vault.py --lock /path/to/file-or-folder
python3 vault.py --unlock /path/to/file-or-folder.vault
```

You will be prompted for passwords securely (input is hidden).

## Examples

Encrypt a file:

```bash
python3 vault.py --lock /home/kali/Documents/secret.txt
```

Result:
- `/home/kali/Documents/secret.txt.vault` is created
- original plaintext file is securely deleted

Decrypt the file:

```bash
python3 vault.py --unlock /home/kali/Documents/secret.txt.vault
```

Encrypt a folder:

```bash
python3 vault.py --lock /home/kali/Documents/private_folder
```

Result:
- `/home/kali/Documents/private_folder.vault` is created
- original folder contents are securely deleted

Decrypt the folder:

```bash
python3 vault.py --unlock /home/kali/Documents/private_folder.vault
```

## Wrong password behavior

If the password is incorrect during unlock, the tool prints:

`Security Alert: Incorrect Key`

It exits safely and does not delete the `.vault` file.
