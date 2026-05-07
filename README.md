# ENcryptfiles

`vault.py` is a standalone CLI to securely lock (encrypt) and unlock (decrypt) files and folders.

## Usage

```bash
python vault.py --lock /path/to/file-or-folder
python vault.py --unlock /path/to/file-or-folder.vault
```

The tool uses AES-256-GCM with PBKDF2-HMAC-SHA256 key derivation, per-encryption random salt/nonce metadata, hidden password prompts, and secure deletion of plaintext after successful lock operations.
