import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vault import (
    MAGIC,
    PBKDF2_ITERATIONS,
    _build_encrypted_blob,
    _file_unlock_output_path,
    _parse_header,
    _safe_extract_tar,
    _secure_delete_file,
    _secure_delete_folder,
    lock_path,
    main,
    unlock_path,
)


class VaultTests(unittest.TestCase):
    def test_file_lock_unlock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "note.txt"
            source.write_text("top secret", encoding="utf-8")

            vault_path = lock_path(str(source), "pass123")
            self.assertTrue(vault_path.exists())
            self.assertFalse(source.exists())

            out_path = unlock_path(str(vault_path), "pass123")
            self.assertTrue(out_path.exists())
            self.assertEqual(out_path.read_text(encoding="utf-8"), "top secret")

    def test_dir_lock_unlock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "docs"
            folder.mkdir()
            (folder / "a.txt").write_text("alpha", encoding="utf-8")
            sub = folder / "sub"
            sub.mkdir()
            (sub / "b.txt").write_text("beta", encoding="utf-8")

            vault_path = lock_path(str(folder), "safe-pass")
            self.assertTrue(vault_path.exists())
            self.assertFalse(folder.exists())

            out_path = unlock_path(str(vault_path), "safe-pass")
            self.assertEqual(out_path, root)
            self.assertEqual((root / "docs" / "a.txt").read_text(encoding="utf-8"), "alpha")
            self.assertEqual((root / "docs" / "sub" / "b.txt").read_text(encoding="utf-8"), "beta")

    def test_incorrect_key_security_alert(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "note.txt"
            source.write_text("classified", encoding="utf-8")
            vault_path = lock_path(str(source), "right-key")
            vault_size_before = vault_path.stat().st_size

            with self.assertRaisesRegex(PermissionError, "Security Alert: Incorrect Key"):
                unlock_path(str(vault_path), "wrong-key")
            self.assertTrue(vault_path.exists())
            self.assertEqual(vault_path.stat().st_size, vault_size_before)

    def test_invalid_magic_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad_vault = root / "bad.vault"
            bad_vault.write_bytes(b"NOTVAULT" + (b"\x00" * 128))
            with self.assertRaisesRegex(ValueError, "Invalid vault file magic"):
                unlock_path(str(bad_vault), "any-password")

    def test_parse_header_rejects_short_blob(self):
        with self.assertRaisesRegex(ValueError, "Invalid vault file format"):
            _parse_header(MAGIC + b"\x00")

    def test_parse_header_reads_metadata(self):
        payload = b"payload data"
        blob = _build_encrypted_blob(payload, "meta-pass", 0)
        flag, salt, nonce, iterations, ciphertext = _parse_header(blob)
        self.assertEqual(flag, 0)
        self.assertEqual(len(salt), 16)
        self.assertEqual(len(nonce), 12)
        self.assertEqual(iterations, PBKDF2_ITERATIONS)
        self.assertTrue(ciphertext)

    def test_file_unlock_output_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault_path = root / "secret.txt.vault"
            self.assertEqual(_file_unlock_output_path(vault_path), root / "secret.txt")
            other_path = root / "secret.data"
            self.assertEqual(_file_unlock_output_path(other_path), root / "secret.decrypted")

    def test_unlock_rejects_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "existing.txt"
            source.write_text("data", encoding="utf-8")
            vault_path = lock_path(str(source), "pass123")
            output_path = root / "existing.txt"
            output_path.write_text("already there", encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "Refusing to overwrite existing file"):
                unlock_path(str(vault_path), "pass123")
            self.assertTrue(vault_path.exists())

    def test_unlock_missing_vault_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.vault"
            with self.assertRaisesRegex(FileNotFoundError, "Vault file not found"):
                unlock_path(str(missing), "pass")

    def test_safe_extract_tar_blocks_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            buffer = tempfile.SpooledTemporaryFile()
            with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
                info = tarfile.TarInfo(name="../escape.txt")
                content = b"blocked"
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            buffer.seek(0)
            with self.assertRaisesRegex(ValueError, "Unsafe archive content detected"):
                _safe_extract_tar(buffer.read(), root)

    def test_safe_extract_tar_blocks_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            buffer = tempfile.SpooledTemporaryFile()
            with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
                info = tarfile.TarInfo(name="docs/file.txt")
                content = b"blocked"
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            buffer.seek(0)
            with self.assertRaisesRegex(FileExistsError, "Refusing to overwrite existing path: docs"):
                _safe_extract_tar(buffer.read(), root)

    def test_secure_delete_file_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.txt"
            target.write_text("keep", encoding="utf-8")
            link = root / "link.txt"
            link.symlink_to(target)
            _secure_delete_file(link)
            self.assertFalse(link.exists())
            self.assertTrue(target.exists())

    def test_secure_delete_folder_removes_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "folder"
            folder.mkdir()
            nested = folder / "nested.txt"
            nested.write_text("remove", encoding="utf-8")
            _secure_delete_folder(folder)
            self.assertFalse(folder.exists())

    def test_main_unlock_cli_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "entry.txt"
            source.write_text("entry test", encoding="utf-8")
            vault_path = lock_path(str(source), "cli-pass")

            with patch("vault.getpass", return_value="cli-pass"):
                code = main(["--unlock", str(vault_path)])

            self.assertEqual(code, 0)
            self.assertEqual((root / "entry.txt").read_text(encoding="utf-8"), "entry test")

    def test_main_unlock_cli_wrong_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "entry2.txt"
            source.write_text("entry test 2", encoding="utf-8")
            vault_path = lock_path(str(source), "cli-pass")

            with patch("vault.getpass", return_value="bad-pass"):
                code = main(["--unlock", str(vault_path)])

            self.assertEqual(code, 3)
            self.assertFalse((root / "entry2.txt").exists())
            self.assertTrue(vault_path.exists())

    def test_main_lock_cli_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "cli-lock.txt"
            source.write_text("lock path", encoding="utf-8")

            with patch("vault.getpass", side_effect=["pw123456", "pw123456"]):
                code = main(["--lock", str(source)])

            self.assertEqual(code, 0)
            self.assertFalse(source.exists())
            self.assertTrue((root / "cli-lock.txt.vault").exists())

    def test_main_lock_password_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "bad-lock.txt"
            source.write_text("mismatch", encoding="utf-8")

            with patch("vault.getpass", side_effect=["pw-one", "pw-two"]):
                code = main(["--lock", str(source)])

            self.assertEqual(code, 2)
            self.assertTrue(source.exists())
            self.assertFalse((root / "bad-lock.txt.vault").exists())


if __name__ == "__main__":
    unittest.main()
