import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vault import lock_path, main, unlock_path


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
