import tempfile
import unittest
from pathlib import Path

from vault import lock_path, unlock_path


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

            with self.assertRaisesRegex(PermissionError, "Security Alert: Incorrect Key"):
                unlock_path(str(vault_path), "wrong-key")


if __name__ == "__main__":
    unittest.main()
