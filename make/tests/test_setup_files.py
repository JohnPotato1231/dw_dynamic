"""Repair path/ACL boundaries, without changing an installed agent."""

import importlib.util
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("setup_files", ROOT / "os_win_installer" / "setup_files.py")
files = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(files)
SYSTEM, ADMINS, USER = "S-1-5-18", "S-1-5-32-544", "S-1-5-21-123-1001"
TRUSTED = {SYSTEM, ADMINS, "S-1-5-80-123"}


class DirectoryAclTests(unittest.TestCase):
    def test_trusted_owner_and_system_write_with_user_read_are_allowed(self):
        files.validate_directory_acl(ADMINS, [(0, 0, 0x1F01FF, SYSTEM),
            (0, 0, 0x1200A9, USER)], TRUSTED)

    def test_untrusted_owner_or_null_dacl_are_rejected(self):
        for owner, aces in ((USER, []), (SYSTEM, None)):
            with self.assertRaises(ValueError):
                files.validate_directory_acl(owner, aces, TRUSTED)

    def test_each_untrusted_write_permission_is_rejected_including_inherited(self):
        for mask in (2, 4, 0x10, 0x40, 0x100, 0x10000, 0x40000,
                     0x80000, 0x40000000, 0x10000000):
            for flags in (0, 0x10):
                with self.subTest(mask=mask, flags=flags), self.assertRaises(ValueError):
                    files.validate_directory_acl(SYSTEM, [(0, flags, mask, USER)], TRUSTED)

    def test_inherit_only_aces_and_standard_deny_aces_do_not_grant_folder_access(self):
        files.validate_directory_acl(SYSTEM, [(0, 8, 0x1F01FF, USER),
            (1, 0, 0x1F01FF, USER), (9, 8, 0, None)], TRUSTED)

    def test_unknown_effective_ace_types_fail_closed_even_for_trusted_accounts(self):
        for kind in (2, 5, 9, 11, 255):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                files.validate_directory_acl(SYSTEM, [(kind, 0, 0, SYSTEM)], TRUSTED)

    def test_earlier_deny_does_not_relax_conservative_untrusted_write_policy(self):
        with self.assertRaises(ValueError):
            files.validate_directory_acl(SYSTEM, [(1, 0, 2, USER), (0, 0, 2, USER)], TRUSTED)

    def test_directory_check_uses_acl_policy_and_preserves_existing_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "keep.txt"
            sentinel.write_text("unchanged", encoding="utf-8")
            with patch.object(files, "_read_directory_acl", return_value=(SYSTEM,
                    [(0, 0, 2, USER)], TRUSTED)):
                with self.assertRaises(ValueError):
                    files.verify_protected_directory(directory)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")

    @unittest.skipUnless(os.name == "nt", "Windows security API smoke test")
    def test_real_program_files_acl_is_readable_and_protected(self):
        files.verify_protected_directory(Path(os.environ["ProgramFiles"]))


class DirectoryPathTests(unittest.TestCase):
    def test_ordinary_nested_directory_and_missing_new_destination_are_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            nested = Path(directory) / "nested"
            nested.mkdir()
            (nested / "keep.txt").write_text("unchanged")
            files.verify_no_reparse_points(directory, recursive=True)
            files.verify_no_reparse_points(nested / "new")

    def test_reparse_ancestor_or_descendant_is_rejected_without_following_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir()
            original = Path.lstat

            def mark_reparse(path):
                details = original(path)
                return SimpleNamespace(st_mode=details.st_mode,
                    st_file_attributes=0x400) if path == nested else details

            with patch.object(Path, "lstat", mark_reparse):
                with self.assertRaises(ValueError):
                    files.verify_no_reparse_points(nested / "missing")
                with self.assertRaises(ValueError):
                    files.verify_no_reparse_points(root, recursive=True)

    def test_symbolic_link_mode_is_also_rejected(self):
        with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFLNK,
                                                                   st_file_attributes=0)):
            with self.assertRaises(ValueError):
                files.verify_no_reparse_points("some-folder")

    def test_rename_preserves_old_contents_and_refuses_existing_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            source, backup = Path(directory) / "agent", Path(directory) / "backup"
            source.mkdir()
            (source / "keep.txt").write_text("unchanged")
            self.assertEqual(files.rename_with_retry(source, backup), backup)
            self.assertEqual((backup / "keep.txt").read_text(), "unchanged")
            source.mkdir()
            with self.assertRaises(FileExistsError):
                files.rename_with_retry(source, backup)
            self.assertTrue(source.is_dir())
            self.assertEqual((backup / "keep.txt").read_text(), "unchanged")

    def test_sharing_errors_are_retried_but_other_errors_are_immediate(self):
        with tempfile.TemporaryDirectory() as directory:
            source, backup = Path(directory) / "agent", Path(directory) / "backup"
            source.mkdir()
            sharing = OSError("busy")
            sharing.winerror = 32
            with patch.object(Path, "rename", side_effect=[sharing, backup]) as rename, \
                    patch.object(files.time, "sleep") as sleep:
                files.rename_with_retry(source, backup)
            self.assertEqual(rename.call_count, 2)
            sleep.assert_called_once_with(0.2)
            with patch.object(Path, "rename", side_effect=OSError("disk error")) as rename, \
                    patch.object(files.time, "sleep") as sleep:
                with self.assertRaises(OSError):
                    files.rename_with_retry(source, backup)
            rename.assert_called_once()
            sleep.assert_not_called()

    def test_sharing_retry_deadline_is_bounded_and_cross_parent_move_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            source, backup = Path(directory) / "agent", Path(directory) / "backup"
            source.mkdir()
            sharing = OSError("busy")
            sharing.winerror = 5
            with patch.object(Path, "rename", side_effect=sharing), \
                    patch.object(files.time, "sleep") as sleep:
                with self.assertRaises(OSError):
                    files.rename_with_retry(source, backup, timeout=0)
            sleep.assert_not_called()
            with self.assertRaises(ValueError):
                files.rename_with_retry(source, Path(directory) / "nested" / "backup")


if __name__ == "__main__":
    unittest.main()
