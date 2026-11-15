"""The new setup collects P and C together and retains its installed identity."""

import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_support_setup as fixtures

auth = fixtures.setup_auth
support = fixtures.support_setup
installer = fixtures.installer
ui = fixtures.ui

PROFILE = {"main_executable": "fixture_agent.exe", "service_executable": "fixture_service.exe",
           "service_name": "FixtureAgent", "service_display_name": "Fixture Remote Support",
           "install_path": r"%ProgramFiles%\Fixture Company\Agent", "publisher": "Fixture Company Ω"}


class CombinedSetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = auth.make_password_record("fixture-password")

    def setUp(self):
        self.setup = support.SupportInstall()
        self.setup._options = {"server_install_identity": True, "install_identity_version": 2,
                               "combined_password_code": True, "setup_password": self.record}
        self.setup._native.check_init_install = Mock(return_value=None)
        self.setup._native.get_install_path = Mock(return_value=None)
        self.setup._native.get_service_state = Mock(return_value=None)
        self.current = ui.BaseUI()
        self.screen = self.setup.step_init(self.current)

    def approved(self, password, options, *, install_identity=None):
        if install_identity is not None:
            install_identity.update(PROFILE)
        return True

    def test_first_screen_requires_only_p_and_c_in_the_same_masked_form(self):
        self.assertIsInstance(self.screen, ui.Inputs)
        fields = self.screen.get_inputs()
        self.assertEqual([field["key"] for field in fields], ["password", "code"])
        self.assertEqual([field["label"].upper() for field in fields], ["P", "C"])
        self.assertTrue(all(field["mandatory"] for field in fields))
        self.assertTrue(all(field["variable"].is_password() for field in fields))
        self.assertFalse(self.screen.is_back_enabled())

    def test_submit_verifies_p_then_starts_install_without_a_second_credentials_screen(self):
        self.setup._setup_password.set("fixture-password")
        self.setup._install_code.set("111222333")
        with patch.object(support, "verify_access_password", side_effect=self.approved) as verify, \
                patch.object(self.setup, "step_begin", return_value="installing") as begin:
            self.assertEqual(self.screen.fire_next_step(), "installing")
        verify.assert_called_once()
        begin.assert_called_once_with(self.screen)
        self.assertTrue(self.setup._setup_authorized)
        self.assertEqual(self.setup._setup_password.get(), "")
        self.assertEqual(self.setup._options["install_identity"], PROFILE)

    def test_empty_c_clears_p_without_contacting_portal_or_installing(self):
        self.setup._setup_password.set("fixture-password")
        self.setup._install_code.set("   ")
        with patch.object(support, "verify_access_password") as verify, \
                patch.object(self.setup, "step_begin") as begin:
            self.assertIsInstance(self.setup.step_password(self.screen), ui.ErrorDialog)
        verify.assert_not_called()
        begin.assert_not_called()
        self.assertEqual(self.setup._setup_password.get(), "")
        self.assertFalse(self.setup._setup_authorized)

    def test_wrong_p_never_applies_metadata_or_begins_install(self):
        self.setup._setup_password.set("wrong")
        self.setup._install_code.set("111222333")
        with patch.object(support, "verify_access_password", return_value=False), \
                patch.object(self.setup, "step_begin") as begin:
            self.assertIsInstance(self.setup.step_password(self.screen), ui.ErrorDialog)
        begin.assert_not_called()
        self.assertFalse(self.setup._setup_authorized)
        self.assertEqual(self.setup._setup_password.get(), "")
        self.assertEqual(self.setup._options["install_identity"], auth.DEFAULT_INSTALL_IDENTITY)

    def test_code_retry_requires_fresh_p_and_c_and_cannot_reuse_authorization(self):
        self.setup._setup_password.set("fixture-password")
        self.setup._install_code.set("111222333")
        with patch.object(support, "verify_access_password", side_effect=self.approved), \
                patch.object(self.setup, "step_begin"):
            self.setup.step_password(self.screen)
        self.setup._files_installed = True
        retry = self.setup.step_code(self.current)
        self.assertFalse(self.setup._setup_authorized)
        self.assertEqual([field["key"] for field in retry.get_inputs()], ["password", "code"])
        with patch.object(installer.Install, "step_install") as install, \
                patch.object(self.setup, "step_config_install_request") as link:
            self.setup.step_begin(retry)
        install.assert_not_called()
        link.assert_not_called()

    def test_reauthorization_after_files_exist_cannot_rename_installed_components(self):
        self.setup._apply_install_identity(PROFILE)
        self.setup._files_installed = True
        self.setup._install_path.set(r"D:\Original Company\Agent")
        self.setup._setup_password.set("fixture-password")
        self.setup._install_code.set("111222333")
        changed = {**PROFILE, "main_executable": "different_agent.exe", "service_name": "DifferentAgent",
                   "publisher": "Different Publisher", "install_path": r"D:\Different Company\Agent"}

        def new_server_profile(password, options, *, install_identity=None):
            if install_identity is not None:
                install_identity.update(changed)
            return True

        with patch.object(support, "verify_access_password", side_effect=new_server_profile), \
                patch.object(self.setup, "step_begin", return_value="linking"):
            self.assertEqual(self.setup.step_password(self.screen), "linking")
        self.assertEqual(self.setup._options["install_identity"], PROFILE)
        self.assertEqual(self.setup._native._runtime, PROFILE["main_executable"])
        self.assertEqual(self.setup._install_path.get(), r"D:\Original Company\Agent")

    def test_authorization_cannot_be_reused_after_code_is_changed(self):
        self.setup._setup_password.set("fixture-password")
        self.setup._install_code.set("111222333")
        with patch.object(support, "verify_access_password", side_effect=self.approved), \
                patch.object(self.setup, "step_begin"):
            self.setup.step_password(self.screen)
        self.setup._install_code.set("999888777")
        with patch.object(installer.Install, "step_install") as install:
            result = self.setup.step_begin(self.current)
        install.assert_not_called()
        self.assertFalse(self.setup._setup_authorized)
        self.assertIsInstance(result, ui.Inputs)


class InstalledMetadataTests(unittest.TestCase):
    def test_saved_access_profile_and_service_properties_keep_publisher_and_path(self):
        setup = support.SupportInstall()
        setup._options = {"server_install_identity": True}
        setup._apply_install_identity(PROFILE)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "native").mkdir()
            setup._install_path.set(folder)
            setup._native.set_install_path(folder)
            setup._native.prepare_file()
            properties = (root / "native" / "service.properties").read_text(encoding="utf-8")
            self.assertIn("publisher=" + PROFILE["publisher"], properties)
            with patch.object(installer.Install, "_download_files"):
                setup._download_files(0, 1)
            saved = json.loads((root / support.ACCESS_FILE).read_text(encoding="utf-8"))
            self.assertEqual(saved["install_identity"], PROFILE)


class RuntimeDestinationTests(unittest.TestCase):
    def setUp(self):
        self.setup = support.SupportInstall()
        self.setup._options = {"server_install_identity": True, "install_identity_version": 2,
                               "install_identity": dict(PROFILE)}
        self.setup._apply_install_identity(PROFILE)
        self.setup._uinterface = Mock()

    def test_destination_expands_os_program_files_and_accepts_explicit_paths_inside_it(self):
        with tempfile.TemporaryDirectory() as folder, \
                patch.dict(os.environ, {"ProgramFiles": r"Z:\Untrusted Environment"}), \
                patch.object(support, "program_files_directory", return_value=Path(folder)), \
                patch.object(self.setup, "_validate_destination") as validate:
            expected = Path(folder) / "Fixture Company" / "Agent"
            self.assertEqual(self.setup._resolve_destination("FixtureAgent"), expected)
            validate.assert_called_once_with(expected)
            validate.reset_mock()
            explicit = Path(folder) / "Explicit Company" / "Remote Agent"
            self.setup._options["install_identity"]["install_path"] = str(explicit)
            self.assertEqual(self.setup._resolve_destination("FixtureAgent"), explicit)
            validate.assert_called_once_with(explicit)
            validate.reset_mock()
            self.setup._options["install_identity"]["install_path"] = ""
            default = Path(folder) / "FixtureAgent"
            self.assertEqual(self.setup._resolve_destination("FixtureAgent"), default)
            validate.assert_called_once_with(default)

    def test_explicit_path_outside_os_program_files_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(support, "program_files_directory", return_value=Path(folder)), \
                patch.object(self.setup, "_validate_destination"):
            self.setup._options["install_identity"]["install_path"] = r"D:\Fixture Company\Agent"
            with self.assertRaisesRegex(ValueError, "inside the Windows Program Files directory"):
                self.setup._resolve_destination("FixtureAgent")

    def test_existing_vendor_directory_is_rejected_without_modifying_its_contents(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            vendor = base / "Existing Company"
            vendor.mkdir()
            sentinel = vendor / "keep.txt"
            sentinel.write_text("existing company data", encoding="utf-8")
            destination = vendor / "New Agent"
            self.setup._options["install_identity"]["install_path"] = str(destination)
            with patch.object(support, "program_files_directory", return_value=base), \
                    patch.object(self.setup, "_validate_destination"):
                with self.assertRaisesRegex(ValueError, "new application subfolders directly under Program Files"):
                    self.setup._resolve_destination("FixtureAgent")
            self.assertFalse(destination.exists())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "existing company data")

    def test_protected_path_limit_counts_utf16_units_and_reserves_space_for_service_name(self):
        base = Path(r"C:\Program Files")
        prefix_units = len(str(base).encode("utf-16-le")) // 2 + 1
        for service_name in ("FixtureAgent", "A" * 80):
            self.setup._name = service_name
            limit = min(180, 246 - len(service_name))
            destination = base / ("A" * (limit - prefix_units - 2) + "😀")
            self.assertEqual(len(str(destination).encode("utf-16-le")) // 2, limit)
            with self.subTest(service_name=service_name):
                self.setup._validate_protected_destination(destination, base)
                with self.assertRaisesRegex(ValueError, "too long"):
                    self.setup._validate_protected_destination(Path(str(destination) + "😀"), base)

    def test_program_files_helper_reads_the_os_known_folder_instead_of_environment(self):
        def known_folder(window, folder_id, token, flags, buffer):
            self.assertEqual(folder_id, 0x26)
            buffer.value = r"C:\Protected Program Files"
            return 0

        with patch.dict(os.environ, {"ProgramFiles": r"D:\Caller Supplied Folder"}), \
                patch.object(support.ctypes.windll.shell32, "SHGetFolderPathW", side_effect=known_folder) as api:
            self.assertEqual(support.program_files_directory(), Path(r"C:\Protected Program Files"))
            api.assert_called_once()

    def test_nonfixed_and_network_volumes_are_rejected_before_filesystem_access(self):
        destination = Path(r"Z:\Fixture Company\Agent")
        for drive_type in (0, 1, 2, 4, 5, 6):
            with self.subTest(drive_type=drive_type), \
                    patch.object(support.ctypes.windll.kernel32, "GetDriveTypeW", return_value=drive_type) as drive, \
                    patch.object(Path, "lstat") as stat:
                with self.assertRaisesRegex(ValueError, "local fixed drive"):
                    self.setup._validate_destination(destination)
                drive.assert_called_once_with(destination.anchor)
                stat.assert_not_called()

    def test_existing_reparse_ancestor_rejects_a_missing_child_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            redirected = Path(folder) / "redirected"
            redirected.mkdir()
            destination = redirected / "New Agent"
            actual_lstat = Path.lstat

            def attributes(path):
                if path == redirected:
                    return SimpleNamespace(st_file_attributes=0x400)
                return actual_lstat(path)

            with patch.object(support.ctypes.windll.kernel32, "GetDriveTypeW", return_value=3), \
                    patch.object(Path, "lstat", autospec=True, side_effect=attributes):
                with self.assertRaisesRegex(ValueError, "junction or symbolic link"):
                    self.setup._validate_destination(destination)
            self.assertFalse(destination.exists())
            self.assertTrue(redirected.is_dir())

    def test_system_root_and_its_children_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            windows = Path(folder) / "Windows"
            with patch.dict(os.environ, {"SystemRoot": str(windows)}), \
                    patch.object(support.ctypes.windll.kernel32, "GetDriveTypeW", return_value=3):
                for destination in (windows, windows / "Agent"):
                    with self.subTest(destination=destination), self.assertRaisesRegex(ValueError, "Windows directory"):
                        self.setup._validate_destination(destination)

    def test_new_nested_directory_is_created_and_existing_data_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "New Company" / "Remote Support" / "Agent"
            self.setup._install_path.set(str(destination))
            with patch.object(support.ctypes.windll.kernel32, "GetDriveTypeW", return_value=3), \
                    patch.object(support, "program_files_directory", return_value=Path(folder)):
                self.setup._make_directory(0, 1)
                self.assertTrue(destination.is_dir())
                sentinel = destination / "keep.txt"
                sentinel.write_text("existing installation data", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "new application subfolders"):
                    self.setup._make_directory(0, 1)
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "existing installation data")

    def test_existing_direct_application_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "Existing Agent"
            destination.mkdir()
            sentinel = destination / "keep.txt"
            sentinel.write_text("existing installation data", encoding="utf-8")
            self.setup._install_path.set(str(destination))
            with patch.object(support.ctypes.windll.kernel32, "GetDriveTypeW", return_value=3), \
                    patch.object(support, "program_files_directory", return_value=Path(folder)):
                with self.assertRaises(FileExistsError):
                    self.setup._make_directory(0, 1)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "existing installation data")


if __name__ == "__main__":
    unittest.main()
