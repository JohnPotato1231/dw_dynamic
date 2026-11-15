"""Default and authenticated installation identities, without installing services."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_support_setup as fixtures

auth = fixtures.setup_auth
support = fixtures.support_setup
installer = fixtures.installer
ui = fixtures.ui
sys.path.insert(0, str(fixtures.ROOT / "make"))
from package_windows_installer import prepare_install_config

PROFILE = {"main_executable": "fixture_agent.exe", "service_executable": "fixture_service.exe",
           "service_name": "FixtureAgent", "service_display_name": "Fixture Remote Support"}


class IdentitySetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = auth.make_password_record("fixture-password")

    def setUp(self):
        self.setup = support.SupportInstall()
        self.setup._options = {"server_install_identity": True, "setup_password": self.record}
        self.setup._native.check_init_install = Mock(return_value=None)
        self.setup._native.get_install_path = Mock(return_value=None)
        self.current = ui.BaseUI()
        self.setup.step_init(self.current)

    def test_forged_local_authorization_or_local_recovery_keeps_defaults(self):
        self.setup._setup_password.set("fixture-password")
        self.setup.step_password(self.current)
        self.assertTrue(self.setup._setup_authorized)
        self.assertEqual(self.setup._options["install_identity"], auth.DEFAULT_INSTALL_IDENTITY)
        self.assertEqual(self.setup._native._runtime, "dwagent.exe")

    def test_profile_applies_only_after_success_and_failed_retry_resets_everything(self):
        def approved(password, options, *, install_identity):
            install_identity.update(PROFILE)
            return True
        with patch.object(support, "verify_access_password", side_effect=approved):
            self.setup.step_password(self.current)
        self.assertEqual(self.setup._native._runtime, PROFILE["main_executable"])
        self.assertEqual(self.setup._native._service_executable, PROFILE["service_executable"])
        with patch.object(support, "verify_access_password", return_value=False):
            self.setup.step_password(self.current)
        self.assertFalse(self.setup._setup_authorized)
        self.assertEqual(self.setup._options["install_identity"], auth.DEFAULT_INSTALL_IDENTITY)

    def test_copies_are_renamed_and_properties_keep_distinct_display_name(self):
        self.setup._apply_install_identity(PROFILE)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "runtime").mkdir()
            (root / "native").mkdir()
            (root / "runtime" / "dwagent.exe").write_bytes(b"runtime fixture")
            (root / "native" / "dwagsvc.exe").write_bytes(b"service fixture")
            self.setup._install_path.set(folder)
            self.setup._native.set_install_path(folder)
            with patch.object(installer.Install, "copy_runtime"), patch.object(installer.Install, "copy_native"):
                self.setup.copy_runtime(0, 1)
                self.setup.copy_native(0, 1)
            self.setup._native.prepare_file()
            properties = (root / "native" / "service.properties").read_text()
            self.assertTrue((root / "runtime" / PROFILE["main_executable"]).is_file())
            self.assertTrue((root / "native" / PROFILE["service_executable"]).is_file())
            self.assertIn("serviceName=" + PROFILE["service_name"], properties)
            self.assertIn("serviceDisplayName=" + PROFILE["service_display_name"], properties)
            self.assertIn(PROFILE["main_executable"], properties)

    def test_installed_profile_survives_uninstall_name_initialization(self):
        self.setup._apply_install_identity(PROFILE)
        with tempfile.TemporaryDirectory() as folder:
            self.setup._install_path.set(folder)
            with patch.object(installer.Install, "_download_files"):
                self.setup._download_files(0, 1)
            saved = json.loads((Path(folder) / support.ACCESS_FILE).read_text())
            self.assertEqual(saved["install_identity"], PROFILE)
            removal = support.SupportUninstall()
            with patch.object(support, "__file__", str(Path(folder) / "support_setup.py")):
                removal._load_access_config()
            removal._native.set_name(PROFILE["service_name"])
            self.assertEqual(removal._native._runtime, PROFILE["main_executable"])
            self.assertEqual(removal._native._service_executable, PROFILE["service_executable"])

    def test_packaging_strips_custom_identity_even_when_input_contains_it(self):
        config = prepare_install_config({"server_install_identity": True, "setup_flow": "password_code",
                                        "remote_password": {}, "name": PROFILE["service_name"],
                                        "service_executable": PROFILE["service_executable"], "install_identity": PROFILE})
        self.assertEqual(config["name"], "DWAgent")
        self.assertEqual(config["service_executable"], "dwagsvc.exe")
        self.assertNotIn("install_identity", config)
        self.assertNotIn(PROFILE["service_name"], json.dumps(config))

    def test_dynamic_installation_never_deletes_existing_folder_or_service(self):
        self.setup._uinterface = Mock()
        with tempfile.TemporaryDirectory() as folder:
            sentinel = Path(folder) / "keep.txt"
            sentinel.write_text("existing data")
            self.setup._install_path.set(folder)
            with self.assertRaises(FileExistsError):
                self.setup._make_directory(0, 1)
            self.assertEqual(sentinel.read_text(), "existing data")
        self.setup._native = Mock()
        self.setup._native.get_service_state.return_value = 4
        with self.assertRaises(ValueError):
            self.setup._install_service(0, 1)
        self.setup._native.stop_service.assert_not_called()
        self.setup._native.delete_service.assert_not_called()
        self.setup._native.install_service.assert_not_called()
        self.setup._native.get_service_state.return_value = None
        self.setup._native.install_service.return_value = True
        self.setup._native.start_service.return_value = True
        self.setup._install_service(0, 1)
        self.setup._native.stop_service.assert_not_called()
        self.setup._native.delete_service.assert_not_called()


if __name__ == "__main__":
    unittest.main()
