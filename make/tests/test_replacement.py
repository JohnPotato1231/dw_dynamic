"""Authenticated replacement verifies ownership before changing an installation."""

from contextlib import ExitStack, nullcontext
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_support_setup as fixtures

support = fixtures.support_setup
PROFILE = {"main_executable": "fixture_agent.exe", "service_executable": "fixture_service.exe",
           "service_name": "FixtureAgent", "service_display_name": "Fixture Remote Support"}
REMOTE = json.loads((fixtures.ROOT / "os_win_installer" / "install-dynamic-10443-v2.json").read_text(
    encoding="utf-8"))["remote_password"]


class ReplacementPlanningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.destination = self.base / "agent"
        self.destination.mkdir()
        (self.destination / "native").mkdir()
        (self.destination / "runtime").mkdir()
        (self.destination / "native" / PROFILE["service_executable"]).write_bytes(b"fixture-not-an-executable")
        (self.destination / "runtime" / PROFILE["main_executable"]).write_bytes(b"fixture-not-an-executable")
        self.access = {"remote_password": dict(REMOTE), "install_identity": dict(PROFILE),
                       "service_executable": PROFILE["service_executable"]}
        self.write_access()
        self.properties = self.destination / "native" / "service.properties"
        self.properties.write_text("serviceName=" + PROFILE["service_name"] + "\npythonPath=" +
            str(self.destination / "runtime" / PROFILE["main_executable"]) + "\n", encoding="utf-8")
        (self.destination / "config.json").write_text(json.dumps({"name": PROFILE["service_name"]}),
                                                      encoding="utf-8")
        (self.destination / "keep.txt").write_text("previous installation data", encoding="utf-8")
        self.setup = support.SupportInstall()
        self.setup._options = {"server_install_identity": True, "install_identity_version": 2,
            "combined_password_code": True, "replace_existing_installation": True,
            "remote_password": dict(REMOTE)}
        self.setup._apply_install_identity(PROFILE)
        self.setup._setup_authorized = True
        self.current_native = self.setup._native
        self.current_native.get_install_path = Mock(return_value=str(self.destination))
        self.current_native.get_service_state = Mock(return_value=4)
        self.current_native.get_service_image_path = Mock(return_value=self.service_command(self.destination))
        self.old_native = Mock()
        self.old_native.get_install_path.return_value = str(self.destination)
        self.old_native.get_service_state.return_value = 4
        self.old_native.get_service_image_path.return_value = self.service_command(self.destination)
        self.old_native.stop_service.return_value = True
        self.old_native.start_service.return_value = True
        self.old_native.delete_service.return_value = True
        self.old_native.remove_auto_run_monitor.return_value = True
        self.old_native.remove_shortcuts.return_value = True
        self.old_native.last_service_error = "fixture service error"
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(support, "SupportWindows", return_value=self.old_native))
        stack.enter_context(patch.object(support, "verify_protected_directory", create=True))
        stack.enter_context(patch.object(support, "program_files_directory", return_value=self.base))

    def write_access(self):
        (self.destination / "setup-access.json").write_text(json.dumps(self.access), encoding="utf-8")

    def service_command(self, directory):
        return subprocess.list2cmdline([str(directory / "native" / PROFILE["service_executable"]), "run"])

    def assert_files_untouched(self):
        self.assertEqual((self.destination / "keep.txt").read_text(encoding="utf-8"),
                         "previous installation data")
        for native in (self.current_native, self.old_native):
            for name in ("stop_service", "delete_service", "remove_shortcuts", "remove_auto_run_monitor"):
                operation = getattr(native, name, None)
                if isinstance(operation, Mock):
                    operation.assert_not_called()

    def test_owned_legacy_four_field_profile_is_planned_without_changing_files_or_service(self):
        plan = self.setup._plan_replacement(self.destination)
        self.assertIsInstance(plan, dict)
        expected = hashlib.sha256((self.destination / "setup-access.json").read_bytes() +
                                  self.properties.read_bytes()).hexdigest()
        self.assertEqual(plan["fingerprint"], expected)
        self.assert_files_untouched()

    def test_fresh_destination_without_registration_or_service_needs_no_replacement(self):
        self.current_native.get_install_path.return_value = None
        self.current_native.get_service_state.return_value = None
        self.current_native.get_service_image_path.return_value = None
        self.assertIsNone(self.setup._plan_replacement(self.base / "new-agent"))
        self.assert_files_untouched()

    def test_unrelated_nonempty_folder_is_preserved_and_rejected(self):
        unrelated = self.base / "unrelated"
        unrelated.mkdir()
        sentinel = unrelated / "keep.txt"
        sentinel.write_text("unrelated data", encoding="utf-8")
        self.current_native.get_install_path.return_value = None
        self.current_native.get_service_state.return_value = None
        self.current_native.get_service_image_path.return_value = None
        with self.assertRaises(ValueError):
            self.setup._plan_replacement(unrelated)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "unrelated data")

    def test_another_portal_endpoint_cannot_claim_an_existing_installation(self):
        self.access["remote_password"]["url"] = "https://82.25.46.70/api/verify"
        self.write_access()
        with self.assertRaises(ValueError):
            self.setup._plan_replacement(self.destination)
        self.assert_files_untouched()

    def test_service_image_outside_verified_installation_is_not_owned(self):
        self.old_native.get_service_image_path.return_value = self.service_command(self.base / "other-agent")
        self.current_native.get_service_image_path.return_value = self.old_native.get_service_image_path.return_value
        with self.assertRaises(ValueError):
            self.setup._plan_replacement(self.destination)
        self.assert_files_untouched()

    def test_registry_name_collision_at_a_different_folder_is_rejected(self):
        self.current_native.get_install_path.return_value = str(self.base / "other-agent")
        with self.assertRaises(ValueError):
            self.setup._plan_replacement(self.destination)
        self.assert_files_untouched()

    def test_new_portal_service_name_cannot_replace_an_unrelated_registered_service(self):
        self.setup._apply_install_identity(dict(PROFILE, service_name="NewFixtureAgent"))
        self.current_native.get_install_path.return_value = None
        self.current_native.get_service_state.return_value = 4
        with self.assertRaises(ValueError):
            self.setup._plan_replacement(self.destination)
        self.assert_files_untouched()

    def test_optional_metadata_in_previous_profile_remains_verifiable(self):
        self.access["install_identity"].update({"install_path": r"%ProgramFiles%\Fixture Company\Agent",
                                                 "publisher": "Fixture Company"})
        self.write_access()
        self.assertIsInstance(self.setup._plan_replacement(self.destination), dict)
        self.assert_files_untouched()

    def test_password_authorization_is_required_even_for_ownership_planning(self):
        self.setup._setup_authorized = False
        with self.assertRaises(ValueError):
            self.setup._plan_replacement(self.destination)
        self.assert_files_untouched()

    def test_verified_leftover_without_registered_service_still_retains_owner_profile(self):
        self.current_native.get_install_path.return_value = None
        self.current_native.get_service_state.return_value = None
        self.current_native.get_service_image_path.return_value = None
        self.old_native.get_install_path.return_value = None
        self.old_native.get_service_state.return_value = None
        self.old_native.get_service_image_path.return_value = None
        self.assertIsInstance(self.setup._plan_replacement(self.destination), dict)
        self.assert_files_untouched()

    def test_preparation_stops_service_then_keeps_all_old_files_in_a_backup(self):
        self.setup._replacement = self.setup._plan_replacement(self.destination)
        events = []
        rename = support.rename_with_retry

        def move(source, destination):
            events.append("rename")
            return rename(source, destination)

        self.old_native.stop_service.side_effect = lambda: events.append("stop") or True
        self.old_native.delete_service.side_effect = lambda: events.append("delete") or True
        with patch.object(self.setup, "_replacement_tool", return_value=nullcontext()), \
                patch.object(support.installer, "stop_monitor") as monitor, \
                patch.object(support, "rename_with_retry", side_effect=move):
            self.setup._prepare_replacement(self.destination)
        self.assertEqual(events[:3], ["stop", "rename", "delete"])
        monitor.assert_called_once_with(str(self.destination))
        self.assertFalse(self.destination.exists())
        backups = list(self.base.glob("agent.previous-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / "keep.txt").read_text(encoding="utf-8"),
                         "previous installation data")
        self.assertTrue((backups[0] / "setup-access.json").is_file())
        self.assertTrue((backups[0] / "native" / PROFILE["service_executable"]).is_file())

    def test_locked_folder_remains_intact_and_original_running_service_is_restarted(self):
        self.setup._replacement = self.setup._plan_replacement(self.destination)
        locked = OSError("fixture sharing violation")
        locked.winerror = 32
        with patch.object(self.setup, "_replacement_tool", return_value=nullcontext()), \
                patch.object(support.installer, "stop_monitor"), \
                patch.object(support, "rename_with_retry", side_effect=locked):
            with self.assertRaises(OSError):
                self.setup._prepare_replacement(self.destination)
        self.old_native.start_service.assert_called_once()
        self.old_native.delete_service.assert_not_called()
        self.assertEqual((self.destination / "keep.txt").read_text(encoding="utf-8"),
                         "previous installation data")
        self.assertFalse(list(self.base.glob("agent.previous-*")))

    def test_ownership_changes_after_planning_block_preparation_before_service_stop(self):
        self.setup._replacement = self.setup._plan_replacement(self.destination)
        with self.properties.open("a", encoding="utf-8") as stream:
            stream.write("# fixture changed after planning\n")
        with patch.object(support.installer, "stop_monitor") as monitor:
            with self.assertRaisesRegex(ValueError, "changed"):
                self.setup._prepare_replacement(self.destination)
        monitor.assert_not_called()
        self.assert_files_untouched()

    def test_preparation_requires_password_authorization(self):
        self.setup._replacement = self.setup._plan_replacement(self.destination)
        self.setup._setup_authorized = False
        with patch.object(support.installer, "stop_monitor") as monitor:
            with self.assertRaises(ValueError):
                self.setup._prepare_replacement(self.destination)
        monitor.assert_not_called()
        self.assert_files_untouched()

    def test_shortcut_cleanup_failure_restores_original_files_registration_and_running_service(self):
        self.setup._replacement = self.setup._plan_replacement(self.destination)
        self.old_native.remove_shortcuts.return_value = False
        with patch.object(self.setup, "_replacement_tool", return_value=nullcontext()), \
                patch.object(support.installer, "stop_monitor"):
            with self.assertRaisesRegex(RuntimeError, "Cannot finish replacing"):
                self.setup._prepare_replacement(self.destination)
        self.old_native.delete_service.assert_not_called()
        self.old_native.install_shortcuts.assert_called_once()
        self.old_native._service_command.assert_called_once_with("installAutoRun")
        self.old_native.start_service.assert_called_once()
        self.assertEqual((self.destination / "keep.txt").read_text(encoding="utf-8"),
                         "previous installation data")
        self.assertFalse(list(self.base.glob("agent.previous-*")))
        self.assertIsNone(self.setup._replacement_backup)

    def test_autorun_cleanup_failure_keeps_service_and_restores_original_folder(self):
        self.setup._replacement = self.setup._plan_replacement(self.destination)
        self.old_native.remove_auto_run_monitor.return_value = False
        with patch.object(self.setup, "_replacement_tool", return_value=nullcontext()), \
                patch.object(support.installer, "stop_monitor"):
            with self.assertRaisesRegex(RuntimeError, "Cannot finish replacing"):
                self.setup._prepare_replacement(self.destination)
        self.old_native.remove_shortcuts.assert_not_called()
        self.old_native.delete_service.assert_not_called()
        self.old_native.install_shortcuts.assert_called_once()
        self.old_native._service_command.assert_called_once_with("installAutoRun")
        self.old_native.start_service.assert_called_once()
        self.assertTrue((self.destination / "setup-access.json").is_file())
        self.assertEqual((self.destination / "keep.txt").read_text(encoding="utf-8"),
                         "previous installation data")
        self.assertFalse(list(self.base.glob("agent.previous-*")))

    def test_marker_only_partial_installation_without_service_properties_is_verifiable(self):
        partial = self.base / "partial-agent"
        partial.mkdir()
        marker = partial / "setup-owner.json"
        marker.write_text(json.dumps({"format": 1, "remote_password": REMOTE,
                                      "install_identity": PROFILE}), encoding="utf-8")
        original = marker.read_bytes()
        self.current_native.get_install_path.return_value = None
        self.current_native.get_service_state.return_value = None
        self.current_native.get_service_image_path.return_value = None
        self.old_native.get_install_path.return_value = None
        self.old_native.get_service_state.return_value = None
        self.old_native.get_service_image_path.return_value = None
        plan = self.setup._plan_replacement(partial)
        self.assertEqual(plan["fingerprint"], hashlib.sha256(original).hexdigest())
        self.assertEqual(marker.read_bytes(), original)
        self.old_native.stop_service.assert_not_called()

    def test_verified_empty_folder_is_preserved_as_backup_without_service_operations(self):
        empty = self.base / "empty-agent"
        empty.mkdir()
        self.current_native.get_install_path.return_value = None
        self.current_native.get_service_state.return_value = None
        self.current_native.get_service_image_path.return_value = None
        self.setup._replacement = self.setup._plan_replacement(empty)
        self.assertEqual(self.setup._replacement["fingerprint"], "empty")
        with patch.object(self.setup, "_replacement_tool") as tool, \
                patch.object(support.installer, "stop_monitor") as monitor:
            self.setup._prepare_replacement(empty)
        tool.assert_not_called()
        monitor.assert_not_called()
        self.old_native.stop_service.assert_not_called()
        self.assertFalse(empty.exists())
        backups = list(self.base.glob("empty-agent.previous-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(list(backups[0].iterdir()), [])

    def test_pending_older_cleanup_is_waited_out_after_backup_without_real_delay(self):
        (self.destination / "agent.uninstall").write_bytes(b"\x00")
        self.setup._replacement = self.setup._plan_replacement(self.destination)
        self.setup._uinterface = Mock()

        def verify_wait(seconds):
            self.assertEqual(seconds, 65)
            self.assertFalse(self.destination.exists())
            self.assertTrue((self.setup._replacement_backup / "agent.uninstall").is_file())
            self.old_native.delete_service.assert_called_once()

        with patch.object(self.setup, "_replacement_tool", return_value=nullcontext()), \
                patch.object(support.installer, "stop_monitor"), \
                patch.object(support.time, "sleep", side_effect=verify_wait) as sleep:
            self.setup._prepare_replacement(self.destination)
        sleep.assert_called_once_with(65)
        self.setup._uinterface.wait_message.assert_called_once()
        self.assertEqual((self.setup._replacement_backup / "keep.txt").read_text(encoding="utf-8"),
                         "previous installation data")


if __name__ == "__main__":
    unittest.main()
