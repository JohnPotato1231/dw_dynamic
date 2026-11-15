"""Exercise setup/removal gates without registering or removing a service."""

import json
import io
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "core"), str(ROOT / "os_win_installer"), str(ROOT)]

import setup_auth
import support_setup
from ui import installer, ui


class SetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = setup_auth.make_password_record("test-only-password")

    def setUp(self):
        self.setup = support_setup.SupportInstall()
        self.setup._options = {"name": "MyDWagent1", "setup_password": self.record}
        self.setup._native = Mock()
        self.setup._native.check_init_install.return_value = None
        self.setup._native.get_install_path.return_value = None
        self.current = ui.BaseUI()
        self.current.set_key("supportCode")

    def authorize(self):
        self.setup._setup_password.set("test-only-password")
        with patch.object(self.setup, "step_begin"):
            self.setup.step_password(self.current)
        return self.setup.step_code(self.current)

    def test_hash_verification_and_malformed_records(self):
        self.assertTrue(setup_auth.verify_password("test-only-password", self.record))
        self.assertFalse(setup_auth.verify_password("wrong", self.record))
        for record in (None, {}, {**self.record, "iterations": 0},
                       {**self.record, "digest": "bad"}, {**self.record, "salt": None}):
            self.assertFalse(setup_auth.verify_password("test-only-password", record))

    def test_first_screen_has_optional_reference_and_password(self):
        screen = self.setup.step_init(self.current)
        self.assertIsInstance(screen, ui.Inputs)
        self.assertTrue(screen.get_message().startswith("REMO\n"))
        self.assertEqual([field["key"] for field in screen.get_inputs()], ["reference", "password"])
        self.assertEqual(screen.get_param("next_label"), installer.messages.get_message("next"))
        self.assertEqual(screen.get_inputs()[0]["label"], "Optional reference")
        self.assertEqual(screen.get_inputs()[1]["label"], "Enter the password")
        self.assertFalse(screen.get_inputs()[0]["mandatory"])
        self.assertTrue(screen.get_inputs()[1]["mandatory"])
        self.assertFalse(screen.get_inputs()[0]["variable"].is_password())
        self.assertTrue(screen.get_inputs()[1]["variable"].is_password())
        self.assertFalse(screen.is_back_enabled())
        self.setup._native.get_install_path.assert_not_called()

    def test_reference_is_ignored_and_correct_password_opens_code_screen(self):
        screen = self.setup.step_init(self.current)
        self.setup._optional_reference.set("anything may be entered here")
        self.setup._setup_password.set("test-only-password")
        code_screen = screen.fire_next_step()
        self.assertIsInstance(code_screen, ui.Inputs)
        self.assertEqual([field["key"] for field in code_screen.get_inputs()], ["code"])
        self.assertEqual(self.setup._optional_reference.get(), "")
        self.assertEqual(self.setup._setup_password.get(), "")
        self.assertTrue(self.setup._setup_authorized)

    def test_code_submit_starts_install_after_password_authorization(self):
        password_screen = self.setup.step_init(self.current)
        self.setup._setup_password.set("test-only-password")
        code_screen = password_screen.fire_next_step()
        self.setup._install_code.set(" 111 222 333 ")
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"ProgramFiles": directory}), \
                    patch.object(installer.Install, "step_install", return_value="installing") as install:
                self.assertEqual(code_screen.fire_next_step(), "installing")
                install.assert_called_once_with(code_screen)
        self.assertTrue(self.setup._setup_authorized)
        self.assertEqual(self.setup._setup_password.get(), "")
        self.assertEqual(self.setup._install_code.get(), "111222333")
        self.assertTrue(self.setup._install_code.is_password())

    def test_invalid_password_cannot_open_code_screen_or_install(self):
        screen = self.setup.step_init(self.current)
        self.setup._optional_reference.set("ignored")
        self.setup._setup_password.set("wrong")
        with patch.object(installer.Install, "step_install") as install:
            self.assertEqual(screen.fire_next_step().get_message(), "Incorrect P.")
            install.assert_not_called()
        self.setup._native.get_install_path.assert_not_called()
        self.assertFalse(self.setup._setup_authorized)
        self.assertEqual(self.setup._optional_reference.get(), "")
        self.assertEqual(self.setup._setup_password.get(), "")

    def test_wrong_password_cannot_install(self):
        self.setup._setup_password.set("wrong")
        with patch.object(installer.Install, "step_install") as install:
            self.assertIsInstance(self.setup.step_password(self.current), ui.ErrorDialog)
            self.setup.step_install(self.current)
            install.assert_not_called()
        self.assertFalse(self.setup._setup_authorized)

    def test_next_screen_has_only_code_and_notice(self):
        screen = self.authorize()
        self.assertEqual([field["key"] for field in screen.get_inputs()], ["code"])
        self.assertEqual(screen.get_inputs()[0]["label"], "c")
        self.assertTrue(screen.get_inputs()[0]["variable"].is_password())
        self.assertEqual(self.setup._setup_password.get(), "")
        self.assertFalse(screen.is_back_enabled())

    def test_empty_code_cannot_install(self):
        self.authorize()
        with patch.object(installer.Install, "step_install") as install:
            self.assertIsInstance(self.setup.step_begin(self.current), ui.ErrorDialog)
            install.assert_not_called()

    def test_default_path_without_path_or_welcome_screens(self):
        self.authorize()
        self.setup._install_code.set(" 111 222 333 ")
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "Notepad+"
            with patch.dict(os.environ, {"ProgramFiles": directory}), \
                    patch.object(installer.Install, "step_install", return_value="installing") as install:
                self.assertEqual(self.setup.step_begin(self.current), "installing")
                install.assert_called_once_with(self.current)
            self.assertEqual(self.setup._install_path.get(), str(destination))
            self.assertEqual(self.setup._install_code.get(), "111222333")

    def test_existing_folder_is_never_removed(self):
        self.authorize()
        self.setup._install_code.set("111222333")
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "Notepad+"
            destination.mkdir()
            keep = destination / "keep.txt"
            keep.write_text("keep", encoding="utf-8")
            with patch.dict(os.environ, {"ProgramFiles": directory}), \
                    patch.object(installer.Install, "step_install") as install:
                self.assertIsInstance(self.setup.step_begin(self.current), ui.Message)
                install.assert_not_called()
            self.assertEqual(keep.read_text(), "keep")

    def test_already_installed_is_not_overwritten(self):
        self.authorize()
        self.setup._install_code.set("111222333")
        self.setup._native.get_install_path.return_value = "existing-install"
        with patch.object(installer.Install, "step_install") as install:
            self.assertIsInstance(self.setup.step_begin(self.current), ui.Message)
            install.assert_not_called()

    def test_collected_code_is_submitted_after_install(self):
        self.authorize()
        with patch.object(self.setup, "step_config_install_request", return_value="linked") as request:
            self.assertEqual(self.setup.step_config_init(self.current), "linked")
            request.assert_called_once_with(self.current)
        self.assertTrue(self.setup._files_installed)
        self.assertEqual(self.setup._inatall_agent_mode, "installCode")

    def test_only_successful_installation_requests_automatic_close(self):
        success = ui.Message(self.setup._get_message("endInstall"))
        failure = ui.ErrorDialog("Connection failed")
        retry = ui.Chooser()
        deferred = ui.Message("Installed but not linked")
        for result in (success, failure, retry, deferred):
            with patch.object(installer.Install, "step_config_install_request", return_value=result):
                actual = self.setup.step_config_install_request(self.current)
                self.assertIs(actual, result)
                if isinstance(actual, ui.BaseUI):
                    self.assertEqual(actual.get_param("auto_close", False), result is success)

    def test_success_closes_without_waiting_for_close_button_but_errors_stay_open(self):
        window = ui.UI({}, None)
        window._action = Mock()
        success = ui.Message("Done")
        success.set_param("auto_close", True)
        with patch.object(window, "close") as close:
            window._op_complete(success)
            close.assert_called_once()
            self.assertIsNone(window._action)
        with patch.object(window, "close") as close, patch.object(window, "_show_error") as error:
            window._op_complete(ui.ErrorDialog("Install failed"))
            close.assert_not_called()
            error.assert_called_once_with("Install failed")

    def test_progress_only_gui_has_no_status_label_and_keeps_progress_when_linking(self):
        window = ui.UI({"progress_only": True}, None)
        window._gui_enable = True
        window._btnext, window._btback, window._btclose = Mock(), Mock(), Mock()
        window._pnlmain = Mock()
        with patch.object(window, "_prepare_main_panel"), \
                patch.object(ui.gdi, "Label") as label, \
                patch.object(ui.gdi, "ProgressBar") as progress:
            window.wait_message("Downloading internal filename", perc=60, progr=0.6)
            window.wait_message("Linking account")
            label.assert_not_called()
            progress.assert_called_once()
            self.assertEqual(progress.return_value.set_percent.call_args.args, (0.6,))
            window._btnext.set_visible.assert_called_with(False)
            window._btback.set_visible.assert_called_with(False)
            window._btclose.set_visible.assert_called_with(False)
            screen = ui.Message("A visible error or retry screen")
            with patch.object(window, "_prepare_buttons"), patch.object(window, "_show_message"):
                window._prepare_step(screen)
            window._btclose.set_visible.assert_called_with(True)

    def test_retry_code_does_not_reinstall(self):
        self.authorize()
        self.setup._files_installed = True
        self.setup._install_code.set("111222333")
        with patch.object(self.setup, "step_config_install_request", return_value="linked"), \
                patch.object(installer.Install, "step_install") as install:
            self.assertEqual(self.setup.step_begin(self.current), "linked")
            install.assert_not_called()

    def test_uninstall_guard_is_copied_after_download(self):
        self.setup._options["service_executable"] = "dwagsvc1.exe"
        with tempfile.TemporaryDirectory() as directory:
            self.setup._install_path.set(directory)
            with patch.object(installer.Install, "_download_files"):
                self.setup._download_files(0, 1)
            saved = json.loads((Path(directory) / support_setup.ACCESS_FILE).read_text())
            self.assertEqual(saved["setup_password"], self.record)
            self.assertEqual(saved["service_executable"], "dwagsvc1.exe")
            self.assertTrue((Path(directory) / "support_setup.py").is_file())
            self.assertTrue((Path(directory) / "setup_auth.py").is_file())
            self.assertNotIn("test-only-password", json.dumps(saved))

    def test_custom_icon_uses_upstream_branding_directory(self):
        config = json.loads((ROOT / "os_win_installer" / "install.json").read_text())
        icon_name = config["logoxos"]
        self.assertEqual(icon_name, "remo.ico")
        icon = (ROOT / "os_win_installer" / "installer.ico").read_bytes()
        self.setup._options["logoxos"] = icon_name
        previous_directory = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / icon_name
            source.write_bytes(icon)
            destination = Path(directory) / "installed"
            try:
                os.chdir(directory)
                self.setup._copy_custom_images({"logoxos": icon_name}, str(destination))
            finally:
                os.chdir(previous_directory)
            installed_icon = destination / "ui" / "images" / "custom" / icon_name
            self.assertEqual(installed_icon.read_bytes(), icon)

    def test_silent_or_missing_password_never_bypasses_gate(self):
        self.setup._silent = True
        self.assertIsInstance(self.setup.step_init(self.current), ui.Message)
        self.setup._silent = False
        self.setup._options = {}
        self.assertIsInstance(self.setup.step_init(self.current), ui.Message)
        self.assertFalse(self.setup._setup_authorized)

    def test_uninstaller_rejects_wrong_password_and_direct_remove(self):
        removal = support_setup.SupportUninstall()
        removal._password_record = self.record
        removal._setup_password.set("wrong")
        with patch.object(installer.Uninstall, "step_init") as confirm, \
                patch.object(installer.Uninstall, "step_remove") as remove:
            self.assertIsInstance(removal.step_password(self.current), ui.ErrorDialog)
            self.assertIsInstance(removal.step_remove(self.current), ui.Inputs)
            confirm.assert_not_called()
            remove.assert_not_called()

    def test_uninstaller_accepts_same_password_and_neutral_title(self):
        removal = support_setup.SupportUninstall()
        removal._password_record = self.record
        removal._setup_password.set("test-only-password")
        removal._native = Mock()
        removal._native.check_init_uninstall.return_value = None
        removal._native.get_install_path.return_value = r"C:\Program Files\MyDWagent2"
        with patch.object(installer.Uninstall, "step_init") as confirm, \
                patch.object(installer.Uninstall, "step_remove", return_value="removed") as remove:
            screen = removal.step_init(self.current)
            self.assertEqual(screen.fire_next_step(), "removed")
            confirm.assert_not_called()
            remove.assert_called_once_with(screen)
        self.assertEqual(removal._install_path, r"C:\Program Files\MyDWagent2")
        self.assertEqual(removal._get_message("titleUninstall"), "REMO")
        self.assertEqual(removal._setup_password.get(), "")
        with patch.object(installer.Uninstall, "step_remove", return_value="removed"):
            self.assertEqual(removal.step_remove(self.current), "removed")

    def test_uninstall_closes_only_on_success(self):
        removal = support_setup.SupportUninstall()
        removal._setup_authorized = True
        for result in (ui.Message(removal._get_message("endUninstall")), ui.ErrorDialog("Service failed to stop")):
            with patch.object(installer.Uninstall, "step_remove", return_value=result):
                actual = removal.step_remove(self.current)
                self.assertIs(actual, result)
                if isinstance(result, ui.Message):
                    self.assertTrue(result.get_param("auto_close", False))

    def test_uninstall_start_requests_progress_only_ui(self):
        removal = support_setup.SupportUninstall()
        with patch.object(installer.Uninstall, "start") as start:
            removal.start({"gui": True})
        self.assertTrue(start.call_args.args[0]["progress_only"])

    def test_terminal_uninstall_passes_password_only_over_private_stdin(self):
        removal = support_setup.SupportUninstall()
        removal._password_record = self.record
        removal._terminal_mode = True
        removal._native = Mock()
        removal._native.check_init_uninstall.return_value = None
        removal._native.get_install_path.return_value = r"C:\Program Files\MyDWagent2"
        removal._setup_password.set("test-only-password")
        worker = Mock(returncode=0)
        with patch.object(support_setup.subprocess, "Popen", return_value=worker) as spawn, \
                patch.object(installer.Uninstall, "step_remove") as local_remove:
            result = removal.step_password(self.current)
        self.assertTrue(result.get_param("auto_close"))
        self.assertTrue(removal._removal_complete)
        self.assertNotIn("test-only-password", str(spawn.call_args))
        self.assertEqual(spawn.call_args.args[0][0], sys.executable)
        self.assertIn("-console-worker", spawn.call_args.args[0])
        self.assertEqual(json.loads(worker.communicate.call_args.args[0])["password"], "test-only-password")
        local_remove.assert_not_called()

    def test_wrong_terminal_password_cannot_launch_worker(self):
        removal = support_setup.SupportUninstall()
        removal._password_record = self.record
        removal._terminal_mode = True
        removal._setup_password.set("wrong")
        with patch.object(support_setup.subprocess, "Popen") as spawn:
            self.assertIsInstance(removal.step_password(self.current), ui.ErrorDialog)
        spawn.assert_not_called()

    def test_masked_terminal_input_handles_backspace_without_printing_password(self):
        keys = iter("12\b3\r")
        output = io.StringIO()
        value = ui._read_masked_characters("Password: ", lambda: next(keys), output)
        self.assertEqual(value, "13")
        self.assertNotIn("12", output.getvalue())
        self.assertNotIn("13", output.getvalue())
        self.assertIn("*", output.getvalue())

    def test_dw_shell_extra_newline_does_not_submit_password(self):
        keys = iter("\ntest-only\r\nsecond-test\r\n")
        output = io.StringIO()
        read = lambda: next(keys)
        self.assertEqual(ui._read_masked_characters("Password: ", read, output), "test-only")
        self.assertEqual(ui._read_masked_characters("Password: ", read, output), "second-test")
        self.assertNotIn("test-only", output.getvalue())
        self.assertNotIn("second-test", output.getvalue())

    def test_terminal_retry_never_displays_or_reuses_previous_password(self):
        window = ui.UI({}, None)
        secret = ui.VarString("previous-secret", True)
        screen = ui.Inputs()
        screen.add("password", "P", secret, True)
        window._cur_step_ui = screen
        with patch.object(window, "_printcl"), patch.object(window, "_clmode_read", return_value="") as read, \
                patch.object(window, "_clmode_next"):
            window._show_inputs(screen)
        read.assert_called_once_with("P:", True)
        self.assertEqual(secret.get(), "")

    def test_console_password_input_rejects_wrong_then_accepts_correct_password(self):
        removal = support_setup.SupportUninstall()
        removal._password_record = self.record
        removal._terminal_mode = True
        removal._native = Mock()
        removal._native.check_init_uninstall.return_value = None
        removal._native.get_install_path.return_value = r"C:\Program Files\MyDWagent2"
        window = ui.UI({}, None)
        screen = removal.step_init(self.current)
        window._cur_step_ui = screen
        with patch.object(ui, "read_password", side_effect=["wrong", "test-only-password"]) as read, \
                patch.object(window, "_printcl"), patch.object(window, "_show_error") as error, \
                patch.object(support_setup.subprocess, "Popen", return_value=Mock(returncode=0)) as worker:
            window._show_inputs(screen)
            error.assert_called_once_with("Incorrect P.")
            worker.assert_not_called()
            self.assertFalse(window._closing)
            self.assertEqual(removal._setup_password.get(), "")
            window._show_inputs(screen)
            worker.assert_called_once()
            self.assertTrue(window._closing)
            self.assertTrue(removal._removal_complete)
            self.assertTrue(all(call.args[0] == "P: " for call in read.call_args_list))

    def test_terminal_worker_failure_does_not_report_success(self):
        removal = support_setup.SupportUninstall()
        removal._password_record = self.record
        removal._terminal_mode = True
        removal._native = Mock()
        removal._native.check_init_uninstall.return_value = None
        removal._native.get_install_path.return_value = r"C:\Program Files\MyDWagent2"
        removal._setup_password.set("test-only-password")
        with patch.object(support_setup.subprocess, "Popen", return_value=Mock(returncode=1)):
            self.assertIsInstance(removal.step_password(self.current), ui.ErrorDialog)
        self.assertFalse(removal._removal_complete)

    def test_terminal_checks_admin_before_requesting_password(self):
        removal = support_setup.SupportUninstall()
        removal._load_access_config = Mock()
        removal._native = Mock()
        removal._native.check_init_uninstall.return_value = "Admin required"
        output = io.StringIO()
        with patch.object(Path, "read_text", return_value='{"name":"MyDWagent2"}'), \
                patch.object(ui, "read_password") as password, patch.object(sys, "stdout", output):
            status = support_setup.run_terminal_uninstall(removal)
        self.assertEqual(status, 1)
        self.assertIn("Please try again using an Administrator Command Prompt", output.getvalue())
        password.assert_not_called()

    def test_terminal_wrong_password_retries_immediately_without_extra_enter(self):
        removal = support_setup.SupportUninstall()
        removal._load_access_config = Mock()
        removal._password_record = self.record
        removal._native = Mock()
        removal._native.check_init_uninstall.return_value = None
        removal._native.get_install_path.return_value = r"C:\Program Files\MyDWagent2"
        output = io.StringIO()
        with patch.object(Path, "read_text", return_value='{"name":"MyDWagent2"}'), \
                patch.object(ui, "read_password", side_effect=["wrong", "wrong-again", "test-only-password"]) as password, \
                patch.object(support_setup.subprocess, "Popen", return_value=Mock(returncode=0)) as worker, \
                patch.object(sys, "stdout", output):
            status = support_setup.run_terminal_uninstall(removal)
        self.assertEqual(status, 0)
        self.assertEqual(password.call_count, 3)
        worker.assert_called_once()
        self.assertEqual(output.getvalue().count("Incorrect password. Please try again."), 2)
        self.assertNotIn("Press enter", output.getvalue())
        self.assertIn("Uninstall completed successfully.", output.getvalue())

    def test_terminal_failure_does_not_print_success(self):
        removal = support_setup.SupportUninstall()
        removal._load_access_config = Mock()
        removal._password_record = self.record
        removal._native = Mock()
        removal._native.check_init_uninstall.return_value = None
        removal._native.get_install_path.return_value = r"C:\Program Files\MyDWagent2"
        output = io.StringIO()
        with patch.object(Path, "read_text", return_value='{"name":"MyDWagent2"}'), \
                patch.object(ui, "read_password", return_value="test-only-password"), \
                patch.object(support_setup.subprocess, "Popen", return_value=Mock(returncode=1)), \
                patch.object(sys, "stdout", output):
            status = support_setup.run_terminal_uninstall(removal)
        self.assertEqual(status, 1)
        self.assertIn("Uninstall failed", output.getvalue())
        self.assertNotIn("Successfully removed", output.getvalue())

    def test_cleanup_refuses_unverified_installation_path(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(support_setup.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(RuntimeError, "path could not be verified"):
                    support_setup.schedule_console_cleanup(directory)
                spawn.assert_not_called()

    def test_correct_uninstall_password_still_requires_admin_and_installed_path(self):
        for admin_error, path in (("Administrator privileges required", r"C:\Program Files\MyDWagent2"),
                                  (None, None)):
            removal = support_setup.SupportUninstall()
            removal._password_record = self.record
            removal._setup_password.set("test-only-password")
            removal._native = Mock()
            removal._native.check_init_uninstall.return_value = admin_error
            removal._native.get_install_path.return_value = path
            with patch.object(installer.Uninstall, "step_remove") as remove:
                self.assertIsInstance(removal.step_password(self.current), ui.Message)
                remove.assert_not_called()
                self.assertFalse(removal._setup_authorized)

    def test_uninstaller_fails_closed_without_hash_or_in_silent_mode(self):
        removal = support_setup.SupportUninstall()
        self.assertIsInstance(removal.step_remove(self.current), ui.Message)
        removal._password_record = self.record
        removal._silent = True
        self.assertIsInstance(removal.step_remove(self.current), ui.Message)
        self.assertFalse(removal._setup_authorized)

    def test_existing_input_layout_defaults_are_unchanged(self):
        self.assertEqual(ui.Inputs().get_message_height(), 100)
        self.assertEqual(ui.Inputs().get_message_hyperlinks(), [])

    def test_required_field_messages_use_visible_labels(self):
        screen = self.setup.step_init(self.current)
        self.assertEqual(screen.fire_next_step().get_message(), "The field Enter the password is required.")
        self.setup._setup_password.set("test-only-password")
        code_screen = screen.fire_next_step()
        self.assertEqual(code_screen.fire_next_step().get_message(), "The field c is required.")
        self.assertTrue(self.setup._setup_authorized)

    def test_install_button_label_resets_on_other_screens(self):
        window = ui.UI({}, None)
        window._gui_enable = True
        window._btnext = Mock()
        window._btback = Mock()
        window._btclose = Mock()
        screen = self.setup.step_init(self.current)
        window._prepare_buttons(screen)
        window._btnext.set_text.assert_called_with(installer.messages.get_message("next"))
        self.setup._setup_password.set("test-only-password")
        code_screen = screen.fire_next_step()
        window._prepare_buttons(code_screen)
        window._btnext.set_text.assert_called_with(installer.messages.get_message("install"))
        window._prepare_buttons(ui.Message("Done"))
        window._btnext.set_text.assert_called_with(installer.messages.get_message("next"))

    def test_retry_screen_has_only_code_and_next_action(self):
        self.authorize()
        self.setup._files_installed = True
        screen = self.setup.step_code(self.current)
        self.assertEqual([field["key"] for field in screen.get_inputs()], ["code"])
        self.assertEqual(screen.get_param("next_label"), installer.messages.get_message("next"))

    def test_short_label_forms_render_with_upstream_ui_dispatch(self):
        forms = [self.setup.step_init(self.current), self.authorize()]
        for form in forms:
            window = ui.UI({}, None)
            with patch.object(window, "_prepare_buttons"), patch.object(window, "_show_inputs") as render:
                window._prepare_step(form)
                render.assert_called_once_with(form)

    def test_setup_and_removal_use_remo_branding(self):
        config = json.loads((ROOT / "os_win_installer" / "install.json").read_text())
        self.assertEqual(config["title"], "REMO")
        for operation in (self.setup, support_setup.SupportUninstall()):
            operation._name = "MyDWagent1"
            self.assertIn("REMO", operation._get_message("confirmUninstall"))
            self.assertNotIn("MyDWagent1", operation._get_message("confirmUninstall"))

    def test_service_actions_use_renamed_executable(self):
        native = support_setup.SupportWindows()
        native.set_install_path(r"C:\Program Files\MyDWagent1")
        native.set_service_executable("dwagsvc1.exe")
        native.executecmd = Mock(return_value=True)
        actions = {"install_service": "installService", "start_service": "startService",
                   "stop_service": "stopService", "delete_service": "deleteService",
                   "remove_auto_run_monitor": "removeAutoRun", "install_shortcuts": "installShortcuts",
                   "remove_shortcuts": "removeShortcuts"}
        for method, action in actions.items():
            with self.subTest(action=action):
                self.assertTrue(getattr(native, method)())
                native.executecmd.assert_called_with(subprocess.list2cmdline(
                    [r"C:\Program Files\MyDWagent1\native\dwagsvc1.exe", action]))

    def test_monitor_starts_only_after_successful_registration(self):
        native = support_setup.SupportWindows()
        native.set_install_path(r"C:\Program Files\MyDWagent1")
        native.set_service_executable("dwagsvc1.exe")
        native.executecmd = Mock(return_value=True)
        with patch.object(installer, "NativeWindowsPopenUnicode") as launch:
            self.assertTrue(native.install_auto_run_monitor())
            native.executecmd.assert_called_once_with(subprocess.list2cmdline(
                [r"C:\Program Files\MyDWagent1\native\dwagsvc1.exe", "installAutoRun"]))
            self.assertIn("dwaglnc.exe", launch.call_args.args[0])
            launch.reset_mock()
            native.executecmd.return_value = False
            self.assertFalse(native.install_auto_run_monitor())
            launch.assert_not_called()

    def test_uninstaller_loads_service_filename_and_supports_old_installs(self):
        with tempfile.TemporaryDirectory() as directory:
            for filename in ("dwagsvc1.exe", None):
                access = {"setup_password": self.record}
                if filename:
                    access["service_executable"] = filename
                (Path(directory) / support_setup.ACCESS_FILE).write_text(json.dumps(access))
                removal = support_setup.SupportUninstall()
                with patch.object(support_setup, "__file__", str(Path(directory) / "support_setup.py")), \
                        patch.object(installer.Uninstall, "start"):
                    removal.start()
                self.assertEqual(removal._native._service_executable, filename or "dwagsvc.exe")

    def test_online_install_and_uninstall_fail_closed_when_server_is_unreachable(self):
        remote = {"url": "https://portal.test/api/verify",
                  "ca_pem": "-----BEGIN CERTIFICATE-----\ntest"}
        self.setup._options = {"remote_password": remote}
        removal = support_setup.SupportUninstall()
        removal._access_config = {"remote_password": remote}
        for operation, next_method in ((self.setup, "step_begin"), (removal, "step_remove")):
            operation._setup_password.set("entered-password")
            with self.subTest(operation=type(operation).__name__), \
                    patch.object(support_setup, "verify_access_password",
                                 side_effect=setup_auth.PasswordServerUnavailable("Server offline")), \
                    patch.object(operation, next_method) as advance:
                self.assertEqual(operation.step_password(self.current).get_message(), "Server offline")
                advance.assert_not_called()
                self.assertFalse(operation._setup_authorized)

    def test_online_credentials_are_preserved_for_uninstall_without_static_hash(self):
        remote = {"url": "https://portal.test/api/verify",
                  "ca_pem": "-----BEGIN CERTIFICATE-----\ntest"}
        self.setup._options = {"remote_password": remote, "service_executable": "dwagsvc2.exe"}
        with tempfile.TemporaryDirectory() as directory:
            self.setup._install_path.set(directory)
            with patch.object(installer.Install, "_download_files"):
                self.setup._download_files(0, 1)
            saved = json.loads((Path(directory) / support_setup.ACCESS_FILE).read_text())
            self.assertEqual(saved["remote_password"], remote)
            self.assertNotIn("setup_password", saved)
            removal = support_setup.SupportUninstall()
            with patch.object(support_setup, "__file__", str(Path(directory) / "support_setup.py")), \
                    patch.object(installer.Uninstall, "start"):
                removal.start()
            self.assertEqual(removal._access_config, saved)
            removal._native.check_init_uninstall = Mock(return_value=None)
            removal._native.get_install_path = Mock(return_value=directory)
            with patch.object(support_setup, "verify_access_password", return_value=True) as verify, \
                    patch.object(installer.Uninstall, "step_remove", return_value="removed"):
                removal._setup_password.set("online-password")
                self.assertEqual(removal.step_password(self.current), "removed")
                verify.assert_called_once_with("online-password", saved)

    def test_recovery_hash_is_saved_for_uninstall_and_authorizes_both_operations(self):
        recovery = setup_auth.make_password_record("local-recovery-test")
        remote = {"url": "https://portal.test/api/verify",
                  "ca_pem": "-----BEGIN CERTIFICATE-----\ntest"}
        self.setup._options = {"remote_password": remote, "recovery_password": recovery}
        with tempfile.TemporaryDirectory() as directory:
            self.setup._install_path.set(directory)
            with patch.object(installer.Install, "_download_files"):
                self.setup._download_files(0, 1)
            saved = json.loads((Path(directory) / support_setup.ACCESS_FILE).read_text())
            self.assertEqual(saved["recovery_password"], recovery)
            self.assertNotIn("local-recovery-test", json.dumps(saved))
            removal = support_setup.SupportUninstall()
            removal._access_config = saved
            removal._native = Mock()
            removal._native.check_init_uninstall.return_value = None
            removal._native.get_install_path.return_value = directory
            with patch.object(setup_auth.http.client, "HTTPSConnection") as network:
                self.setup._setup_password.set("local-recovery-test")
                code_screen = self.setup.step_password(self.current)
                self.assertIsInstance(code_screen, ui.Inputs)
                self.assertTrue(self.setup._setup_authorized)
                removal._setup_password.set("local-recovery-test")
                with patch.object(installer.Uninstall, "step_remove", return_value="uninstall-authorized"):
                    self.assertEqual(removal.step_password(self.current), "uninstall-authorized")
                network.assert_not_called()

    def test_service_filename_must_not_contain_a_path_or_command(self):
        native = support_setup.SupportWindows()
        for filename in ("../dwagsvc1.exe", r"C:\dwagsvc1.exe", "svc.exe & echo", None):
            with self.assertRaises(ValueError):
                native.set_service_executable(filename)

    def test_uninstall_does_not_report_success_when_service_is_still_running(self):
        removal = support_setup.SupportUninstall()
        removal._setup_authorized = True
        removal._silent = False
        removal._install_path = r"C:\Program Files\MyDWagent2"
        removal._install_log = None
        removal._native = Mock()
        removal._native.get_service_state.return_value = 4
        removal._uinterface = Mock()
        self.current.set_key("confirm")
        with patch.object(removal, "_uninstall_monitor"), patch.object(removal, "_uninstall_shortcuts") as shortcuts, \
                patch.object(installer.utils, "file_open", side_effect=OSError("test log disabled")):
            result = removal.step_remove(self.current)
        self.assertIsInstance(result, ui.ErrorDialog)
        self.assertIn("could not stop", result.get_message())
        removal._native.delete_service.assert_not_called()
        shortcuts.assert_not_called()

    def test_uninstall_verifies_service_deletion_and_handles_already_stopped(self):
        for states in ([4, 1, None], [1, None], [None]):
            removal = support_setup.SupportUninstall()
            removal._native = Mock()
            removal._native.get_service_state.side_effect = states
            removal._native.delete_service.return_value = True
            removal._uinterface = Mock()
            removal._uninstall_service(0, 1)
            self.assertEqual(removal._native.stop_service.call_count, 1 if states[0] == 4 else 0)
            self.assertEqual(removal._native.delete_service.call_count, 0 if states[0] is None else 1)

    def test_uninstall_blocks_folder_removal_when_service_delete_fails(self):
        removal = support_setup.SupportUninstall()
        removal._native = Mock()
        removal._native.get_service_state.return_value = 1
        removal._native.delete_service.return_value = False
        removal._uinterface = Mock()
        with self.assertRaisesRegex(RuntimeError, "could not remove"):
            removal._uninstall_service(0, 1)

    def test_uninstall_detects_remaining_app_registration(self):
        removal = support_setup.SupportUninstall()
        removal._native = Mock()
        removal._native.remove_shortcuts.return_value = True
        removal._native.get_install_path.return_value = r"C:\Program Files\MyDWagent2"
        removal._uinterface = Mock()
        with self.assertRaisesRegex(RuntimeError, "registration"):
            removal._uninstall_shortcuts(0, 1)


if __name__ == "__main__":
    unittest.main()
