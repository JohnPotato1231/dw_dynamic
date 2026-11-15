"""Uninstall races and native error details without changing Windows services."""

import unittest
from unittest.mock import Mock, patch

import test_support_setup as fixtures

support = fixtures.support_setup
installer = fixtures.installer


class UninstallDiagnosticTests(unittest.TestCase):
    def test_native_failure_retains_the_windows_error(self):
        native = support.SupportWindows()
        child = Mock()
        child.communicate.return_value = (b"ERROR: Windows error 5", b"")
        with patch.object(installer, "NativeWindowsPopenUnicode", return_value=child):
            self.assertFalse(native.executecmd("fixture.exe removeShortcuts"))
        self.assertIn("Windows error 5", native.last_service_error)
        removal = support.SupportUninstall()
        removal._native = native
        removal._uinterface = Mock()
        with patch.object(native, "remove_shortcuts", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "Windows error 5"):
                removal._uninstall_shortcuts(0, 1)

    def test_later_success_clears_the_previous_native_error(self):
        native = support.SupportWindows()
        child = Mock()
        child.communicate.side_effect = [(b"ERROR: Windows error 5", b""), (b"OK", b"")]
        with patch.object(installer, "NativeWindowsPopenUnicode", return_value=child):
            self.assertFalse(native.executecmd("fixture"))
            self.assertTrue(native.executecmd("fixture"))
        self.assertEqual(native.last_service_error, "")

    def test_stop_pending_is_polled_before_service_deletion(self):
        removal = support.SupportUninstall()
        removal._native = Mock()
        removal._uinterface = Mock()
        removal._native.get_service_state.side_effect = [4, 3, 1, None]
        removal._native.stop_service.return_value = True
        removal._native.delete_service.return_value = True
        with patch.object(support.time, "sleep") as sleep:
            removal._uninstall_service(0, 1)
        sleep.assert_called_once_with(0.2)
        removal._native.delete_service.assert_called_once()

    def test_service_disappearing_during_stop_is_already_removed(self):
        removal = support.SupportUninstall()
        removal._native = Mock()
        removal._uinterface = Mock()
        removal._native.get_service_state.side_effect = [4, None]
        removal._native.stop_service.return_value = True
        removal._uninstall_service(0, 1)
        removal._native.delete_service.assert_not_called()


if __name__ == "__main__":
    unittest.main()
