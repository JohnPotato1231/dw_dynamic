"""A replacement operates through a private copy of the new native helper."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_support_setup as fixtures

support = fixtures.support_setup
PROFILE = {"main_executable": "fixture_agent.exe", "service_executable": "fixture_service.exe",
           "service_name": "FixtureAgent", "service_display_name": "Fixture Support", "publisher": "Fixture Company"}


class ReplacementToolTests(unittest.TestCase):
    def test_helper_uses_fresh_binary_and_verified_old_identity_in_private_folder(self):
        setup = support.SupportInstall()
        native = support.SupportWindows()
        native.set_install_identity(PROFILE)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "installer" / "native"
            source.mkdir(parents=True)
            (source / "dwagsvc.exe").write_bytes(b"fresh bundled helper")
            old = root / "old installation"
            (old / "native").mkdir(parents=True)
            (old / "native" / PROFILE["service_executable"]).write_bytes(b"old helper")
            native.set_install_path(str(old))
            with patch.object(support, "program_files_directory", return_value=root), \
                    patch.object(support, "__file__", str(source.parent / "support_setup.py")):
                with setup._replacement_tool(native):
                    helper = native._service_tool_path
                    self.assertEqual(helper.read_bytes(), b"fresh bundled helper")
                    self.assertNotEqual(helper.parent, old / "native")
                    properties = (helper.parent / "service.properties").read_text(encoding="utf-8")
                    self.assertIn("workPath=" + str(old), properties)
                    self.assertIn("serviceName=FixtureAgent", properties)
                    self.assertIn("publisher=Fixture Company", properties)
            self.assertFalse(helper.exists())
            self.assertIsNone(native._service_tool_path)
            self.assertEqual((old / "native" / PROFILE["service_executable"]).read_bytes(), b"old helper")


if __name__ == "__main__":
    unittest.main()
