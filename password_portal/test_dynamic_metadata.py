"""Profile metadata stays authenticated while older installers retain their schema."""

import json
import unittest
from unittest.mock import Mock, patch

import test_portal as fixtures

portal = fixtures.portal
auth = fixtures.setup_auth
PROFILE = {"main_executable": "fixture_agent.exe", "service_executable": "fixture_service.exe",
           "service_name": "FixtureAgent", "service_display_name": "Fixture Remote Support"}
METADATA = {"install_path": r"%ProgramFiles%\Fixture Company\Remote Agent", "publisher": "Fixture Company Ω"}


class MetadataValidationTests(unittest.TestCase):
    def test_old_profiles_and_valid_metadata_have_identical_client_server_interpretation(self):
        for extra in ({}, METADATA, {"install_path": "", "publisher": "DWService"},
                      {"install_path": r"D:\Company Name\Agent", "publisher": "Ünicode & Company"}):
            profile = {**PROFILE, **extra}
            with self.subTest(profile=profile):
                self.assertEqual(auth.validate_install_identity(profile), profile)
                self.assertEqual(portal.validate_install_identity(profile), profile)

    def test_installation_paths_reject_ambiguous_or_unsafe_windows_destinations(self):
        invalid = [r"\\server\share\Agent", r"\\?\C:\Company\Agent", r"\\.\C:\Agent",
                   "Agent", r"C:Agent", r"\Company\Agent", "C:\\", r"C:\Windows",
                   r"C:\Windows\Temp\Agent", r"C:\Company\..\Agent", r"C:\Company\.\Agent",
                   r"C:\Company\Agent:stream", r"C:\Company\Ag?ent", r"C:\Company\Ag|ent",
                   r"C:\Company\CON.txt", r"C:\Company\COM1", r"C:\Company\LPT¹.txt",
                   "C:\\Company\\Agent.", "C:\\Company\\Agent ", "C:\\Company\\A\nB",
                   r"%TEMP%\Company\Agent", r"%ProgramFiles%\..\Agent",
                   "%ProgramFiles%", "C:\\" + "A" * 180]
        for value in invalid:
            for validator in (auth.validate_install_identity, portal.validate_install_identity):
                with self.subTest(value=value, validator=validator.__module__), self.assertRaises(ValueError):
                    validator({**PROFILE, "install_path": value})

    def test_publisher_rejects_properties_injection_and_unbounded_text(self):
        for value in ("", "A\nserviceName=Injected", "A\rB", "A\x00B", "A\tB", "x" * 101, 123, None):
            for validator in (auth.validate_install_identity, portal.validate_install_identity):
                with self.subTest(value=value, validator=validator.__module__), self.assertRaises(ValueError):
                    validator({**PROFILE, "publisher": value})
        for validator in (auth.validate_install_identity, portal.validate_install_identity):
            with self.assertRaises(ValueError):
                validator({**PROFILE, "unexpected_setting": "value"})


class MetadataPortalTests(unittest.TestCase):
    setUp = fixtures.PortalTests.setUp
    tearDown = fixtures.PortalTests.tearDown
    request = fixtures.PortalTests.request
    login = fixtures.PortalTests.login

    def verify_identity(self, version=None):
        fields = {"password": "initial-exe-password", "include_install_identity": True}
        if version is not None:
            fields["install_identity_version"] = version
        status, _, body = self.request("/api/verify", fields,
            extra_headers={"Authorization": "Bearer " + auth._INSTALL_IDENTITY_CLIENT_PASSWORD})
        self.assertEqual(status, 200)
        return json.loads(body)["install_identity"]

    def test_api_keeps_legacy_schema_and_only_version_two_includes_metadata(self):
        self.store.save_install_identity({**PROFILE, **METADATA})
        self.assertEqual(self.verify_identity(), PROFILE)
        self.assertEqual(self.verify_identity(2), {**PROFILE, **METADATA})

    def test_version_two_fills_metadata_defaults_for_an_older_stored_profile(self):
        self.store.save_install_identity(PROFILE)
        self.assertEqual(self.verify_identity(2), {**PROFILE, "install_path": "", "publisher": "DWService"})
        self.assertEqual(self.verify_identity(), PROFILE)

    def test_dashboard_saves_metadata_with_existing_authentication_and_escapes_publisher(self):
        cookie, csrf = self.login()
        fields = {**PROFILE, **METADATA, "publisher": "Fixture <Company> & Partners", "csrf": csrf}
        self.assertEqual(self.request("/install-identity", fields, cookie)[0], 303)
        expected = {key: value for key, value in fields.items() if key != "csrf"}
        self.assertEqual(portal.Store(self.store.path).install_identity(), expected)
        status, _, body = self.request("/", cookie=cookie, method="GET")
        self.assertEqual(status, 200)
        self.assertIn('name="install_path"', body)
        self.assertIn('name="publisher"', body)
        self.assertIn("Fixture &lt;Company&gt; &amp; Partners", body)
        self.assertNotIn("Fixture <Company>", body)
        fields["install_path"] = r"C:\Windows\Agent"
        self.assertEqual(self.request("/install-identity", fields, cookie)[0], 400)
        self.assertEqual(self.store.install_identity(), expected)

    def test_legacy_admin_submission_does_not_erase_metadata(self):
        self.store.save_install_identity({**PROFILE, **METADATA})
        cookie, csrf = self.login()
        changed = {**PROFILE, "service_display_name": "Updated Fixture Support"}
        self.assertEqual(self.request("/install-identity", {**changed, "csrf": csrf}, cookie)[0], 303)
        self.assertEqual(self.store.install_identity(), {**changed, **METADATA})


class MetadataClientTests(unittest.TestCase):
    setUp = fixtures.OnlineClientTests.setUp

    def request_body(self, version, with_identity=True):
        if version is not None:
            self.options["install_identity_version"] = version
        connection = Mock()
        connection.getresponse.return_value = Mock(status=200, read=Mock(return_value=b'{"allowed":true}'))
        kwargs = {"install_identity": {}} if with_identity else {}
        with patch.object(auth.ssl, "create_default_context"), \
                patch.object(auth.http.client, "HTTPSConnection", return_value=connection):
            self.assertTrue(auth.verify_access_password("server-password", self.options, **kwargs))
        return json.loads(connection.request.call_args.kwargs["body"])

    def test_metadata_schema_is_requested_only_by_new_profile_clients(self):
        for version, with_identity, expected in ((None, True, False), (1, True, False),
                                                  (2, True, True), (2, False, False)):
            self.options.pop("install_identity_version", None)
            with self.subTest(version=version, with_identity=with_identity):
                body = self.request_body(version, with_identity)
                self.assertEqual("install_identity_version" in body, expected)
                if expected:
                    self.assertEqual(body["install_identity_version"], 2)

    def test_new_profile_response_loads_metadata_and_rejects_path_injection(self):
        for path, valid in ((METADATA["install_path"], True), (r"C:\Windows\Agent", False)):
            identity = dict(PROFILE)
            profile = {**PROFILE, **METADATA, "install_path": path}
            connection = Mock()
            connection.getresponse.return_value = Mock(status=200,
                read=Mock(return_value=json.dumps({"allowed": True, "install_identity": profile}).encode()))
            with self.subTest(path=path), patch.object(auth.ssl, "create_default_context"), \
                    patch.object(auth.http.client, "HTTPSConnection", return_value=connection):
                if valid:
                    self.assertTrue(auth.verify_access_password("server-password", self.options, install_identity=identity))
                    self.assertEqual(identity, profile)
                else:
                    with self.assertRaises(auth.PasswordServerUnavailable):
                        auth.verify_access_password("server-password", self.options, install_identity=identity)
                    self.assertEqual(identity, {})


if __name__ == "__main__":
    unittest.main()
