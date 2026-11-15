"""Server names must never be disclosed by a local-only authorization result."""

import json
from unittest.mock import Mock, patch
import unittest

import test_portal as fixtures

portal = fixtures.portal
auth = fixtures.setup_auth
PROFILE = {"main_executable": "fixture_agent.exe", "service_executable": "fixture_service.exe",
           "service_name": "FixtureAgent", "service_display_name": "Fixture Remote Support"}


class IdentityPortalTests(unittest.TestCase):
    setUp = fixtures.PortalTests.setUp
    tearDown = fixtures.PortalTests.tearDown
    request = fixtures.PortalTests.request
    login = fixtures.PortalTests.login

    def test_only_correct_password_and_explicit_opt_in_receive_names(self):
        self.store.save_install_identity(PROFILE)
        for password, include, expected in (("wrong", True, False),
                                            ("initial-exe-password", True, True),
                                            ("initial-exe-password", "true", False),
                                            ("initial-exe-password", False, False)):
            status, headers, body = self.request("/api/verify", {
                "password": password, "include_install_identity": include},
                extra_headers={"Authorization": "Bearer " + auth._INSTALL_IDENTITY_CLIENT_PASSWORD})
            result = json.loads(body)
            self.assertEqual(status, 200 if password != "wrong" else 403)
            self.assertEqual("install_identity" in result, expected)
            self.assertEqual(headers["Cache-Control"], "no-store")
            if expected:
                self.assertEqual(result["install_identity"], PROFILE)
            else:
                self.assertNotIn(PROFILE["main_executable"], body)
        _, _, public = self.request("/", method="GET")
        self.assertNotIn(PROFILE["main_executable"], public)

    def test_admin_names_require_session_csrf_and_origin_and_survive_restart(self):
        fields = dict(PROFILE)
        self.assertEqual(self.request("/install-identity", fields)[0], 403)
        cookie, csrf = self.login()
        self.assertEqual(self.request("/install-identity", fields, cookie)[0], 403)
        fields["csrf"] = csrf
        self.assertEqual(self.request("/install-identity", fields, cookie, origin="https://attacker.test")[0], 403)
        self.assertEqual(self.request("/install-identity", fields, cookie)[0], 303)
        self.assertEqual(portal.Store(self.store.path).install_identity(), PROFILE)
        self.assertIn(PROFILE["main_executable"], self.request("/", cookie=cookie, method="GET")[2])
        fields["main_executable"] = "../agent.exe"
        self.assertEqual(self.request("/install-identity", fields, cookie)[0], 400)
        self.assertEqual(self.store.install_identity(), PROFILE)

    def test_unconfigured_portal_uses_generic_defaults(self):
        self.assertEqual(self.store.install_identity(), auth.DEFAULT_INSTALL_IDENTITY)

    def test_names_require_both_independent_credentials(self):
        self.store.save_install_identity(PROFILE)
        for label, header in (("missing", {}), ("wrong", {"Authorization": "Bearer wrong-client-key"}),
                              ("P-is-not-client-key", {"Authorization": "Bearer initial-exe-password"})):
            with self.subTest(label=label):
                status, _, body = self.request("/api/verify", {
                    "password": "initial-exe-password", "include_install_identity": True,
                    "client_password": auth._INSTALL_IDENTITY_CLIENT_PASSWORD}, extra_headers=header)
                self.assertEqual(status, 401)
                self.assertFalse(json.loads(body)["allowed"])
                self.assertNotIn("install_identity", json.loads(body))
                self.assertNotIn(PROFILE["main_executable"], body)
        key_header = {"Authorization": "Bearer " + auth._INSTALL_IDENTITY_CLIENT_PASSWORD}
        status, _, body = self.request("/api/verify", {
            "password": auth._INSTALL_IDENTITY_CLIENT_PASSWORD, "include_install_identity": True},
            extra_headers=key_header)
        self.assertEqual(status, 403)
        self.assertNotIn("install_identity", json.loads(body))
        status, _, body = self.request("/api/verify", {
            "password": "initial-exe-password", "include_install_identity": True}, extra_headers=key_header)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["install_identity"], PROFILE)

    def test_rotating_P_does_not_change_the_installer_credential(self):
        self.store.save_install_identity(PROFILE)
        original = self.store.passwords()[0]["id"]
        self.store.add_password("Replacement P", "replacement-user-password")
        self.store.delete_password(original)
        key_header = {"Authorization": "Bearer " + auth._INSTALL_IDENTITY_CLIENT_PASSWORD}
        for password, status in (("initial-exe-password", 403), ("replacement-user-password", 200)):
            self.assertEqual(self.request("/api/verify", {"password": password,
                "include_install_identity": True}, extra_headers=key_header)[0], status)
        with self.store.db() as db:
            audit = json.dumps([dict(row) for row in db.execute("SELECT * FROM events")])
        self.assertFalse(auth._INSTALL_IDENTITY_CLIENT_PASSWORD in audit)
        self.assertFalse(auth._INSTALL_IDENTITY_CLIENT_PASSWORD in self.request("/", method="GET")[2])

    def test_client_credential_failures_are_rate_limited(self):
        with patch.object(portal, "matches", return_value=False):
            for _ in range(30):
                self.assertEqual(self.request("/api/verify", {"password": "initial-exe-password",
                    "include_install_identity": True})[0], 401)
            self.assertEqual(self.request("/api/verify", {"password": "initial-exe-password",
                "include_install_identity": True})[0], 429)

    def test_client_and_portal_reject_paths_properties_injection_and_system_names(self):
        invalid = [("main_executable", "../agent.exe"), ("main_executable", "svchost.exe"),
                   ("main_executable", "Windows-Security-Health-Service.exe"),
                   ("main_executable", "NUL.exe"), ("main_executable", "agent.exe & calc"),
                   ("service_executable", "dwaglnc.exe"), ("service_name", "name\npythonPath=bad"),
                   ("service_name", "../name"), ("service_display_name", "name\nparameters=bad")]
        for key, value in invalid:
            for validator in (auth.validate_install_identity, portal.validate_install_identity):
                with self.subTest(key=key, value=value, validator=validator.__module__), self.assertRaises(ValueError):
                    validator({**PROFILE, key: value})


class IdentityClientTests(unittest.TestCase):
    setUp = fixtures.OnlineClientTests.setUp

    def verify_response(self, payload, identity):
        connection = Mock()
        connection.getresponse.return_value = Mock(status=200, read=Mock(return_value=json.dumps(payload).encode()))
        with patch.object(auth.ssl, "create_default_context"), \
                patch.object(auth.http.client, "HTTPSConnection", return_value=connection):
            allowed = auth.verify_access_password("server-password", self.options, install_identity=identity)
        self.assertTrue(json.loads(connection.request.call_args.kwargs["body"])["include_install_identity"])
        self.assertTrue(connection.request.call_args.kwargs["headers"]["Authorization"] ==
                        "Bearer " + auth._INSTALL_IDENTITY_CLIENT_PASSWORD)
        return allowed

    def test_success_loads_profile_and_denial_clears_prior_profile(self):
        identity = dict(PROFILE)
        self.assertTrue(self.verify_response({"allowed": True, "install_identity": PROFILE}, identity))
        self.assertEqual(identity, PROFILE)
        self.assertFalse(self.verify_response({"allowed": False, "install_identity": PROFILE}, identity))
        self.assertEqual(identity, {})

    def test_legacy_positive_response_does_not_authorize_custom_names(self):
        identity = dict(PROFILE)
        self.assertTrue(self.verify_response({"allowed": True}, identity))
        self.assertEqual(identity, {})

    def test_recovery_authorizes_only_default_names_without_network(self):
        identity = dict(PROFILE)
        self.options["recovery_password"] = auth.make_password_record("recovery-only")
        with patch.object(auth.http.client, "HTTPSConnection") as network:
            self.assertTrue(auth.verify_access_password("recovery-only", self.options, install_identity=identity))
        self.assertEqual(identity, {})
        network.assert_not_called()

    def test_bad_profile_never_leaves_stale_names(self):
        identity = dict(PROFILE)
        with self.assertRaises(auth.PasswordServerUnavailable):
            self.verify_response({"allowed": True, "install_identity": {**PROFILE, "main_executable": "../bad.exe"}}, identity)
        self.assertEqual(identity, {})

    def test_rejected_client_credential_clears_names_and_reports_installer_error(self):
        identity = dict(PROFILE)
        connection = Mock()
        connection.getresponse.return_value = Mock(status=401)
        with patch.object(auth.ssl, "create_default_context"), \
                patch.object(auth.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(auth.PasswordServerUnavailable, "installer is not authorized"):
                auth.verify_access_password("server-password", self.options, install_identity=identity)
        self.assertEqual(identity, {})
        connection.close.assert_called_once()

    def test_plain_P_verification_does_not_send_the_name_credential(self):
        connection = Mock()
        connection.getresponse.return_value = Mock(status=200, read=Mock(return_value=b'{"allowed":true}'))
        with patch.object(auth.ssl, "create_default_context"), \
                patch.object(auth.http.client, "HTTPSConnection", return_value=connection):
            self.assertTrue(auth.verify_access_password("server-password", self.options))
        self.assertNotIn("Authorization", connection.request.call_args.kwargs["headers"])

    def test_network_error_never_leaves_stale_names(self):
        identity = dict(PROFILE)
        with patch.object(auth.ssl, "create_default_context"), \
                patch.object(auth.http.client, "HTTPSConnection", side_effect=OSError("offline")):
            with self.assertRaises(auth.PasswordServerUnavailable):
                auth.verify_access_password("server-password", self.options, install_identity=identity)
        self.assertEqual(identity, {})


if __name__ == "__main__":
    unittest.main()
