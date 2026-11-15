"""Exercise password changes, permissions, CSRF and live installer verification."""

import http.client
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import threading
import unittest
from urllib.parse import urlencode
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "os_win_installer"))
import setup_auth

spec = importlib.util.spec_from_file_location("portal_server", Path(__file__).with_name("server.py"))
portal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(portal)


class PortalTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = portal.Store(Path(self.directory.name) / "state.sqlite3")
        self.store.initialize("admin-test-password-123", portal.password_record("initial-exe-password"))
        template = Path(__file__).with_name("index.html").read_text(encoding="utf-8")
        self.server = portal.PortalServer(("127.0.0.1", 0), self.store, template, "https://portal.test")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.directory.cleanup()

    def request(self, path, fields=None, cookie=None, origin="https://portal.test", method="POST", extra_headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {"Origin": origin}
        body = None
        if fields is not None:
            if path == "/api/verify":
                body, headers["Content-Type"] = json.dumps(fields), "application/json"
            else:
                body, headers["Content-Type"] = urlencode(fields), "application/x-www-form-urlencoded"
        if cookie:
            headers["Cookie"] = cookie
        headers.update(extra_headers or {})
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        status, response_headers, body = response.status, dict(response.getheaders()), response.read().decode()
        connection.close()
        return status, response_headers, body

    def login(self):
        status, headers, _ = self.request("/login", {"username": "admin", "password": "admin-test-password-123"})
        self.assertEqual(status, 303)
        self.assertIn("Secure; HttpOnly; SameSite=Strict", headers["Set-Cookie"])
        cookie = headers["Set-Cookie"].split(";")[0]
        status, _, body = self.request("/", cookie=cookie, method="GET")
        self.assertEqual(status, 200)
        return cookie, re.search(r'name="csrf" value="([^"]+)"', body).group(1)

    def test_multiple_passwords_and_immediate_individual_revocation_survive_new_store(self):
        self.assertEqual(self.request("/api/verify", {"password": "initial-exe-password"})[0], 200)
        self.assertEqual(self.request("/api/verify", {"password": "wrong"})[0], 403)
        cookie, csrf = self.login()
        self.assertEqual(self.request("/passwords/add", {"csrf": csrf, "name": "Laptop 2", "password": "new-live-password",
                                                  "confirm": "new-live-password"}, cookie)[0], 303)
        self.assertEqual(self.request("/api/verify", {"password": "initial-exe-password"})[0], 200)
        status, _, body = self.request("/api/verify", {"password": "new-live-password"})
        self.assertEqual((status, json.loads(body)), (200, {"allowed": True}))
        reopened = portal.Store(self.store.path)
        self.assertTrue(reopened.verify_password("new-live-password"))
        original_id = next(row["id"] for row in self.store.passwords() if row["name"] == "Existing password")
        self.assertEqual(self.request("/passwords/delete", {"csrf": csrf, "id": original_id}, cookie)[0], 303)
        self.assertEqual(self.request("/api/verify", {"password": "initial-exe-password"})[0], 403)
        self.assertEqual(self.request("/api/verify", {"password": "new-live-password"})[0], 200)
        self.store.migrate_passwords()
        self.assertFalse(reopened.verify_password("initial-exe-password"))
        self.assertTrue(reopened.verify_password("new-live-password"))
        self.assertNotIn("new-live-password", Path(self.store.path).read_bytes().decode(errors="ignore"))

    def test_password_update_requires_login_csrf_and_same_origin(self):
        fields = {"name": "Laptop 2", "password": "new-live-password", "confirm": "new-live-password"}
        self.assertEqual(self.request("/passwords/add", fields)[0], 403)
        cookie, csrf = self.login()
        self.assertEqual(self.request("/passwords/add", fields, cookie)[0], 403)
        fields["csrf"] = csrf
        self.assertEqual(self.request("/passwords/add", fields, cookie, origin="https://attacker.test")[0], 403)
        original_id = self.store.passwords()[0]["id"]
        for csrf_value in ("", "wrong-token"):
            self.assertEqual(self.request("/passwords/delete", {"id": original_id, "csrf": csrf_value}, cookie)[0], 403)
        self.assertTrue(self.store.verify_password("initial-exe-password"))

    def test_login_page_preserves_origin_for_browser_form_submissions(self):
        status, headers, body = self.request("/", method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Referrer-Policy"], "same-origin")
        self.assertIn('action="/login" method="post"', body)
        fields = {"username": "admin", "password": "admin-test-password-123"}
        for origin in ("null", "https://attacker.test"):
            self.assertEqual(self.request("/login", fields, origin=origin)[0], 403)
        self.assertEqual(self.request("/login", fields)[0], 303)

    def test_admin_password_change_revokes_sessions(self):
        cookie, csrf = self.login()
        fields = {"csrf": csrf, "current": "admin-test-password-123",
                  "password": "replacement-admin-123", "confirm": "replacement-admin-123"}
        self.assertEqual(self.request("/admin-password", fields, cookie)[0], 303)
        self.assertEqual(self.request("/passwords/add", fields, cookie)[0], 403)
        self.assertFalse(portal.matches("admin-test-password-123", self.store.setting("admin")))

    def test_duplicate_passwords_are_rejected_and_deleted_password_does_not_return(self):
        cookie, csrf = self.login()
        fields = {"csrf": csrf, "name": "Duplicate", "password": "initial-exe-password",
                  "confirm": "initial-exe-password"}
        self.assertEqual(self.request("/passwords/add", fields, cookie)[0], 400)
        original_id = self.store.passwords()[0]["id"]
        self.assertEqual(self.request("/passwords/delete", {"id": original_id, "csrf": csrf}, cookie)[0], 303)
        self.assertEqual(self.request("/api/verify", {"password": "initial-exe-password"})[0], 403)
        self.store.migrate_passwords()
        self.assertEqual(len(self.store.passwords()), 0)

    def test_labels_are_escaped_in_dashboard(self):
        cookie, csrf = self.login()
        fields = {"csrf": csrf, "name": '<img src=x onerror="alert(1)">', "password": "new-live-password",
                  "confirm": "new-live-password"}
        self.assertEqual(self.request("/passwords/add", fields, cookie)[0], 303)
        _, _, body = self.request("/", cookie=cookie, method="GET")
        self.assertNotIn('<img src=x onerror=', body)
        self.assertIn('&lt;img src=x', body)

    def test_more_than_ten_passwords_work_with_indexed_verification(self):
        for index in range(12):
            self.store.add_password("Extra " + str(index), "extra-password-" + str(index))
        self.assertEqual(len(self.store.passwords()), 13)
        with patch.object(portal, "matches", wraps=portal.matches) as verify:
            self.assertTrue(self.store.verify_password("extra-password-11"))
            # Only one indexed candidate plus the single legacy entry may be checked.
            self.assertLessEqual(verify.call_count, 2)
        password_id = next(row["id"] for row in self.store.passwords() if row["name"] == "Extra 11")
        self.store.delete_password(password_id)
        self.assertFalse(self.store.verify_password("extra-password-11"))

    def test_missing_lookup_key_can_recover_existing_passwords_without_plaintext(self):
        self.store.add_password("Second", "second-password")
        Path(self.store.path + ".lookup-key").unlink()
        recovered = portal.Store(self.store.path)
        recovered.migrate_passwords()
        self.assertTrue(recovered.verify_password("second-password"))

    def test_rate_limit_and_malformed_json(self):
        for _ in range(30):
            self.assertEqual(self.request("/api/verify", {"password": "wrong"})[0], 403)
        self.assertEqual(self.request("/api/verify", {"password": "wrong"})[0], 429)


class OnlineClientTests(unittest.TestCase):
    def setUp(self):
        self.options = {"remote_password": {"url": "https://portal.test/api/verify",
                         "ca_pem": "-----BEGIN CERTIFICATE-----\ntest"},
                        "setup_password": setup_auth.make_password_record("old-static-password")}

    def test_remote_mode_never_falls_back_and_closes_connection(self):
        response = Mock(status=403)
        connection = Mock()
        connection.getresponse.return_value = response
        with patch.object(setup_auth.ssl, "create_default_context"), \
                patch.object(setup_auth.http.client, "HTTPSConnection", return_value=connection), \
                patch.object(setup_auth, "verify_password") as local:
            self.assertFalse(setup_auth.verify_access_password("old-static-password", self.options))
            local.assert_not_called()
            connection.close.assert_called_once()

    def test_network_failure_and_invalid_response_fail_closed(self):
        for failure in (OSError("offline"), None):
            connection = Mock()
            if failure:
                connection.request.side_effect = failure
            else:
                connection.getresponse.return_value = Mock(status=200, read=Mock(return_value=b'{"allowed":"yes"}'))
            with self.subTest(failure=failure), patch.object(setup_auth.ssl, "create_default_context"), \
                    patch.object(setup_auth.http.client, "HTTPSConnection", return_value=connection):
                with self.assertRaises(setup_auth.PasswordServerUnavailable):
                    setup_auth.verify_access_password("password", self.options)

    def test_explicit_positive_response_authorizes(self):
        connection = Mock()
        connection.getresponse.return_value = Mock(status=200, read=Mock(return_value=b'{"allowed":true}'))
        with patch.object(setup_auth.ssl, "create_default_context"), \
                patch.object(setup_auth.http.client, "HTTPSConnection", return_value=connection), \
                patch.object(setup_auth.socket, "gethostname", return_value="OFFICE-LAPTOP"):
            self.assertTrue(setup_auth.verify_access_password("password", self.options))
        body = json.loads(connection.request.call_args.kwargs["body"])
        self.assertEqual(body, {"password": "password", "device_name": "OFFICE-LAPTOP"})

    def test_device_name_is_bounded(self):
        connection = Mock()
        connection.getresponse.return_value = Mock(status=200, read=Mock(return_value=b'{"allowed":true}'))
        with patch.object(setup_auth.ssl, "create_default_context"), \
                patch.object(setup_auth.http.client, "HTTPSConnection", return_value=connection), \
                patch.object(setup_auth.socket, "gethostname", return_value="x" * 300):
            self.assertTrue(setup_auth.verify_access_password("password", self.options))
        body = json.loads(connection.request.call_args.kwargs["body"])
        self.assertEqual(body["device_name"], "x" * 255)

    def test_missing_or_failing_hostname_does_not_block_authorization(self):
        for hostname, failure in (("", None), (None, None), (None, OSError("hostname unavailable")),
                                  (None, RuntimeError("hostname lookup failed"))):
            connection = Mock()
            connection.getresponse.return_value = Mock(status=200, read=Mock(return_value=b'{"allowed":true}'))
            with self.subTest(hostname=hostname, failure=failure), \
                    patch.object(setup_auth.ssl, "create_default_context"), \
                    patch.object(setup_auth.http.client, "HTTPSConnection", return_value=connection), \
                    patch.object(setup_auth.socket, "gethostname", return_value=hostname, side_effect=failure):
                self.assertTrue(setup_auth.verify_access_password("password", self.options))
                body = json.loads(connection.request.call_args.kwargs["body"])
                self.assertEqual(body, {"password": "password", "device_name": ""})

    def test_bad_online_config_cannot_fall_back_to_local(self):
        self.options["remote_password"]["url"] = "http://portal.test/api/verify"
        self.assertFalse(setup_auth.valid_access_config(self.options))
        with self.assertRaises(setup_auth.PasswordServerUnavailable):
            setup_auth.verify_access_password("old-static-password", self.options)

    def test_recovery_hash_accepts_correct_password_without_contacting_server(self):
        self.options["recovery_password"] = setup_auth.make_password_record("local-recovery-test")
        with patch.object(setup_auth.http.client, "HTTPSConnection") as network, \
                patch.object(setup_auth.socket, "gethostname") as hostname:
            self.assertTrue(setup_auth.verify_access_password("local-recovery-test", self.options))
            network.assert_not_called()
            hostname.assert_not_called()

    def test_server_password_still_works_with_recovery_enabled(self):
        self.options["recovery_password"] = setup_auth.make_password_record("local-recovery-test")
        connection = Mock()
        connection.getresponse.return_value = Mock(status=200, read=Mock(return_value=b'{"allowed":true}'))
        with patch.object(setup_auth.ssl, "create_default_context"), \
                patch.object(setup_auth.http.client, "HTTPSConnection", return_value=connection):
            self.assertTrue(setup_auth.verify_access_password("server-password-test", self.options))
            body = json.loads(connection.request.call_args.kwargs["body"])
            self.assertEqual(body["password"], "server-password-test")

    def test_wrong_password_rejected_when_neither_hash_nor_server_accepts(self):
        self.options["recovery_password"] = setup_auth.make_password_record("local-recovery-test")
        connection = Mock()
        connection.getresponse.return_value = Mock(status=403)
        with patch.object(setup_auth.ssl, "create_default_context"), \
                patch.object(setup_auth.http.client, "HTTPSConnection", return_value=connection):
            self.assertFalse(setup_auth.verify_access_password("wrong-password", self.options))

    def test_wrong_recovery_password_cannot_bypass_offline_server(self):
        self.options["recovery_password"] = setup_auth.make_password_record("local-recovery-test")
        with patch.object(setup_auth.ssl, "create_default_context"), \
                patch.object(setup_auth.http.client, "HTTPSConnection", side_effect=OSError("offline")):
            with self.assertRaises(setup_auth.PasswordServerUnavailable):
                setup_auth.verify_access_password("wrong-password", self.options)

    def test_malformed_recovery_hash_is_not_accepted(self):
        self.options["recovery_password"] = {"digest": "invalid"}
        self.assertFalse(setup_auth.valid_access_config(self.options))
        with self.assertRaises(setup_auth.PasswordServerUnavailable):
            setup_auth.verify_access_password("anything", self.options)


if __name__ == "__main__":
    unittest.main()
