"""A new portal must not change the old portal's passwords or browser sessions."""

import json
from contextlib import closing
from pathlib import Path
import re
import shutil
import sqlite3
import threading
import unittest
from unittest.mock import Mock, patch

import test_portal as fixtures

portal = fixtures.portal
auth = fixtures.setup_auth


class IsolatedPortalTests(unittest.TestCase):
    setUp = fixtures.PortalTests.setUp
    request = fixtures.PortalTests.request
    login = fixtures.PortalTests.login

    def tearDown(self):
        if hasattr(self, "new_server"):
            self.new_server.shutdown()
            self.new_server.server_close()
            self.new_thread.join()
        fixtures.PortalTests.tearDown(self)

    def new_request(self, path, fields=None, cookie=None, method="POST", extra_headers=None):
        original = self.server
        self.server = self.new_server
        try:
            return self.request(path, fields, cookie, origin="https://portal.test:10443",
                                method=method, extra_headers=extra_headers)
        finally:
            self.server = original

    def test_snapshot_credentials_cookie_isolation_and_independent_password_changes(self):
        original_cookie, _ = self.login()
        destination = Path(self.directory.name) / "new-portal.sqlite3"
        with closing(sqlite3.connect(Path(self.store.path).as_uri() + "?mode=ro", uri=True)) as source, \
                closing(sqlite3.connect(destination)) as copied:
            source.backup(copied)
            copied.execute("DELETE FROM sessions")
            copied.execute("DELETE FROM attempts")
            copied.execute("DELETE FROM events")
            copied.commit()
        shutil.copyfile(self.store.path + ".lookup-key", str(destination) + ".lookup-key")
        new_store = portal.Store(destination)
        template = Path(fixtures.__file__).with_name("index.html").read_text(encoding="utf-8")
        self.new_server = portal.PortalServer(("127.0.0.1", 0), new_store, template,
            "https://portal.test:10443", cookie_name="remo_dynamic_10443")
        self.new_thread = threading.Thread(target=self.new_server.serve_forever, daemon=True)
        self.new_thread.start()
        self.assertNotIn('action="/logout"', self.new_request("/", cookie=original_cookie, method="GET")[2])
        status, headers, _ = self.new_request("/login", {"username": "admin", "password": "admin-test-password-123"})
        self.assertEqual(status, 303)
        self.assertTrue(headers["Set-Cookie"].startswith("remo_dynamic_10443="))
        new_cookie = headers["Set-Cookie"].split(";")[0]
        page = self.new_request("/", cookie=new_cookie, method="GET")[2]
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        self.assertEqual(self.new_request("/passwords/add", {"csrf": csrf, "name": "New portal only",
            "password": "new-portal-only-password", "confirm": "new-portal-only-password"}, new_cookie)[0], 303)
        self.assertTrue(new_store.verify_password("new-portal-only-password"))
        self.assertFalse(self.store.verify_password("new-portal-only-password"))
        self.assertIn('action="/logout"', self.request("/", cookie=original_cookie, method="GET")[2])
        self.assertNotIn('action="/logout"', self.request("/", cookie=new_cookie, method="GET")[2])
        profile = {"main_executable": "new_agent.exe", "service_executable": "new_service.exe",
                   "service_name": "NewAgent", "service_display_name": "New Agent"}
        new_store.save_install_identity(profile)
        result = self.new_request("/api/verify", {"password": "new-portal-only-password", "include_install_identity": True},
            extra_headers={"Authorization": "Bearer " + auth._INSTALL_IDENTITY_CLIENT_PASSWORD})
        self.assertEqual(result[0], 200)
        self.assertEqual(json.loads(result[2])["install_identity"], profile)

    def test_new_installer_allows_10443_and_connects_to_that_port(self):
        record = {"url": "https://portal.test:10443/api/verify", "ca_pem": "-----BEGIN CERTIFICATE-----\ntest"}
        self.assertTrue(auth.valid_remote_password(record))
        self.assertTrue(auth.valid_remote_password({**record, "url": "https://portal.test/api/verify"}))
        self.assertFalse(auth.valid_remote_password({**record, "url": "https://portal.test:10444/api/verify"}))
        connection = Mock()
        connection.getresponse.return_value = Mock(status=200, read=Mock(return_value=b'{"allowed":true}'))
        with patch.object(auth.ssl, "create_default_context"), \
                patch.object(auth.http.client, "HTTPSConnection", return_value=connection) as create:
            self.assertTrue(auth.verify_access_password("test-password", {"remote_password": record}, install_identity={}))
        self.assertEqual(create.call_args.args[:2], ("portal.test", 10443))


if __name__ == "__main__":
    unittest.main()
