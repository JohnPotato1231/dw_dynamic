"""Audit metadata, legacy history migration, and protected log retention."""

from datetime import datetime, timedelta, timezone
import html
import http.client
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

import test_portal as fixtures

portal = fixtures.portal


class AuditLogTests(unittest.TestCase):
    setUp = fixtures.PortalTests.setUp
    tearDown = fixtures.PortalTests.tearDown
    request = fixtures.PortalTests.request
    login = fixtures.PortalTests.login

    def verification_events(self):
        with self.store.db() as db:
            return db.execute("SELECT * FROM events WHERE action IN "
                              "('EXE password accepted','EXE password rejected') ORDER BY rowid").fetchall()

    def login_with_user_agent(self, password, user_agent):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.request("POST", "/login", urlencode({"username": "admin", "password": password}), {
                "Origin": "https://portal.test", "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": user_agent, "X-Forwarded-For": "192.0.2.99"})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            connection.close()

    def test_admin_sign_in_audits_user_agent_and_keeps_history_private(self):
        wrong_password = "private-wrong-admin-password"
        rejected_agent = "Failed-browser\t<script>alert(3)</script>" + "a" * 300
        expected_rejected_agent = ("Failed-browser<script>alert(3)</script>" + "a" * 300)[:255]
        status, _, rejected_page = self.login_with_user_agent(wrong_password, rejected_agent)
        self.assertEqual(status, 401)
        self.assertNotIn("<th>Event</th>", rejected_page)
        self.assertNotIn(expected_rejected_agent, rejected_page)
        status, headers, _ = self.login_with_user_agent("admin-test-password-123", "Laptop 2 browser")
        self.assertEqual(status, 303)
        cookie = headers["Set-Cookie"].split(";")[0]
        with self.store.db() as db:
            events = db.execute("SELECT * FROM events ORDER BY rowid").fetchall()
        self.assertEqual([(row["action"], row["device_name"], row["ip"], row["password_label"]) for row in events], [
            ("Admin sign-in rejected", expected_rejected_agent, "127.0.0.1", ""),
            ("Admin signed in", "Laptop 2 browser", "127.0.0.1", "")])
        status, _, public_page = self.request("/", method="GET")
        self.assertEqual(status, 200)
        self.assertNotIn("<th>Event</th>", public_page)
        self.assertNotIn("Admin sign-in rejected", public_page)
        status, _, private_page = self.request("/", cookie=cookie, method="GET")
        self.assertEqual(status, 200)
        self.assertIn("Admin sign-in rejected", private_page)
        self.assertIn("Admin signed in", private_page)
        self.assertIn("Failed-browser&lt;script&gt;alert(3)&lt;/script&gt;", private_page)
        self.assertIn("Laptop 2 browser", private_page)
        self.assertNotIn("<script>", private_page)
        serialized = json.dumps([dict(row) for row in events])
        database_text = Path(self.store.path).read_bytes().decode(errors="ignore")
        for secret in (wrong_password, "admin-test-password-123"):
            self.assertNotIn(secret, serialized)
            self.assertNotIn(secret, database_text)
            self.assertNotIn(secret, private_page)

    def test_admin_sign_in_without_user_agent_keeps_unknown_device(self):
        self.assertEqual(self.request("/login", {"username": "admin", "password": "wrong-admin-password"})[0], 401)
        cookie, _ = self.login()
        with self.store.db() as db:
            events = db.execute("SELECT action,device_name FROM events ORDER BY rowid").fetchall()
        self.assertEqual([(row["action"], row["device_name"]) for row in events], [
            ("Admin sign-in rejected", ""), ("Admin signed in", "")])
        status, _, page = self.request("/", cookie=cookie, method="GET")
        self.assertEqual(status, 200)
        self.assertIn("Unknown", page)

    def test_success_and_failure_capture_device_ip_and_only_success_label(self):
        password = "private-audit-password"
        self.store.add_password("Laptop 2 access", password)
        good = self.request("/api/verify", {"password": password, "device_name": "LAPTOP-2",
                                            "password_label": "untrusted label"})
        bad = self.request("/api/verify", {"password": "wrong-audit-password", "device_name": "OFFICE-PC"})
        self.assertEqual((good[0], json.loads(good[2])), (200, {"allowed": True}))
        self.assertEqual((bad[0], json.loads(bad[2])), (403, {"allowed": False}))
        events = self.verification_events()
        self.assertEqual([(row["action"], row["device_name"], row["ip"], row["password_label"]) for row in events], [
            ("EXE password accepted", "LAPTOP-2", "127.0.0.1", "Laptop 2 access"),
            ("EXE password rejected", "OFFICE-PC", "127.0.0.1", "")])
        serialized = json.dumps([dict(row) for row in events])
        for secret in (password, "wrong-audit-password", "untrusted label"):
            self.assertNotIn(secret, serialized)
            self.assertNotIn(secret, Path(self.store.path).read_bytes().decode(errors="ignore"))

    def test_legacy_and_invalid_device_metadata_preserve_authentication(self):
        self.assertEqual(self.request("/api/verify", {"password": "initial-exe-password"})[0], 200)
        for value in (None, 123, ["not", "a", "name"], {"name": "bad"}):
            with self.subTest(value=value):
                self.assertEqual(self.request("/api/verify", {"password": "initial-exe-password",
                                                              "device_name": value})[0], 200)
        for event in self.verification_events():
            self.assertEqual(event["device_name"], "")
            self.assertEqual(event["password_label"], "Existing password")

    def test_device_and_label_are_escaped_in_dashboard(self):
        label = '<img src=x onerror="alert(1)">'
        self.store.add_password(label, "escaped-password")
        self.assertEqual(self.request("/api/verify", {
            "password": "escaped-password", "device_name": "<script>alert(2)</script>\r\n\x00"})[0], 200)
        cookie, _ = self.login()
        status, _, body = self.request("/", cookie=cookie, method="GET")
        self.assertEqual(status, 200)
        self.assertIn("<th>Event</th><th>Password label</th><th>Device</th><th>Source IP</th>", body)
        self.assertIn("&lt;img src=x", body)
        self.assertIn("&lt;script&gt;alert(2)&lt;/script&gt;", body)
        self.assertNotIn("<img src=x", body)
        self.assertNotIn("<script>", body)
        self.assertNotIn("escaped-password", body)
        self.assertIn('action="/logs/cleanup" method="post"', body)
        self.assertIn("Delete logs older than 7 days", body)
        self.assertIn("Unknown", body)  # Browser sign-in does not report a computer name.
        self.assertEqual(self.verification_events()[0]["device_name"], "<script>alert(2)</script>")

    def test_device_names_are_bounded(self):
        self.request("/api/verify", {"password": "wrong", "device_name": "a" * 300})
        self.assertEqual(self.verification_events()[0]["device_name"], "a" * 255)

    def test_revocation_during_hashing_prevents_success_and_label_disclosure(self):
        password_id = self.store.add_password("Revoke during verification", "racing-password")

        def revoke(*_):
            self.store.delete_password(password_id)
            return True

        with patch.object(portal, "matches", side_effect=revoke):
            self.assertIsNone(self.store.verify_password_label("racing-password"))
        self.assertFalse(self.store.verify_password("racing-password"))
        status, _, body = self.request("/api/verify", {"password": "racing-password", "device_name": "PC"})
        self.assertEqual((status, json.loads(body)), (403, {"allowed": False}))
        self.assertEqual(self.verification_events()[0]["password_label"], "")

    def test_old_hundred_event_cap_no_longer_discards_history(self):
        for number in range(125):
            self.store.event("Entry {}".format(number), "127.0.0.1")
        with self.store.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 125)
        visible = self.store.events()
        self.assertEqual(len(visible), 100)
        self.assertEqual(visible[0]["action"], "Entry 124")
        self.assertEqual(visible[-1]["action"], "Entry 25")

    def seed_retention_events(self, now):
        cutoff = now - 7 * 86400
        with self.store.db() as db:
            db.executemany("INSERT INTO events (at,action,ip,created_at) VALUES (?,?,?,?)", [
                (portal.timestamp(), "Older than 7 days", "192.0.2.1", cutoff - 0.1),
                (portal.timestamp(), "Exactly 7 days", "192.0.2.2", cutoff),
                (portal.timestamp(), "New event", "192.0.2.3", now)])

    def test_cleanup_preserves_exact_boundary_and_recent_events(self):
        now = portal.time.time()
        self.seed_retention_events(now)
        with patch.object(portal.time, "time", return_value=now):
            self.assertEqual(self.store.cleanup_events(), 1)
        with self.store.db() as db:
            self.assertEqual({row["action"] for row in db.execute("SELECT action FROM events")},
                             {"Exactly 7 days", "New event"})

    def test_cleanup_requires_post_session_origin_and_csrf_and_preserves_auth_data(self):
        now = portal.time.time()
        self.seed_retention_events(now)
        self.assertEqual(self.request("/logs/cleanup", {"csrf": "unknown"})[0], 403)
        cookie, csrf = self.login()
        for fields, origin in (({"other": "value"}, "https://portal.test"), ({"csrf": "bad"}, "https://portal.test"),
                               ({"csrf": csrf}, "https://attacker.test")):
            self.assertEqual(self.request("/logs/cleanup", fields, cookie, origin=origin)[0], 403)
        self.assertEqual(self.request("/logs/cleanup", cookie=cookie, method="GET")[0], 404)
        with self.store.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE action='Older than 7 days'").fetchone()[0], 1)
            before = {table: [tuple(row) for row in db.execute("SELECT * FROM " + table + " ORDER BY 1")]
                      for table in ("settings", "passwords", "sessions", "attempts")}
        with patch.object(portal.time, "time", return_value=now):
            status, headers, _ = self.request("/logs/cleanup", {"csrf": csrf}, cookie)
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/?logs=cleaned")
        with self.store.db() as db:
            after = {table: [tuple(row) for row in db.execute("SELECT * FROM " + table + " ORDER BY 1")]
                     for table in before}
            actions = {row["action"] for row in db.execute("SELECT action FROM events")}
        self.assertEqual(before, after)
        self.assertNotIn("Older than 7 days", actions)
        self.assertIn("Exactly 7 days", actions)
        self.assertIn("New event", actions)
        self.assertIn("Removed 1 log entries older than 7 days", actions)
        self.assertIn("Logs older than 7 days removed.", self.request(headers["Location"], cookie=cookie, method="GET")[2])


class LegacyAuditMigrationTests(unittest.TestCase):
    def test_legacy_events_migrate_idempotently_without_losing_history_or_passwords(self):
        with tempfile.TemporaryDirectory() as directory:
            store = portal.Store(Path(directory) / "state.sqlite3")
            store.initialize("test-admin-password", portal.password_record("test-exe-password"))
            store.migrate_passwords()
            now = portal.time.time()
            old_at = (datetime.now(timezone.utc) - timedelta(days=8)).strftime("%Y-%m-%d %H:%M UTC")
            entries = [(old_at, "Old accepted attempt", "192.0.2.1"),
                       (portal.timestamp(), "Recent rejected attempt", "192.0.2.2"),
                       ("unknown legacy date", "Unparseable old entry", "192.0.2.3")]
            with store.db() as db:
                before = {table: [tuple(row) for row in db.execute("SELECT * FROM " + table + " ORDER BY 1")]
                          for table in ("settings", "passwords")}
                db.execute("DROP TABLE events")
                db.execute("CREATE TABLE events (at TEXT NOT NULL, action TEXT NOT NULL, ip TEXT NOT NULL)")
                db.executemany("INSERT INTO events VALUES (?,?,?)", entries)
            with patch.object(portal.time, "time", return_value=now):
                store.migrate_events()
            with store.db() as db:
                rows = db.execute("SELECT * FROM events ORDER BY rowid").fetchall()
            self.assertEqual([(row["at"], row["action"], row["ip"]) for row in rows], entries)
            self.assertTrue(all(row["device_name"] == row["password_label"] == "" for row in rows))
            self.assertEqual(rows[0]["created_at"], datetime.strptime(old_at, "%Y-%m-%d %H:%M UTC").replace(
                tzinfo=timezone.utc).timestamp())
            self.assertEqual(rows[2]["created_at"], now)
            original_rows = [dict(row) for row in rows]
            with patch.object(portal.time, "time", return_value=now + 60):
                store.migrate_events()
            with store.db() as db:
                self.assertEqual([dict(row) for row in db.execute("SELECT * FROM events ORDER BY rowid")], original_rows)
                after = {table: [tuple(row) for row in db.execute("SELECT * FROM " + table + " ORDER BY 1")]
                         for table in before}
            self.assertEqual(before, after)
            with patch.object(portal.time, "time", return_value=now):
                self.assertEqual(store.cleanup_events(), 1)
            self.assertEqual({row["action"] for row in store.events()},
                             {"Recent rejected attempt", "Unparseable old entry"})
            self.assertTrue(store.verify_password("test-exe-password"))


class AuditLogFilterTests(unittest.TestCase):
    setUp = fixtures.PortalTests.setUp
    tearDown = fixtures.PortalTests.tearDown
    request = fixtures.PortalTests.request
    login = fixtures.PortalTests.login

    def get_dashboard(self, cookie, **filters):
        return self.request("/?" + urlencode(filters), cookie=cookie, method="GET")

    def activity_rows(self, page):
        return re.findall(r"<tbody>(.*?)</tbody>", page, re.DOTALL)[-1]

    def test_ist_display_crosses_midnight_without_changing_stored_utc(self):
        cookie, _ = self.login()
        event_epoch = datetime(2026, 10, 16, 20, 10, tzinfo=timezone.utc).timestamp()
        with self.store.db() as db:
            # The event display must use its epoch, rather than this unrelated text.
            db.execute("INSERT INTO events (at,action,ip,created_at) VALUES (?,?,?,?)",
                       ("2000-01-01 00:00 UTC", "Epoch display", "192.0.2.1", event_epoch))
            db.execute("UPDATE passwords SET created=?", ("2026-12-31 21:05 UTC",))
            db.execute("UPDATE settings SET value=? WHERE name='updated'", (json.dumps("2026-01-31 22:50 UTC"),))
            before = {table: [tuple(row) for row in db.execute("SELECT * FROM " + table + " ORDER BY rowid")]
                      for table in ("events", "passwords", "settings")}
        status, _, page = self.request("/", cookie=cookie, method="GET")
        self.assertEqual(status, 200)
        self.assertIn("2026-10-17 01:40 IST", self.activity_rows(page))
        self.assertIn("2027-01-01 02:35 IST", page)
        self.assertIn("Last updated 2026-02-01 04:20 IST", page)
        self.assertIn("IST (UTC+05:30)", page)
        for original in ("2000-01-01 00:00 UTC", "2026-12-31 21:05 UTC", "2026-01-31 22:50 UTC"):
            self.assertNotIn(original, page)
        with self.store.db() as db:
            after = {table: [tuple(row) for row in db.execute("SELECT * FROM " + table + " ORDER BY rowid")]
                     for table in before}
        self.assertEqual(before, after)

    def test_combined_filters_find_old_records_before_limit_and_include_last_minute(self):
        cookie, _ = self.login()
        start = datetime(2026, 10, 16, 18, 30, tzinfo=timezone.utc).timestamp()
        records = [
            ("EXE password accepted", "Retired Laptop", "too-early", start - 0.001),
            ("EXE password accepted", "Retired Laptop", "at-start", start),
            ("EXE password accepted", "Retired Laptop", "last-second", start + 59.999),
            ("EXE password accepted", "Retired Laptop", "next-minute", start + 60),
            ("EXE password rejected", "Retired Laptop", "wrong-event", start),
            ("EXE password accepted", "Retired Laptop 2", "wrong-label", start)]
        records.extend(("Newer event", "Other label", "newer-{}".format(number), start + 120 + number)
                       for number in range(125))
        with self.store.db() as db:
            db.executemany("INSERT INTO events (at,action,password_label,device_name,created_at,ip) "
                           "VALUES ('2026-10-16 18:30 UTC',?,?,?,?, '192.0.2.1')", records)
        filters = {"event": "EXE password accepted", "label": "Retired Laptop",
                   "from": "2026-10-17T00:00", "to": "2026-10-17T00:00"}
        status, _, page = self.get_dashboard(cookie, **filters)
        self.assertEqual(status, 200)
        rows = self.activity_rows(page)
        for included in ("at-start", "last-second"):
            self.assertIn(included, rows)
        for excluded in ("too-early", "next-minute", "wrong-event", "wrong-label", "newer-"):
            self.assertNotIn(excluded, rows)
        self.assertIn('<option value="Retired Laptop" selected>', page)
        self.assertIn('<option value="Retired Laptop 2">', page)
        self.assertIn('<option value="Newer event">', page)
        for key in ("from", "to"):
            self.assertIn('name="{}" type="datetime-local" value="{}"'.format(key, filters[key]), page)
        # Each time boundary is optional; equality and the inclusive To minute still apply.
        self.assertIn("next-minute", self.activity_rows(self.get_dashboard(
            cookie, event=filters["event"], label=filters["label"], **{"from": filters["from"]})[2]))
        self.assertIn("too-early", self.activity_rows(self.get_dashboard(
            cookie, event=filters["event"], label=filters["label"], to=filters["to"])[2]))

    def test_exact_event_and_label_filters_escape_values_and_parameterize_queries(self):
        cookie, _ = self.login()
        event = '<script>event</script>\' OR 1=1 --'
        label = 'Laptop "A" & <retired>'
        self.store.event(event, "192.0.2.1", device_name="exact-row", password_label=label)
        self.store.event(event + " extra", "192.0.2.2", device_name="other-event", password_label=label)
        self.store.event(event, "192.0.2.3", device_name="other-label", password_label=label + " extra")
        status, _, page = self.get_dashboard(cookie, event=event, label=label)
        self.assertEqual(status, 200)
        rows = self.activity_rows(page)
        self.assertIn("exact-row", rows)
        self.assertNotIn("other-event", rows)
        self.assertNotIn("other-label", rows)
        for selected in (event, label):
            self.assertIn('<option value="{}" selected>'.format(html.escape(selected, quote=True)), page)
        self.assertNotIn("<script>", page)
        self.assertNotIn("<retired>", page)
        status, _, page = self.get_dashboard(cookie, event="missing' OR 1=1 --", label=label)
        self.assertEqual(status, 200)
        self.assertIn("No matching activity.", self.activity_rows(page))
        self.assertNotIn("exact-row", self.activity_rows(page))

    def test_invalid_dates_and_reversed_ranges_are_rejected_with_escaped_selections(self):
        cookie, _ = self.login()
        cases = [({"from": "2026-02-30T10:00"}, "Enter valid From and To"),
                 ({"to": "2026-10-17T12:00Z"}, "Enter valid From and To"),
                 ({"from": '\"><script>alert(9)</script>'}, "Enter valid From and To"),
                 ({"from": "2026-10-17T12:00", "to": "2026-10-17T11:59"}, "From time must be at or before")]
        before = [dict(row) for row in self.store.events()]
        for dates, message in cases:
            with self.subTest(dates=dates):
                values = dict(dates, event="Saved event", label='Saved "label"')
                status, _, page = self.get_dashboard(cookie, **values)
                self.assertEqual(status, 400)
                self.assertIn(message, page)
                self.assertIn('<option value="Saved event" selected>', page)
                self.assertIn('<option value="Saved &quot;label&quot;" selected>', page)
                self.assertNotIn("<script>", page)
                self.assertIn("No matching activity.", self.activity_rows(page))
                for key, value in dates.items():
                    self.assertIn('name="{}" type="datetime-local" value="{}"'.format(
                        key, html.escape(value, quote=True)), page)
        self.assertEqual(before, [dict(row) for row in self.store.events()])

    def test_anonymous_pages_never_expose_filter_options_or_activity(self):
        self.store.event("Private historical event", "192.0.2.1", password_label="Private revoked label")
        for cookie in (None, "remo_session=invalid-session"):
            with self.subTest(cookie=cookie):
                status, _, page = self.get_dashboard(cookie, event="Private historical event",
                                                    label="Private revoked label", **{"from": "invalid"})
                self.assertEqual(status, 200)
                self.assertIn('action="/login"', page)
                for private in ("Private historical event", "Private revoked label", 'id="filter-event"',
                                'id="filter-label"', 'type="datetime-local"', "<th>Event</th>"):
                    self.assertNotIn(private, page)

    def test_filter_queries_preserve_existing_notices_and_clear_control(self):
        cookie, _ = self.login()
        notices = [("saved", "1", "Password added. It is active now."),
                   ("removed", "1", "Password removed. It will be rejected on the next online check."),
                   ("admin", "1", "Admin password updated. Sign in with your new password."),
                   ("logs", "cleaned", "Logs older than 7 days removed.")]
        for key, value, message in notices:
            with self.subTest(key=key):
                status, _, page = self.get_dashboard(cookie, event="Saved selection", **{key: value})
                self.assertEqual(status, 200)
                self.assertIn(message, page)
                self.assertIn('<option value="Saved selection" selected>', page)
                self.assertIn('<a href="/">Clear</a>', page)
        status, _, page = self.get_dashboard(None, admin="1")
        self.assertEqual(status, 200)
        self.assertIn("Admin password updated. Sign in with your new password.", page)
        self.assertNotIn('id="filter-event"', page)


if __name__ == "__main__":
    unittest.main()
