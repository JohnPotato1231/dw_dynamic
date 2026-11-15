"""HTTPS password control for REMO setup and uninstall. Python 3.9+, no dependencies."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
import ntpath
import os
import re
from pathlib import Path
import secrets
import sqlite3
import ssl
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit

ITERATIONS = 600000
SESSION_SECONDS = 8 * 60 * 60
MAX_BODY = 8192
LOG_RETENTION_SECONDS = 7 * 24 * 60 * 60
LOG_DISPLAY_LIMIT = 100
IST = timezone(timedelta(hours=5, minutes=30), "IST")

# Independent of portal-managed P; store only the salted client-password hash.
INSTALL_IDENTITY_CLIENT_PASSWORD_RECORD = {'algorithm': 'pbkdf2-sha256', 'iterations': 600000, 'salt': 'a167f68a6e334aa0f931ef44acdd4ed7', 'digest': 'f2e002a97571c564ce16c1d921295d145da770a991296811c6e329f478608966'}


# Validate independently at the server and client trust boundaries.
DEFAULT_INSTALL_IDENTITY = {
    "main_executable": "dwagent.exe",
    "service_executable": "dwagsvc.exe",
    "service_name": "DWAgent",
    "service_display_name": "DWAgent",
}

DEFAULT_INSTALL_METADATA = {"install_path": "", "publisher": "DWService"}


def validate_install_path(value):
    """Validate a Windows application directory, including on the Linux portal."""
    if not isinstance(value, str) or len(value) > 180:
        raise ValueError("Installation path must be at most 180 characters.")
    if not value:
        return value
    path = value.replace("/", "\\")
    if path.lower().startswith("%programfiles%\\"):
        path = "C:\\Program Files\\" + path[len("%ProgramFiles%\\"):]
    drive, tail = ntpath.splitdrive(path)
    if not re.fullmatch(r"[A-Za-z]:", drive) or not tail.startswith("\\"):
        raise ValueError("Use an absolute local application path or %ProgramFiles%\\Application.")
    parts = tail[1:].split("\\")
    if (not parts or any(not part or part in (".", "..") or part.endswith((".", " "))
                         or re.search(r'[<>:"/\\|?*%\x00-\x1f\x7f]', part)
                         or re.fullmatch(r"(?:con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(?:\..*)?", part, re.I)
                         for part in parts)
            or parts[0].lower() in {"windows", "winnt", "system volume information", "$recycle.bin"}
            or (len(parts) == 1 and parts[0].lower() in {"program files", "program files (x86)", "programdata", "users"})):
        raise ValueError("Choose a new application subfolder outside Windows system directories.")
    return value


def validate_install_identity(value):
    """Accept only plain filenames and names safe for Windows properties files."""
    if (not isinstance(value, dict) or not set(DEFAULT_INSTALL_IDENTITY).issubset(value)
            or set(value) - set(DEFAULT_INSTALL_IDENTITY) - set(DEFAULT_INSTALL_METADATA)):
        raise ValueError("Invalid installation naming settings.")
    for key in ("main_executable", "service_executable"):
        name = value[key]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}\.exe", name, re.I):
            raise ValueError("Executable names must be plain .exe filenames.")
        stem = name[:-4].lower()
        if (stem in {"con", "prn", "aux", "nul", "svchost", "lsass", "services", "winlogon", "securityhealthservice"}
                or re.fullmatch(r"(?:com|lpt)[0-9]", stem)
                or stem.startswith(("windows", "microsoft"))):
            raise ValueError("Choose an application name rather than a Windows system name.")
    if value["service_executable"].lower() in {"dwaglnc.exe", "dwagupd.exe"}:
        raise ValueError("The service filename conflicts with another agent component.")
    if not isinstance(value["service_name"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,79}", value["service_name"]):
        raise ValueError("Service names must use letters, digits, underscores or hyphens.")
    if value["service_name"].lower() in {"con", "prn", "aux", "nul"} or re.fullmatch(r"(?:com|lpt)[0-9]", value["service_name"], re.I):
        raise ValueError("The service name is reserved by Windows.")
    if not isinstance(value["service_display_name"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _().-]{0,99}", value["service_display_name"]):
        raise ValueError("Enter a display name of 1-100 plain text characters.")
    if "install_path" in value:
        validate_install_path(value["install_path"])
    if "publisher" in value:
        publisher = value["publisher"]
        if (not isinstance(publisher, str) or not 1 <= len(publisher) <= 100
                or publisher != publisher.strip() or not publisher.isprintable()):
            raise ValueError("Publisher must be 1-100 printable characters without surrounding spaces.")
    return dict(value)


def password_record(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS)
    return {"algorithm": "pbkdf2-sha256", "iterations": ITERATIONS,
            "salt": salt, "digest": digest.hex()}


def matches(password, record):
    if not isinstance(password, str) or not password or len(password) > 1024:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(record["salt"]), record["iterations"])
    return hmac.compare_digest(digest.hex(), record["digest"])


def token_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def display_time(value):
    """Present stored UTC text or an epoch in IST without changing storage."""
    try:
        if isinstance(value, (int, float)):
            date = datetime.fromtimestamp(value, timezone.utc)
        else:
            date = datetime.strptime(value, "%Y-%m-%d %H:%M UTC").replace(tzinfo=timezone.utc)
        return date.astimezone(IST).strftime("%Y-%m-%d %H:%M IST")
    except (TypeError, ValueError, OverflowError, OSError):
        return value if isinstance(value, str) else "Unknown"


def log_time_range(filters):
    """Interpret the selected minutes in IST; the final minute is inclusive."""
    bounds = []
    for key in ("from", "to"):
        value = filters.get(key, "")
        try:
            bounds.append(datetime.strptime(value, "%Y-%m-%dT%H:%M").replace(
                tzinfo=IST).timestamp() if value else None)
        except (TypeError, ValueError, OverflowError, OSError) as error:
            raise ValueError("Enter valid From and To dates and times in IST.") from error
    start, end = bounds
    if start is not None and end is not None and start > end:
        raise ValueError("From time must be at or before To time (IST).")
    return start, end + 60 if end is not None else None


def select_options(values, selected, title):
    choices = list(values)
    if selected and selected not in choices:
        choices.append(selected)
    return '<option value="">{}</option>'.format(html.escape(title)) + "".join(
        '<option value="{}"{}>{}</option>'.format(
            html.escape(value, quote=True), " selected" if value == selected else "", html.escape(value))
        for value in choices)


def clean_device_name(value):
    if not isinstance(value, str):
        return ""
    return "".join(character for character in value if character.isprintable()).strip()[:255]


class Store:
    def __init__(self, path):
        self.path = str(path)
        key_path = Path(str(path) + ".lookup-key")
        self.new_lookup_key = False
        try:
            descriptor = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as key_file:
                key_file.write(secrets.token_bytes(32))
            self.new_lookup_key = True
        self.lookup_key = key_path.read_bytes()
        if len(self.lookup_key) != 32:
            raise ValueError("Invalid password lookup key")

    def password_lookup(self, password):
        return hmac.new(self.lookup_key, password.encode("utf-8"), hashlib.sha256).hexdigest()

    @contextmanager
    def db(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self, admin_password, installer_record):
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions
                    (token TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS attempts (ip TEXT, kind TEXT, at REAL);
                CREATE INDEX IF NOT EXISTS attempts_lookup ON attempts(ip,kind,at);
                CREATE TABLE IF NOT EXISTS events
                    (at TEXT NOT NULL, action TEXT NOT NULL, ip TEXT NOT NULL,
                     device_name TEXT NOT NULL DEFAULT '', password_label TEXT NOT NULL DEFAULT '',
                     created_at REAL NOT NULL);
            """)
            if db.execute("SELECT 1 FROM settings LIMIT 1").fetchone():
                raise ValueError("Portal already initialized; existing passwords were preserved.")
            for name, value in (("admin", password_record(admin_password)),
                                ("installer", installer_record), ("updated", timestamp())):
                db.execute("INSERT INTO settings VALUES (?,?)", (name, json.dumps(value)))

    def setting(self, name):
        with self.db() as db:
            return json.loads(db.execute("SELECT value FROM settings WHERE name=?", (name,)).fetchone()[0])

    def install_identity(self):
        with self.db() as db:
            row = db.execute("SELECT value FROM settings WHERE name='install_identity'").fetchone()
        return validate_install_identity(json.loads(row[0])) if row else dict(DEFAULT_INSTALL_IDENTITY)

    def save_install_identity(self, identity):
        identity = validate_install_identity(identity)
        with self.db() as db:
            db.execute("INSERT INTO settings(name,value) VALUES ('install_identity',?) "
                       "ON CONFLICT(name) DO UPDATE SET value=excluded.value", (json.dumps(identity),))

    def migrate_passwords(self):
        """Preserve the existing password when upgrading a running portal."""
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS passwords "
                       "(id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, record TEXT NOT NULL, created TEXT NOT NULL)")
            if "lookup" not in {row["name"] for row in db.execute("PRAGMA table_info(passwords)")}:
                db.execute("ALTER TABLE passwords ADD COLUMN lookup TEXT")
            if self.new_lookup_key:
                # Keep existing passwords working if the separate lookup key was lost.
                db.execute("UPDATE passwords SET lookup=NULL")
                self.new_lookup_key = False
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS password_lookup ON passwords(lookup)")
            legacy = db.execute("SELECT value FROM settings WHERE name='installer'").fetchone()
            if legacy is not None:
                db.execute("INSERT INTO passwords (id,name,record,created) VALUES (?,?,?,?)",
                           (secrets.token_hex(16), "Existing password", legacy["value"], timestamp()))
                db.execute("DELETE FROM settings WHERE name='installer'")

    def migrate_events(self):
        """Extend existing audit records without clearing their history."""
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            columns = {row["name"] for row in db.execute("PRAGMA table_info(events)")}
            for name in ("device_name", "password_label"):
                if name not in columns:
                    db.execute("ALTER TABLE events ADD COLUMN " + name + " TEXT NOT NULL DEFAULT ''")
            if "created_at" not in columns:
                db.execute("ALTER TABLE events ADD COLUMN created_at REAL")
            migrated_at = time.time()
            for row in db.execute("SELECT rowid,at FROM events WHERE created_at IS NULL").fetchall():
                try:
                    created_at = datetime.strptime(row["at"], "%Y-%m-%d %H:%M UTC").replace(
                        tzinfo=timezone.utc).timestamp()
                except (TypeError, ValueError, OverflowError):
                    # An unreadable legacy date must not trigger immediate deletion.
                    created_at = migrated_at
                db.execute("UPDATE events SET created_at=? WHERE rowid=?", (created_at, row["rowid"]))
            db.execute("CREATE INDEX IF NOT EXISTS events_created_at ON events(created_at)")

    def passwords(self):
        with self.db() as db:
            return db.execute("SELECT id,name,created FROM passwords ORDER BY created DESC,rowid DESC").fetchall()

    def add_password(self, name, password):
        record = password_record(password)
        lookup = self.password_lookup(password)
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM passwords WHERE name=?", (name,)).fetchone():
                raise ValueError("That label is already in use.")
            legacy = db.execute("SELECT record FROM passwords WHERE lookup IS NULL").fetchall()
            if (db.execute("SELECT 1 FROM passwords WHERE lookup=?", (lookup,)).fetchone()
                    or any(matches(password, json.loads(row["record"])) for row in legacy)):
                raise ValueError("This password is already active. Use a different password.")
            password_id = secrets.token_hex(16)
            db.execute("INSERT INTO passwords (id,name,record,created,lookup) VALUES (?,?,?,?,?)",
                       (password_id, name, json.dumps(record), timestamp(), lookup))
            db.execute("UPDATE settings SET value=? WHERE name='updated'", (json.dumps(timestamp()),))
            return password_id

    def delete_password(self, password_id):
        with self.db() as db:
            changed = db.execute("DELETE FROM passwords WHERE id=?", (password_id,)).rowcount > 0
            if changed:
                db.execute("UPDATE settings SET value=? WHERE name='updated'", (json.dumps(timestamp()),))
            return changed

    def verify_password(self, password):
        return self.verify_password_label(password) is not None

    def verify_password_label(self, password):
        if not isinstance(password, str) or not password or len(password) > 1024:
            return None
        lookup = self.password_lookup(password)
        with self.db() as db:
            records = db.execute("SELECT id,record FROM passwords WHERE lookup=? OR lookup IS NULL", (lookup,)).fetchall()
        for row in records:
            if matches(password, json.loads(row["record"])):
                # Recheck membership after hashing, in case an admin just revoked it.
                with self.db() as db:
                    db.execute("UPDATE passwords SET lookup=? WHERE id=? AND record=?",
                               (lookup, row["id"], row["record"]))
                    current = db.execute("SELECT name FROM passwords WHERE id=? AND record=?",
                                         (row["id"], row["record"])).fetchone()
                    return current["name"] if current is not None else None
        return None

    def attempt(self, ip, kind, limit):
        now = time.time()
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM attempts WHERE at < ?", (now - 600,))
            count = db.execute("SELECT COUNT(*) FROM attempts WHERE ip=? AND kind=?",
                               (ip, kind)).fetchone()[0]
            if count >= limit:
                return False
            db.execute("INSERT INTO attempts VALUES (?,?,?)", (ip, kind, now))
            return True

    def event(self, action, ip, device_name=None, password_label=None):
        with self.db() as db:
            db.execute("INSERT INTO events (at,action,ip,device_name,password_label,created_at) "
                       "VALUES (?,?,?,?,?,?)", (timestamp(), action, ip, clean_device_name(device_name),
                                               password_label if isinstance(password_label, str) else "", time.time()))

    def events(self, event="", label="", start=None, end=None):
        conditions, parameters = [], []
        for column, value in (("action", event), ("password_label", label)):
            if value:
                conditions.append(column + "=?")
                parameters.append(value)
        if start is not None:
            conditions.append("created_at>=?")
            parameters.append(start)
        if end is not None:
            conditions.append("created_at<?")
            parameters.append(end)
        query = "SELECT * FROM events"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY rowid DESC LIMIT ?"
        with self.db() as db:
            return db.execute(query, parameters + [LOG_DISPLAY_LIMIT]).fetchall()

    def event_filter_options(self):
        with self.db() as db:
            actions = [row[0] for row in db.execute("SELECT DISTINCT action FROM events WHERE action<>'' ORDER BY action")]
            labels = [row[0] for row in db.execute("SELECT DISTINCT password_label FROM events "
                                                 "WHERE password_label<>'' ORDER BY password_label")]
            return actions, labels

    def cleanup_events(self, older_than_seconds=LOG_RETENTION_SECONDS):
        if older_than_seconds < 0:
            raise ValueError("Log age must not be negative")
        with self.db() as db:
            return db.execute("DELETE FROM events WHERE created_at < ?",
                              (time.time() - older_than_seconds,)).rowcount


class PortalServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address, store, template, origin, tls_context=None, cookie_name="remo_session"):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", cookie_name):
            raise ValueError("Invalid session cookie name")
        store.migrate_passwords()
        store.migrate_events()
        self.store, self.template, self.origin = store, template, origin
        self.cookie_name = cookie_name
        self.workers = threading.BoundedSemaphore(16)
        self.tls_context = tls_context
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.workers.release()
            raise

    def process_request_thread(self, request, client_address):
        raw_request = request
        try:
            request.settimeout(10)
            if self.tls_context:
                request = self.tls_context.wrap_socket(request, server_side=True)
            super().process_request_thread(request, client_address)
        except (ssl.SSLError, OSError):
            self.shutdown_request(request)
        finally:
            raw_request.close()
            self.workers.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "REMO"
    sys_version = ""

    def log_message(self, format, *args):
        # Never log request bodies, passwords, cookies, or query strings.
        pass

    @property
    def store(self):
        return self.server.store

    def send(self, status, body, content_type="text/html; charset=utf-8", extra=()):
        data = body.encode("utf-8")
        self.send_response(status)
        for key, value in (("Content-Type", content_type), ("Content-Length", str(len(data))),
                           ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                           # Basic browser form POSTs send Origin: null with no-referrer.
                           # Retain the origin on same-origin forms, but not external requests.
                           ("Referrer-Policy", "same-origin"), ("X-Frame-Options", "DENY"),
                           ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")):
            self.send_header(key, value)
        for key, value in extra:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def json(self, status, value):
        self.send(status, json.dumps(value), "application/json")

    def session(self):
        try:
            cookie = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            token = cookie[self.server.cookie_name].value
            if len(token) > 128:
                return None
        except (KeyError, cookies.CookieError):
            return None
        with self.store.db() as db:
            return db.execute("SELECT * FROM sessions WHERE token=? AND expires>?",
                               (token_hash(token), time.time())).fetchone()

    def redirect(self, location, cookie=None):
        headers = [("Location", location)]
        if cookie:
            headers.append(("Set-Cookie", cookie))
        self.send(303, "", extra=headers)

    def render(self, session=None, message="", status=200, filters=None):
        if session is None:
            content = """<section class="card login"><p class="eyebrow">ADMIN SIGN IN</p>
              <h2>Access starts here.</h2><p class="muted">Sign in to manage the password for REMO setup and uninstall.</p>
              <form action="/login" method="post"><label for="username">Username</label>
              <input id="username" name="username" value="admin" autocomplete="username" required>
              <label for="password">Admin password</label><input id="password" name="password" type="password" autocomplete="current-password" maxlength="1024" required>
              <button type="submit">Sign in <span aria-hidden="true">&rarr;</span></button></form>
              <p class="fine">Your admin login is separate from the EXE password.</p></section>"""
        else:
            csrf = html.escape(session["csrf"], quote=True)
            filters = {key: (filters or {}).get(key, "") for key in ("event", "label", "from", "to")}
            try:
                start, end = log_time_range(filters)
                events = self.store.events(filters["event"], filters["label"], start, end)
            except ValueError as error:
                events, message, status = [], str(error), 400
            actions, labels = self.store.event_filter_options()
            event_options = select_options(actions, filters["event"], "All events")
            label_options = select_options(labels, filters["label"], "All password labels")
            rows = "".join("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                html.escape(row["action"]), html.escape(row["password_label"]) or "&mdash;",
                html.escape(row["device_name"] or "Unknown"), html.escape(row["ip"]),
                html.escape(display_time(row["created_at"]))) for row in events)
            rows = rows or '<tr><td colspan="5">{}</td></tr>'.format(
                "No matching activity." if any(filters.values()) else "No activity yet.")
            updated = html.escape(display_time(self.store.setting("updated")))
            identity = {**DEFAULT_INSTALL_METADATA, **self.store.install_identity()}
            identity_fields = "".join(
                '<label for="identity-{key}">{label}</label>'
                '<input id="identity-{key}" name="{key}" value="{value}" maxlength="{limit}" {required}>'.format(
                    key=key, label=label, value=html.escape(identity[key], quote=True), limit=limit,
                    required="" if key == "install_path" else "required")
                for key, label, limit in (
                    ("main_executable", "Main process filename", 68),
                    ("service_executable", "Service process filename", 68),
                    ("service_name", "Windows service name", 80),
                    ("service_display_name", "Service display name", 100),
                    ("install_path", "Installation path (new subfolders under Program Files; blank uses service name)", 180),
                    ("publisher", "Publisher in Installed Apps", 100)))
            passwords = self.store.passwords()
            password_rows = "".join(
                '<tr><td><strong>{name}</strong></td><td>{created}</td><td>'
                '<form action="/passwords/delete" method="post"><input type="hidden" name="csrf" value="{csrf}">'
                '<input type="hidden" name="id" value="{id}"><button class="secondary" style="margin:0;padding:8px 12px;width:auto">Remove</button></form></td></tr>'.format(
                    name=html.escape(row["name"]), created=html.escape(display_time(row["created"])), csrf=csrf, id=row["id"])
                for row in passwords)
            password_rows = password_rows or '<tr><td colspan="3">No server passwords. Add one below to enable online access.</td></tr>'
            content = """<div class="topline"><div><p class="eyebrow">ACCESS CONTROL</p><h2>Your passwords. Live everywhere.</h2></div>
              <form action="/logout" method="post"><input type="hidden" name="csrf" value="{csrf}"><button class="secondary">Sign out</button></form></div>
              <div class="stats"><div class="stat"><span class="dot"></span><strong>{count} active server passwords</strong><p>Any active password works for setup &amp; uninstall</p></div>
              <div class="stat"><strong>Changes apply immediately</strong><p>Last updated {updated}</p></div></div>
              <section class="card activity" style="margin-bottom:24px"><p class="eyebrow">ACTIVE PASSWORDS</p><h3>Manage server access</h3>
              <p class="muted">Removing a password revokes it on the next online check. Other passwords keep working.</p>
              <div class="table-scroll"><table><thead><tr><th>Label</th><th>Created</th><th>Action</th></tr></thead><tbody>{password_rows}</tbody></table></div></section>
              <div class="columns"><section class="card"><p class="eyebrow">EXE PASSWORDS</p><h3>Add access password</h3>
              <p class="muted">Add as many passwords as you need. Changes apply without rebuilding the EXE.</p>
              <form action="/passwords/add" method="post"><input type="hidden" name="csrf" value="{csrf}">
              <label for="name">Label</label><input id="name" name="name" maxlength="80" placeholder="e.g. Laptop 2" required>
              <label for="new">New EXE password</label><input id="new" name="password" type="password" minlength="1" maxlength="128" autocomplete="new-password" required>
              <label for="confirm">Confirm new password</label><input id="confirm" name="confirm" type="password" minlength="1" maxlength="128" autocomplete="new-password" required>
              <button>Add password <span aria-hidden="true">&rarr;</span></button></form>
              <p class="fine">1–128 characters. The current password is never displayed.</p></section>
              <section class="card"><p class="eyebrow">ADMIN ACCOUNT</p><h3>Secure your portal</h3><p class="muted">Change the password used to sign in here. This does not change the EXE password.</p>
              <form action="/admin-password" method="post"><input type="hidden" name="csrf" value="{csrf}">
              <label for="current">Current admin password</label><input id="current" name="current" type="password" autocomplete="current-password" maxlength="1024" required>
              <label for="admin-new">New admin password</label><input id="admin-new" name="password" type="password" minlength="12" maxlength="128" autocomplete="new-password" required>
              <label for="admin-confirm">Confirm admin password</label><input id="admin-confirm" name="confirm" type="password" minlength="12" maxlength="128" autocomplete="new-password" required>
              <button class="secondary">Update admin password</button></form></section></div>
              <section class="card activity" style="margin-bottom:24px"><p class="eyebrow">INSTALLATION SETTINGS</p>
              <h3>Settings for newly authorized installations</h3>
              <p class="muted">These values are returned only after the server accepts an EXE password.
              Installers contain DWAgent defaults. Offline recovery and older servers use those defaults.
              Saving settings affects new installations; existing installations keep their saved settings.
              Use new subfolders under Program Files, such as %ProgramFiles%\\Company\\Application.
              Publisher changes the Installed Apps entry. Windows UAC publisher requires code signing.</p>
              <form action="/install-identity" method="post"><input type="hidden" name="csrf" value="{csrf}">
              {identity_fields}<button>Save installation settings</button></form></section>
              <section class="card activity"><div class="topline"><div><p class="eyebrow">RECENT ACTIVITY</p><h3>Access log</h3></div>
              <form action="/logs/cleanup" method="post"><input type="hidden" name="csrf" value="{csrf}">
              <button class="secondary">Delete logs older than 7 days</button></form></div>
              <p class="muted">Latest 100 matching events. Older entries are kept until you remove them. All times are IST (UTC+05:30).</p>
              <form action="/" method="get" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-bottom:24px">
              <div><label for="filter-event">Event</label><select id="filter-event" name="event" style="width:100%;padding:12px;font:inherit">{event_options}</select></div>
              <div><label for="filter-label">Password label</label><select id="filter-label" name="label" style="width:100%;padding:12px;font:inherit">{label_options}</select></div>
              <div><label for="filter-from">From (IST)</label><input id="filter-from" name="from" type="datetime-local" value="{filter_from}"></div>
              <div><label for="filter-to">To (IST, inclusive minute)</label><input id="filter-to" name="to" type="datetime-local" value="{filter_to}"></div>
              <div style="display:flex;gap:16px;align-items:center;align-self:end"><button type="submit" style="margin:0;width:auto">Apply filters</button><a href="/">Clear</a></div></form>
              <p class="fine">For admin sign-ins, Device shows browser details. Browsers do not provide the computer name.</p>
              <div class="table-scroll"><table><thead><tr><th>Event</th><th>Password label</th><th>Device</th><th>Source IP</th><th>Time</th></tr></thead><tbody>{rows}</tbody></table></div></section>
              <p class="fine">Server passwords require an internet connection. The separate local recovery password in compatible EXEs also works offline and cannot be revoked here. Existing remote sessions are not disconnected when a password is removed.</p>""".format(
                  csrf=csrf, updated=updated, rows=rows, password_rows=password_rows, count=len(passwords), identity_fields=identity_fields,
                  event_options=event_options, label_options=label_options,
                  filter_from=html.escape(filters["from"], quote=True), filter_to=html.escape(filters["to"], quote=True))
        page = self.server.template.replace("{{CONTENT}}", content).replace("{{MESSAGE}}",
            '<div class="notice" role="status">' + html.escape(message) + '</div>' if message else "")
        self.send(status, page)

    def do_GET(self):
        if self.path == "/health":
            self.json(200, {"status": "ok"})
        elif self.path == "/favicon.ico":
            self.send(204, "", "image/x-icon")
        else:
            try:
                path = urlsplit(self.path)
                if path.path != "/":
                    self.json(404, {"error": "Not found"})
                    return
                fields = parse_qs(path.query, keep_blank_values=True, max_num_fields=10)
            except ValueError:
                self.json(400, {"error": "Invalid query"})
                return
            notices = (("saved", "1", "Password added. It is active now."),
                       ("removed", "1", "Password removed. It will be rejected on the next online check."),
                       ("admin", "1", "Admin password updated. Sign in with your new password."),
                       ("logs", "cleaned", "Logs older than 7 days removed."))
            notice = next((text for key, value, text in notices if fields.get(key) == [value]), "")
            self.render(self.session(), notice, filters={key: fields.get(key, [""])[0] for key in ("event", "label", "from", "to")})

    def do_POST(self):
        ip = self.client_address[0]
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY or self.headers.get("Transfer-Encoding"):
                self.json(400, {"error": "Invalid request size"})
                return
            raw = self.rfile.read(length)
            media = self.headers.get("Content-Type", "").split(";")[0]
            if self.path == "/api/verify":
                if media != "application/json":
                    self.json(415, {"error": "JSON required"})
                    return
                if not self.store.attempt(ip, "verify", 30):
                    self.json(429, {"error": "Too many attempts; retry in 10 minutes"})
                    return
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise ValueError("JSON object required")
                if payload.get("include_install_identity") is True:
                    authorization = self.headers.get("Authorization", "")
                    scheme, separator, client_password = authorization.partition(" ")
                    if (scheme.lower() != "bearer" or not separator
                            or not matches(client_password, INSTALL_IDENTITY_CLIENT_PASSWORD_RECORD)):
                        self.store.event("Installer credential rejected", ip)
                        self.json(401, {"allowed": False, "error": "Installer authentication required"})
                        return
                label = self.store.verify_password_label(payload.get("password"))
                allowed = label is not None
                self.store.event("EXE password accepted" if allowed else "EXE password rejected", ip,
                                 device_name=payload.get("device_name"), password_label=label)
                result = {"allowed": allowed}
                if allowed and payload.get("include_install_identity") is True:
                    identity = self.store.install_identity()
                    if type(payload.get("install_identity_version")) is int and payload["install_identity_version"] == 2:
                        result["install_identity"] = {**DEFAULT_INSTALL_METADATA, **identity}
                    else:
                        result["install_identity"] = {key: identity[key] for key in DEFAULT_INSTALL_IDENTITY}
                self.json(200 if allowed else 403, result)
                return
            if media != "application/x-www-form-urlencoded":
                self.json(415, {"error": "Form required"})
                return
            # HTML forms come from this exact HTTPS origin. No cross-origin writes.
            if self.headers.get("Origin") != self.server.origin:
                self.json(403, {"error": "Origin rejected"})
                return
            fields = parse_qs(raw.decode("utf-8"), max_num_fields=10)
            field = lambda name: fields.get(name, [""])[0]
            if self.path == "/login":
                device = self.headers.get("User-Agent", "")
                if not self.store.attempt(ip, "login", 10):
                    self.render(message="Too many sign-in attempts. Retry in 10 minutes.", status=429)
                    return
                valid = matches(field("password"), self.store.setting("admin"))
                if field("username") != "admin" or not valid:
                    self.store.event("Admin sign-in rejected", ip, device_name=device)
                    self.render(message="Incorrect username or admin password.", status=401)
                    return
                token = secrets.token_urlsafe(32)
                with self.store.db() as db:
                    db.execute("DELETE FROM sessions WHERE expires <= ?", (time.time(),))
                    db.execute("INSERT INTO sessions VALUES (?,?,?)",
                               (token_hash(token), secrets.token_urlsafe(32), time.time() + SESSION_SECONDS))
                self.store.event("Admin signed in", ip, device_name=device)
                self.redirect("/", self.server.cookie_name + "=" + token + "; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=" + str(SESSION_SECONDS))
                return
            session = self.session()
            if session is None or not hmac.compare_digest(field("csrf"), session["csrf"]):
                self.json(403, {"error": "Session expired or invalid request. Sign in again."})
                return
            if self.path == "/logout":
                with self.store.db() as db:
                    db.execute("DELETE FROM sessions WHERE token=?", (session["token"],))
                self.redirect("/", self.server.cookie_name + "=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")
                return
            if self.path == "/install-identity":
                try:
                    identity = {key: field(key).strip() for key in DEFAULT_INSTALL_IDENTITY}
                    previous = self.store.install_identity()
                    identity.update({key: field(key) if key in fields else previous.get(key, default)
                                     for key, default in DEFAULT_INSTALL_METADATA.items()
                                     if key in fields or key in previous})
                    self.store.save_install_identity(identity)
                except ValueError as error:
                    self.render(session, str(error), 400)
                    return
                self.store.event("Installation names updated", ip)
                self.redirect("/?identity=saved")
                return
            if self.path == "/logs/cleanup":
                removed = self.store.cleanup_events()
                self.store.event("Removed {} log entries older than 7 days".format(removed), ip)
                self.redirect("/?logs=cleaned")
                return
            if self.path == "/passwords/delete":
                if not self.store.delete_password(field("id")):
                    self.render(session, "Password not found. It may already have been removed.", 404)
                    return
                self.store.event("EXE password removed", ip)
                self.redirect("/?removed=1")
                return
            if self.path not in ("/passwords/add", "/admin-password"):
                self.json(404, {"error": "Not found"})
                return
            admin = self.path == "/admin-password"
            password = field("password")
            minimum = 12 if admin else 1
            if len(password) < minimum or len(password) > 128 or password != field("confirm"):
                self.render(session, "Passwords must match and contain {}–128 characters.".format(minimum), 400)
                return
            if admin and (not self.store.attempt(ip, "admin-change", 10)
                          or not matches(field("current"), self.store.setting("admin"))):
                self.render(session, "Current admin password is incorrect, or too many attempts.", 403)
                return
            if not admin:
                name = field("name").strip()
                if not name or len(name) > 80:
                    self.render(session, "Enter a label of 1-80 characters.", 400)
                    return
                try:
                    self.store.add_password(name, password)
                except ValueError as error:
                    self.render(session, str(error), 400)
                    return
                self.store.event("EXE password added", ip)
                self.redirect("/?saved=1")
                return
            with self.store.db() as db:
                db.execute("UPDATE settings SET value=? WHERE name=?",
                           (json.dumps(password_record(password)), "admin"))
                db.execute("DELETE FROM sessions")
            self.store.event("Admin password changed", ip)
            self.redirect("/?admin=1")
        except (ValueError, UnicodeError):
            self.json(400, {"error": "Invalid request"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--initialize", action="store_true")
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--origin", default="https://13.210.214.189")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--cookie-name", default="remo_session")
    args = parser.parse_args()
    store = Store(args.database)
    if args.initialize:
        payload = json.load(sys.stdin)
        record = payload["installer_record"]
        if (record.get("algorithm") != "pbkdf2-sha256" or not 100000 <= record["iterations"] <= 2000000
                or len(bytes.fromhex(record["salt"])) != 16 or len(bytes.fromhex(record["digest"])) != 32
                or len(payload["admin_password"]) < 12):
            raise ValueError("Invalid initial password configuration")
        store.initialize(payload["admin_password"], record)
        args.database.chmod(0o600)
        print("Portal initialized")
        return
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.certificate, args.private_key)
    template = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")
    server = PortalServer(("0.0.0.0", args.port), store, template, args.origin, context, args.cookie_name)
    server.serve_forever()


if __name__ == "__main__":
    main()
