"""Verify add/remove behavior using temporary passwords; preserve existing access."""

import getpass
import http.client
import json
from pathlib import Path
import re
import secrets
import ssl
import sys
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "os_win_installer"))
from setup_auth import verify_access_password


def main():
    admin_password = getpass.getpass("Admin password (hidden): ")
    config = json.loads((ROOT / "os_win_installer" / "install.json").read_text())
    context = ssl.create_default_context(cadata=config["remote_password"]["ca_pem"])

    def request(path, fields=None, cookie=None):
        connection = http.client.HTTPSConnection("13.210.214.189", timeout=10, context=context)
        headers = {"Origin": "https://13.210.214.189"}
        if cookie:
            headers["Cookie"] = cookie
        body = None
        if fields is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urlencode(fields)
        connection.request("GET" if fields is None else "POST", path, body, headers)
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read().decode()
        connection.close()
        return result

    status, headers, _ = request("/login", {"username": "admin", "password": admin_password})
    assert status == 303, "Live admin login failed"
    cookie = headers["Set-Cookie"].split(";")[0]
    status, _, page = request("/", cookie=cookie)
    assert status == 200 and "Add access password" in page
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)

    def ids():
        _, _, page = request("/", cookie=cookie)
        return set(re.findall(r'name="id" value="([a-f0-9]{32})"', page))

    created = set()
    try:
        values = []
        for _ in range(2):
            before = ids()
            password = secrets.token_urlsafe(16)
            status, _, _ = request("/passwords/add", {"csrf": csrf, "name": "Verification " + secrets.token_hex(4),
                "password": password, "confirm": password}, cookie)
            assert status == 303, "Live password creation failed"
            added = ids() - before
            created.update(added)
            assert len(added) == 1
            values.append((added.pop(), password))
            assert verify_access_password(password, config)
        first_id, first_password = values[0]
        status, _, _ = request("/passwords/delete", {"csrf": csrf, "id": first_id}, cookie)
        assert status == 303
        created.remove(first_id)
        assert not verify_access_password(first_password, config), "Removed password still accepted"
        assert verify_access_password(values[1][1], config), "Other active password was revoked"
    finally:
        for password_id in created:
            request("/passwords/delete", {"csrf": csrf, "id": password_id}, cookie)
        request("/logout", {"csrf": csrf}, cookie)
    print("PASS: live admin sign-in, multiple passwords and individual revocation; temporary passwords removed")


if __name__ == "__main__":
    main()
