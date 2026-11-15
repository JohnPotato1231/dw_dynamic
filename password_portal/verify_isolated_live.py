"""Check only the new 10443 portal with a temporary P and temporary session."""

import argparse
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import secrets
import ssl
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "make" / "tmp" / "server-deploy-tools"))
import paramiko
sys.path.insert(0, str(ROOT / "os_win_installer"))
import setup_auth


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--password-stdin", action="store_true", required=True)
    parser.add_argument("--install-config", default="install-dynamic-10443.json")
    args = parser.parse_args()
    password = sys.stdin.readline().rstrip("\r\n")
    version2 = args.install_config == "install-dynamic-10443-v2.json"
    if args.install_config not in ("install-dynamic-10443.json", "install-dynamic-10443-v2.json"):
        parser.error("Use an isolated 10443 installer configuration")
    work = ROOT / "make" / "tmp" / ("dynamic-10443-v2" if version2 else "dynamic-10443")
    config = json.loads((ROOT / "os_win_installer" / args.install_config).read_text(encoding="utf-8"))
    assert config["remote_password"]["url"] == "https://82.25.46.70:10443/api/verify"
    context = ssl.create_default_context(cadata=config["remote_password"]["ca_pem"])
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.load_host_keys(str(ROOT / "make" / "tmp" / "server82-known-hosts"))
    client.connect("82.25.46.70", username="root", password=password,
                   look_for_keys=False, allow_agent=False, timeout=10)
    password = None

    def remote(script):
        incoming, out, error = client.exec_command("python3 -", timeout=30)
        incoming.write(script)
        incoming.flush()
        incoming.channel.shutdown_write()
        result = out.read().decode()
        errors = error.read().decode()
        if out.channel.recv_exit_status():
            raise RuntimeError(errors[-2000:])
        return json.loads(result)

    def request(path, body=None, headers=None):
        conn = http.client.HTTPSConnection("82.25.46.70", 10443, timeout=10, context=context)
        try:
            supplied = dict(headers or {})
            if body is not None:
                supplied["Content-Type"] = "application/json"
                body = json.dumps(body)
            conn.request("POST" if body is not None else "GET", path, body=body, headers=supplied)
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            conn.close()

    prefix = """
import importlib.util,json,sqlite3,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('portal','/opt/remo-dynamic-portal/server.py')
portal=importlib.util.module_from_spec(spec);spec.loader.exec_module(portal)
store=portal.Store('/var/lib/remo-dynamic-portal/state.sqlite3')
"""
    test_password = secrets.token_urlsafe(32)
    session_token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    test_id = None
    try:
        created = remote(prefix + "\npid=store.add_password('Deployment QA '+" + repr(secrets.token_hex(6)) + "," + repr(test_password) + ")\n"
            + "with store.db() as db: db.execute('INSERT INTO sessions VALUES (?,?,?)',(portal.token_hash("
            + repr(session_token) + ")," + repr(csrf) + ",time.time()+180))\n"
            + "print(json.dumps({'id':pid,'profile':store.install_identity()}))\n")
        test_id, profile = created["id"], created["profile"]
        assert request("/health")[0] == 200
        page = request("/")
        assert page[0] == 200 and profile["main_executable"] not in page[2]
        assert page[1]["Cache-Control"] == "no-store"
        for key in (None, "incorrect-client-credential"):
            headers = {} if key is None else {"Authorization": "Bearer " + key}
            code, _, body = request("/api/verify", {"password": test_password, "include_install_identity": True}, headers)
            assert code == 401 and "install_identity" not in json.loads(body)
        headers = {"Authorization": "Bearer " + setup_auth._INSTALL_IDENTITY_CLIENT_PASSWORD}
        code, _, body = request("/api/verify", {"password": "wrong-"+test_password, "include_install_identity": True}, headers)
        assert code == 403 and "install_identity" not in json.loads(body)
        code, _, body = request("/api/verify", {"password": test_password})
        assert code == 200 and json.loads(body) == {"allowed": True}
        received = {}
        assert setup_auth.verify_access_password(test_password, config, install_identity=received)
        expected = ({**setup_auth.DEFAULT_INSTALL_METADATA, **profile} if version2 else
                    {key: profile[key] for key in setup_auth.DEFAULT_INSTALL_IDENTITY})
        assert received == expected
        legacy = dict(config)
        legacy.pop("install_identity_version", None)
        old_received = {}
        assert setup_auth.verify_access_password(test_password, legacy, install_identity=old_received)
        assert old_received == {key: profile[key] for key in setup_auth.DEFAULT_INSTALL_IDENTITY}
        assert 'action="/logout"' not in request("/", headers={"Cookie":"remo_session="+session_token})[2]
        dashboard = request("/", headers={"Cookie":"remo_dynamic_10443="+session_token})
        assert dashboard[0] == 200 and 'action="/passwords/add"' in dashboard[2]
        assert 'action="/install-identity"' in dashboard[2] and profile["main_executable"] in dashboard[2]
        if version2:
            assert 'name="install_path"' in dashboard[2] and 'name="publisher"' in dashboard[2]
        restart = remote("import json,subprocess\nsubprocess.run(['systemctl','restart','remo-dynamic-portal.service'],check=True)\nprint(json.dumps({'ok':True}))\n")
        assert restart["ok"]
        for attempt in range(15):
            try:
                if request("/health")[0] == 200:
                    break
            except OSError:
                time.sleep(0.5)
        else:
            raise RuntimeError("New portal did not return after its restart")
        assert setup_auth.verify_access_password(test_password, config, install_identity={})
        revoked = remote(prefix + "\nprint(json.dumps({'removed':store.delete_password(" + repr(test_id) + ")}))\n")
        assert revoked["removed"]
        code, _, body = request("/api/verify", {"password": test_password, "include_install_identity": True}, headers)
        assert code == 403 and "install_identity" not in json.loads(body)
        logs = remote("import json,subprocess\nprint(json.dumps({'text':subprocess.check_output(['journalctl','-u','remo-dynamic-portal.service','-n','80','--no-pager','-o','cat'],text=True)}))\n")["text"]
        assert test_password not in logs and setup_auth._INSTALL_IDENTITY_CLIENT_PASSWORD not in logs
        result = {"public_https":True,"both_credentials_required":True,"P_only_returns_no_names":True,
                  "portal_manages_P_and_names":True,"cookie_isolation":True,
                  "restart_persistence":True,"revocation":True,"no_credentials_in_journal":True,
                  "legacy_four_field_compatibility": True, "metadata_version_2":version2}
        (work / "live-tests.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result))
    finally:
        if test_id is not None:
            remote(prefix + "\nstore.delete_password("+repr(test_id)+")\nwith store.db() as db: db.execute('DELETE FROM sessions WHERE token=?',(portal.token_hash("
                   +repr(session_token)+"),))\nprint(json.dumps({'temporary_credentials_removed':True}))\n")
        client.close()


if __name__ == "__main__":
    main()
