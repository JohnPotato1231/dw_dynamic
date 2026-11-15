"""Deploy the portal to its existing EC2 host. Credentials travel over SSH stdin."""

import argparse
import json
from pathlib import Path
import secrets
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", required=True)
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    root = folder.parent
    host = "ec2-user@13.210.214.189"
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-i", args.identity, host]
    scp = ["scp", "-o", "BatchMode=yes", "-i", args.identity]

    def remote(command, input=None):
        return subprocess.run(ssh + [command], input=input, text=True,
                              capture_output=True, check=True).stdout.strip()

    # SQLite's backup API produces a consistent snapshot while the old portal runs.
    remote("python3 -", "import os, sqlite3, time\n"
           "from pathlib import Path\n"
           "source = Path('/var/lib/remo-password-portal/state.sqlite3')\n"
           "if source.exists():\n"
           "    backup = source.with_name('state-backup-' + str(time.time_ns()) + '.sqlite3')\n"
           "    with sqlite3.connect(str(source)) as db, sqlite3.connect(str(backup)) as out:\n"
           "        db.backup(out)\n"
           "    os.chmod(str(backup), 0o600)\n"
           "    lookup = Path(str(source) + '.lookup-key')\n"
           "    if lookup.exists():\n"
           "        saved_key = Path(str(backup) + '.lookup-key')\n"
           "        saved_key.write_bytes(lookup.read_bytes())\n"
           "        os.chmod(str(saved_key), 0o600)\n")

    remote("mkdir -p /home/ec2-user/remo-portal-upload; chmod 700 /home/ec2-user/remo-portal-upload")
    subprocess.run(scp + [str(folder / name) for name in
                         ("server.py", "index.html", "remo-password-portal.service")]
                   + [host + ":/home/ec2-user/remo-portal-upload/"], check=True, capture_output=True)
    remote("sudo -n install -d -m 755 /opt/remo-password-portal && "
           "sudo -n install -d -m 700 -o ec2-user -g ec2-user /var/lib/remo-password-portal && "
           "sudo -n install -m 644 /home/ec2-user/remo-portal-upload/server.py /home/ec2-user/remo-portal-upload/index.html /opt/remo-password-portal/ && "
           "sudo -n install -m 644 /home/ec2-user/remo-portal-upload/remo-password-portal.service /etc/systemd/system/")
    remote("if ! test -f /var/lib/remo-password-portal/server.crt; then "
           "umask 077; openssl req -x509 -newkey rsa:3072 -nodes "
           "-keyout /var/lib/remo-password-portal/server.key "
           "-out /var/lib/remo-password-portal/server.crt -days 3650 "
           "-subj /CN=13.210.214.189 -addext subjectAltName=IP:13.210.214.189 "
           "-addext basicConstraints=critical,CA:TRUE "
           "-addext keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign; fi")
    config_path = root / "os_win_installer" / "install.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    existing = remote("if test -f /var/lib/remo-password-portal/state.sqlite3; then echo yes; fi")
    admin_password = None
    if not existing:
        admin_password = secrets.token_urlsafe(24)
        payload = json.dumps({"admin_password": admin_password,
                              "installer_record": config["setup_password"]})
        remote("python3 /opt/remo-password-portal/server.py "
               "--database /var/lib/remo-password-portal/state.sqlite3 --initialize", payload)
    cert = remote("cat /var/lib/remo-password-portal/server.crt") + "\n"
    (folder / "server.crt").write_text(cert, encoding="ascii")
    config.pop("setup_password", None)
    config["remote_password"] = {"url": "https://13.210.214.189/api/verify", "ca_pem": cert}
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    remote("sudo -n systemctl daemon-reload && sudo -n systemctl enable remo-password-portal.service && "
           "sudo -n systemctl restart remo-password-portal.service && "
           "sudo -n systemctl is-active remo-password-portal.service")
    print(json.dumps({"url": "https://13.210.214.189", "username": "admin",
                      "admin_password": admin_password, "status": "active"}))


if __name__ == "__main__":
    main()
