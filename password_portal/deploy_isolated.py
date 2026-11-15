"""Deploy an independent P/naming portal on 10443 without changing old services."""

import argparse
import getpass
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
try:
    import paramiko
except ImportError:
    sys.path.insert(0, str(ROOT / "make" / "tmp" / "server-deploy-tools"))
    import paramiko


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="82.25.46.70")
    parser.add_argument("--username", default="root")
    parser.add_argument("--password-stdin", action="store_true")
    args = parser.parse_args()
    if args.host != "82.25.46.70":
        parser.error("This deployment is scoped to 82.25.46.70")
    password = sys.stdin.readline().rstrip("\r\n") if args.password_stdin else getpass.getpass("SSH password: ")
    work = ROOT / "make" / "tmp" / "dynamic-10443"
    work.mkdir(parents=True, exist_ok=True)
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    hosts = ROOT / "make" / "tmp" / "server82-known-hosts"
    if hosts.exists():
        client.load_host_keys(str(hosts))
    client.connect(args.host, username=args.username, password=password,
                   look_for_keys=False, allow_agent=False, timeout=10, auth_timeout=15)
    password = None

    def remote(script):
        incoming, outgoing, errors = client.exec_command("python3 -", timeout=40)
        incoming.write(script)
        incoming.flush()
        incoming.channel.shutdown_write()
        output = outgoing.read().decode("utf-8", errors="replace")
        error = errors.read().decode("utf-8", errors="replace")
        if outgoing.channel.recv_exit_status():
            raise RuntimeError("Isolated deployment failed: " + error[-4000:])
        return json.loads(output)

    snapshot = r'''
import hashlib,json,re,sqlite3,subprocess
from pathlib import Path
def snapshot():
    files = ['/opt/remo-password-portal/server.py','/opt/remo-password-portal/index.html',
             '/etc/systemd/system/remo-password-portal.service']
    units = ['remo-password-portal.service','bl-replace.service','nginx.service','postgresql@16-main.service']
    state = {}
    for unit in units:
        state[unit] = subprocess.check_output(['systemctl','show',unit,'-p','MainPID','-p','ActiveState'],text=True)
    source = Path('/var/lib/remo-password-portal/state.sqlite3')
    db = sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)
    try:
        credentials = db.execute('SELECT * FROM passwords ORDER BY id').fetchall()
        admin = db.execute("SELECT value FROM settings WHERE name='admin'").fetchone()
    finally: db.close()
    listeners = []
    for line in subprocess.check_output(['ss','-H','-lntp'],text=True).splitlines():
        address = line.split()[3]
        if address.rsplit(':',1)[-1] != '10443':
            processes = sorted(re.findall(r'"([^"]+)",pid=(\d+)',line))
            listeners.append([address,processes])
    listeners.sort()
    return {'listeners':listeners,'units':state,
            'source_files':{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in files},
            'credentials':hashlib.sha256(json.dumps([credentials,admin],sort_keys=True).encode()).hexdigest(),
            'password_count':len(credentials)}
'''
    try:
        before = remote(snapshot + r'''
import socket
for p in ['/opt/remo-dynamic-portal','/var/lib/remo-dynamic-portal','/etc/systemd/system/remo-dynamic-portal.service']:
    if Path(p).exists(): raise RuntimeError('Refusing an existing deployment path: '+p)
with socket.socket() as probe:
    probe.bind(('0.0.0.0',10443))
print(json.dumps(snapshot()))
''')
        (work / "server-before.json").write_text(json.dumps(before, indent=2), encoding="utf-8")
        print("Preflight passed: 10443 unused; original services and credentials recorded.", flush=True)
        remote(r'''
import json,pwd,subprocess
try: pwd.getpwnam('remo-dynamic')
except KeyError:
    subprocess.run(['useradd','--system','--home-dir','/var/lib/remo-dynamic-portal',
                    '--shell','/usr/sbin/nologin','remo-dynamic'],check=True)
else: raise RuntimeError('Refusing an existing Unix account: remo-dynamic')
subprocess.run(['install','-d','-m','755','/opt/remo-dynamic-portal'],check=True)
subprocess.run(['install','-d','-m','700','/var/lib/remo-dynamic-portal'],check=True)
print(json.dumps({'directories':'created'}))
''')
        with client.open_sftp() as sftp:
            for name in ("server.py", "index.html"):
                target = "/opt/remo-dynamic-portal/" + name
                sftp.put(str(ROOT / "password_portal" / name), target)
                sftp.chmod(target, 0o644)
            target = "/etc/systemd/system/remo-dynamic-portal.service"
            sftp.put(str(ROOT / "password_portal" / "remo-dynamic-portal.service"), target)
            sftp.chmod(target, 0o644)
        result = remote(r'''
from contextlib import closing
import importlib.util,json,os,pwd,sqlite3,subprocess
from pathlib import Path
source=Path('/var/lib/remo-password-portal/state.sqlite3')
destination=Path('/var/lib/remo-dynamic-portal/state.sqlite3')
key=Path(str(source)+'.lookup-key').read_bytes()
with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as old, closing(sqlite3.connect(destination)) as new:
    old.backup(new)
    for table in ('sessions','attempts','events'): new.execute('DELETE FROM '+table)
    new.commit()
if key != Path(str(source)+'.lookup-key').read_bytes(): raise RuntimeError('Source lookup key changed during snapshot')
Path(str(destination)+'.lookup-key').write_bytes(key)
spec=importlib.util.spec_from_file_location('dynamic_portal','/opt/remo-dynamic-portal/server.py')
portal=importlib.util.module_from_spec(spec);spec.loader.exec_module(portal)
store=portal.Store(destination);store.migrate_passwords();store.migrate_events()
store.save_install_identity({'main_executable':'remo_dwagent.exe','service_executable':'remo_dwagsvc.exe',
                             'service_name':'remo_dwagent','service_display_name':'REMO Remote Support'})
subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes',
 '-keyout','/var/lib/remo-dynamic-portal/server.key','-out','/var/lib/remo-dynamic-portal/server.crt',
 '-days','3650','-subj','/CN=82.25.46.70','-addext','subjectAltName=IP:82.25.46.70',
 '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign'],
 check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
account=pwd.getpwnam('remo-dynamic')
directory=Path('/var/lib/remo-dynamic-portal')
os.chown(directory,account.pw_uid,account.pw_gid)
for path in directory.iterdir():
    os.chown(path,account.pw_uid,account.pw_gid);path.chmod(0o600)
subprocess.run(['systemd-analyze','verify','/etc/systemd/system/remo-dynamic-portal.service'],check=True,
               stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now','remo-dynamic-portal.service'],check=True,
               stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
print(json.dumps({'active':subprocess.check_output(['systemctl','is-active','remo-dynamic-portal.service'],text=True).strip(),
                  'password_count':len(store.passwords())}))
''')
        with client.open_sftp() as sftp:
            certificate = sftp.open("/var/lib/remo-dynamic-portal/server.crt", "r").read().decode("ascii")
        certificate_path = work / "server.crt"
        certificate_path.write_text(certificate, encoding="ascii")
        original_config = (ROOT / "os_win_installer" / "install.json").read_bytes()
        config = json.loads(original_config)
        config["name"] = "DWAgent"
        config["service_executable"] = "dwagsvc.exe"
        config["server_install_identity"] = True
        config.pop("install_identity", None)
        config["remote_password"] = {"url": "https://82.25.46.70:10443/api/verify", "ca_pem": certificate}
        (ROOT / "os_win_installer" / "install-dynamic-10443.json").write_text(json.dumps(config, indent=2)+"\n", encoding="utf-8")
        assert (ROOT / "os_win_installer" / "install.json").read_bytes() == original_config
        after = remote(snapshot + "\nprint(json.dumps(snapshot()))\n")
        if after != before:
            raise RuntimeError("Original service snapshot changed; inspect server-before.json before proceeding")
        report = {"origin": "https://82.25.46.70:10443", "service": "remo-dynamic-portal.service",
                  "active": result["active"], "passwords_copied": result["password_count"],
                  "original_services_unchanged": True, "original_config_unchanged": True}
        (work / "deployment.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report))
    finally:
        client.close()


if __name__ == "__main__":
    main()
