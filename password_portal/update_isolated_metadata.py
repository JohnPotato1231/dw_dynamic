"""Update only the already isolated 10443 portal; keep a rollback copy."""

import argparse
import ast
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "make/tmp/server-deploy-tools"))
import paramiko


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--password-stdin", action="store_true", required=True)
    parser.parse_args()
    password = sys.stdin.readline().rstrip("\r\n")
    work = ROOT / "make/tmp/dynamic-10443-v2"
    work.mkdir(parents=True, exist_ok=True)
    source = ast.parse((ROOT / "password_portal/deploy_isolated.py").read_text(encoding="utf-8"))
    snapshot = next(ast.literal_eval(node.value) for node in ast.walk(source)
                    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "snapshot" for t in node.targets))
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.load_host_keys(str(ROOT / "make/tmp/server82-known-hosts"))
    client.connect("82.25.46.70", username="root", password=password,
                   look_for_keys=False, allow_agent=False, timeout=10)
    password = None

    def remote(script):
        incoming, out, errors = client.exec_command("python3 -", timeout=40)
        incoming.write(script)
        incoming.flush()
        incoming.channel.shutdown_write()
        result, error = out.read().decode(), errors.read().decode()
        if out.channel.recv_exit_status():
            raise RuntimeError(error[-2000:])
        return json.loads(result)

    try:
        before = remote(snapshot + "\nprint(json.dumps(snapshot()))\n")
        (work / "server-before.json").write_text(json.dumps(before, indent=2))
        backup = remote(r'''
import json,os,shutil,sqlite3,subprocess,time
from pathlib import Path
code=Path('/opt/remo-dynamic-portal/server.py')
database=Path('/var/lib/remo-dynamic-portal/state.sqlite3')
assert code.is_file() and database.is_file()
assert subprocess.check_output(['systemctl','is-active','remo-dynamic-portal.service'],text=True).strip()=='active'
folder=database.parent / ('backup-metadata-'+time.strftime('%Y%m%dT%H%M%S'))
folder.mkdir(mode=0o700)
shutil.copy2(code,folder/'server.py')
with sqlite3.connect(database) as live, sqlite3.connect(folder/'state.sqlite3') as backup: live.backup(backup)
shutil.copy2(str(database)+'.lookup-key',folder/'state.sqlite3.lookup-key')
print(json.dumps({'folder':str(folder)}))
''')["folder"]
        with client.open_sftp() as sftp:
            sftp.put(str(ROOT / "password_portal/server.py"), "/opt/remo-dynamic-portal/server.py.metadata-new")
            sftp.chmod("/opt/remo-dynamic-portal/server.py.metadata-new", 0o644)
        try:
            result = remote(r'''
import hashlib,json,os,subprocess,time,urllib.request,ssl
from pathlib import Path
staged=Path('/opt/remo-dynamic-portal/server.py.metadata-new')
compile(staged.read_text(encoding='utf-8'),str(staged),'exec')
os.replace(staged,'/opt/remo-dynamic-portal/server.py')
subprocess.run(['systemctl','restart','remo-dynamic-portal.service'],check=True)
context=ssl.create_default_context(cafile='/var/lib/remo-dynamic-portal/server.crt')
for attempt in range(20):
    try:
        with urllib.request.urlopen('https://82.25.46.70:10443/health',context=context,timeout=2) as response:
            assert response.status==200
        break
    except OSError: time.sleep(0.25)
else: raise RuntimeError('Updated portal health check failed')
print(json.dumps({'active':True,'source_sha256':hashlib.sha256(Path('/opt/remo-dynamic-portal/server.py').read_bytes()).hexdigest()}))
''')
        except Exception:
            remote("import json,shutil,subprocess\nshutil.copy2(" + repr(backup + "/server.py")
                   + ",'/opt/remo-dynamic-portal/server.py')\nsubprocess.run(['systemctl','restart','remo-dynamic-portal.service'],check=True)\nprint(json.dumps({'source_restored':True}))\n")
            raise
        after = remote(snapshot + "\nprint(json.dumps(snapshot()))\n")
        (work / "server-after.json").write_text(json.dumps(after, indent=2))
        assert before == after, "An existing listener, process, credential or source changed"
        report = {**result, "old_services_and_credentials_unchanged": True, "backup": backup}
        (work / "deployment.json").write_text(json.dumps(report, indent=2))
        print(json.dumps(report))
    finally:
        client.close()


if __name__ == "__main__":
    main()
