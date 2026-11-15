"""Stage a disposable uninstall UI check, without installing a Windows service."""

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--stage", required=True, type=Path)
parser.add_argument("--runtime", required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
fixture = Path(tempfile.mkdtemp(prefix="uninstall-check-", dir=root / "make" / "tmp"))
shutil.copytree(args.stage.resolve(), fixture, dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("*.7z", "__pycache__"))
shutil.copytree(args.runtime.resolve(), fixture / "runtime")
shutil.copytree(fixture / "native_win_x86_64", fixture / "native")
config = json.loads((fixture / "install.json").read_text(encoding="utf-8"))
shutil.copy2(fixture / "runtime" / "dwagent.exe",
             fixture / "runtime" / (config["name"].lower() + ".exe"))
(fixture / "config.json").write_text(json.dumps({"name": config["name"]}), encoding="utf-8")
(fixture / "setup-access.json").write_text(
    json.dumps({"setup_password": config["setup_password"],
                "service_executable": config.get("service_executable", "dwagsvc.exe")}),
    encoding="utf-8")
os.chdir(fixture)
sys.path.insert(0, str(fixture))
from ui.installer import NativeWindows

native = NativeWindows()
native.set_name(config["name"])
native.set_install_path(str(fixture))
native.prepare_file()
print(fixture)
