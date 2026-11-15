"""Package a compiled x64 stub, native libraries, and Python runtime archive."""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import sys


def prepare_install_config(config):
    """Server naming profiles belong on the portal, never in a new installer."""
    config = dict(config)
    if config.get("server_install_identity"):
        if config.get("setup_flow") != "password_code" or "remote_password" not in config:
            raise ValueError("Server naming requires the online password setup flow")
        config["name"] = "DWAgent"
        config["service_executable"] = "dwagsvc.exe"
        for key in ("install_identity", "main_executable", "service_name", "service_display_name", "install_path", "publisher"):
            config.pop(key, None)
    return config


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stub", required=True, type=Path)
    parser.add_argument("--runtime-archive", required=True, type=Path)
    parser.add_argument("--runtime-license", required=True, type=Path)
    parser.add_argument("--sevenzip", required=True, type=Path)
    parser.add_argument("--install-config", type=Path,
                        help="Installer branding settings to bundle as install.json")
    parser.add_argument("--output", type=Path, default=root / "dwagent-github-x64.exe")
    parser.add_argument("--native-dir", type=Path, default=root / "make" / "native")
    args = parser.parse_args()
    for name in ("stub", "runtime_archive", "runtime_license", "sevenzip"):
        path = getattr(args, name).resolve(strict=True)
        if not path.is_file():
            parser.error("Expected a file: " + str(path))
        setattr(args, name, path)
    install_config = None
    service_executable = "dwagsvc.exe"
    if args.install_config is not None:
        install_config = json.loads(args.install_config.read_text(encoding="utf-8"))
        if not isinstance(install_config, dict):
            parser.error("Installer configuration must be a JSON object")
        try:
            install_config = prepare_install_config(install_config)
        except ValueError as error:
            parser.error(str(error))
        icon_name = install_config.get("logoxos")
        if icon_name is not None and (not isinstance(icon_name, str) or not re.fullmatch(
                r"[A-Za-z0-9_-]+\.ico", icon_name, re.IGNORECASE)):
            parser.error("Installer icon must be a plain .ico filename")
        service_executable = install_config.get("service_executable", "dwagsvc.exe")
        if not isinstance(service_executable, str) or not re.fullmatch(
                r"[A-Za-z0-9_-]+\.exe", service_executable, re.IGNORECASE):
            parser.error("Service executable must be a plain .exe filename")
        if service_executable != "dwagsvc.exe" and install_config.get("setup_flow") != "password_code":
            parser.error("A renamed service executable requires the custom setup flow")
        if install_config.get("setup_flow") == "password_code":
            sys.path.insert(0, str(root / "os_win_installer"))
            from setup_auth import valid_access_config
            if not valid_access_config(install_config):
                parser.error("Password-first setup requires a valid local or online password configuration")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    build_parent = root / "make" / "tmp"
    build_parent.mkdir(parents=True, exist_ok=True)
    build = Path(tempfile.mkdtemp(prefix="windows-installer-", dir=build_parent))
    stage = build / "stage"
    stage.mkdir()
    if install_config is not None:
        (stage / "install.json").write_text(
            json.dumps(install_config, indent=2) + "\n", encoding="utf-8")
        if install_config.get("logoxos"):
            shutil.copy2(root / "os_win_installer" / "installer.ico",
                         stage / install_config["logoxos"])

    for name in ("communication.py", "listener.py", "ipc.py", "utils.py",
                 "detectinfo.py", "native.py", "resources.py", "cacerts.pem"):
        shutil.copy2(root / "core" / name, stage / name)
    shutil.copy2(root / "os_win_installer" / "installer.py", stage / "installer.py")
    for name in ("support_setup.py", "setup_auth.py", "setup_files.py", "setup_version.py", "uninstall.cmd"):
        shutil.copy2(root / "os_win_installer" / name, stage / name)

    # Resource loaders use ui.messages and ui.images, so preserve the package.
    ui = stage / "ui"
    ui.mkdir()
    for path in (root / "ui").glob("*.py"):
        shutil.copy2(path, ui / path.name)
    for name in ("messages", "images"):
        shutil.copytree(root / "ui" / name, ui / name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    native = stage / "native_win_x86_64"
    shutil.copytree(args.native_dir, native)
    for name in ("dwaggdi.dll", "dwaglib.dll", "dwaglnc.exe", "dwagsvc.exe"):
        if not (native / name).is_file():
            raise FileNotFoundError("Compile native libraries first: " + name)
    if service_executable != "dwagsvc.exe":
        if (native / service_executable).exists():
            raise FileExistsError("Service filename conflicts with another bundled file")
        (native / "dwagsvc.exe").rename(native / service_executable)
    (stage / "native_win_x86_32").mkdir()
    shutil.copy2(args.runtime_archive, stage / "runtimepy3.7z")

    licenses = stage / "LICENSES"
    licenses.mkdir()
    shutil.copy2(root / "README.md", licenses / "README")
    shutil.copy2(root / "core" / "LICENSE", licenses / "core")
    shutil.copy2(root / "ui" / "LICENSE", licenses / "ui")
    shutil.copy2(args.runtime_license, licenses / "runtime")

    subprocess.run([str(args.sevenzip), "a", "-t7z", "-mx=3",
                    str(build / "win.7z"), ".\\*"], cwd=stage, check=True)
    candidate = build / output.name
    with candidate.open("wb") as destination:
        for path in (args.stub, root / "os_win_installer" / "config.txt",
                     build / "win.7z"):
            with path.open("rb") as source:
                shutil.copyfileobj(source, destination)
    subprocess.run([str(args.sevenzip), "t", str(candidate)], check=True)
    shutil.copy2(candidate, output)
    print("Installer: " + str(output))
    print("Build files: " + str(build))


if __name__ == "__main__":
    main()
