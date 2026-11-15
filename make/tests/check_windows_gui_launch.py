"""Check GUI launcher console visibility without starting an agent or service."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


PROBE = '''import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import sys

ctypes.windll.kernel32.GetConsoleWindow.restype = wintypes.HWND
ctypes.windll.user32.IsWindowVisible.argtypes = [wintypes.HWND]
console = ctypes.windll.kernel32.GetConsoleWindow()
Path("launch-result.json").write_text(json.dumps({
    "module": Path(__file__).stem,
    "arguments": sys.argv[1:],
    "visible_console": bool(console and ctypes.windll.user32.IsWindowVisible(console))
}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    fixture = Path(tempfile.mkdtemp(prefix="GUI launcher check ", dir=root / "make" / "tmp"))
    native = fixture / "native"
    native.mkdir()
    shutil.copy2(args.launcher.resolve(), native / "dwaglnc.exe")
    shutil.copytree(args.runtime.resolve(), fixture / "runtime")
    (native / "service.properties").write_text(
        "pythonPath=" + str(fixture / "runtime" / "dwagent.exe") + "\n",
        encoding="utf-8")
    for module in ("monitor", "configure", "installer", "support_setup"):
        (fixture / (module + ".py")).write_text(PROBE, encoding="utf-8")
    report = fixture / "launch-result.json"
    cases = [("monitor", "monitor", ["window"]),
             ("systray", "monitor", ["systray"]),
             ("configure", "configure", []),
             ("uninstallAsAdimn", "installer", ["uninstall"]),
             ("uninstallAsAdimn", "support_setup", ["uninstall"])]
    for command, module, arguments in cases:
        if module == "support_setup":
            (fixture / "setup-access.json").write_text("{}", encoding="utf-8")
        if report.exists():
            report.unlink()
        subprocess.run([str(native / "dwaglnc.exe"), command], cwd=fixture,
                       check=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
        deadline = time.monotonic() + 10
        while not report.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        if not report.exists():
            raise RuntimeError("Launcher did not start probe: " + command)
        result = json.loads(report.read_text(encoding="utf-8"))
        if result != {"module": module, "arguments": arguments, "visible_console": False}:
            raise AssertionError(result)
        print("PASS: " + command + " / " + module + " opens no visible console")
    print("Fixture: " + str(fixture))


if __name__ == "__main__":
    main()
