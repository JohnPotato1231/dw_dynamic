"""Preview a staged setup GUI with elevation and installation disabled."""

import argparse
import os
from pathlib import Path
import sys
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, type=Path)
    args = parser.parse_args()
    stage = args.stage.resolve(strict=True)
    test_root = Path(__file__).resolve().parents[1] / "tmp"
    if not stage.is_relative_to(test_root.resolve()):
        parser.error("The preview must use an isolated make/tmp fixture")
    os.chdir(stage)
    sys.path.insert(0, str(stage))
    from support_setup import SupportInstall, SupportWindows
    from ui import ui

    with patch.object(SupportWindows, "check_init_install", return_value=None), \
            patch.object(SupportInstall, "step_begin", return_value=ui.Message(
                "Preview only. No installation performed.")):
        SupportInstall().start({"gui": True})


if __name__ == "__main__":
    main()
