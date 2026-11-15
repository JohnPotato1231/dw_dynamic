"""Entry point used by the Windows self-extracting installer."""

import sys
import json
from pathlib import Path

from ui.installer import fmain as standard_main


if __name__ == "__main__":
    config_path = Path("install.json")
    config = json.loads(config_path.read_text(encoding="utf-8")) if config_path.is_file() else {}
    if config.get("setup_flow") == "password_code":
        from support_setup import fmain
        fmain(sys.argv)
    else:
        standard_main(sys.argv)
