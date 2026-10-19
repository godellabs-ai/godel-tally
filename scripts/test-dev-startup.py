#!/usr/bin/env python3
"""Compatibility entrypoint for the combined-runtime development startup fixture."""
import subprocess
import sys
from pathlib import Path
subprocess.run([sys.executable, str(Path(__file__).with_name("test-deployment.py")),
    "Deployment.test_live_reload_uses_one_rust_watcher_and_no_router"], check=True)
