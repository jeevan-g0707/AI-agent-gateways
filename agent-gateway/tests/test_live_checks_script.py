"""examples/live_checks.py must skip cleanly (exit 0) when no live service is configured."""
import os
import subprocess
import sys
from pathlib import Path


def test_live_checks_skips_without_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GATEWAY_LIVE_", "GATEWAY_SMTP_"))}
    p = subprocess.run([sys.executable, str(Path(__file__).parent.parent / "examples" / "live_checks.py")],
                       capture_output=True, text=True, env=env, timeout=60)
    assert p.returncode == 0, p.stdout + p.stderr
    assert p.stdout.count("[SKIP]") == 4 and "0 failed" in p.stdout
