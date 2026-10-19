#!/usr/bin/env python3
"""Read a key from stdin; print only its verified expiry. No credential appears in argv/logs."""
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone


def main():
    key = sys.stdin.read().strip()
    portal = os.environ.get("TALLY_UPGRADE_REGISTRATION_API_URL", "https://godel-gate.godel-labs.ai").rstrip("/")
    try:
        if not key.startswith("gg_") or not key.isascii() or len(key) != 67:
            raise ValueError("missing key")
        for route in ("users/me", "registration-keys/self"):
            request = urllib.request.Request(f"{portal}/api/v1/{route}", headers={"x-godel-key": key})
            with urllib.request.urlopen(request, timeout=10) as response:
                body = json.load(response)
        expiry = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
        if body.get("valid") is not True or expiry <= datetime.now(timezone.utc):
            raise ValueError("expired")
    except Exception:
        print("Registration key is expired, deactivated, or could not be verified. Upgrade is not possible. Contact support@godel-labs.ai to activate the key or extend the license.", file=sys.stderr)
        return 1
    print(expiry.isoformat())
    return 0


if __name__ == "__main__":
    sys.exit(main())
