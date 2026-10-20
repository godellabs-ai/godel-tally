#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
for script in install.sh uninstall.sh dev-run.sh prod-run.sh scripts/{runtime-common,data-services,install-runtime,package-release,build-release,docker-run,docker-upgrade,upgrade-tally-to-gate}.sh; do bash -n "$script"; done
python3 scripts/test-deployment.py
python3 scripts/test-upgrade-runtime.py
python3 scripts/test-upgrade-cutover.py
python3 scripts/test-upgrade-verification.py
python3 scripts/test-upgrade-migrations.py
python3 scripts/test-upgrade-prepare.py
