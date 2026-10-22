#!/usr/bin/env bash
#
# Reads /status.php from a running lab container and optionally asserts whether
# the PHP build is expected to be vulnerable or patched.
#
#   BASE_URL=http://localhost:8080 EXPECT=vulnerable ./scripts/verify.sh
#   BASE_URL=http://localhost:8080 EXPECT=patched    ./scripts/verify.sh

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
EXPECT="${EXPECT:-any}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required to parse the status response" >&2
    exit 1
fi

json="$(curl -fsS --retry 10 --retry-delay 1 --retry-connrefused "${BASE_URL}/status.php")"

python3 - "$json" "$EXPECT" <<'PY'
import json
import sys

status = json.loads(sys.argv[1])
expect = sys.argv[2]

print(f"PHP version:                     {status['php_version']}")
print(f"Server API:                      {status['sapi']}")
print(f"session.upload_progress.enabled: {status['session_upload_progress']}")
print(f"memory_limit:                    {status['memory_limit']}")
print(f"vulnerable:                      {status['vulnerable']}")

if expect == "vulnerable" and not status["vulnerable"]:
    sys.exit("FAIL: expected a vulnerable PHP build")
if expect == "patched" and status["vulnerable"]:
    sys.exit("FAIL: expected a patched PHP build")

print(f"OK: expected '{expect}'")
PY
