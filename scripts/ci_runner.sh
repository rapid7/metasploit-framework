#!/bin/bash
set -euo pipefail

# =====================================================================
# CI Runner for test_env — bridges msfconsole resource scripts to
# standard Unix exit codes for GitHub Actions / any CI system.
# =====================================================================

MODULE="${1:-}"
VARIANT="${2:-}"
PROFILE="${3:-default}"
EXIT_CODE=1

# ---------------------------------------------------------------------
# Validate arguments
# ---------------------------------------------------------------------
if [[ -z "$MODULE" || -z "$VARIANT" ]]; then
    echo "Usage: $0 <module_fullname> <variant> [profile]"
    echo ""
    echo "Examples:"
    echo "  $0 exploit/multi/http/apache_activemq_jolokia_rce 5.18.6 default"
    echo "  $0 exploit/multi/misc/apache_activemq_rce_cve_2023_46604 5.18.2 broker-only"
    echo "  $0 exploit/unix/webapp/wp_admin_shell_upload latest default"
    exit 1
fi

# ---------------------------------------------------------------------
# Validate environment
# ---------------------------------------------------------------------
if [[ ! -x "./msfconsole" ]]; then
    echo "Error: ./msfconsole not found or not executable."
    echo "Run this script from the metasploit-framework root directory."
    exit 1
fi


# ---------------------------------------------------------------------
# Generate unique temp files (supports parallel CI jobs)
# ---------------------------------------------------------------------
TIMESTAMP=$(date +%s)_$$
RC_FILE="/tmp/test_env_${TIMESTAMP}.rc"
LOG_FILE="/tmp/test_env_${TIMESTAMP}.log"

# ---------------------------------------------------------------------
# Build the Metasploit resource script dynamically
# ---------------------------------------------------------------------
cat > "$RC_FILE" <<EOF
load test_env
use ${MODULE}
test_env build VARIANT=${VARIANT} PROFILE=${PROFILE}
test_env exec 1 -z
test_env validate 1
test_env remove-all
exit -y
EOF

echo ">>> CI Runner Started"
echo ">>> Module:    $MODULE"
echo ">>> Variant:   $VARIANT"
echo ">>> Profile:   $PROFILE"
echo ">>> RC Script: $RC_FILE"
echo ">>> Log File:  $LOG_FILE"
echo ""


# ---------------------------------------------------------------------
# Execute msfconsole headlessly
# ---------------------------------------------------------------------
echo ">>> Running msfconsole..."
./msfconsole -q -n -r "$RC_FILE" | tee "$LOG_FILE"

# ---------------------------------------------------------------------
# Parse result from log (PASS / FAIL / unclear)
# ---------------------------------------------------------------------
echo ""
if grep -q "FAIL:" "$LOG_FILE"; then
    echo ">>> RESULT: VALIDATION FAILED"
    EXIT_CODE=1
elif grep -q "PASS:" "$LOG_FILE"; then
    echo ">>> RESULT: VALIDATION PASSED"
    EXIT_CODE=0
else
    echo ">>> RESULT: UNCLEAR — no PASS or FAIL found in output"
    echo ">>> This usually means the exploit or health check failed early."
    EXIT_CODE=1
fi

# ---------------------------------------------------------------------
# Cleanup and report
# ---------------------------------------------------------------------
rm -f "$RC_FILE"
echo ">>> Full log preserved at: $LOG_FILE"
echo ">>> CI Runner Finished"

exit "$EXIT_CODE"
