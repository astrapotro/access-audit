#!/bin/bash

###############################################################################
#
# Access Audit - Global Collector
#
###############################################################################

PROG=$(basename "$0")
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

AWK=$(command -v gawk)

if [ -z "$AWK" ]
then
    echo "ERROR: gawk not found" >&2
    exit 1
fi

###############################################################################
# FUNCTIONS
###############################################################################

usage()
{
    echo "Usage: $PROG <YYYY-MM-DD>"
    exit 1
}

error()
{
    echo "ERROR: $1" >&2
    exit 1
}

###############################################################################
# VALIDATE ARGUMENTS
###############################################################################

if [ "$#" -ne 1 ]
then
    usage
fi

DATE="$1"

if ! echo "$DATE" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
then
    error "invalid date format: $DATE"
fi

###############################################################################
# PATHS
###############################################################################

MODULES="$SCRIPT_DIR/modules"

NAS_ACCESS_AUDIT_DIR="/tmp/access-audit-nas"

NAS_MACHINE_DIR="$NAS_ACCESS_AUDIT_DIR/machines"
GLOBAL_OUTPUT_DIR="$NAS_ACCESS_AUDIT_DIR/global"

GLOBAL_OUTPUT_FILE="$GLOBAL_OUTPUT_DIR/$DATE.json"

#
# Production default.
#
# For testing:
#
#   EXPECTED_MACHINES=1 ./global-collector.sh 2026-08-19
#
EXPECTED_MACHINES="${EXPECTED_MACHINES:-12}"

###############################################################################
# VALIDATE MACHINE DIRECTORY
###############################################################################

if [ ! -d "$NAS_MACHINE_DIR" ]
then
    error "machine directory does not exist: $NAS_MACHINE_DIR"
fi

mkdir -p "$GLOBAL_OUTPUT_DIR" ||
    error "cannot create global output directory: $GLOBAL_OUTPUT_DIR"

###############################################################################
# COLLECT MACHINE FILES
###############################################################################

MACHINE_JSON_FILES=()
MACHINE_UNIQ_FILES=()
MACHINE_NAMES=()

while IFS= read -r -d '' MACHINE_DIR
do
    MACHINE=$(basename "$MACHINE_DIR")

    JSON_FILE="$MACHINE_DIR/$DATE.json"
    UNIQ_FILE="$MACHINE_DIR/$DATE.uniq.gz"

    if [ ! -f "$JSON_FILE" ]
    then
        error "missing machine JSON: $MACHINE/$DATE.json"
    fi

    if [ ! -f "$UNIQ_FILE" ]
    then
        error "missing machine UNIQ: $MACHINE/$DATE.uniq.gz"
    fi

    MACHINE_NAMES+=("$MACHINE")
    MACHINE_JSON_FILES+=("$JSON_FILE")
    MACHINE_UNIQ_FILES+=("$UNIQ_FILE")

done < <(
    find "$NAS_MACHINE_DIR" \
        -mindepth 1 \
        -maxdepth 1 \
        -type d \
        -print0 |
    sort -z
)

###############################################################################
# VALIDATE MACHINE COUNT
###############################################################################

if [ "${#MACHINE_NAMES[@]}" -ne "$EXPECTED_MACHINES" ]
then
    error "expected $EXPECTED_MACHINES machines for date $DATE, found ${#MACHINE_NAMES[@]}: ${MACHINE_NAMES[*]}"
fi

###############################################################################
# TEMPORARY OUTPUT
###############################################################################

TMP_OUTPUT=$(mktemp "$GLOBAL_OUTPUT_DIR/.$DATE.XXXXXX.json") ||
    error "cannot create temporary global output"

trap 'rm -f "${TMP_OUTPUT:-}"' EXIT

###############################################################################
# BUILD AWK INPUT LISTS
###############################################################################

JSON_FILES=$(printf '%s\n' "${MACHINE_JSON_FILES[@]}")
UNIQ_FILES=$(printf '%s\n' "${MACHINE_UNIQ_FILES[@]}")

###############################################################################
# RUN GLOBAL COLLECTOR
###############################################################################

"$AWK" \
    -v DATE="$DATE" \
    -v SOURCE="global-collector" \
    -v EXPECTED_MACHINES="$EXPECTED_MACHINES" \
    -v MACHINE_JSON_FILES="$JSON_FILES" \
    -v MACHINE_UNIQ_FILES="$UNIQ_FILES" \
    -f "$MODULES/global-collector.awk" \
    > "$TMP_OUTPUT"

AWK_STATUS=$?

###############################################################################
# CHECK AWK RESULT
###############################################################################

if [ "$AWK_STATUS" -ne 0 ]
then
    error "global collector failed"
fi

###############################################################################
# INSTALL OUTPUT
###############################################################################

mv "$TMP_OUTPUT" "$GLOBAL_OUTPUT_FILE" ||
    error "cannot install global output: $GLOBAL_OUTPUT_FILE"

TMP_OUTPUT=""

###############################################################################
# SUMMARY
###############################################################################

echo ""
echo "======================================================================="
echo " Global collector"
echo "======================================================================="
echo "Date:             $DATE"
echo "Machines:         ${#MACHINE_NAMES[@]} / $EXPECTED_MACHINES"
echo "Global JSON:      $GLOBAL_OUTPUT_FILE"
echo "======================================================================="
