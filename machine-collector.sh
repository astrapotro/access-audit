#!/bin/bash

###############################################################################
#
# Access Audit - Machine Collector
#
###############################################################################

PROG=$(basename "$0")
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

MACHINE=$(uname -n)

AUDIT_OUTPUT_DIR="/tmp/access-audit"
MACHINE_OUTPUT_DIR="$AUDIT_OUTPUT_DIR/machine"

BACKUP_LOG_BASE="/web/log/apache2"

AWK=$(command -v gawk)

if [ -z "$AWK" ]
then
    error "gawk not found"
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

MACHINE_OUTPUT_FILE="$MACHINE_OUTPUT_DIR/$DATE.json"

TAR_FILE="$BACKUP_LOG_BASE/$MACHINE/${DATE:0:4}/${DATE:5:2}/access-audit-$DATE.tar.gz"


###############################################################################
# PREPARE TEMPORARY DIRECTORY
###############################################################################

TMP_DIR=$(mktemp -d "/tmp/access-audit-machine.XXXXXX") ||
    error "cannot create temporary directory"

trap 'rm -rf "$TMP_DIR"' EXIT


###############################################################################
# COLLECT JSON FILES
###############################################################################

JSON_FILES=()


###############################################################################
# 1. JSON FILES FROM /tmp
###############################################################################

while IFS= read -r -d '' JSON_FILE
do
    JSON_FILES+=("$JSON_FILE")

done < <(
    find "$AUDIT_OUTPUT_DIR" \
        -mindepth 2 \
        -maxdepth 3 \
        -type f \
        -name "access-audit-$DATE.json" \
        -not -path "$MACHINE_OUTPUT_DIR/*" \
        -print0 |
    sort -z
)


###############################################################################
# 2. IF NONE FOUND, USE HISTORICAL TAR
###############################################################################

if [ "${#JSON_FILES[@]}" -eq 0 ]
then

    if [ ! -f "$TAR_FILE" ]
    then
        error "no audit JSON files found for date $DATE and historical TAR does not exist: $TAR_FILE"
    fi

    echo "Using historical TAR:"
    echo "  $TAR_FILE"

    TAR_TMP_DIR="$TMP_DIR/json"

    mkdir -p "$TAR_TMP_DIR" ||
        error "cannot create TAR extraction directory"

    tar -xzf "$TAR_FILE" -C "$TAR_TMP_DIR" ||
        error "cannot extract historical TAR: $TAR_FILE"

    while IFS= read -r -d '' JSON_FILE
    do
        JSON_FILES+=("$JSON_FILE")

    done < <(
        find "$TAR_TMP_DIR" \
            -type f \
            -name "access-audit-$DATE.json" \
            -print0 |
        sort -z
    )

fi


###############################################################################
# CHECK INPUT
###############################################################################

if [ "${#JSON_FILES[@]}" -eq 0 ]
then
    error "no audit JSON files found for date: $DATE"
fi


###############################################################################
# PREPARE OUTPUT
###############################################################################

mkdir -p "$MACHINE_OUTPUT_DIR" ||
    error "cannot create output directory: $MACHINE_OUTPUT_DIR"

TMP_OUTPUT=$(mktemp "$MACHINE_OUTPUT_DIR/.${DATE}.XXXXXX.json") ||
    error "cannot create temporary output file"


###############################################################################
# BUILD MACHINE JSON
###############################################################################

"$AWK" \
    -v MACHINE="$MACHINE" \
    -v DATE="$DATE" \
    -v SOURCE="machine-collector" \
    -f "$SCRIPT_DIR/modules/machine-collector.awk" \
    "${JSON_FILES[@]}" \
    > "$TMP_OUTPUT"


###############################################################################
# VALIDATE JSON
###############################################################################

if command -v jq >/dev/null 2>&1
then

    if ! jq empty "$TMP_OUTPUT" >/dev/null 2>&1
    then
        rm -f "$TMP_OUTPUT"
        error "generated JSON is invalid"
    fi

fi


###############################################################################
# INSTALL OUTPUT
###############################################################################

mv "$TMP_OUTPUT" "$MACHINE_OUTPUT_FILE" ||
    error "cannot create output file: $MACHINE_OUTPUT_FILE"


###############################################################################
# SUMMARY
###############################################################################

echo ""
echo "======================================================================="
echo " Machine collector"
echo "======================================================================="
echo "Machine:          $MACHINE"
echo "Date:             $DATE"
echo "JSON files:       ${#JSON_FILES[@]}"
echo "Output:           $MACHINE_OUTPUT_FILE"
echo "======================================================================="
echo ""
