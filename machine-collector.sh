#!/bin/bash

###############################################################################
#
# Access Audit - Machine Collector
#
###############################################################################

PROG=$(basename "$0")
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

MACHINE=$(uname -n)
MODULES="$SCRIPT_DIR/modules"

AUDIT_OUTPUT_DIR="/tmp/access-audit"
MACHINE_OUTPUT_DIR="$AUDIT_OUTPUT_DIR/machine"

BACKUP_LOG_BASE="/web/log/apache2"

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

MACHINE_OUTPUT_FILE="$MACHINE_OUTPUT_DIR/$DATE.json"

TAR_FILE="$BACKUP_LOG_BASE/$MACHINE/${DATE:0:4}/${DATE:5:2}/access-audit-$DATE.tar.gz"


###############################################################################
# PREPARE TEMPORARY DIRECTORY
###############################################################################

TMP_DIR=$(mktemp -d "/tmp/access-audit-machine.XXXXXX") ||
    error "cannot create temporary directory"

trap 'rm -rf "$TMP_DIR"' EXIT


###############################################################################
# COLLECT INPUT FILES
###############################################################################

JSON_FILES=()
AGG_FILES=()
UNIQ_FILES=()

###############################################################################
# 1. JSON + AGG + UNIQ FILES FROM /tmp
###############################################################################

while IFS= read -r -d '' FILE
do

    case "$FILE" in

        *.json)
            JSON_FILES+=("$FILE")
            ;;

        *.agg)
            AGG_FILES+=("$FILE")
            ;;

	*.uniq.gz)
	    UNIQ_FILES+=("$FILE")
            ;;

    esac

done < <(
    find "$AUDIT_OUTPUT_DIR" \
        -mindepth 3 \
        -maxdepth 3 \
        -type f \
        \( \
            -name "access-audit-$DATE.json" \
            -o \
            -name "access-audit-$DATE.agg" \
            -o \
            -name "access-audit-$DATE.uniq.gz" \
        \) \
        -not -path "$MACHINE_OUTPUT_DIR/*" \
        -print0 |
    sort -z
)


###############################################################################
# 2. CHECK WHETHER INPUT FILES ARE COMPLETE
#
# Compare the files actually present with the files available in the
# historical TAR. Counts alone are not sufficient: one JSON and one AGG
# can be missing while both counts remain equal.
###############################################################################

if [ ! -f "$TAR_FILE" ]
then
    error "historical TAR does not exist: $TAR_FILE"
fi

TAR_TMP_DIR="$TMP_DIR/tar"

mkdir -p "$TAR_TMP_DIR" ||
    error "cannot create TAR extraction directory"

tar -xzf "$TAR_FILE" -C "$TAR_TMP_DIR" ||
    error "cannot extract historical TAR: $TAR_FILE"


###############################################################################
# BUILD LIST OF EXISTING FILES
###############################################################################

declare -A EXISTING_JSON
declare -A EXISTING_AGG
declare -A EXISTING_UNIQ

for FILE in "${JSON_FILES[@]}"
do
    RELATIVE="${FILE#$AUDIT_OUTPUT_DIR/}"
    EXISTING_JSON["$RELATIVE"]=1
done

for FILE in "${AGG_FILES[@]}"
do
    RELATIVE="${FILE#$AUDIT_OUTPUT_DIR/}"
    EXISTING_AGG["$RELATIVE"]=1
done


for FILE in "${UNIQ_FILES[@]}"
do
    RELATIVE="${FILE#$AUDIT_OUTPUT_DIR/}"
    EXISTING_UNIQ["$RELATIVE"]=1
done


###############################################################################
# RECOVER MISSING FILES FROM TAR
###############################################################################


echo "DEBUG TAR_TMP_DIR=[$TAR_TMP_DIR]"
echo "DEBUG EXISTING UNIQ:"
for KEY in "${!EXISTING_UNIQ[@]}"
do
    echo "  [$KEY]"
done

echo "DEBUG UNIQ FILES IN TAR:"
find "$TAR_TMP_DIR" \
    -type f \
    -name "access-audit-$DATE.uniq.gz" \
    -print


while IFS= read -r -d '' FILE
do
    RELATIVE="${FILE#$TAR_TMP_DIR/}"
    RELATIVE="${RELATIVE#./}"

	echo "DEBUG TAR FILE=[$FILE]"
	echo "DEBUG RELATIVE=[$RELATIVE]"
	echo "DEBUG EXISTING_UNIQ=[$(echo "${EXISTING_UNIQ[$RELATIVE]}")]"

    case "$FILE" in

        *.json)
            if [ -z "${EXISTING_JSON[$RELATIVE]}" ]
            then
                JSON_FILES+=("$FILE")
                echo "  Recovered JSON: $RELATIVE"
            fi
            ;;

        *.agg)
            if [ -z "${EXISTING_AGG[$RELATIVE]}" ]
            then
                AGG_FILES+=("$FILE")
                echo "  Recovered AGG:  $RELATIVE"
            fi
            ;;

        *.uniq.gz)
            if [ -z "${EXISTING_UNIQ[$RELATIVE]}" ]
            then
                UNIQ_FILES+=("$FILE")
                echo "  Recovered UNIQ: $RELATIVE"
            fi
            ;;

    esac

done < <(
    find "$TAR_TMP_DIR" \
        -type f \
        \( \
            -name "access-audit-$DATE.json" \
            -o \
            -name "access-audit-$DATE.agg" \
            -o \
            -name "access-audit-$DATE.uniq.gz" \
        \) \
        -print0 |
    sort -z
)



mapfile -t JSON_FILES < <(printf '%s\n' "${JSON_FILES[@]}" | sort)
mapfile -t AGG_FILES < <(printf '%s\n' "${AGG_FILES[@]}" | sort)
mapfile -t UNIQ_FILES < <(printf '%s\n' "${UNIQ_FILES[@]}" | sort)

###############################################################################
# 3. CHECK INPUT
###############################################################################
if [ "${#JSON_FILES[@]}" -ne "${#AGG_FILES[@]}" ] ||
   [ "${#JSON_FILES[@]}" -ne "${#UNIQ_FILES[@]}" ]
then
    error "JSON/AGG/UNIQ files still incomplete after TAR recovery for date: $DATE (JSON=${#JSON_FILES[@]}, AGG=${#AGG_FILES[@]}, UNIQ=${#UNIQ_FILES[@]})"
fi




###############################################################################
# PREPARE OUTPUT
###############################################################################

mkdir -p "$MACHINE_OUTPUT_DIR" ||
    error "cannot create output directory: $MACHINE_OUTPUT_DIR"

TMP_OUTPUT=$(mktemp "$MACHINE_OUTPUT_DIR/.${DATE}.XXXXXX.json") ||
    error "cannot create temporary output file"


###############################################################################
# BUILD INPUT FILE LIST
###############################################################################

INPUT_FILES=()

INPUT_FILES+=("${AGG_FILES[@]}")
INPUT_FILES+=("${JSON_FILES[@]}")


###############################################################################
# BUILD MACHINE JSON
###############################################################################

"$AWK" \
    -v MACHINE="$MACHINE" \
    -v DATE="$DATE" \
    -v SOURCE="machine-collector" \
    -v UNIQ_FILES="$(printf '%s\n' "${UNIQ_FILES[@]}")" \
    -f "$MODULES/globals.awk" \
    -f "$MODULES/utils.awk" \
    -f "$MODULES/machine-collector.awk" \
    "${INPUT_FILES[@]}" \
    > "$TMP_OUTPUT"

AWK_STATUS=$?


###############################################################################
# CHECK AWK RESULT
###############################################################################

if [ "$AWK_STATUS" -ne 0 ]
then
    rm -f "$TMP_OUTPUT"
    error "machine collector failed"
fi


###############################################################################
# MOVE OUTPUT INTO PLACE
###############################################################################

mv "$TMP_OUTPUT" "$MACHINE_OUTPUT_FILE" ||
    error "cannot install machine output: $MACHINE_OUTPUT_FILE"


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
echo "AGG files:        ${#AGG_FILES[@]}"
echo "UNIQ files:       ${#UNIQ_FILES[@]}"
echo "Input files:      ${#INPUT_FILES[@]}"
echo "Output:           $MACHINE_OUTPUT_FILE"
echo "======================================================================="
