###############################################################################
#
# Access Audit
#
###############################################################################

PROG=$(basename "$0")
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULES="$SCRIPT_DIR/modules"
MACHINE=$(uname -n)


AWK=$(command -v gawk)

if [ -z "$AWK" ]; then
    echo "ERROR: gawk not found."
    exit 1
fi

VERSION=$(cat "$SCRIPT_DIR/VERSION")


echo ""
echo "======================================================================="
echo "                     Apache access audit $VERSION"
echo "======================================================================="

run_audit()
{
    local LOGFILE="$1"
    local TITLE="$2"
    local DATE="$3"
    local SOURCE="$4"
    local AUDIT_FILE="$5"
    local CONFIGURATION="$6"
    local JSON_FILE="/tmp/prueba.json"

    "$AWK" \
        -v AUDIT_TITLE="$TITLE" \
        -v AUDIT_DATE="$DATE" \
        -v AUDIT_SOURCE="$SOURCE" \
        -v AUDIT_FILE="$AUDIT_FILE" \
	-v AUDIT_CONFIGURATION="$CONFIGURATION" \
	-v JSON_FILE="$JSON_FILE" \
        -f "$MODULES/globals.awk" \
        -f "$MODULES/utils.awk" \
        -f "$MODULES/parser.awk" \
        -f "$MODULES/statistics.awk" \
        -f "$MODULES/security.awk" \
        -f "$MODULES/search.awk" \
        -f "$MODULES/report.awk" \
        -f "$MODULES/rankings.awk" \
        -f "$MODULES/json.awk" \
        -f "$SCRIPT_DIR/access-audit.awk" \
        "$LOGFILE"
}


###############################################################################
# LOG normal
###############################################################################
run_log_audit()
{
    local LOGFILE="$1"
    local TITLE
    local DATE
    local CONFIGURATION
    local AUDIT_FILE

    # Path para mostrar: aseguramos que empieza por /
    AUDIT_FILE="$LOGFILE"

    if [[ "$AUDIT_FILE" != /* ]]
    then
        AUDIT_FILE="/$AUDIT_FILE"
    fi

    # Directorio inmediatamente superior al access.log
    TITLE=$(basename "$(dirname "$LOGFILE")")

    if [ "$TITLE" = "." ]
    then
        TITLE="UNKNOWN"
    fi

    TITLE="${TITLE^^}"

    # Fecha del access.log
    DATE=$(basename "$LOGFILE" |
           sed -E 's/^access-([0-9]{4}-[0-9]{2}-[0-9]{2}).*$/\1/')

    # Configuración obtenida del path
    CONFIGURATION=$(echo "$LOGFILE" |
                    grep -oE '/conf_[^/]+' |
                    head -1 |
                    sed 's|^/||')

    if [ -z "$CONFIGURATION" ]
    then
        CONFIGURATION="UNKNOWN"
    fi

    CONFIGURATION="${CONFIGURATION^^}"

    run_audit \
        "$LOGFILE" \
        "$TITLE" \
        "$DATE" \
        "log" \
        "$AUDIT_FILE" \
        "$CONFIGURATION" \
	"$JSON_FILE"
}

###############################################################################
# LOG comprimido (.gz)
###############################################################################

run_gz_audit()
{
    local GZFILE="$1"
    local TITLE
    local DATE
    local TMPFILE

    TITLE=$(basename "$(dirname "$GZFILE")")
    TITLE="${TITLE^^}"

    DATE=$(basename "$GZFILE" |
           sed -E 's/^access-([0-9]{4}-[0-9]{2}-[0-9]{2}).*\.log\.gz$/\1/')

    TMPFILE=$(mktemp /tmp/access-audit.XXXXXX.log)

    gzip -dc "$GZFILE" > "$TMPFILE" || {
        echo "ERROR: no se ha podido descomprimir $GZFILE" >&2
        rm -f "$TMPFILE"
        return 1
    }

    run_audit "$TMPFILE" "$TITLE" "$DATE" "gz" "$GZFILE"

    rm -f "$TMPFILE"
}


###############################################################################
# TAR.GZ
###############################################################################
run_tar_audit()
{
    local TARFILE="$1"
    local ENTRY
    local TMPFILE
    local TITLE
    local DATE
    local CONFIGURATION
    local AUDIT_FILE

    # Configuración obtenida del nombre del TAR
    CONFIGURATION=$(basename "$TARFILE" |
                    sed -E 's/_access-[0-9]{4}-[0-9]{2}-[0-9]{2}\.tar\.gz$//')

    CONFIGURATION="${CONFIGURATION^^}"

    while IFS= read -r ENTRY
    do
        # Path para mostrar: el contenido del TAR no lleva /
        AUDIT_FILE="/$ENTRY"

        # Directorio inmediatamente superior al access.log
        TITLE=$(basename "$(dirname "$ENTRY")")
        TITLE="${TITLE^^}"

        # Fecha del access.log
        DATE=$(basename "$ENTRY" |
               sed -E 's/^access-([0-9]{4}-[0-9]{2}-[0-9]{2}).*$/\1/')

        # Extraer el access.log a un temporal
        TMPFILE=$(mktemp /tmp/access-audit.XXXXXX.log)

        tar -xOzf "$TARFILE" "$ENTRY" > "$TMPFILE" || {
            echo "ERROR: no se ha podido extraer $ENTRY" >&2
            rm -f "$TMPFILE"
            continue
        }

        run_audit \
            "$TMPFILE" \
            "$TITLE" \
            "$DATE" \
            "tar.gz" \
            "$AUDIT_FILE" \
            "$CONFIGURATION" \
	    "$JSON_FILE"


        rm -f "$TMPFILE"

    done < <(
        tar -ztf "$TARFILE" |
        grep -E 'access-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}:[0-9]{2}\.log$'
    )
}

###############################################################################
# MAIN
###############################################################################

if [ "$#" -ne 1 ]; then
    echo "Uso: $0 <access.log|access.log.gz|access.tar.gz>"
    exit 1
fi

INPUT="$1"

if [ ! -f "$INPUT" ]; then
    echo "ERROR: no existe el fichero: $INPUT" >&2
    exit 1
fi


case "$INPUT" in

    *.tar.gz|*.tgz)
        run_tar_audit "$INPUT"
        ;;

    *.gz)
        run_gz_audit "$INPUT"
        ;;

    *)
        run_log_audit "$INPUT"
        ;;

esac


