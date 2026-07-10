#!/bin/sh

# Run this script on an ASUSWRT-Merlin router after uploading both files to /tmp.

set -u

SOURCE_FILE="${1:-/tmp/router-crash-collector.sh}"
TARGET_FILE="/jffs/scripts/router-crash-collector.sh"
SERVICES_START="/jffs/scripts/services-start"
SERVICES_STOP="/jffs/scripts/services-stop"
MARKER="syslog-analyzer router crash collector"

if [ ! -f "$SOURCE_FILE" ]; then
    printf 'Collector source not found: %s\n' "$SOURCE_FILE" >&2
    exit 1
fi

mkdir -p /jffs/scripts
cp "$SOURCE_FILE" "$TARGET_FILE"
chmod 0755 "$TARGET_FILE"

ensure_hook_file() {
    hook_file="$1"
    if [ ! -f "$hook_file" ]; then
        printf '#!/bin/sh\n' > "$hook_file"
        chmod 0755 "$hook_file"
    fi
}

ensure_hook_file "$SERVICES_START"
ensure_hook_file "$SERVICES_STOP"

if ! grep -Fq "$MARKER" "$SERVICES_START"; then
    cp "$SERVICES_START" "$SERVICES_START.syslog-analyzer.bak"
    {
        printf '\n# %s\n' "$MARKER"
        printf '%s start\n' "$TARGET_FILE"
    } >> "$SERVICES_START"
fi

if ! grep -Fq "$MARKER" "$SERVICES_STOP"; then
    cp "$SERVICES_STOP" "$SERVICES_STOP.syslog-analyzer.bak"
    {
        printf '\n# %s\n' "$MARKER"
        printf '%s shutdown service-stop\n' "$TARGET_FILE"
    } >> "$SERVICES_STOP"
fi

chmod 0755 "$SERVICES_START" "$SERVICES_STOP"
"$TARGET_FILE" start
"$TARGET_FILE" status

