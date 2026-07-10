#!/bin/sh

# Lightweight ASUSWRT-Merlin crash evidence collector.
# It only writes its small state under JFFS and emits evidence through syslog.

TAG="router-crash-collector"
STATE_DIR="/jffs/.syslog-crash-collector"
STATE_FILE="$STATE_DIR/state"
CRASH_SIGNATURE_FILE="$STATE_DIR/last-crash-signature"
CRASH_DEVICE="${CRASH_DEVICE:-/dev/mtd3ro}"
MEMORY_WARN_KB="${MEMORY_WARN_KB:-65536}"
CONNTRACK_WARN_PERCENT="${CONNTRACK_WARN_PERCENT:-85}"
TEMPERATURE_WARN_MILLIC="${TEMPERATURE_WARN_MILLIC:-85000}"
LOAD_WARN="${LOAD_WARN:-4.0}"

log_message() {
    priority="$1"
    shift
    logger -p "$priority" -t "$TAG" "$*"
}

current_boot_id() {
    cat /proc/sys/kernel/random/boot_id 2>/dev/null || printf 'unavailable'
}

firmware_version() {
    firmver="$(nvram get firmver 2>/dev/null)"
    buildno="$(nvram get buildno 2>/dev/null)"
    extendno="$(nvram get extendno 2>/dev/null)"
    printf '%s_%s_%s' "${firmver:-unknown}" "${buildno:-unknown}" "${extendno:-unknown}"
}

max_temperature() {
    max_temp=0
    found=0
    for temp_file in /sys/class/thermal/thermal_zone*/temp; do
        [ -r "$temp_file" ] || continue
        temp_value="$(cat "$temp_file" 2>/dev/null)"
        case "$temp_value" in
            ''|*[!0-9]*) continue ;;
        esac
        found=1
        [ "$temp_value" -gt "$max_temp" ] && max_temp="$temp_value"
    done
    [ "$found" -eq 1 ] && printf '%s' "$max_temp" || printf '0'
}

memory_available_kb() {
    awk '
        /MemAvailable:/ { print $2; found=1; exit }
        /MemFree:/ { free=$2 }
        /Buffers:/ { buffers=$2 }
        /^Cached:/ { cached=$2 }
        END { if (!found) print free + buffers + cached }
    ' /proc/meminfo 2>/dev/null
}

conntrack_value() {
    if [ -r /proc/sys/net/netfilter/nf_conntrack_count ]; then
        cat /proc/sys/net/netfilter/nf_conntrack_count
    elif [ -r /proc/net/nf_conntrack ]; then
        wc -l < /proc/net/nf_conntrack
    else
        printf '0'
    fi
}

sample_resources() {
    uptime_seconds="$(awk '{ print int($1) }' /proc/uptime 2>/dev/null)"
    load1="$(awk '{ print $1 }' /proc/loadavg 2>/dev/null)"
    mem_available_kb="$(memory_available_kb)"
    conntrack_count="$(conntrack_value)"
    conntrack_max="$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
    temperature_millic="$(max_temperature)"

    uptime_seconds="${uptime_seconds:-0}"
    load1="${load1:-0}"
    mem_available_kb="${mem_available_kb:-0}"
    conntrack_count="${conntrack_count:-0}"
    conntrack_max="${conntrack_max:-0}"
    temperature_millic="${temperature_millic:-0}"

    log_message user.info "HEARTBEAT uptime_seconds=$uptime_seconds load1=$load1 mem_available_kb=$mem_available_kb conntrack=$conntrack_count/$conntrack_max temperature_millic=$temperature_millic"

    if [ "$mem_available_kb" -gt 0 ] 2>/dev/null && [ "$mem_available_kb" -lt "$MEMORY_WARN_KB" ]; then
        log_message user.crit "RESOURCE_ALERT type=memory mem_available_kb=$mem_available_kb threshold_kb=$MEMORY_WARN_KB"
    fi

    if [ "$conntrack_max" -gt 0 ] 2>/dev/null; then
        conntrack_percent=$((conntrack_count * 100 / conntrack_max))
        if [ "$conntrack_percent" -ge "$CONNTRACK_WARN_PERCENT" ]; then
            log_message user.crit "RESOURCE_ALERT type=conntrack usage_percent=$conntrack_percent count=$conntrack_count max=$conntrack_max"
        fi
    fi

    if [ "$temperature_millic" -ge "$TEMPERATURE_WARN_MILLIC" ] 2>/dev/null; then
        log_message user.crit "RESOURCE_ALERT type=temperature temperature_millic=$temperature_millic threshold_millic=$TEMPERATURE_WARN_MILLIC"
    fi

    if awk -v value="$load1" -v threshold="$LOAD_WARN" 'BEGIN { exit !(value >= threshold) }'; then
        log_message user.warning "RESOURCE_ALERT type=load load1=$load1 threshold=$LOAD_WARN"
    fi
}

extract_crashlog() {
    [ -r "$CRASH_DEVICE" ] || {
        log_message user.warning "CRASHLOG_UNAVAILABLE device=$CRASH_DEVICE"
        return
    }

    raw_file="/tmp/router-crashlog-raw.$$"
    evidence_file="/tmp/router-crashlog-evidence.$$"
    dd if="$CRASH_DEVICE" bs=4096 count=128 2>/dev/null | strings > "$raw_file"
    grep -Ei \
        'Linux version|Running on kernel|Unable to handle kernel|Internal error: Oops|Kernel panic|Fatal exception|Process .+pid:|CPU:|Hardware name:|pc :|lr :|Call trace:|inet6_sk_rx_dst_set|tcp_v6_syn_recv_sock|tcp_check_req|tcp_v4_rcv|bcm_tcp_v4_recv|chan_thread_handler|kthread|ret_from_fork|Code:|end trace|Out of memory|Killed process|soft lockup|hard lockup|watchdog.*(reset|timeout|lockup)' \
        "$raw_file" > "$evidence_file"

    if ! grep -Eqi 'Kernel panic|Internal error: Oops|Unable to handle kernel|Fatal exception|Out of memory|soft lockup|hard lockup' "$evidence_file"; then
        log_message user.info "CRASHLOG_EMPTY device=$CRASH_DEVICE"
        rm -f "$raw_file" "$evidence_file"
        return
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        signature="$(sha256sum < "$evidence_file" 2>/dev/null | awk '{ print $1 }')"
    elif command -v md5sum >/dev/null 2>&1; then
        signature="$(md5sum < "$evidence_file" 2>/dev/null | awk '{ print $1 }')"
    else
        signature="size-$(wc -c < "$evidence_file" 2>/dev/null)"
    fi
    signature="${signature:-unavailable}"
    previous_signature="$(cat "$CRASH_SIGNATURE_FILE" 2>/dev/null)"
    if [ "$signature" = "$previous_signature" ]; then
        log_message user.info "CRASHLOG_PRESENT signature=$signature already_reported=true"
        rm -f "$raw_file" "$evidence_file"
        return
    fi

    log_message user.crit "CRASHLOG_BEGIN signature=$signature current_firmware=$(firmware_version)"
    while IFS= read -r evidence_line; do
        [ -n "$evidence_line" ] && log_message user.crit "CRASHLOG $evidence_line"
    done < "$evidence_file"
    log_message user.crit "CRASHLOG_END signature=$signature"
    printf '%s\n' "$signature" > "$CRASH_SIGNATURE_FILE"
    sync
    rm -f "$raw_file" "$evidence_file"
}

record_boot() {
    mkdir -p "$STATE_DIR"
    boot_id="$(current_boot_id)"
    previous_state="$(cat "$STATE_FILE" 2>/dev/null)"

    case "$previous_state" in
        "running $boot_id"*)
            log_message user.info "COLLECTOR_ALREADY_RUNNING boot_id=$boot_id"
            sample_resources
            return
            ;;
    esac

    reboot_reason="$(nvram get sys_reboot_reason 2>/dev/null)"
    reset_reason="$(dmesg 2>/dev/null | grep -m1 'Last RESET due to' | tr ' ' '_')"
    log_message user.notice "BOOT_MARKER boot_id=$boot_id firmware=$(firmware_version) nvram_reason=${reboot_reason:-unknown} reset_reason=${reset_reason:-unknown} previous_state=${previous_state:-first_install}"

    case "$previous_state" in
        running\ *)
            log_message user.crit "UNCLEAN_BOOT suspected=true previous_state=$previous_state"
            ;;
        clean\ *)
            log_message user.info "BOOT_CLASSIFICATION clean_shutdown_seen=true previous_state=$previous_state"
            ;;
        *)
            log_message user.info "BOOT_CLASSIFICATION first_observation=true"
            ;;
    esac

    printf 'running %s %s\n' "$boot_id" "$(date +%s 2>/dev/null)" > "$STATE_FILE"
    sync
    extract_crashlog
    sample_resources
}

start_collector() {
    mkdir -p "$STATE_DIR"
    cru d RouterCrashCollector >/dev/null 2>&1
    cru a RouterCrashCollector "*/5 * * * * /jffs/scripts/router-crash-collector.sh sample"
    record_boot
}

record_shutdown() {
    mkdir -p "$STATE_DIR"
    boot_id="$(current_boot_id)"
    reason="${2:-service-stop}"
    log_message user.notice "CLEAN_SHUTDOWN boot_id=$boot_id reason=$reason"
    printf 'clean %s %s %s\n' "$boot_id" "$(date +%s 2>/dev/null)" "$reason" > "$STATE_FILE"
    sync
    cru d RouterCrashCollector >/dev/null 2>&1
}

case "${1:-status}" in
    start|boot)
        start_collector
        ;;
    sample)
        sample_resources
        ;;
    shutdown|stop)
        record_shutdown "$@"
        ;;
    crashlog)
        mkdir -p "$STATE_DIR"
        extract_crashlog
        ;;
    status)
        printf 'state=%s\n' "$(cat "$STATE_FILE" 2>/dev/null)"
        printf 'last_crash_signature=%s\n' "$(cat "$CRASH_SIGNATURE_FILE" 2>/dev/null)"
        cru l 2>/dev/null | grep RouterCrashCollector
        ;;
    *)
        printf 'Usage: %s {start|sample|shutdown|crashlog|status}\n' "$0" >&2
        exit 2
        ;;
esac
