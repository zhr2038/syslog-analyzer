#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="${LOG_DIR:-/volume1/docker/syslog/log}"
ARCHIVE_DIR="${ARCHIVE_DIR:-/volume1/docker/syslog/archive}"
RETENTION_DAYS="${RETENTION_DAYS:-45}"
COMPRESS_AFTER_DAYS="${COMPRESS_AFTER_DAYS:-2}"
ROTATE_ACTIVE_MAX_MB="${ROTATE_ACTIVE_MAX_MB:-200}"
SYSLOG_CONTAINER="${SYSLOG_CONTAINER:-syslog-ng}"
LOCK_FILE="${LOCK_FILE:-/tmp/syslog-retention.lock}"
DRY_RUN="${DRY_RUN:-false}"

log() {
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

run() {
  if [ "$DRY_RUN" = "true" ]; then
    log "DRY-RUN: $*"
  else
    "$@"
  fi
}

require_dir() {
  if [ ! -d "$1" ]; then
    log "missing directory: $1"
    exit 1
  fi
}

relative_path() {
  local file="$1"
  printf '%s' "${file#"$LOG_DIR"/}"
}

archive_path_for() {
  local file="$1"
  local relative
  relative="$(relative_path "$file")"
  printf '%s/%s.gz' "$ARCHIVE_DIR" "$relative"
}

compress_to_archive() {
  local file="$1"
  [ -f "$file" ] || return 0
  case "$file" in
    *.gz) return 0 ;;
  esac

  local target tmp target_dir
  target="$(archive_path_for "$file")"
  target_dir="$(dirname "$target")"
  tmp="${target}.tmp"

  if [ "$DRY_RUN" = "true" ]; then
    log "DRY-RUN: gzip archive $file -> $target"
    return 0
  fi

  mkdir -p "$target_dir"
  gzip -c "$file" > "$tmp"
  mv "$tmp" "$target"
  rm -f "$file"
  log "archived $file -> $target"
}

reload_syslog_ng() {
  if [ "$DRY_RUN" = "true" ]; then
    log "DRY-RUN: reload $SYSLOG_CONTAINER"
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1; then
    log "docker not found; skip syslog-ng reload"
    return 1
  fi

  if docker exec "$SYSLOG_CONTAINER" sh -c 'if [ -s /config/syslog-ng.pid ]; then kill -HUP "$(cat /config/syslog-ng.pid)"; else kill -HUP "$(pidof syslog-ng)"; fi' >/dev/null 2>&1; then
    log "reloaded $SYSLOG_CONTAINER"
    return 0
  fi

  log "reload failed; restarting $SYSLOG_CONTAINER"
  docker restart "$SYSLOG_CONTAINER" >/dev/null
}

rotate_active_file_if_needed() {
  local file="$1"
  [ -f "$file" ] || return 0

  local max_bytes size rotated mode owner_group
  max_bytes=$((ROTATE_ACTIVE_MAX_MB * 1024 * 1024))
  size="$(stat -c '%s' "$file")"
  if [ "$size" -lt "$max_bytes" ]; then
    return 1
  fi

  rotated="${file}.$(date '+%Y%m%d-%H%M%S')"
  mode="$(stat -c '%a' "$file")"
  owner_group="$(stat -c '%u:%g' "$file")"

  if [ "$DRY_RUN" = "true" ]; then
    log "DRY-RUN: rotate $file -> $rotated"
    return 0
  fi

  mv "$file" "$rotated"
  : > "$file"
  chown "$owner_group" "$file" || true
  chmod "$mode" "$file" || true
  log "rotated $file -> $rotated"
  printf '%s\n' "$rotated"
}

main() {
  require_dir "$LOG_DIR"
  mkdir -p "$ARCHIVE_DIR"

  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    log "another retention job is running"
    exit 0
  fi

  log "retention start log_dir=$LOG_DIR archive_dir=$ARCHIVE_DIR"

  local rotated_files=()
  local rotated
  for active in "$LOG_DIR/messages" "$LOG_DIR/messages-kv.log"; do
    rotated="$(rotate_active_file_if_needed "$active" || true)"
    if [ -n "$rotated" ] && [ "$DRY_RUN" != "true" ]; then
      rotated_files+=("$rotated")
    fi
  done

  if [ "${#rotated_files[@]}" -gt 0 ]; then
    reload_syslog_ng || true
    sleep 2
    for file in "${rotated_files[@]}"; do
      compress_to_archive "$file"
    done
  fi

  if [ -d "$LOG_DIR/remote" ]; then
    find "$LOG_DIR/remote" -type f -name '*.log' -mtime +"$COMPRESS_AFTER_DAYS" -print0 |
      while IFS= read -r -d '' file; do
        compress_to_archive "$file"
      done
  fi

  find "$LOG_DIR" -maxdepth 1 -type f \( -name 'messages.*' -o -name 'messages-kv.log.*' \) -mtime +"$COMPRESS_AFTER_DAYS" -print0 |
    while IFS= read -r -d '' file; do
      compress_to_archive "$file"
    done

  find "$ARCHIVE_DIR" -type f -name '*.gz' -mtime +"$RETENTION_DAYS" -print -delete
  find "$LOG_DIR" "$ARCHIVE_DIR" -mindepth 1 -type d -empty -print -delete 2>/dev/null || true

  log "retention complete"
}

main "$@"
