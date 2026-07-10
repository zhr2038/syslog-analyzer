from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .nas_log_center import NasLogCenter, is_virtual_path
from .rules_engine import Rule, RuleSet, highest_severity


MAX_API_LIMIT = 5_000
MAX_ANALYZE_LIMIT = 20_000
MAX_SCAN_LINES = 50_000
DEFAULT_COMPACT_MAX_GAP_SECONDS = int(os.getenv("LOG_COMPACT_MAX_GAP_SECONDS", "120"))
FALLBACK_CATEGORIES = {"general_event", "generic_error", "generic_warning"}
SPECIFIC_NAS_FILE_CATEGORIES = {"nas_file_write", "nas_file_access"}
SPECIFIC_NAS_LOGIN_CATEGORIES = {
    "nas_ssh_login_success",
    "nas_web_login_success",
    "nas_web_login_failed",
}
GENERIC_NAS_CATEGORIES_TO_SUPPRESS = {
    "nas_operation",
    "nas_login_success",
    "nas_login_failed",
}
DEFAULT_AUDIT_PATH_EXCLUDES = (
    "/volume1/docker/syslog",
    "/volume1/docker/syslog-analysis",
    "/volume1/docker/syslog-analyzer",
)

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

ISO_TS_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[,.]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
RFC3164_RE = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[^\s]+)?"
)
KV_DEVICE_RE = re.compile(
    r'\b(?:host|hostname|device|source|src_host)=("(?P<quoted>[^"]+)"|(?P<plain>[^\s]+))',
    re.IGNORECASE,
)
SYSLOG_HOST_AFTER_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[,.]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+"
    r"(?P<host>[^\s]+)"
)
INTERFACE_RE = re.compile(
    r"\b(?P<iface>"
    r"(?:eth|enp|ens|wan|lan|ppp|pppoe|vlan|br|bond|wlan|wifi)[\w./:-]*"
    r"|ge-\d+/\d+/\d+|xe-\d+/\d+/\d+|te-\d+/\d+/\d+"
    r"|gigabitethernet[\w/.-]+|fastethernet[\w/.-]+"
    r"|port\s*\d+|interface\s+[\w/.-]+"
    r")\b",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_RE = re.compile(r"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", re.IGNORECASE)
LONG_HEX_RE = re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE)
NUMBER_RE = re.compile(r"\b\d+\b")
PATH_RE = re.compile(r"(?P<path>/(?:[^\s|'\"<>]+/?)+)")
OPERATOR_RE = re.compile(r"\boperator=([^\s]+)", re.IGNORECASE)
PIPE_CONTENT_RE = re.compile(r"\bcontent=([^|\s]+)\|(?:\d{1,3}\.){3}\d{1,3}\|([^|\s]+)", re.IGNORECASE)
NAS_ACTION_PATTERNS = (
    ("create_file", "create"),
    ("create file", "create"),
    ("write file", "write"),
    ("read file", "read"),
    ("pwrite", "write"),
    ("pread", "read"),
    ("unlink", "delete"),
    ("delete", "delete"),
    ("rename", "rename"),
    ("mkdir", "mkdir"),
    ("rmdir", "rmdir"),
    ("open", "open"),
    ("connect", "connect"),
)
SYSLOG_RELATED_AUDIT_PATHS = tuple(
    item.strip().lower()
    for item in os.getenv("AUDIT_PATH_EXCLUDES", ",".join(DEFAULT_AUDIT_PATH_EXCLUDES)).split(",")
    if item.strip()
)
NAS_DEVICE_HINTS = {
    item.strip().lower()
    for item in os.getenv(
        "NAS_DEVICE_HINTS",
        f"NAS,HR-Cloud,UGREEN,{os.getenv('NAS_LOG_CENTER_DEVICE', '')}",
    ).split(",")
    if item.strip()
}
NAS_CONTEXT_RE = re.compile(
    r"\b(ugreen_syslog|ugos|ug_login|log_server_record|transfer_log|smbd_audit|"
    r"storage_serv|syncbackup_serv|filemgr_serv|conf_tool)\b",
    re.IGNORECASE,
)

class LogAccessError(ValueError):
    pass


class LogReader:
    def __init__(
        self,
        root: str | Path,
        rules: RuleSet,
        nas_log_center: NasLogCenter | None = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.rules = rules
        self.nas_log_center = nas_log_center

    def list_files(self) -> list[dict[str, object]]:
        if not self.root.exists():
            return []

        files: list[dict[str, object]] = []
        for path in self._iter_log_files():
            try:
                stat = path.stat()
            except OSError:
                continue
            rel = self._relative_path(path)
            files.append(
                {
                    "path": rel,
                    "name": path.name,
                    "device": device_from_path(rel) or "local",
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                    "kind": "remote" if rel.startswith("remote/") else "local",
                }
            )
        if self.nas_log_center:
            files.extend(self.nas_log_center.list_files())
        return sorted(files, key=lambda item: str(item["path"]).lower())

    def get_entries(
        self,
        file: str | None = None,
        limit: int = 500,
        keyword: str | None = None,
        device: str | None = None,
        severity: str | None = None,
        scan_multiplier: int = 10,
    ) -> list[dict[str, object]]:
        safe_limit = max(1, min(limit, MAX_SCAN_LINES))
        if file and file != "all":
            paths = [] if is_virtual_path(file) else [self.safe_path(file)]
            virtual_sources = [file] if is_virtual_path(file) else []
        else:
            paths = list(self._iter_log_files())
            virtual_sources = self.nas_log_center.source_paths() if self.nas_log_center else []
        keyword_norm = keyword.lower().strip() if keyword else None
        device_norm = device.lower().strip() if device else None
        severity_norm = severity.lower().strip() if severity else None
        scan_limit = min(MAX_SCAN_LINES, max(safe_limit, safe_limit * max(1, scan_multiplier)))
        per_path_scan_limit = scan_limit
        source_count = len(paths) + len(virtual_sources)
        if source_count > 1:
            minimum_per_path = 500 if keyword_norm else 100
            per_path_scan_limit = min(
                scan_limit,
                max(minimum_per_path, scan_limit // source_count + minimum_per_path),
            )

        entries: list[dict[str, object]] = []
        order = 0
        for path in paths:
            if path is None:
                continue
            rel_path = self._relative_path(path)
            path_device = device_from_path(rel_path)
            for raw_line in tail_lines(path, per_path_scan_limit):
                if not raw_line.strip():
                    continue
                if keyword_norm and keyword_norm not in raw_line.lower():
                    continue

                entry = parse_log_line(
                    raw_line,
                    rel_path,
                    path_device=path_device,
                    rules=self.rules,
                )
                if is_excluded_syslog_related_entry(entry):
                    continue

                if device_norm and str(entry["device"]).lower() != device_norm:
                    continue
                if severity_norm and str(entry["severity"]).lower() != severity_norm:
                    continue

                entry["_order"] = order
                entries.append(entry)
                order += 1

        if self.nas_log_center:
            for source in virtual_sources:
                for raw_item in self.nas_log_center.read_entries(
                    source,
                    limit=per_path_scan_limit,
                    keyword=keyword_norm,
                ):
                    entry = parse_log_line(
                        str(raw_item["raw"]),
                        str(raw_item["source_file"]),
                        path_device=str(raw_item["path_device"]),
                        rules=self.rules,
                    )
                    if is_excluded_syslog_related_entry(entry):
                        continue

                    if device_norm and str(entry["device"]).lower() != device_norm:
                        continue
                    if severity_norm and str(entry["severity"]).lower() != severity_norm:
                        continue

                    entry["_order"] = raw_item["order"]
                    entries.append(entry)

        entries.sort(key=lambda item: (item.get("_timestamp_sort") or "", item.get("_order", 0)))
        return entries[-safe_limit:]

    def safe_path(self, relative_file: str | None) -> Path | None:
        if not relative_file or relative_file == "all":
            return None
        if is_virtual_path(relative_file):
            return None
        if "\x00" in relative_file:
            raise LogAccessError("invalid file path")

        candidate_rel = Path(relative_file)
        if candidate_rel.is_absolute():
            raise LogAccessError("absolute paths are not allowed")

        candidate = (self.root / candidate_rel).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise LogAccessError("path traversal is not allowed") from exc

        if not candidate.is_file():
            raise LogAccessError("log file does not exist")
        return candidate

    def _iter_log_files(self) -> Iterable[Path]:
        if not self.root.exists():
            return []

        paths: list[Path] = []
        for path in self.root.rglob("*"):
            if not path.is_file():
                continue
            try:
                path.resolve().relative_to(self.root)
            except ValueError:
                continue
            paths.append(path)
        return paths

    def _relative_path(self, path: Path) -> str:
        return path.resolve().relative_to(self.root).as_posix()


def is_excluded_syslog_related_entry(entry: dict[str, object]) -> bool:
    if not SYSLOG_RELATED_AUDIT_PATHS:
        return False
    raw = str(entry.get("raw") or "").lower()
    return any(path in raw for path in SYSLOG_RELATED_AUDIT_PATHS)


def tail_lines(path: Path, limit: int) -> list[str]:
    if limit <= 0:
        return []

    chunk_size = 8192
    data = b""
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        position = handle.tell()
        while position > 0 and data.count(b"\n") <= limit:
            read_size = min(chunk_size, position)
            position -= read_size
            handle.seek(position)
            data = handle.read(read_size) + data

    return [
        line.decode("utf-8", errors="replace")
        for line in data.splitlines()[-limit:]
    ]


def parse_log_line(
    raw_line: str,
    source_file: str,
    path_device: str | None,
    rules: RuleSet,
) -> dict[str, object]:
    timestamp = parse_timestamp(raw_line)
    matched_rules = rules.match(raw_line)
    nas_rules = [rule for rule in matched_rules if rule.category.startswith("nas_")]
    non_nas_rules = [rule for rule in matched_rules if not rule.category.startswith("nas_")]
    if is_nas_context(source_file, path_device, raw_line):
        nas_rules = prefer_specific_nas_rules(nas_rules)
        effective_rules = nas_rules or non_nas_rules
    else:
        effective_rules = non_nas_rules
    categories = unique_preserve_order([rule.category for rule in effective_rules])
    specific_rules = [rule for rule in effective_rules if rule.category not in FALLBACK_CATEGORIES]
    non_general_rules = [rule for rule in effective_rules if rule.category != "general_event"]
    display_rules = specific_rules or non_general_rules or matched_rules
    severity = highest_severity(
        [rule.severity for rule in display_rules],
        "info" if display_rules else infer_severity(raw_line),
    )
    summaries = unique_preserve_order([rule.chinese_summary for rule in display_rules])
    suggestions = unique_preserve_order([rule.suggestion for rule in display_rules])
    device = path_device or parse_device(raw_line) or "local"
    interface = extract_interface(raw_line)

    timestamp_text = timestamp.isoformat(sep=" ", timespec="seconds") if timestamp else ""
    return {
        "time": timestamp_text,
        "timestamp_dt": timestamp,
        "_timestamp_sort": timestamp.isoformat() if timestamp else "",
        "source_file": source_file,
        "device": device,
        "severity": severity,
        "categories": categories,
        "category": categories[0] if categories else "",
        "interface": interface or "",
        "chinese_summary": "；".join(summaries) if summaries else default_summary(raw_line, severity),
        "suggestions": suggestions,
        "suggestion": "；".join(suggestions),
        "matched_rules": [rule.id for rule in matched_rules],
        "raw": raw_line,
    }


def is_nas_context(source_file: str, path_device: str | None, raw_line: str) -> bool:
    if is_virtual_path(source_file) or source_file.startswith("nas-log-center/"):
        return True
    device_norm = (path_device or "").strip().lower()
    if device_norm and device_norm in NAS_DEVICE_HINTS:
        return True
    return bool(NAS_CONTEXT_RE.search(raw_line))


def public_entry(entry: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in entry.items()
        if not key.startswith("_") and key != "timestamp_dt"
    }


def compact_entries(
    entries: list[dict[str, object]],
    max_gap_seconds: int = DEFAULT_COMPACT_MAX_GAP_SECONDS,
) -> list[dict[str, object]]:
    if not entries:
        return []

    compacted: list[dict[str, object]] = []
    current: list[dict[str, object]] = []
    current_signature: tuple[str, ...] | None = None
    safe_gap = max(0, max_gap_seconds)

    for entry in entries:
        signature = compact_signature(entry)
        if current and current_signature == signature and within_compact_gap(current[-1], entry, safe_gap):
            current.append(entry)
            continue

        if current:
            compacted.append(build_compact_entry(current))
        current = [entry]
        current_signature = signature

    if current:
        compacted.append(build_compact_entry(current))
    return compacted


def compact_signature(entry: dict[str, object]) -> tuple[str, ...]:
    category = str(entry.get("category") or "")
    categories = entry.get("categories")
    category_set = set(categories) if isinstance(categories, list) else {category}
    raw = str(entry.get("raw") or "")
    base = (
        str(entry.get("device") or ""),
        str(entry.get("severity") or ""),
        category,
        str(entry.get("interface") or ""),
    )

    if category_set & SPECIFIC_NAS_FILE_CATEGORIES:
        return base + (
            "nas-file",
            extract_operator(raw),
            extract_first_ip(raw),
            extract_nas_action(raw),
            normalize_log_path(raw),
        )

    if category_set & SPECIFIC_NAS_LOGIN_CATEGORIES:
        return base + (
            "nas-login",
            extract_operator(raw),
            extract_first_ip(raw),
            normalize_generic_message(raw),
        )

    return base + ("generic", normalize_generic_message(raw))


def within_compact_gap(previous: dict[str, object], current: dict[str, object], max_gap_seconds: int) -> bool:
    previous_dt = previous.get("timestamp_dt")
    current_dt = current.get("timestamp_dt")
    if isinstance(previous_dt, datetime) and isinstance(current_dt, datetime):
        delta = (current_dt - previous_dt).total_seconds()
        return 0 <= delta <= max_gap_seconds
    return True


def build_compact_entry(group: list[dict[str, object]]) -> dict[str, object]:
    if len(group) == 1:
        entry = dict(group[0])
        entry["repeat_count"] = 1
        entry["grouped"] = False
        return entry

    first = group[0]
    last = group[-1]
    entry = dict(last)
    first_time = str(first.get("time") or "")
    last_time = str(last.get("time") or "")
    entry["time"] = first_time or last_time
    entry["first_time"] = first_time
    entry["last_time"] = last_time
    entry["repeat_count"] = len(group)
    entry["grouped"] = True
    entry["source_files"] = unique_preserve_order([str(item.get("source_file") or "") for item in group])
    entry["raw_samples"] = compact_raw_samples([str(item.get("raw") or "") for item in group])
    entry["suggestions"] = unique_preserve_order(
        [suggestion for item in group for suggestion in item.get("suggestions", [])]
    )
    entry["suggestion"] = "；".join(entry["suggestions"])
    entry["matched_rules"] = unique_preserve_order(
        [rule_id for item in group for rule_id in item.get("matched_rules", [])]
    )
    entry["_timestamp_sort"] = last.get("_timestamp_sort") or first.get("_timestamp_sort") or ""
    entry["_order"] = last.get("_order", 0)
    return entry


def compact_raw_samples(raw_values: list[str]) -> list[str]:
    distinct = unique_preserve_order([item for item in raw_values if item])
    if len(distinct) <= 4:
        return distinct
    return distinct[:2] + distinct[-2:]


def extract_operator(raw: str) -> str:
    match = OPERATOR_RE.search(raw)
    if match:
        return match.group(1).lower()
    pipe_match = PIPE_CONTENT_RE.search(raw)
    if pipe_match:
        return pipe_match.group(1).lower()
    return "-"


def extract_first_ip(raw: str) -> str:
    match = IPV4_RE.search(raw)
    return match.group(0) if match else "-"


def extract_nas_action(raw: str) -> str:
    lowered = raw.lower()
    pipe_match = PIPE_CONTENT_RE.search(raw)
    if pipe_match:
        return normalize_nas_action(pipe_match.group(2).lower())
    for token, action in NAS_ACTION_PATTERNS:
        if token in lowered:
            return action
    return "-"


def normalize_nas_action(action: str) -> str:
    normalized = action.strip().lower().replace("-", "_")
    if normalized in {"pwrite", "write", "write_file"}:
        return "write"
    if normalized in {"pread", "read", "read_file", "open"}:
        return "read"
    if normalized in {"create", "create_file", "mkdir"}:
        return "create"
    if normalized in {"delete", "unlink", "rmdir"}:
        return "delete"
    return normalized or "-"


def normalize_log_path(raw: str) -> str:
    matches = list(PATH_RE.finditer(raw))
    if not matches:
        return "-"
    path = matches[-1].group("path").rstrip(".,;)")
    parts = [part for part in path.split("/") if part]
    normalized = [normalize_path_segment(part, is_last=index == len(parts) - 1) for index, part in enumerate(parts)]
    return "/" + "/".join(normalized)


def normalize_path_segment(segment: str, is_last: bool = False) -> str:
    if is_last and "." in segment:
        return "<file>"
    if re.fullmatch(r"\d{6,}", segment):
        return "<date>"
    if re.fullmatch(r"[0-9a-f]{8,}", segment, re.IGNORECASE):
        return "<id>"
    return re.sub(r"[0-9a-f]{8,}", "<id>", segment, flags=re.IGNORECASE)


def normalize_generic_message(raw: str) -> str:
    lowered = raw.lower()
    lowered = ISO_TS_RE.sub("<ts>", lowered)
    lowered = RFC3164_RE.sub("<ts> ", lowered)
    lowered = re.sub(r"\bid=\d+\b", "id=<n>", lowered)
    lowered = re.sub(r"\blevel=(critical|error|warning|info)\b", "level=<level>", lowered)
    lowered = MAC_RE.sub("<mac>", lowered)
    lowered = LONG_HEX_RE.sub("<hex>", lowered)
    lowered = NUMBER_RE.sub("<n>", lowered)
    lowered = PATH_RE.sub("<path>", lowered)
    lowered = re.sub(r"\s+", " ", lowered)
    return lowered.strip()


def parse_timestamp(line: str) -> datetime | None:
    iso_match = ISO_TS_RE.search(line)
    if iso_match:
        raw = iso_match.group("ts").replace(",", ".")
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
            return parsed.replace(tzinfo=None)
        except ValueError:
            pass

    rfc_match = RFC3164_RE.search(line)
    if rfc_match:
        now = datetime.now()
        month = MONTHS[rfc_match.group("mon")]
        day = int(rfc_match.group("day"))
        hour, minute, second = [int(part) for part in rfc_match.group("time").split(":")]
        try:
            return datetime(now.year, month, day, hour, minute, second)
        except ValueError:
            return None
    return None


def parse_device(line: str) -> str | None:
    kv_match = KV_DEVICE_RE.search(line)
    if kv_match:
        return kv_match.group("quoted") or kv_match.group("plain")

    rfc_match = RFC3164_RE.search(line)
    if rfc_match and rfc_match.group("host"):
        return rfc_match.group("host")

    iso_host = SYSLOG_HOST_AFTER_ISO_RE.search(line)
    if iso_host:
        return iso_host.group("host")
    return None


def device_from_path(relative_path: str) -> str | None:
    parts = Path(relative_path).parts
    if len(parts) >= 3 and parts[0] == "remote":
        return parts[1]
    return None


def extract_interface(line: str) -> str | None:
    match = INTERFACE_RE.search(line)
    if not match:
        return None
    return " ".join(match.group("iface").split())


def infer_severity(line: str) -> str:
    lower = line.lower()
    if any(token in lower for token in ("kernel panic", "critical", "crit", "fatal", "emerg", "alert", "crash")):
        return "critical"
    if any(token in lower for token in ("error", " err ", "failed", "failure", "denied", "down")):
        return "error"
    if any(token in lower for token in ("warning", " warn", "timeout", "flapping", "retry")):
        return "warning"
    return "info"


def default_summary(line: str, severity: str) -> str:
    if severity in {"critical", "error"}:
        return "发现异常日志，但当前规则库没有更具体的中文解释"
    if severity == "warning":
        return "发现告警日志，请结合上下文确认是否影响业务"
    return "普通运行日志"


def prefer_specific_nas_rules(rules: list[Rule]) -> list[Rule]:
    categories = {rule.category for rule in rules}
    if categories & (SPECIFIC_NAS_FILE_CATEGORIES | SPECIFIC_NAS_LOGIN_CATEGORIES):
        return [
            rule
            for rule in rules
            if rule.category not in GENERIC_NAS_CATEGORIES_TO_SUPPRESS
        ]
    return rules


def unique_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            result.append(item)
            seen.add(item)
    return result
