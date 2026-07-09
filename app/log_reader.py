from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .rules_engine import Rule, RuleSet, highest_severity


MAX_API_LIMIT = 5_000
MAX_ANALYZE_LIMIT = 20_000
MAX_SCAN_LINES = 50_000
FALLBACK_CATEGORIES = {"general_event", "generic_error", "generic_warning"}
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
SYSLOG_RELATED_AUDIT_PATHS = tuple(
    item.strip().lower()
    for item in os.getenv("AUDIT_PATH_EXCLUDES", ",".join(DEFAULT_AUDIT_PATH_EXCLUDES)).split(",")
    if item.strip()
)

class LogAccessError(ValueError):
    pass


class LogReader:
    def __init__(self, root: str | Path, rules: RuleSet) -> None:
        self.root = Path(root).resolve()
        self.rules = rules

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
        paths = [self.safe_path(file)] if file and file != "all" else list(self._iter_log_files())
        keyword_norm = keyword.lower().strip() if keyword else None
        device_norm = device.lower().strip() if device else None
        severity_norm = severity.lower().strip() if severity else None
        scan_limit = min(MAX_SCAN_LINES, max(safe_limit, safe_limit * max(1, scan_multiplier)))
        per_path_scan_limit = scan_limit
        if len(paths) > 1:
            minimum_per_path = 500 if keyword_norm else 100
            per_path_scan_limit = min(
                scan_limit,
                max(minimum_per_path, scan_limit // len(paths) + minimum_per_path),
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

        entries.sort(key=lambda item: (item.get("_timestamp_sort") or "", item.get("_order", 0)))
        return entries[-safe_limit:]

    def safe_path(self, relative_file: str | None) -> Path | None:
        if not relative_file or relative_file == "all":
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
    effective_rules = nas_rules or matched_rules
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


def public_entry(entry: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in entry.items()
        if not key.startswith("_") and key != "timestamp_dt"
    }


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


def unique_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            result.append(item)
            seen.add(item)
    return result
