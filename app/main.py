from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .ai_analyzer import AIAnalyzerError, MAX_AI_LINES, ai_status, analyze_logs_with_ai
from .analyzer import analyze_entries
from .log_reader import (
    LogAccessError,
    LogReader,
    MAX_ANALYZE_LIMIT,
    MAX_API_LIMIT,
    public_entry,
)
from .rules_engine import RuleSet


BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
LOG_ROOT = os.getenv("LOG_ROOT", "/logs")
RULES_FILE = os.getenv("RULES_FILE", str(BASE_DIR / "rules.yaml"))
SUMMARY_SCAN_LINES = int(os.getenv("SUMMARY_SCAN_LINES", "20000"))

rules = RuleSet.load(RULES_FILE)
reader = LogReader(LOG_ROOT, rules)

app = FastAPI(
    title="Syslog Analyzer",
    description="Dockerized syslog-ng log analyzer with Chinese translations and troubleshooting suggestions.",
    version="0.1.0",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "log_root": str(reader.root),
        "log_root_exists": reader.root.exists(),
        "rules_file": str(RULES_FILE),
        "rules_count": len(rules.rules),
        "ai": ai_status(),
    }


@app.get("/api/files")
def api_files() -> dict[str, object]:
    files = reader.list_files()
    devices = sorted({str(item["device"]) for item in files if item.get("device")})
    return {
        "root": str(reader.root),
        "count": len(files),
        "devices": devices,
        "files": files,
    }


@app.get("/api/logs")
def api_logs(
    file: str | None = Query(default=None, description="Relative log path under /logs, or omitted for all files"),
    limit: int = Query(default=500, ge=1, le=MAX_API_LIMIT),
    keyword: str | None = Query(default=None),
    device: str | None = Query(default=None),
    severity: str | None = Query(default=None, pattern="^(critical|error|warning|info)?$"),
) -> dict[str, object]:
    try:
        entries = reader.get_entries(
            file=file,
            limit=limit,
            keyword=keyword,
            device=device,
            severity=severity,
        )
    except LogAccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "count": len(entries),
        "entries": [public_entry(entry) for entry in entries],
    }


@app.get("/api/analyze")
def api_analyze(
    file: str | None = Query(default=None, description="Relative log path under /logs, or omitted for all files"),
    limit: int = Query(default=2000, ge=1, le=MAX_ANALYZE_LIMIT),
    keyword: str | None = Query(default=None),
    device: str | None = Query(default=None),
) -> dict[str, object]:
    try:
        entries = reader.get_entries(
            file=file,
            limit=limit,
            keyword=keyword,
            device=device,
            scan_multiplier=1,
        )
    except LogAccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    problems = analyze_entries(entries)
    return {
        "count": len(problems),
        "scanned_logs": len(entries),
        "problems": problems,
    }


@app.get("/api/ai-analyze")
def api_ai_analyze(
    file: str | None = Query(default=None, description="Relative log path under /logs, or omitted for all files"),
    limit: int = Query(default=500, ge=1, le=MAX_AI_LINES),
    keyword: str | None = Query(default=None),
    device: str | None = Query(default=None),
    severity: str | None = Query(default=None, pattern="^(critical|error|warning|info)?$"),
) -> dict[str, object]:
    try:
        entries = reader.get_entries(
            file=file,
            limit=limit,
            keyword=keyword,
            device=device,
            severity=severity,
            scan_multiplier=1,
        )
        result = analyze_logs_with_ai(entries)
    except LogAccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except AIAnalyzerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return result


@app.get("/api/summary")
def api_summary() -> dict[str, object]:
    try:
        entries = reader.get_entries(limit=SUMMARY_SCAN_LINES, scan_multiplier=1)
    except LogAccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    today = datetime.now().date()
    today_entries = [
        entry for entry in entries
        if entry.get("timestamp_dt") and entry["timestamp_dt"].date() == today
    ]
    count_base = today_entries if today_entries else entries
    alert_count = sum(1 for entry in count_base if entry.get("severity") in {"critical", "error", "warning"})
    problems = analyze_entries(entries)
    latest_serious = problems[0] if problems else None

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "today_log_count": len(today_entries),
        "scanned_log_count": len(entries),
        "alert_count": alert_count,
        "problem_count": len(problems),
        "latest_serious_problem": latest_serious,
        "files_count": len(reader.list_files()),
        "rules_count": len(rules.rules),
        "note": "today_log_count uses parsed timestamps; scanned_log_count is a bounded recent scan.",
    }


@app.get("/api/rules")
def api_rules() -> dict[str, object]:
    return rules.to_public_dict()
