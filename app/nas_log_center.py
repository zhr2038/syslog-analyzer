from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable


VIRTUAL_PREFIX = "nas-log-center"


@dataclass(frozen=True)
class NasLogCenterSource:
    virtual_path: str
    db_name: str
    title: str
    program: str


SOURCES = {
    f"{VIRTUAL_PREFIX}/log_server_record.db": NasLogCenterSource(
        virtual_path=f"{VIRTUAL_PREFIX}/log_server_record.db",
        db_name="log_server_record.db",
        title="NAS 日志中心 - 系统/登录/操作",
        program="ugreen_log_center",
    ),
    f"{VIRTUAL_PREFIX}/transfer_log.db": NasLogCenterSource(
        virtual_path=f"{VIRTUAL_PREFIX}/transfer_log.db",
        db_name="transfer_log.db",
        title="NAS 日志中心 - 文件传输/写入",
        program="ugreen_transfer_log",
    ),
}


def is_virtual_path(path: str | None) -> bool:
    return bool(path and path in SOURCES)


class NasLogCenter:
    def __init__(self, root: str | Path | None, device: str = "NAS") -> None:
        self.root = Path(root).resolve() if root else None
        self.device = device or "NAS"

    def exists(self) -> bool:
        return bool(self.root and self.root.exists())

    def list_files(self) -> list[dict[str, object]]:
        if not self.exists():
            return []

        files: list[dict[str, object]] = []
        for source in SOURCES.values():
            db_path = self._db_path(source)
            if not db_path.is_file():
                continue
            try:
                stat = db_path.stat()
                count = self._count_rows(db_path)
            except OSError:
                continue
            files.append(
                {
                    "path": source.virtual_path,
                    "name": source.title,
                    "device": self.device,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                    "kind": "nas-log-center",
                    "records": count,
                }
            )
        return files

    def source_paths(self) -> list[str]:
        return [item["path"] for item in self.list_files()]

    def read_entries(
        self,
        source_path: str,
        limit: int,
        keyword: str | None = None,
    ) -> list[dict[str, object]]:
        source = SOURCES.get(source_path)
        if not source or not self.exists():
            return []

        db_path = self._db_path(source)
        if not db_path.is_file():
            return []

        rows = self._query_rows(db_path, limit=limit, keyword=keyword)
        return [self._entry_from_row(source, row) for row in rows]

    def _db_path(self, source: NasLogCenterSource) -> Path:
        if not self.root:
            return Path("/")
        return self.root / source.db_name

    def _connect(self, db_path: Path) -> sqlite3.Connection:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def _count_rows(self, db_path: Path) -> int:
        conn = None
        try:
            conn = self._connect(db_path)
            row = conn.execute("select count(*) as count from log_record").fetchone()
            return int(row["count"]) if row else 0
        except sqlite3.Error:
            return 0
        finally:
            if conn is not None:
                conn.close()

    def _query_rows(self, db_path: Path, limit: int, keyword: str | None) -> list[sqlite3.Row]:
        safe_limit = max(1, min(limit, 50_000))
        where = ""
        params: list[object] = []
        if keyword:
            like = f"%{keyword}%"
            where = (
                "where content like ? or operator like ? or module like ? "
                "or device_id like ? or log_id like ?"
            )
            params.extend([like, like, like, like, like])

        sql = (
            "select id, log_id, level, module, operator, content, device_id, create_time "
            "from log_record "
            f"{where} "
            "order by id desc limit ?"
        )
        params.append(safe_limit)
        conn = None
        try:
            conn = self._connect(db_path)
            rows = list(conn.execute(sql, params))
        except sqlite3.Error:
            return []
        finally:
            if conn is not None:
                conn.close()

        rows.reverse()
        return rows

    def _entry_from_row(self, source: NasLogCenterSource, row: sqlite3.Row) -> dict[str, object]:
        create_time = row["create_time"]
        try:
            timestamp = datetime.fromtimestamp(int(create_time))
        except (TypeError, ValueError, OSError):
            timestamp = None

        level = level_name(row["level"])
        module = str(row["module"] or "unknown")
        operator = str(row["operator"] or "")
        content = str(row["content"] or "")
        device_id = str(row["device_id"] or "")
        time_text = timestamp.isoformat(sep=" ", timespec="seconds") if timestamp else ""
        raw = (
            f"{time_text} {self.device} {source.program}[{module}]: "
            f"id={row['id']} level={level} operator={operator or '-'} "
            f"device_id={device_id or '-'} content={content}"
        )
        return {
            "raw": raw,
            "source_file": source.virtual_path,
            "path_device": self.device,
            "order": int(row["id"] or 0),
        }


def level_name(level: object) -> str:
    try:
        value = int(level)
    except (TypeError, ValueError):
        return "info"
    if value >= 3:
        return "critical"
    if value == 2:
        return "error"
    if value == 1:
        return "warning"
    return "info"
