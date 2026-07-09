from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


MAX_AI_LINES = 1_000
MAX_AI_CHARS = 40_000
AI_MODE_BALANCED = "balanced"
AI_MODE_RECENT = "recent"

IPV4_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")
MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}\b")
PHONE_RE = re.compile(r"\b1[3-9]\d{9}\b")
ACCOUNT_RE = re.compile(
    r"\b(?P<key>user(?:name)?|account|acct|login|uid|admin|operator)\s*[:=]\s*"
    r"(?P<quote>[\"']?)(?P<value>[^\s,\"';]+)(?P=quote)",
    re.IGNORECASE,
)
USER_PHRASE_RE = re.compile(
    r"\b(?P<prefix>(?:invalid user|failed password for|accepted password for|login user|user)\s+)"
    r"(?P<value>[A-Za-z0-9._@-]{2,64})\b",
    re.IGNORECASE,
)
SERIAL_RE = re.compile(
    r"\b(?P<key>sn|s/n|serial(?:\s+number)?|serialno|serial_number)\s*[:= ]+\s*"
    r"(?P<value>[A-Za-z0-9][A-Za-z0-9._-]{4,})\b",
    re.IGNORECASE,
)
SEVERITY_SCORE = {
    "critical": 400,
    "error": 300,
    "warning": 200,
    "info": 100,
}
IMPORTANT_CATEGORY_SCORE = {
    "kernel_crash": 120,
    "watchdog": 110,
    "reboot": 100,
    "wan_down": 100,
    "pppoe_down": 95,
    "dhcp_failed": 90,
    "dns_failed": 85,
    "link_down": 85,
    "port_flapping": 85,
    "generic_error": 80,
    "generic_warning": 50,
    "auth_failed": 75,
    "nas_login_failed": 70,
    "nas_web_login_failed": 70,
    "nas_storage_alert": 90,
    "nas_transfer_failed": 65,
    "nas_file_write": 10,
    "nas_file_access": 5,
    "nas_web_login_success": 5,
    "nas_ssh_login_success": 20,
}


@dataclass(frozen=True)
class AISelection:
    entries: list[dict[str, object]]
    metadata: dict[str, object]


@dataclass(frozen=True)
class AIConfig:
    enabled: bool
    configured: bool
    model: str
    base_url: str
    timeout_seconds: int


class AIAnalyzerError(RuntimeError):
    pass


def get_ai_config() -> AIConfig:
    enabled = os.getenv("ENABLE_AI", "false").strip().lower() in {"1", "true", "yes", "on"}
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    return AIConfig(
        enabled=enabled,
        configured=bool(api_key),
        model=os.getenv("OPENAI_MODEL", "deepseek-v4-flash").strip() or "deepseek-v4-flash",
        base_url=os.getenv("OPENAI_BASE_URL", "https://api.deepseek.com").strip() or "https://api.deepseek.com",
        timeout_seconds=max(5, int(os.getenv("AI_TIMEOUT_SECONDS", "90"))),
    )


def ai_status() -> dict[str, object]:
    config = get_ai_config()
    return {
        "enabled": config.enabled,
        "configured": config.configured,
        "model": config.model,
        "base_url": public_base_url(config.base_url),
        "max_lines": MAX_AI_LINES,
        "redaction": ["IP", "MAC", "账号", "SN", "手机号"],
    }


def analyze_logs_with_ai(entries: list[dict[str, object]]) -> dict[str, object]:
    config = get_ai_config()
    if not config.enabled:
        raise AIAnalyzerError("AI mode is disabled. Set ENABLE_AI=true to enable it.")
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise AIAnalyzerError("OPENAI_API_KEY is not configured.")
    if not entries:
        raise AIAnalyzerError("No log entries were selected for AI analysis.")

    selected = entries[-MAX_AI_LINES:]
    sanitized_lines = build_sanitized_log_lines(selected)
    prompt_logs = trim_to_char_budget("\n".join(sanitized_lines), MAX_AI_CHARS)
    payload = {
        "model": config.model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "你是一名资深网络设备和 Linux/Syslog 运维专家。"
                    "你只根据用户提供的脱敏日志分析，不要臆造不存在的设备、IP、账号或事实。"
                    "请用中文输出，重点给出问题总结、根因判断、处理建议。"
                ),
            },
            {
                "role": "user",
                "content": (
                    "下面是用户在 Web 页面当前条件下选中的 syslog，已经默认脱敏 IP、MAC、账号、SN、手机号。\n"
                    "请按以下格式输出：\n"
                    "## 问题总结\n"
                    "- 用 3-6 条总结主要异常和影响范围。\n"
                    "## 根因判断\n"
                    "- 按可能性从高到低判断根因，并说明证据。\n"
                    "## 处理建议\n"
                    "- 给出可执行排障步骤，先做低风险确认，再做变更操作。\n"
                    "## 关键证据\n"
                    "- 引用关键日志片段，不要超过 8 条。\n\n"
                    f"日志行数：{len(sanitized_lines)}\n"
                    f"日志内容：\n{prompt_logs}"
                ),
            },
        ],
        "temperature": 0.2,
        "max_tokens": 1600,
    }

    response = post_chat_completion(
        url=chat_completions_url(config.base_url),
        api_key=api_key,
        payload=payload,
        timeout=config.timeout_seconds,
    )
    content = extract_content(response)
    return {
        "enabled": True,
        "model": config.model,
        "sent_lines": len(sanitized_lines),
        "redaction_enabled": True,
        "analysis": content,
    }


def select_ai_entries(
    entries: list[dict[str, object]],
    total_limit: int,
    per_device_limit: int,
    mode: str = AI_MODE_BALANCED,
) -> AISelection:
    safe_total = max(1, min(total_limit, MAX_AI_LINES))
    safe_per_device = max(1, min(per_device_limit, MAX_AI_LINES))
    normalized_mode = mode if mode in {AI_MODE_BALANCED, AI_MODE_RECENT} else AI_MODE_BALANCED

    if normalized_mode == AI_MODE_RECENT:
        selected = entries[-safe_total:]
        return AISelection(
            entries=selected,
            metadata={
                "mode": AI_MODE_RECENT,
                "scanned_lines": len(entries),
                "candidate_lines": len(entries),
                "selected_lines": len(selected),
                "total_limit": safe_total,
                "per_device_limit": safe_per_device,
                "devices": device_selection_summary(selected, entries),
            },
        )

    grouped: dict[str, list[dict[str, object]]] = {}
    for entry in entries:
        device = str(entry.get("device") or "unknown")
        grouped.setdefault(device, []).append(entry)

    selected_by_device: list[dict[str, object]] = []
    device_meta: list[dict[str, object]] = []
    for device in sorted(grouped):
        group = grouped[device]
        ranked = sorted(group, key=importance_sort_key, reverse=True)
        selected = ranked[:safe_per_device]
        selected_by_device.extend(selected)
        device_meta.append(
            {
                "device": device,
                "available": len(group),
                "selected": 0,
                "highest_severity": highest_entry_severity(group),
            }
        )

    selected_final = balanced_device_selection(selected_by_device, safe_total)
    selected_final.sort(key=lambda item: (str(item.get("device") or ""), importance_sort_key(item)))
    selected_counts: dict[str, int] = {}
    for item in selected_final:
        device = str(item.get("device") or "unknown")
        selected_counts[device] = selected_counts.get(device, 0) + 1
    for item in device_meta:
        item["selected"] = selected_counts.get(str(item["device"]), 0)

    return AISelection(
        entries=selected_final,
        metadata={
            "mode": AI_MODE_BALANCED,
            "scanned_lines": len(entries),
            "candidate_lines": len(entries),
            "selected_lines": len(selected_final),
            "total_limit": safe_total,
            "per_device_limit": safe_per_device,
            "devices": device_meta,
        },
    )


def balanced_device_selection(entries: list[dict[str, object]], total_limit: int) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = {}
    for entry in entries:
        grouped.setdefault(str(entry.get("device") or "unknown"), []).append(entry)
    for group in grouped.values():
        group.sort(key=importance_sort_key, reverse=True)

    first_pass = [group[0] for group in grouped.values() if group]
    first_pass.sort(key=importance_sort_key, reverse=True)
    if len(first_pass) >= total_limit:
        return first_pass[:total_limit]

    selected = list(first_pass)
    remaining: list[dict[str, object]] = []
    for group in grouped.values():
        remaining.extend(group[1:])
    remaining.sort(key=importance_sort_key, reverse=True)
    selected.extend(remaining[: max(0, total_limit - len(selected))])
    return selected


def importance_sort_key(entry: dict[str, object]) -> tuple[int, str, int]:
    severity = str(entry.get("severity") or "info").lower()
    categories = entry.get("categories")
    category_list = categories if isinstance(categories, list) else [entry.get("category")]
    category_score = max(
        [IMPORTANT_CATEGORY_SCORE.get(str(category), 0) for category in category_list if category],
        default=0,
    )
    repeat_bonus = min(int(entry.get("repeat_count") or 1), 20)
    score = SEVERITY_SCORE.get(severity, 100) + category_score + repeat_bonus
    return (score, str(entry.get("_timestamp_sort") or ""), int(entry.get("_order") or 0))


def highest_entry_severity(entries: list[dict[str, object]]) -> str:
    if not entries:
        return "info"
    return max(
        (str(entry.get("severity") or "info") for entry in entries),
        key=lambda severity: SEVERITY_SCORE.get(severity, 0),
    )


def device_selection_summary(
    selected_entries: list[dict[str, object]],
    all_entries: list[dict[str, object]],
) -> list[dict[str, object]]:
    devices = sorted({str(entry.get("device") or "unknown") for entry in all_entries})
    return [
        {
            "device": device,
            "available": sum(1 for entry in all_entries if str(entry.get("device") or "unknown") == device),
            "selected": sum(1 for entry in selected_entries if str(entry.get("device") or "unknown") == device),
            "highest_severity": highest_entry_severity(
                [entry for entry in all_entries if str(entry.get("device") or "unknown") == device]
            ),
        }
        for device in devices
    ]


def build_sanitized_log_lines(entries: list[dict[str, object]]) -> list[str]:
    lines: list[str] = []
    for entry in entries[-MAX_AI_LINES:]:
        repeat_count = int(entry.get("repeat_count") or 1)
        time_text = entry.get("time") or "-"
        if repeat_count > 1 and entry.get("first_time") and entry.get("last_time"):
            time_text = f"{entry.get('first_time')}~{entry.get('last_time')}"
        parts = [
            f"time={time_text}",
            f"device={entry.get('device') or '-'}",
            f"severity={entry.get('severity') or '-'}",
            f"category={entry.get('category') or '-'}",
            f"repeat_count={repeat_count}",
            f"summary={entry.get('chinese_summary') or '-'}",
            f"raw={entry.get('raw') or ''}",
        ]
        lines.append(redact_sensitive(" | ".join(str(part) for part in parts)))
    return lines


def redact_sensitive(text: str) -> str:
    text = MAC_RE.sub("<MAC>", text)
    text = IPV4_RE.sub("<IP>", text)
    text = IPV6_RE.sub("<IPV6>", text)
    text = PHONE_RE.sub("<PHONE>", text)
    text = ACCOUNT_RE.sub(lambda match: f"{match.group('key')}=<ACCOUNT>", text)
    text = USER_PHRASE_RE.sub(lambda match: f"{match.group('prefix')}<ACCOUNT>", text)
    text = SERIAL_RE.sub(lambda match: f"{match.group('key')}=<SN>", text)
    return text


def trim_to_char_budget(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[-max_chars:]


def post_chat_completion(url: str, api_key: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise AIAnalyzerError(f"AI provider returned HTTP {exc.code}: {safe_error_body(body)}") from exc
    except urllib.error.URLError as exc:
        raise AIAnalyzerError(f"AI provider request failed: {exc.reason}") from exc
    except TimeoutError as exc:
        raise AIAnalyzerError("AI provider request timed out.") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AIAnalyzerError("AI provider returned invalid JSON.") from exc


def extract_content(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise AIAnalyzerError("AI provider response did not contain choices.")
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(message, dict):
        raise AIAnalyzerError("AI provider response did not contain a message.")
    content = message.get("content")
    if not content:
        raise AIAnalyzerError("AI provider response was empty.")
    return str(content).strip()


def chat_completions_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    return f"{normalized}/chat/completions"


def public_base_url(base_url: str) -> str:
    return base_url.replace(os.getenv("OPENAI_API_KEY", ""), "<KEY>") if os.getenv("OPENAI_API_KEY") else base_url


def safe_error_body(body: str) -> str:
    if not body:
        return ""
    redacted = body.replace(os.getenv("OPENAI_API_KEY", ""), "<KEY>") if os.getenv("OPENAI_API_KEY") else body
    return redacted[:500]
