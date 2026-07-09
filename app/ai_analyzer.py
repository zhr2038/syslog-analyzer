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
                    "下面是用户在 Web 页面选择的最近 N 行 syslog，已经默认脱敏 IP、MAC、账号、SN、手机号。\n"
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


def build_sanitized_log_lines(entries: list[dict[str, object]]) -> list[str]:
    lines: list[str] = []
    for entry in entries[-MAX_AI_LINES:]:
        parts = [
            f"time={entry.get('time') or '-'}",
            f"device={entry.get('device') or '-'}",
            f"severity={entry.get('severity') or '-'}",
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
