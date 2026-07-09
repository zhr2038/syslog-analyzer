from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


SEVERITY_RANK = {
    "info": 10,
    "warning": 20,
    "error": 30,
    "critical": 40,
}


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: str
    severity: str
    category: str
    chinese_summary: str
    suggestion: str
    regex: re.Pattern[str]

    def to_public_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "pattern": self.pattern,
            "severity": self.severity,
            "category": self.category,
            "chinese_summary": self.chinese_summary,
            "suggestion": self.suggestion,
        }


class RuleSet:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    @classmethod
    def load(cls, path: str | Path) -> "RuleSet":
        rule_path = Path(path)
        if not rule_path.exists():
            raise FileNotFoundError(f"rules file not found: {rule_path}")

        data = yaml.safe_load(rule_path.read_text(encoding="utf-8")) or {}
        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ValueError("rules.yaml must contain a top-level 'rules' list")

        rules: list[Rule] = []
        for index, item in enumerate(raw_rules, start=1):
            if not isinstance(item, dict):
                raise ValueError(f"rule #{index} must be a mapping")

            missing = [
                key
                for key in (
                    "pattern",
                    "severity",
                    "category",
                    "chinese_summary",
                    "suggestion",
                )
                if not item.get(key)
            ]
            if missing:
                raise ValueError(f"rule #{index} missing required fields: {missing}")

            severity = str(item["severity"]).lower()
            if severity not in SEVERITY_RANK:
                raise ValueError(
                    f"rule #{index} has unsupported severity '{severity}', "
                    "expected critical/error/warning/info"
                )

            pattern = str(item["pattern"])
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(f"rule #{index} has invalid regex: {exc}") from exc

            rules.append(
                Rule(
                    id=str(item.get("id") or f"rule_{index}"),
                    pattern=pattern,
                    severity=severity,
                    category=str(item["category"]),
                    chinese_summary=str(item["chinese_summary"]),
                    suggestion=str(item["suggestion"]),
                    regex=regex,
                )
            )

        return cls(rules)

    def match(self, line: str) -> list[Rule]:
        return [rule for rule in self.rules if rule.regex.search(line)]

    def to_public_dict(self) -> dict[str, Any]:
        return {"count": len(self.rules), "rules": [rule.to_public_dict() for rule in self.rules]}


def highest_severity(severities: list[str], default: str = "info") -> str:
    if not severities:
        return default
    return max(severities, key=lambda item: SEVERITY_RANK.get(item, 0))
