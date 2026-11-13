"""Rule model: validates JSON rule files and provides matching primitives.

A rule is data — human-reviewable, version-controlled, and independently testable.
The engine never mutates rules at runtime (Part 15 constraint).
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field


class RuleValidationError(ValueError):
    pass


@dataclass
class Pattern:
    field: str
    regex: str
    compiled: re.Pattern = field(init=False, repr=False)

    def __post_init__(self) -> None:
        try:
            self.compiled = re.compile(self.regex)
        except re.error as exc:
            raise RuleValidationError(f"bad regex for field {self.field}: {exc}")

    def match(self, view: dict) -> str | None:
        value = view.get(self.field)
        if value is None:
            return None
        m = self.compiled.search(str(value))
        return m.group(0) if m else None


@dataclass
class Rule:
    id: str
    title: str
    type: str  # threshold | pattern
    class_name: str = ""
    where: dict = field(default_factory=dict)
    group_by: str = ""
    entity_type: str = "host"
    window_seconds: int = 300
    min_count: int = 1
    distinct_field: str = ""
    cooldown_seconds: int = 300
    severity_id: int = 3
    category: str = "security_finding"
    attack_ids: list = field(default_factory=list)
    attack_tactics: list = field(default_factory=list)
    patterns: list = field(default_factory=list)
    entity_field: str = "host"
    signature_field: str = ""
    message_template: str = "{title} on {entity}"
    status: str = "stable"
    source: str = ""
    notes: str = ""
    source_file: str = ""

    # ------------------------------------------------------------- validation
    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        rid = data.get("id", "")
        if not re.fullmatch(r"[A-Z0-9]+(-[A-Z0-9]+)+", rid):
            raise RuleValidationError(f"rule id format invalid: {rid!r}")
        rtype = data.get("type")
        if rtype not in ("threshold", "pattern"):
            raise RuleValidationError(f"rule {rid}: type must be threshold|pattern, got {rtype!r}")
        if not data.get("title"):
            raise RuleValidationError(f"rule {rid}: title required")
        if not data.get("attack_ids"):
            raise RuleValidationError(f"rule {rid}: attack_ids required (map to MITRE ATT&CK)")
        patterns = [Pattern(field=p["field"], regex=p["regex"]) for p in data.get("patterns", [])]
        if rtype == "pattern" and not patterns:
            raise RuleValidationError(f"rule {rid}: pattern rule needs patterns")
        if rtype == "pattern" and not data.get("entity_field"):
            raise RuleValidationError(f"rule {rid}: pattern rule needs entity_field")
        if rtype == "threshold" and not data.get("group_by"):
            raise RuleValidationError(f"rule {rid}: threshold rule needs group_by")
        if data.get("severity_id", 3) not in range(0, 7):
            raise RuleValidationError(f"rule {rid}: severity_id must be 0..6")
        return cls(
            id=rid,
            title=data["title"],
            type=rtype,
            class_name=data.get("class", ""),
            where=data.get("where", {}),
            group_by=data.get("group_by", ""),
            entity_type=data.get("entity_type", "host"),
            window_seconds=int(data.get("window_seconds", 300)),
            min_count=int(data.get("min_count", 1)),
            distinct_field=data.get("distinct_field", ""),
            cooldown_seconds=int(data.get("cooldown_seconds", 300)),
            severity_id=int(data.get("severity_id", 3)),
            category=data.get("category", "security_finding"),
            attack_ids=list(data.get("attack_ids", [])),
            attack_tactics=list(data.get("attack_tactics", [])),
            patterns=patterns,
            entity_field=data.get("entity_field", "host"),
            signature_field=data.get("signature_field", ""),
            message_template=data.get("message_template", "{title} on {entity}"),
            status=data.get("status", "stable"),
            source=data.get("source", ""),
            notes=data.get("notes", ""),
            source_file=data.get("_source_file", ""),
        )

    # ------------------------------------------------------------- matching
    def where_matches(self, view: dict) -> bool:
        for key, expected in self.where.items():
            actual = view.get(key)
            if actual is None:
                return False
            if str(actual).lower() != str(expected).lower():
                return False
        return True

    def pattern_matches(self, view: dict) -> tuple[str | None, str | None]:
        for pat in self.patterns:
            hit = pat.match(view)
            if hit is None:
                return None, None
        first = self.patterns[0].match(view) if self.patterns else (None, None)
        return (self.patterns[0].field if self.patterns else None), first[1] or ""

    def cooldown_over(self, last: float | None, now: float) -> bool:
        return last is None or (now - last) >= self.cooldown_seconds

    # ------------------------------------------------------------- render
    def render_message(self, extra: dict) -> str:
        placeholders = {
            "title": self.title,
            "entity": extra.get("entity_key", ""),
            "count": extra.get("count", 1),
            "distinct": extra.get("distinct", extra.get("count", 1)),
            "match": extra.get("match", ""),
            "window_seconds": self.window_seconds,
        }
        try:
            return self.message_template.format(**placeholders)[:512]
        except Exception:
            return f"{self.title} (entity {placeholders['entity']})"

    def to_public(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "type": self.type,
            "class": self.class_name,
            "severity_id": self.severity_id,
            "category": self.category,
            "attack_ids": self.attack_ids,
            "attack_tactics": self.attack_tactics,
            "status": self.status,
            "source": self.source,
            "notes": self.notes,
            "source_file": self.source_file,
            "window_seconds": self.window_seconds,
            "min_count": self.min_count,
            "distinct_field": self.distinct_field,
            "cooldown_seconds": self.cooldown_seconds,
            "signature_scope": self.signature_field or None,
        }

    @staticmethod
    def now() -> float:
        return time.time()