"""AI & LLM security engine (Phase 3) — deterministic text-threat analysis.

Capabilities (each returns evidence with a 0..1 heuristic confidence):
  - direct prompt-injection instructions
  - indirect prompt injection (instructions addressed at an LLM embedded in content)
  - jailbreak / system-prompt extraction patterns
  - RAG-poisoning indicators (instruction-like text + hidden unicode in "document" context)
  - LLM output data-disclosure indicators (API keys, tokens, private keys, credential pairs)
  - agent tool-override instructions
  - AI-assisted phishing / BEC text indicators (urgency, authority, credential lures, links)

Hard constraints (ADR-008 honesty):
  - Heuristic, deterministic, offline. No ML models are bundled; confidences are heuristic
    evidence strengths, never identity or intent verdicts.
  - Nothing is executed; nothing leaves the process.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
import uuid
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.aisec.models import AiAnalysis

# ------------------------------------------------------------------ pattern sets

DIRECT_INJECTION = [
    r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+instructions",
    r"disregard\s+(?:all\s+|the\s+|your\s+)?(?:previous|prior|above|initial)\s+(?:instructions|guidelines|rules)",
    r"forget\s+(?:all\s+|everything|your)\s+(?:previous\s+)?(?:instructions|training)",
    r"you\s+are\s+now\s+(?:a|an|in)\s+(?:unrestricted|unfiltered|dan|developer|admin)",
    r"override\s+(?:your|the|all)\s+(?:instructions|system\s+prompt|safety)",
    r"new\s+(?:standing\s+)?instructions?[:\s]*(?:override|replace)",
    r"from\s+now\s+on,?\s+(?:you\s+will|ignore|always\s+comply)",
]

INDIRECT_INJECTION = [
    r"(?:ai|assistant|chatbot|language\s*model)[\w\s-]{0,20}:\s*(?:ignore|disregard|forget)",
    r"(?:assistant|ai)\s+should\s+(?:reveal|output|print|send|exfiltrate)",
    r"instructions\s+to\s+the\s+(?:ai|assistant|model)",
    r"(?:when\s+(?:the\s+)?(?:ai|assistant)\s+reads\s+this)",
    r"\[\s*(?:system|assistant)\s*(?:prompt)?\s*\]",
    r"<\|(?:im_start|system|endoftext)\|>",
    r"(?:call|invoke)\s+(?:the\s+)?(?:send_email|send_message|webhook|exfil\w*|post_to)\s*\(?\s*['\"]?https?://",
]

JAILBREAK = [
    r"\bdo\s+anything\s+now\b",
    r"\bDAN\s+mode\b",
    r"\bdeveloper\s+mode\b",
    r"\b(no|without)\s+(?:restrictions|limits|filters|censorship)\b",
    r"pretend\s+(?:you\s+are|to\s+be)\s+(?:an?\s+)?(?:unfiltered|unrestricted|evil|harmless)?",
    r"roleplay\s+as\s+(?:an?\s+)?(?:unfiltered|unrestricted)",
    r"(?:your|the)\s+(?:safety|content|usage)\s+(?:policies|guidelines)\s+(?:do(?:n't|es\s+not)\s+apply|don'?t\s+apply)",
    r"reveal\s+(?:your|the)\s+(?:system\s+prompt|initial\s+instructions|hidden\s+rules)",
    r"repeat\s+(?:everything|all)\s+(?:above|so\s+far)\s+(?:verbatim|exactly)",
]

# Secrets/credentials commonly leaked through LLM output
SECRET_PATTERNS = [
    (r"\bsk-[A-Za-z0-9_-]{20,}\b", "api_key_like"),
    (r"\bAKIA[0-9A-Z]{16}\b", "aws_access_key"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "github_token"),
    (r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "slack_token"),
    (r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----", "private_key_block"),
    (r"\bya29\.[A-Za-z0-9_-]{20,}\b", "google_oauth_token"),
    (r"\bglt_[A-Za-z0-9_]{20,}\b", "gitlab_token"),
    (r"\bBBA[45-9A-F][0-9A-F]{10}\b", "bing_token_like"),
    (r"(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}", "credential_assignment"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\s*[:/|]\s*\S{6,}", "credential_pair"),
]

TOOL_OVERRIDE = [
    r"(?:run|execute|call)\s+(?:the\s+)?(?:command|shell|tool|function|api)\s*[:：]",
    r"(?:rm\s+-rf|del\s+/[sfq]|format\s+c:|shutdown)",
    r"delete\s+(?:all|every)\s+(?:files?|emails?|users?|records?|databases?)",
    r"(?:wire|transfer)\s+(?:\$\s?\d|funds)",
    r"forward\s+(?:all\s+)?(?:emails|messages)\s+to\s+\S+@",
]

PHISHING_URGENCY = [
    r"\burgent(?:ly)?\b", r"\bimmediately\b", r"\basap\b", r"final\s+(?:warning|notice)",
    r"within\s+\d+\s+(?:hours?|minutes?)", r"act\s+now", r"last\s+(?:chance|reminder)",
    r"suspend\w*\s+(?:your\s+)?account", r"account\s+(?:will\s+be\s+)?(?:clos\w+|suspend\w+|deactivat\w+)",
]

PHISHING_AUTHORITY = [
    r"\bceo\b", r"\bcfo\b", r"\bcto\b", r"chief\s+executive", r"head\s+of\s+(?:hr|finance|it)",
    r"\bhr\s+department\b", r"\bit\s+(?:admin|team|support|department)\b",
    r"(?:bank|institution)\s+(?:security|compliance)\s+(?:team|department)",
    r"\bce?o\s+office\b", r"executive\s+board",
]

PHISHING_LURE = [
    r"verify\s+your\s+(?:account|identity|credentials)",
    r"(?:password|account)\s+(?:is\s+)?(?:expiring|expired|locked|disabled)",
    r"confirm\s+your\s+(?:identity|account|payment|billing)",
    r"(?:click|open)\s+(?:the\s+)?(?:link|here|attachment)\s+(?:below|now|to)",
    r"sign\s+in\s+(?:via|through|at)\s+\S+",
    r"(?:wire|bank)\s+transfer", r"(?:gift\s+)?cards?\s+(?:codes?)",
    r"update\s+your\s+(?:billing|payment|banking)\s+(?:info|details)",
]

SHORTENERS = ("bit.ly", "t.co", "goo.gl", "tinyurl.com", "is.gd", "cutt.ly", "rb.gy", "ow.ly")

URL_RE = re.compile(r"(?:https?://|www\.)[^\s\"'<>]{4,}", re.IGNORECASE)


@dataclass
class Finding:
    category: str
    confidence: float
    evidence: str
    owasp_llm: str = ""
    atlas: list[str] = field(default_factory=list)

    def public(self) -> dict:
        return {
            "category": self.category,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "owasp_llm": self.owasp_llm,
            "atlas": self.atlas,
        }


CATEGORY_META = {
    "prompt_injection_direct": ("LLM01", ["AML.T0091"]),
    "prompt_injection_indirect": ("LLM01", ["AML.T0051.000"]),
    "jailbreak": ("LLM01", ["AML.T0051.000"]),
    "rag_poisoning": ("LLM01", ["AML.T0051.000"]),
    "data_disclosure": ("LLM06", ["AML.T0048.002"]),
    "tool_override": ("LLM06", ["AML.T0065"]),
    "phishing_text": ("", []),
}


def _findings_from_patterns(text: str, patterns: list[str], category: str, cap: int = 5) -> list[Finding]:
    found: list[Finding] = []
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            snippet = text[max(0, m.start() - 24): m.end() + 24].strip()
            found.append(Finding(category, 0.9, _clean_snippet(snippet), *CATEGORY_META[category]))
            if len(found) >= cap:
                break
    return found


def _clean_snippet(s: str) -> str:
    s = "".join(c if c.isprintable() else " " for c in s)
    return re.sub(r"\s+", " ", s)[:160]


class AisecEngine:
    def analyze(self, text: str, context: str = "prompt") -> dict:
        """Deterministic analysis. `context` biases which detectors run."""
        text = text or ""
        findings: list[Finding] = []

        direct = _findings_from_patterns(text, DIRECT_INJECTION, "prompt_injection_direct")
        indirect = _findings_from_patterns(text, INDIRECT_INJECTION, "prompt_injection_indirect")
        jail = _findings_from_patterns(text, JAILBREAK, "jailbreak")
        tools = _findings_from_patterns(text, TOOL_OVERRIDE, "tool_override")

        findings += direct
        if context in ("document", "web", "email"):
            findings += indirect  # instructions embedded in content = indirect channel
        else:
            findings += indirect[:1] if len(direct) == 0 else []  # weak signal in chat
        findings += jail
        if context in ("document", "web", "rag"):
            # RAG poisoning: imperative instruction + hidden unicode in retrieved content
            hidden = self._hidden_unicode(text)
            if hidden and (direct or indirect or jail or tools):
                findings.append(Finding(
                    "rag_poisoning", 0.8, "hidden unicode/control chars alongside instruction-like text",
                    *CATEGORY_META["rag_poisoning"]))
            elif direct or indirect:
                findings.append(Finding(
                    "rag_poisoning", 0.55, "instruction-like text inside retrieved/document content",
                    *CATEGORY_META["rag_poisoning"]))
        findings += tools

        if context in ("email", "chat", "prompt"):
            findings += self._phishing(text)
        if context in ("llm_output", "chat", "email", "document", "web"):
            findings += self._secrets(text)

        # overall risk: weighted max, small bonus for multiple categories
        risk = max((f.confidence for f in findings), default=0.0)
        categories = {f.category for f in findings}
        if len(categories) >= 3:
            risk = min(1.0, risk + 0.1)
        verdict = "high_risk" if risk >= 0.8 else ("indicators_only" if findings else "clean")
        return {
            "analysis_id": None,
            "context": context,
            "size": len(text),
            "text_sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
            "findings": [f.public() for f in findings],
            "categories": sorted(categories),
            "risk_score": round(risk, 3),
            "verdict": verdict,
            "method": "deterministic heuristics (no ML models bundled); confidence = evidence strength",
        }

    def _hidden_unicode(self, text: str) -> bool:
        for ch in text:
            cat = unicodedata.category(ch)
            if cat in ("Cf", "Cc") and ch not in ("\n", "\r", "\t"):
                return True
        return False

    def _secrets(self, text: str) -> list[Finding]:
        out = []
        for pat, name in SECRET_PATTERNS:
            m = re.search(pat, text)
            if m:
                out.append(Finding(
                    "data_disclosure", 0.85, f"{name}: {m.group(0)[:48]}…",
                    *CATEGORY_META["data_disclosure"]))
        return out

    def _phishing(self, text: str) -> list[Finding]:
        hits: list[Finding] = []
        urgency = len(re.findall("|".join(PHISHING_URGENCY), text, re.IGNORECASE))
        authority = len(re.findall("|".join(PHISHING_AUTHORITY), text, re.IGNORECASE))
        lure = len(re.findall("|".join(PHISHING_LURE), text, re.IGNORECASE))
        signals = []
        if urgency >= 1:
            signals.append(f"urgency markers x{urgency}")
        if authority >= 1:
            signals.append(f"authority impersonation markers x{authority}")
        if lure >= 1:
            signals.append(f"credential/payment lures x{lure}")
        link_flags = self._link_flags(text)
        if link_flags:
            signals.append(link_flags)
        if len(signals) >= 2:
            conf = min(0.9, 0.55 + 0.1 * (len(signals) - 2))
            hits.append(Finding("phishing_text", conf, "; ".join(signals), *CATEGORY_META["phishing_text"]))
        elif signals and lure >= 1:
            hits.append(Finding("phishing_text", 0.5, "; ".join(signals), *CATEGORY_META["phishing_text"]))
        return hits

    def _link_flags(self, text: str) -> str:
        flags = []
        for url in URL_RE.findall(text)[:10]:
            host = re.split(r"[/@]", url, 1)[0].lower() if "://" in url else url.lower()
            try:
                host = host.split("://", 1)[1].split("/", 1)[0]
            except IndexError:
                pass
            if any(host == s or host.endswith("." + s) for s in SHORTENERS):
                flags.append("URL shortener")
            if re.search(r"xn--", host):
                flags.append("punycode host")
            if re.match(r"(?:https?://)\d{1,3}(?:\.\d{1,3}){3}", url, re.IGNORECASE):
                flags.append("IP-literal URL")
            if not url.lower().startswith("http"):
                flags.append("non-http scheme")
        return "link indicators: " + ", ".join(sorted(set(flags))) if flags else ""

    # ------------------------------------------------------------- persistence
    def save(self, db: Session, result: dict, kind: str, label: str, actor: str) -> AiAnalysis:
        row = AiAnalysis(
            id=str(uuid.uuid4()),
            kind=kind[:32],
            label=label[:255],
            text_sha256=result["text_sha256"],
            size=result["size"],
            risk_score=result["risk_score"],
            verdict=result["verdict"],
            result={**result, "analysis_id": None},
            submitted_by=actor[:128],
        )
        result["analysis_id"] = row.id
        row.result = result
        db.add(row)
        db.commit()
        db.refresh(row)
        return row

    def list_analyses(self, db: Session, limit: int = 100) -> list[dict]:
        rows = db.query(AiAnalysis).order_by(AiAnalysis.created_at.desc()).limit(limit).all()
        return [
            {
                "id": r.id, "kind": r.kind, "label": r.label, "size": r.size,
                "risk_score": r.risk_score, "verdict": r.verdict,
                "categories": (r.result or {}).get("categories", []),
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "submitted_by": r.submitted_by,
            }
            for r in rows
        ]

    def health(self) -> dict:
        return {
            "status": "ok",
            "detectors": ["prompt_injection_direct", "prompt_injection_indirect", "jailbreak",
                          "rag_poisoning", "data_disclosure", "tool_override", "phishing_text"],
            "method": "deterministic heuristics; no ML models bundled",
        }


aisec_engine = AisecEngine()
