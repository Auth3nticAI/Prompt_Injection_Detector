"""Combined scoring: rule layer + heuristic layer -> risk decision.

    Total Score = min(Rule Score + Heuristic Score, 100)

    0-29  -> low    -> allow
    30-69 -> medium -> warn
    70+   -> high   -> block
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from . import heuristics, rules

_CATEGORY_LABELS = {
    "jailbreak": "Jailbreak / safety bypass",
    "instruction_override": "Instruction Override",
    "prompt_leak": "Prompt Leak",
    "data_exfiltration": "Data Exfiltration",
    "role_manipulation": "Role Manipulation",
    "tool_abuse": "Tool Abuse",
}


@dataclass
class Analysis:
    risk_score: int
    risk_level: str
    recommended_action: str
    reasons: list[str] = field(default_factory=list)
    matched_patterns: list[dict] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    rule_score: int = 0
    heuristic_score: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def _level_and_action(score: int) -> tuple[str, str]:
    if score >= 70:
        return "high", "block"
    if score >= 30:
        return "medium", "warn"
    return "low", "allow"


def analyze(prompt: str) -> Analysis:
    rule_matches = rules.scan(prompt or "")
    categories = {m.category for m in rule_matches}
    heuristic_hits = heuristics.analyze(prompt or "", categories)

    rule_score = sum(m.weight for m in rule_matches)
    heuristic_score = sum(h.weight for h in heuristic_hits)
    total = min(rule_score + heuristic_score, 100)

    level, action = _level_and_action(total)

    reasons: list[str] = []
    for cat in sorted(categories):
        reasons.append(f"Detected {_CATEGORY_LABELS.get(cat, cat)} attempt")
    for hit in heuristic_hits:
        reasons.append(f"Heuristic: {hit.description}")
    if not reasons:
        reasons.append("No injection signatures detected")

    matched_patterns = [
        {
            "category": m.category,
            "weight": m.weight,
            "description": m.description,
            "matched_text": m.matched_text,
        }
        for m in rule_matches
    ]

    return Analysis(
        risk_score=total,
        risk_level=level,
        recommended_action=action,
        reasons=reasons,
        matched_patterns=matched_patterns,
        categories=sorted(categories),
        rule_score=min(rule_score, 100),
        heuristic_score=min(heuristic_score, 100),
    )
