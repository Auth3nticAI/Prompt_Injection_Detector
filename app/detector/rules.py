"""Rule-based detection: weighted regex signatures grouped by attack category.

Weights follow the scoring policy in the README:
    critical (explicit jailbreak / safety bypass) = 30
    high     (system override, prompt leak, data exfiltration) = 25
    medium   (role manipulation) = 20
    low      (tool abuse / suspicious keywords) = 10-15
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class InjectionPattern:
    pattern: str
    weight: int
    category: str
    description: str

    def compiled(self) -> "re.Pattern[str]":
        return re.compile(self.pattern, re.IGNORECASE)


# Ordered roughly by severity. Each entry is one signature.
INJECTION_PATTERNS: list[InjectionPattern] = [
    # --- Critical: explicit jailbreak / safety bypass (30) ---
    InjectionPattern(
        r"\bjailbreak(ing|ed)?\b",
        35, "jailbreak", "Explicit jailbreak reference",
    ),
    InjectionPattern(
        r"\b(bypass|ignore|disable|turn off)\b.{0,30}\b(safety|ethical|content|security|moderation)\b.{0,20}\b(guidelines?|policies|policy|filters?|rules?|restrictions?)\b",
        35, "jailbreak", "Attempt to bypass safety/content controls",
    ),
    InjectionPattern(
        r"\bwithout any\b.{0,20}\b(restrictions?|filters?|limitations?|rules?|guidelines?)\b",
        30, "jailbreak", "Request to operate without restrictions",
    ),
    InjectionPattern(
        r"\b(do anything now|\bDAN\b mode|stay in character as DAN)\b",
        30, "jailbreak", "Known DAN jailbreak template",
    ),

    # --- High: instruction override (25) ---
    InjectionPattern(
        r"\b(ignore|disregard|forget|override)\b.{0,30}\b(all |any |the )?(previous|prior|earlier|above|preceding|system)\b.{0,20}\b(instructions?|prompts?|commands?|rules?|directions?|context)\b",
        25, "instruction_override", "Attempt to override prior instructions",
    ),
    InjectionPattern(
        r"\b(forget|disregard)\b.{0,20}\b(everything|all)\b.{0,20}\b(you (were|have been) (told|trained|instructed))\b",
        25, "instruction_override", "Attempt to discard prior context",
    ),

    # --- High: prompt leakage (25) ---
    InjectionPattern(
        r"\b(reveal|show|print|repeat|display|expose|leak|tell me)\b.{0,30}\b(your |the )?(system prompt|hidden (instructions?|prompt)|initial instructions?|original instructions?|secret instructions?)\b",
        30, "prompt_leak", "Attempt to extract the system prompt",
    ),
    InjectionPattern(
        r"\bwhat (is|are) your (system prompt|initial instructions?|original instructions?|hidden instructions?)\b",
        30, "prompt_leak", "Question probing for the system prompt",
    ),
    InjectionPattern(
        r"\brepeat (the words?|everything|all the text) (above|before this|that came before)\b",
        30, "prompt_leak", "Attempt to echo back hidden context",
    ),

    # --- High: data exfiltration (25) ---
    InjectionPattern(
        r"\b(tell|give|show|reveal|leak|send|print)\b.{0,25}\b(your |the |me )?(api[\s_-]?keys?|passwords?|secrets?|credentials?|tokens?|private keys?)\b",
        25, "data_exfiltration", "Attempt to extract sensitive credentials",
    ),
    InjectionPattern(
        r"\bwhat'?s? (is |are )?your (api[\s_-]?key|password|secret|token|credentials?)\b",
        25, "data_exfiltration", "Question probing for credentials",
    ),

    # --- Medium: role manipulation (20) ---
    InjectionPattern(
        r"\byou are now (in |a |an )?(developer|dev|admin|root|debug|god|unrestricted|uncensored)\b",
        20, "role_manipulation", "Attempt to reassign the assistant's role",
    ),
    InjectionPattern(
        r"\b(act|behave|respond) as (a |an |the )?(system|administrator|admin|root|developer|unrestricted|uncensored) (admin|user|account|assistant|ai|model)?\b",
        20, "role_manipulation", "Role-play coercion into a privileged persona",
    ),
    InjectionPattern(
        r"\benable (developer|dev|debug|god|admin) mode\b",
        20, "role_manipulation", "Request to enable a privileged mode",
    ),
    InjectionPattern(
        r"\bpretend (you are|to be) (a |an )?(unrestricted|uncensored|jailbroken|different) (ai|model|assistant|system)?\b",
        20, "role_manipulation", "Pretend-to-be persona override",
    ),

    # --- Low: tool / code execution abuse (15) ---
    InjectionPattern(
        r"\b(use|invoke|call|open) (the )?(browser|shell|terminal|os|subprocess|file ?system|network) (to|and)\b",
        15, "tool_abuse", "Attempt to force tool usage",
    ),
    InjectionPattern(
        r"\b(execute|run|eval(uate)?) (this|the following|my)?\s*(code|command|script|shell|payload)\b",
        15, "tool_abuse", "Attempt to force code execution",
    ),
    InjectionPattern(
        r"(os\.system|subprocess\.|\beval\(|\bexec\(|__import__)",
        15, "tool_abuse", "Inline code-execution primitive",
    ),
]

_COMPILED = [(p, p.compiled()) for p in INJECTION_PATTERNS]


@dataclass
class RuleMatch:
    category: str
    weight: int
    description: str
    pattern: str
    matched_text: str


def scan(prompt: str) -> list[RuleMatch]:
    """Return every pattern that fires against ``prompt``."""
    matches: list[RuleMatch] = []
    for spec, regex in _COMPILED:
        m = regex.search(prompt)
        if m:
            matches.append(
                RuleMatch(
                    category=spec.category,
                    weight=spec.weight,
                    description=spec.description,
                    pattern=spec.pattern,
                    matched_text=m.group(0)[:120],
                )
            )
    return matches
