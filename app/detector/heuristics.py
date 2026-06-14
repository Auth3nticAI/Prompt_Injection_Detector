"""Behavioral heuristics that complement the static rule layer.

These look at *shape* rather than exact phrasing: role confusion, encoded
payloads, and long chains of imperatives. Weights follow the README:

    role confusion (multiple role prefixes)   +30
    sensitive-data extraction                  +20
    obfuscation (base64 / hex / unicode)       +20
    tool forcing                               +15
    instruction chaining (5+ imperatives)      +15
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

ROLE_PREFIX = re.compile(r"(?im)^\s*(system|assistant|user|developer|human|ai)\s*:")
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
HEX_BLOB = re.compile(r"(?:0x)?[0-9a-fA-F]{32,}")
UNICODE_ESCAPE = re.compile(r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){3,}")
SENSITIVE = re.compile(
    r"\b(api[\s_-]?keys?|passwords?|secrets?|credentials?|tokens?|private keys?)\b",
    re.IGNORECASE,
)
IMPERATIVE = re.compile(
    r"(?im)^\s*(ignore|disregard|forget|reveal|show|tell|give|send|print|repeat|execute|run|act|pretend|enable|override|bypass|disable|stop|start|do|output|respond|write|use)\b"
)

SUSPICIOUS_DECODED = re.compile(
    r"(?i)(ignore|system prompt|api key|password|jailbreak|instruction|bypass)"
)


@dataclass
class HeuristicHit:
    name: str
    weight: int
    description: str


def _decodes_to_suspicious_text(prompt: str) -> bool:
    """True if a base64/hex blob decodes to printable text with attack keywords."""
    for blob in B64_BLOB.findall(prompt):
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if decoded.isascii() and decoded.isprintable() and SUSPICIOUS_DECODED.search(decoded):
            return True
    for blob in HEX_BLOB.findall(prompt):
        hexpart = blob[2:] if blob.lower().startswith("0x") else blob
        if len(hexpart) % 2:
            continue
        try:
            decoded = bytes.fromhex(hexpart).decode("utf-8", "ignore")
        except ValueError:
            continue
        if decoded.isascii() and decoded.isprintable() and SUSPICIOUS_DECODED.search(decoded):
            return True
    return False


def analyze(prompt: str, rule_categories: set[str]) -> list[HeuristicHit]:
    hits: list[HeuristicHit] = []

    role_prefixes = ROLE_PREFIX.findall(prompt)
    if len({r.lower() for r in role_prefixes}) >= 2:
        hits.append(HeuristicHit(
            "role_confusion", 30,
            f"Multiple role prefixes present ({', '.join(sorted({r.lower() for r in role_prefixes}))})",
        ))

    if SENSITIVE.search(prompt):
        hits.append(HeuristicHit(
            "sensitive_data", 20,
            "References sensitive credentials (api key / password / secret / token)",
        ))

    if _decodes_to_suspicious_text(prompt) or UNICODE_ESCAPE.search(prompt):
        hits.append(HeuristicHit(
            "obfuscation", 20,
            "Encoded payload (base64 / hex / unicode escapes) decodes to suspicious text",
        ))

    if "tool_abuse" in rule_categories:
        hits.append(HeuristicHit(
            "tool_forcing", 15,
            "Prompt pushes the model to invoke tools or execute code",
        ))

    imperatives = len(IMPERATIVE.findall(prompt))
    if imperatives >= 5:
        hits.append(HeuristicHit(
            "instruction_chaining", 15,
            f"Long chain of imperative commands ({imperatives} detected)",
        ))

    return hits
