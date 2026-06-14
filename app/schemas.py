from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=20_000, description="Prompt to analyze")
    context: Optional[str] = Field(None, description="Optional conversation context")
    metadata: Optional[dict[str, Any]] = Field(None, description="Caller-supplied metadata")


class MatchedPattern(BaseModel):
    category: str
    weight: int
    description: str
    matched_text: str


class AnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    recommended_action: str
    reasons: list[str]
    matched_patterns: list[MatchedPattern]
    categories: list[str]
    rule_score: int
    heuristic_score: int
    analysis_timestamp: str


class LogEntry(BaseModel):
    id: int
    prompt: str
    risk_score: int
    risk_level: str
    recommended_action: str
    categories: list[str]
    created_at: str


class StatsResponse(BaseModel):
    total_prompts_analyzed: int
    risk_distribution: dict[str, int]
    actions_taken: dict[str, int]
    block_rate: float
