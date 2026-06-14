from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .database import PromptLog, get_db, init_db, utcnow_iso
from .detector import analyze as analyze_prompt
from .schemas import AnalyzeRequest, AnalyzeResponse, LogEntry, StatsResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Prompt Injection Detector",
    description="Rule-based + heuristic detection of prompt-injection attempts in LLM inputs.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest, db: Session = Depends(get_db)) -> AnalyzeResponse:
    # Context is folded into the scan so injections hidden in "context" still count.
    text = req.prompt if not req.context else f"{req.context}\n{req.prompt}"
    result = analyze_prompt(text)
    timestamp = utcnow_iso()

    db.add(
        PromptLog(
            prompt=req.prompt[:2000],
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            recommended_action=result.recommended_action,
            categories=json.dumps(result.categories),
            created_at=timestamp,
        )
    )
    db.commit()

    payload = result.to_dict()
    payload["analysis_timestamp"] = timestamp
    return AnalyzeResponse(**payload)


@app.get("/logs", response_model=list[LogEntry])
def logs(
    limit: int = Query(20, ge=1, le=100),
    risk_level: Optional[str] = Query(None, pattern="^(low|medium|high)$"),
    db: Session = Depends(get_db),
) -> list[LogEntry]:
    stmt = select(PromptLog).order_by(PromptLog.id.desc())
    if risk_level:
        stmt = stmt.where(PromptLog.risk_level == risk_level)
    rows = db.execute(stmt.limit(limit)).scalars().all()
    return [LogEntry(**row.as_entry()) for row in rows]


@app.get("/stats", response_model=StatsResponse)
def stats(db: Session = Depends(get_db)) -> StatsResponse:
    total = db.scalar(select(func.count()).select_from(PromptLog)) or 0
    dist = {"low": 0, "medium": 0, "high": 0}
    for level, count in db.execute(
        select(PromptLog.risk_level, func.count()).group_by(PromptLog.risk_level)
    ):
        dist[level] = count

    actions = {
        "allowed": dist["low"],
        "warned": dist["medium"],
        "blocked": dist["high"],
    }
    block_rate = round((dist["high"] / total) * 100, 1) if total else 0.0

    return StatsResponse(
        total_prompts_analyzed=total,
        risk_distribution=dist,
        actions_taken=actions,
        block_rate=block_rate,
    )
