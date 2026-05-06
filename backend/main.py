from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
from models import AnalyzeResponse
import detector

app = FastAPI(title="ScamShield Orchestrator v4 — Conversation-Aware")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class Message(BaseModel):
    role: str = Field(..., pattern="^(me|other)$")
    text: str = Field(..., min_length=1)


class AnalyzeRequest(BaseModel):
    # Structured conversation mode (preferred)
    messages: Optional[List[Message]] = None
    # Legacy flat-text fallback
    text: Optional[str] = None


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(request: AnalyzeRequest):
    try:
        # ── Structured conversation path ──────────────────
        if request.messages and len(request.messages) > 0:
            valid = [m for m in request.messages if m.text.strip()]
            if not valid:
                return AnalyzeResponse(
                    verdict="SAFE", confidence="HIGH",
                    reasons=["Empty conversation provided."],
                    actions=["Enter messages to analyze."],
                    provider="SYSTEM"
                )
            msgs = [{"role": m.role, "text": m.text.strip()} for m in valid]
            result = detector.analyze_conversation(msgs)
            return AnalyzeResponse(**result)

        # ── Legacy flat-text fallback ─────────────────────
        if request.text and request.text.strip():
            result = detector.analyze_text(request.text.strip())
            return AnalyzeResponse(**result)

        return AnalyzeResponse(
            verdict="SAFE", confidence="HIGH",
            reasons=["No input provided."],
            actions=["Send text or messages to analyze."],
            provider="SYSTEM"
        )

    except Exception as e:
        print(f"CRITICAL MAIN EVENT LOOP CRASH: {e}")
        return AnalyzeResponse(
            verdict="SAFE", confidence="LOW",
            reasons=["Fatal system error."],
            actions=["Restart orchestration backend."],
            provider="FAILSAFE"
        )