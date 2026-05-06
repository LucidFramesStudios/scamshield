from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
from models import AnalyzeResponse
import detector

app = FastAPI(title="ScamShield Orchestrator v4 — Lite")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health check (Render uptime monitoring) ───────────────
@app.get("/")
def health():
    return {"status": "ok"}


@app.get("/health")
def health_alt():
    return {"status": "ok"}


class Message(BaseModel):
    role: str = Field(..., pattern="^(me|other)$")
    text: str = Field(..., min_length=1)


class AnalyzeRequest(BaseModel):
    messages: Optional[List[Message]] = None
    text: Optional[str] = None


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(request: AnalyzeRequest):
    try:
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
        print(f"CRITICAL: {e}")
        return AnalyzeResponse(
            verdict="SAFE", confidence="LOW",
            reasons=["System error occurred."],
            actions=["Please try again."],
            provider="FAILSAFE"
        )