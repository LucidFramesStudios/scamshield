from pydantic import BaseModel, Field
from typing import List

class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1)

class AnalyzeResponse(BaseModel):
    verdict: str
    confidence: str
    cluster: str = "UNKNOWN"
    matches: List[str] = []
    reasons: List[str]
    actions: List[str]
    provider: str
    trend: str = Field(default="STABLE")