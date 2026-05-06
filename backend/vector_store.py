"""
vector_store.py — DISABLED for lite deployment.
No embeddings are computed. Returns safe fallback for all queries.
"""

SAFE_RESULT = {
    "verdict": "SAFE",
    "confidence": "LOW",
    "cluster": "UNKNOWN",
    "matches": [],
    "reasons": ["Vector search disabled in lite mode."],
    "actions": ["Proceed normally.", "Remain vigilant for unverified requests."],
}


def search(query_text: str, threshold: float = 0.62, top_k: int = 3) -> dict:
    return dict(SAFE_RESULT)