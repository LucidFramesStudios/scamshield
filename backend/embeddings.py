"""
embeddings.py — DISABLED for lite deployment.
SentenceTransformer removed to reduce RAM and cold start time.
"""
import numpy as np


def get_embedding(text: str) -> np.ndarray:
    """Returns a zero vector. Embedding model is disabled."""
    return np.zeros(384)


def cosine_similarity(v1: np.ndarray, v2: np.ndarray) -> float:
    return 0.0