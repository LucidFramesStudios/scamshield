from sentence_transformers import SentenceTransformer
import numpy as np
import warnings

# Suppress harmless huggingface warnings for a clean demo terminal
warnings.filterwarnings("ignore")

print("[SYSTEM] Loading Local Vector Model (all-MiniLM-L6-v2)...")
model = SentenceTransformer('all-MiniLM-L6-v2')
print("[SYSTEM] Vector Model Loaded Successfully.")

def get_embedding(text: str) -> np.ndarray:
    return model.encode(text)

def cosine_similarity(v1: np.ndarray, v2: np.ndarray) -> float:
    dot_product = np.dot(v1, v2)
    norm_v1 = np.linalg.norm(v1)
    norm_v2 = np.linalg.norm(v2)
    if norm_v1 == 0 or norm_v2 == 0: return 0.0
    return float(dot_product / (norm_v1 * norm_v2))