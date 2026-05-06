import vector_store


def analyze(text: str) -> dict:
    """Vector fallback disabled in lite mode."""
    return vector_store.search(text)