import requests, json, re

def analyze(text: str, prompt: str) -> dict:
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": "llama3",  # Change to mistral if preferred
        "prompt": prompt + f'\nTEXT TO ANALYZE: "{text}"',
        "stream": False,
        "format": "json"
    }
    
    # 5.1s timeout slightly higher than orchestrator to allow local processing
    response = requests.post(url, json=payload, timeout=5.1)
    response.raise_for_status()
    
    output = response.json().get("response", "")
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        # LLMs hallucinate markdown even in JSON mode. Strip it aggressively.
        match = re.search(r'\{.*\}', output, re.DOTALL)
        if match: return json.loads(match.group(0))
        raise ValueError("Ollama failed to return a valid JSON structure.")