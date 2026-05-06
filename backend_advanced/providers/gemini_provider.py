import os, json
from google import genai
from google.genai import types

def analyze(text: str, prompt: str) -> dict:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key: raise ValueError("GEMINI_API_KEY missing from .env")
    
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model='gemini-1.5-flash',
        contents=prompt + f'\nTEXT TO ANALYZE: "{text}"',
        config=types.GenerateContentConfig(response_mime_type="application/json")
    )
    return json.loads(response.text)