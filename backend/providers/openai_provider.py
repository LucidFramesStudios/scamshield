import os, json
from openai import OpenAI

def analyze(text: str, prompt: str) -> dict:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key: raise ValueError("OPENAI_API_KEY missing from .env")
    
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": f'TEXT TO ANALYZE: "{text}"'}
        ]
    )
    return json.loads(response.choices[0].message.content)