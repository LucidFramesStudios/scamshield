# ScamShield 
Live demo: https://scamshieldai.vercel.app

> Real-time scam detection built in 24 hours.  
> Four inference layers. Deterministic fallbacks. Self-validating.

---

## The Problem

India received 3.24 crore cyber fraud complaints in 2025. The majority of victims
are elderly and act under live psychological pressure. Awareness campaigns don't
work at the moment of manipulation. A real-time tool does.

---

## What We Built

A layered inference system that analyzes suspicious conversations and returns a
verdict in under 2 seconds - with reasons, in the user's language, and a one-tap
path to the national cyber helpline (1930).

This is not a chatbot wrapper. The LLM is layer four.

---

## Architecture
Text / Voice Input
│
▼
[1] Rules Engine         local  · <10ms  · no network required
│
▼
[2] ML Classifier        local  · Hinglish-normalized · STT-corrected
│
▼
[3] Vector Store (RAG)   local  · semantic matching · 500+ verified patterns
│
▼
[4] LLM Reasoning        Claude API · handles novel / ambiguous cases
│
▼
Verdict Card + Incident Report

Each layer has a deterministic fallback. The first three layers operate without
network connectivity. The transcription layer is a modular input adapter - 
currently network-assisted, architected to accept a local STT engine.

---

## Why This Architecture

We had 24 hours. We made deliberate tradeoffs.

We prioritized the inference stack - the part that requires actual engineering
judgment - over deployment polish and UI completeness. The evaluation infrastructure
took real time to build. It is the asset that compounds.

The alternative was a single LLM call dressed as a product. We chose not to do that.

---

## Validation

We built a closed-loop testing framework rather than trusting manual assessment.

- **Adversarial case generator**: 6 failure categories including STT noise, Hinglish
  code-switching, business fraud, romance scams, evolving tactics
- **Automated test runner**: API coverage across all cases with retry logic
- **Evaluator**: accuracy, FP rate, FN rate, trend accuracy per run
- **Improvement engine**: generates targeted rule patches and retraining suggestions
  from each failure automatically
- **Run history**: tracks accuracy trends across iterations

| Current accuracy | Value |
|---|---|
|  Total test cases | 73 |
| Verdict accuracy | 74.0%  (54/73) |
|  Trend accuracy   | 90.4% |
|  False positives  | 1  (rate 3.1%) |
|  False negatives  | 0  (rate 0.0%) |
|  Under-detection  | 0 (SCAM→SUSPICIOUS) |
|  Over-detection   | 18 (SAFE→SUSPICIOUS) |
|  API errors       | 0 |
|  Elapsed total    | 156.4s |



---

## Failure Modes and Mitigations

| Failure | Mitigation |
|---|---|
| Misses a scam (false negative) | Ambiguous confidence always routes to SUSPICIOUS + 1930 referral |
| Flags a legitimate call (false positive) | UI instructs user to verify via official number, never blocks action |
| Network failure | Layers 1–3 return a verdict locally; no dependency on cloud |
| Novel scam phrasing | Vector + LLM layers catch phrasing not in rules; improvement engine patches |
| Claude API rate limits | Fallback to vector store verdict; degraded but functional |

---

## What's Left (Honest Assessment)

- Local STT engine (Whisper Tiny) to replace network-assisted transcription
- WhatsApp screenshot OCR via vision pipeline
- I4C scam database sync for daily pattern updates
- Production deployment of backend (currently local)

These are well-scoped. The inference architecture does not change.

---

## Setup

### Backend
```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd frontend && npm install && npm run dev
```

### Run adversarial tests
```bash
python run_tests.py
```

### Train classifier
```bash
python train_classifier.py
```

Live demo: https://scamshieldai.vercel.app

---

## Built in 24 hours at AIC × Anthropic Hackathon, IIT Bombay - May 2026 | Team Size : 1 Member