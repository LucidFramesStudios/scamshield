 
<div align="center">

# ScamShield
<img width="491" height="742" alt="image" src="https://github.com/user-attachments/assets/51759775-4199-4644-ba9a-856b38b8dab4" />
<img width="505" height="796" alt="image" src="https://github.com/user-attachments/assets/7e69f305-dc74-4db3-9a48-3c5261353437" />
<img width="712" height="730" alt="image" src="https://github.com/user-attachments/assets/7a8903cc-f9b7-4a99-83d3-cf57270d3b04" />


**Real-time scam interruption via layered inference.**  
Rules · Classifier · Semantic Search · LLM Reasoning

[![Tests](https://img.shields.io/badge/adversarial_tests-74.0%25-brightgreen?style=flat-square)]()
[![Layers](https://img.shields.io/badge/inference_layers-4-blue?style=flat-square)]()
[![Claude](https://img.shields.io/badge/LLM-layer_4_only-orange?style=flat-square)]()
[![Local](https://img.shields.io/badge/inference-local--first-purple?style=flat-square)]()

 https://scamshieldai.vercel.app/ · [Architecture](#architecture) · [Validation](#validation)

</div>

---

 





---

## The Problem

In 2025, India received 32.4 Million cyber fraud complaints. 2.2 Billion Dollars lost.
Digital arrest scams — where victims are held on continuous video calls by
impersonators of CBI, TRAI, or RBI — averaged ₹1,56,502 per victim.

Awareness campaigns exist. They don't work at the moment of manipulation.
The intervention has to be real-time, on-device, and low-friction enough
for a 70-year-old to use in a panic.

---

## What We Built

ScamShield analyzes suspicious conversations — text, voice, or screenshots —
and returns a structured verdict in under 2 seconds: **SCAM**, **SUSPICIOUS**,
or **SAFE**, with the specific behavioral patterns that triggered it,
in the user's language, with a one-tap path to the national cyber helpline (1930).

The system is not a single model call. It is a four-layer inference pipeline
where the LLM is the last resort, not the first.

---

## Architecture
Input  ──────────────────────────────────────────────────────────▶  Verdict
│
▼
 
│  Layer 1 · Rules Engine                                         │
│  60+ compiled regex patterns · Hinglish-aware · <10ms · local   │
│  Catches: forced call-retention, time-pressure, OTP demands,    │
│  fake FIR formats, digital arrest terminology                   │
 
inconclusive │

▼
 
│  Layer 2 · ML Classifier                                        │
│  TF-IDF + LogisticRegression · n-gram (1,3) · local            │
│  STT noise correction · Hinglish normalization                  │
│  Trained on adversarial + synthetic corpus                      │
 
inconclusive │

▼
 
│  Layer 3 · Semantic Vector Store                                │
│  Sentence-Transformers embeddings · cosine similarity · local   │
│  500+ verified scam pattern library · RAG retrieval             │
│  Handles novel phrasing that rules and classifier miss          │

▼

inconclusive │
 
│  Layer 4 · LLM Reasoning                                        │
│  Claude API · handles genuinely ambiguous / novel cases         │
│  Invoked only when layers 1–3 return low-confidence verdicts    │
│  Has deterministic fallback if API unavailable                  │
 
│

▼


Structured verdict + Incident Report

**On network dependency**: Layers 1–3 are fully local. Layer 4 uses the Claude API.
Voice transcription uses a network-assisted STT service; the transcription layer
is a modular input adapter — the inference stack above it is independent of
how text arrives. A local STT engine (Whisper) can be substituted without
changing the detection logic.

---

## Validation

We built a closed-loop testing framework rather than relying on manual assessment.

  Adversarial Test Harness — ScamShield v1                   
                                                             
  Verdict accuracy  : 74.0%  (54/73 cases)                
  False positive    : 1  (rate 3.1%)                      
  False negative    : 0  (rate 0.0%)                       
  Trend accuracy    : 90.4%                                  
                                                             
  System health    : ✗ NEEDS WORK (<75% accuracy — review patches)                             
 

### Test Infrastructure

| Component | What it does |
|---|---|
| `conversation_generator.py` | Generates adversarial synthetic conversations across 6 categories: STT noise, Hinglish, business fraud, romance scams, false positives, evolving tactics |
| `test_runner.py` | Runs all cases against the live API with retry logic and structured result capture |
| `evaluator.py` | Computes accuracy, FP/FN rates, trend accuracy, per-category breakdowns |
| `improvement_engine.py` | Analyzes failures and generates targeted rule patches and classifier retraining suggestions automatically |
| `run_history.json` | Tracks accuracy metrics across iterations — the system is measurably self-improving |

The improvement engine means we don't manually review failures — we generate
structured patch candidates and apply them. This is the loop that compounds.

---

## Failure Modes

We stress-tested the system against its own failure modes before submission.

| Failure | Behavior |
|---|---|
| Ambiguous verdict confidence | Always routes to **SUSPICIOUS** + 1930 referral. Never suppresses uncertainty. |
| False positive (real police call flagged) | UI states: "Verify by calling the official station number." Does not block action. |
| Layer 4 API unavailable | Falls back to Layer 3 verdict. Degraded but functional. All local layers remain. |
| Novel scam phrasing | Layer 3 semantic matching catches rephrased patterns. Layer 4 handles remainder. |
| STT transcription failure | Falls back to text input. Core inference stack unaffected. |

The asymmetry is intentional: a false alarm costs two minutes. A missed scam
costs ₹1,56,502. We weight the system accordingly.

---

## Output

ScamShield produces two artifacts per analysis:

**Verdict Card** — returned in under 2 seconds:
- SCAM / SUSPICIOUS / SAFE with confidence level
- 2–3 specific behavioral patterns that triggered the verdict, in plain language
- One-tap access to national cyber helpline: 1930
- Available in Hindi, English

**Incident Report** — generated on request:
- Caller number, transcript snippet, matched pattern, timestamp
- Formatted for filing at cybercrime.gov.in or sharing with family

---

## Next Engineering Milestones

These are scoped, not speculative:

1. **Local STT** — swap network-assisted transcription for Whisper Tiny; requires
   no changes to the inference stack; estimated 2–3 days of integration work
2. **Vision pipeline** — WhatsApp screenshot → OCR → analysis; Layer 1 already
   handles the text; input adapter needs building
3. **I4C database sync** — daily pull from the national scam pattern repository;
   feeds Layer 3 vector store; straightforward ETL work
4. **Backend deployment** — currently local; containerisation and cloud deployment
   is standard infrastructure work, not architecture work

---

## Setup

## Deployment Modes

ScamShield currently supports two runtime modes:

| Mode | Description |
|---|---|
| **Hosted Demo (Recommended)** | Frontend deployed on Vercel with backend hosted on Render free-tier infrastructure |
| **Local Full Inference Mode** | Run frontend + backend locally for faster response times and unrestricted inference |

### Hosted Demo

Live frontend:
https://scamshieldai.vercel.app/

The public demo uses:
- Vercel frontend hosting
- Render free-tier backend
- Cost-optimized infrastructure

Because Render free-tier instances sleep when inactive, the first request may take several seconds while the inference server wakes up.

The application now includes:
- backend wake-up detection
- realtime loading stages
- graceful retry handling
- degraded-mode recovery states

to ensure the interface never appears frozen.

---

### Local Full Inference Mode (Recommended for judges / testing)

For the best experience:
- run the backend locally
- switch the frontend API endpoint to localhost

This removes:
- Render cold starts
- free-tier latency
- backend sleep delays

#### Step 1 — Start backend locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

### Backend (local inference stack)
```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend (deployed on Vercel)
```bash
cd frontend && npm install && npm run dev
```

### Run adversarial test suite
```bash
python run_tests.py
```

### Train / retrain classifier
```bash
python train_classifier.py
```

### Run improvement engine on failures
```bash
python run_tests.py --eval-only
```

---

<div align="center">

Built at **AIC × Anthropic Claude Hackathon, IIT Bombay** — May 2026  
Track: Governance & Collaboration

</div>
