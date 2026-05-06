"""
train_classifier.py — Trains TF-IDF + LogisticRegression scam classifier (v2).
Improvements:
  - Enhanced preprocessing with STT noise handling
  - Class weighting for imbalanced data
  - n-gram range (1,3) with sublinear TF
  - Full metrics: accuracy, precision, recall, F1
  - Edge case test suite
  - Cross-validation for generalization check
"""
import pickle
import json
import os
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    classification_report, confusion_matrix,
)
import numpy as np


# ═══════════════════════════════════════════════════════════════
#  PREPROCESSING
# ═══════════════════════════════════════════════════════════════

# Common STT misspellings → canonical forms
STT_CORRECTIONS = {
    "warant": "warrant", "arested": "arrested", "acount": "account",
    "transfor": "transfer", "immediate lee": "immediately",
    "dijital": "digital", "offcer": "officer", "depart meant": "department",
    "very fi cation": "verification", "suspishus": "suspicious",
    "prosessing": "processing", "crimnal": "criminal",
    "athority": "authority", "pay meant": "payment",
    "goverment": "government", "frodulent": "fraudulent",
    "complience": "compliance", "investgation": "investigation",
    "immidiately": "immediately", "immediatly": "immediately",
    "acnt": "account", "trnsfr": "transfer", "mny": "money",
    "numbr": "number", "paymt": "payment", "recieve": "receive",
    "verifcation": "verification",
}

# Hinglish → English normalization
HINGLISH_MAP = {
    "sirji": "sir", "kripya": "please", "turant": "immediately",
    "paisa": "money", "suniye": "listen", "samjhiye": "understand",
    "aapka": "your", "police wale": "police",
}

# Filler words from STT
STT_FILLERS = {"uh", "um", "like", "basically", "you know"}


def preprocess(text: str) -> str:
    """Enhanced preprocessing for noisy real-world input."""
    text = text.lower().strip()

    # STT correction pass
    for wrong, right in STT_CORRECTIONS.items():
        text = text.replace(wrong, right)

    # Hinglish normalization
    for hin, eng in HINGLISH_MAP.items():
        text = text.replace(hin, eng)

    # Remove STT fillers
    words = text.split()
    words = [w for w in words if w not in STT_FILLERS]
    text = " ".join(words)

    # Abbreviation expansion
    text = re.sub(r'\bur\b', 'your', text)
    text = re.sub(r'\bpls\b', 'please', text)
    text = re.sub(r'\bbcoz\b', 'because', text)
    text = re.sub(r'\basap\b', 'as soon as possible', text)

    # Normalize patterns
    text = re.sub(r'\d{10,}', 'PHONENUMBER', text)
    text = re.sub(r'\brs\.?\s*[\d,]+', 'MONEY', text, flags=re.I)
    text = re.sub(r'\$\s*[\d,]+', 'MONEY', text)
    text = re.sub(r'\b\d{4,}\b', 'NUM', text)  # Long numbers only
    text = re.sub(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', 'EMAIL', text)
    text = re.sub(r'https?://\S+', 'URL', text)

    # Clean punctuation but keep structure
    text = re.sub(r'[^\w\s]', ' ', text).strip()
    text = re.sub(r'\s+', ' ', text)

    return text


# ═══════════════════════════════════════════════════════════════
#  TRAINING
# ═══════════════════════════════════════════════════════════════

def train():
    if not os.path.exists("dataset.json"):
        print("ERROR: Run data_generator.py first!")
        return

    with open("dataset.json") as f:
        data = json.load(f)

    print(f"Dataset: {len(data)} samples")
    print(f"  Scam:  {sum(1 for d in data if d['label'] == 1)}")
    print(f"  Safe:  {sum(1 for d in data if d['label'] == 0)}")
    print()

    texts = [preprocess(d["text"]) for d in data]
    labels = [d["label"] for d in data]

    # Stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    # TF-IDF with trigrams
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 3),
        max_features=12000,
        sublinear_tf=True,
        min_df=2,
        max_df=0.95,
        strip_accents="unicode",
    )

    # Logistic Regression with balanced class weights
    clf = LogisticRegression(
        C=1.5,
        max_iter=2000,
        class_weight="balanced",
        solver="lbfgs",
        penalty="l2",
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    clf.fit(X_train_vec, y_train)

    # Evaluation
    X_test_vec = vectorizer.transform(X_test)
    y_pred = clf.predict(X_test_vec)

    print("═" * 50)
    print("  TEST SET METRICS")
    print("═" * 50)
    print(f"  Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"  Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"  Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"  F1 Score:  {f1_score(y_test, y_pred):.4f}")
    print()
    print(classification_report(y_test, y_pred, target_names=["SAFE", "SCAM"]))

    cm = confusion_matrix(y_test, y_pred)
    print("Confusion Matrix:")
    print(f"  TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"  FN={cm[1][0]}  TP={cm[1][1]}")
    print()

    # Cross-validation for generalization check
    print("Cross-validation (5-fold)...")
    X_all_vec = vectorizer.transform(texts)
    cv_scores = cross_val_score(clf, X_all_vec, labels, cv=5, scoring="f1")
    print(f"  F1 scores: {[f'{s:.4f}' for s in cv_scores]}")
    print(f"  Mean F1:   {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print()

    # Save
    with open("model.pkl", "wb") as f:
        pickle.dump(clf, f)
    with open("vectorizer.pkl", "wb") as f:
        pickle.dump(vectorizer, f)
    print("Saved → model.pkl, vectorizer.pkl")

    # Run edge case tests
    print()
    test_edge_cases(clf, vectorizer)


# ═══════════════════════════════════════════════════════════════
#  EDGE CASE TESTING
# ═══════════════════════════════════════════════════════════════

EDGE_CASES = [
    # (text, expected_label, description)
    (
        "I am DCP Sharma from Mumbai Police. Your Aadhaar is linked to money laundering. "
        "Pay Rs 50,000 immediately or you will be arrested within 2 hours.",
        1, "Obvious authority scam"
    ),
    (
        "Hi, this is Priya from HDFC Bank. We noticed unusual activity on your account. "
        "Can you confirm the OTP we just sent?",
        1, "Subtle OTP phishing"
    ),
    (
        "Your SBI account XX3847 was debited Rs 25,000 on 15-Jan-2025. "
        "If not done by you, call 18002026161.",
        0, "Legitimate bank alert"
    ),
    (
        "Mom, someone tried to scam me today! They asked me to pay a fine. I didn't fall for it.",
        0, "Safe discussion about scams"
    ),
    (
        "Papa collapsed. We need Rs 1,00,000 for the ICU deposit RIGHT NOW. "
        "Please don't tell anyone. Send to UPI: helpdesk.verify@oksbi",
        1, "Emotional manipulation scam"
    ),
    (
        "Hey Priya, this is Rajiv Sir. I need you to process a wire transfer of Rs 2,50,000 "
        "to a vendor urgently. Keep this confidential.",
        1, "BEC / corporate scam"
    ),
    (
        "Reminder: Never share your OTP with anyone. HDFC Bank will never ask for it.",
        0, "Bank safety advisory"
    ),
    (
        "Dijital arest warant has been issued. Stay on the call. "
        "Do not disconnect. Pay Rs 1,00,000 to safe vault acount.",
        1, "STT-noisy digital arrest scam"
    ),
    (
        "Your Zomato order has been delivered. Rate your experience.",
        0, "Normal delivery notification"
    ),
    (
        "I know we just met online but I feel a deep connection. "
        "I'm stuck and need Rs 25,000 for my flight. I promise I'll pay back.",
        1, "Romance scam"
    ),
]


def test_edge_cases(clf=None, vectorizer=None):
    """Test classifier against adversarial edge cases."""
    if clf is None or vectorizer is None:
        base = os.path.dirname(__file__) or "."
        try:
            with open(os.path.join(base, "model.pkl"), "rb") as f:
                clf = pickle.load(f)
            with open(os.path.join(base, "vectorizer.pkl"), "rb") as f:
                vectorizer = pickle.load(f)
        except FileNotFoundError:
            print("ERROR: model.pkl / vectorizer.pkl not found. Train first!")
            return

    print("═" * 60)
    print("  EDGE CASE TEST SUITE")
    print("═" * 60)

    passed = 0
    failed = 0

    for i, (text, expected, desc) in enumerate(EDGE_CASES, 1):
        processed = preprocess(text)
        vec = vectorizer.transform([processed])
        prob = clf.predict_proba(vec)[0][1]
        predicted = 1 if prob >= 0.5 else 0
        status = "PASS" if predicted == expected else "FAIL"

        if status == "PASS":
            passed += 1
        else:
            failed += 1

        label_str = "SCAM" if predicted == 1 else "SAFE"
        expected_str = "SCAM" if expected == 1 else "SAFE"
        icon = "✓" if status == "PASS" else "✗"

        print(f"  {icon} Case {i:2d}: {status} | Pred: {label_str} ({prob:.3f}) | Expected: {expected_str}")
        print(f"           {desc}")
        if status == "FAIL":
            print(f"           TEXT: {text[:80]}...")
        print()

    print(f"  Results: {passed}/{passed + failed} passed ({passed/(passed+failed)*100:.0f}%)")
    print("═" * 60)


if __name__ == "__main__":
    train()