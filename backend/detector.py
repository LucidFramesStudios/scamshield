"""
detector.py — Multi-layer scam detection engine (v4).
Pipeline: Rule Engine → ML Classifier → Vector Search → Conversation Intelligence → Smart Aggregator

New in v4:
  - analyze_conversation(messages[]) entry point
  - Relationship detection (casual vs formal vs authority)
  - Money intent scoring (requests, repetition, amounts)
  - Escalation pattern detection (phase progression)
  - Emotional manipulation scoring (panic/guilt/fear)
  - Consistency / anomaly scoring
  - Weighted conversation_score blended into final verdict
  - Multi-tier verdict: SCAM / SUSPICIOUS / SAFE
  - Human-readable explainability reasons
"""
import os
import re
import pickle
import threading
import rules

# ── 1. Lazy-load Vector Store ─────────────────────────────
_vs = None
_vs_lock = threading.Lock()


def _get_vs():
    global _vs
    if _vs is None:
        with _vs_lock:
            if _vs is None:
                try:
                    import vector_store as _vs_mod
                    _vs = _vs_mod
                except Exception as e:
                    print(f"[VECTOR] Unavailable: {e}")
                    _vs = False
    return _vs if _vs else None


# ── 2. ML Model Thread-Safe Loading ──────────────────────
_clf = None
_vec = None
_model_lock = threading.Lock()

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
    # PATCH: phonetic spoken-form expansions (STT artefacts)
    "you pee eye": "upi",
    "you pee i": "upi",
    "eye pee ess": "ips",
    "eye p s": "ips",
    "war rant": "warrant",
    "war-rant": "warrant",
    "non bail able": "non-bailable",
    "non bailable": "non-bailable",
    "bail able": "bailable",
    "otpee": "otp",
    "o t p": "otp",
    "o tp": "otp",
    "ot p": "otp",
    "c v v": "cvv",
    "see vee vee": "cvv",
    "girftari": "arrest",
    "giraftari": "arrest",
    "bhejo": "send",
    "band ho jayega": "will be blocked",
    "a count": "account",
    "pleese": "please",
    "reverify": "re-verify",
}

HINGLISH_MAP = {
    "sirji": "sir", "kripya": "please", "turant": "immediately",
    "paisa": "money", "suniye": "listen", "samjhiye": "understand",
    "aapka": "your", "police wale": "police",
    # PATCH: expanded Hinglish threat/money vocabulary
    "paisa bhejo": "send money",
    "paise bhejo": "send money",
    "rupaye bhejo": "send rupees",
    "abhi bhejo": "send immediately",
    "girftari hogi": "arrest will happen",
    "giraftari hogi": "arrest will happen",
    "band ho jayega": "will be blocked",
    "band kar denge": "will block",
    "gir ftari": "arrest",
    "khata": "account",
    "khata band": "account blocked",
    "nahi batana": "do not tell",
    "darr": "fear",
    "dhamki": "threat",
    "kehra": "case",
    "jama karo": "deposit",
    "turant paisa": "send money immediately",
    "warna": "otherwise",
    "pareshaan": "distress",
}

STT_FILLERS = {"uh", "um", "like", "basically", "you know"}

META_INDICATORS = [
    r'\b(?:someone|they)\s+tried\s+to\s+scam\b',
    r'\b(?:don.t|do\s+not|never)\s+(?:fall\s+for|share|give)\b',
    r'\bit.s\s+a\s+scam\b',
    r'\bscam\s+(?:alert|warning|awareness)\b',
    r'\breport\s+(?:to\s+(?:police|cyber|authorities)|it\s+(?:to|as\s+(?:scam|fraud)))\b',
    r'\b(?:fake|fraud)\s+(?:call|message|text)\b',
    r'\bif\s+not\s+(?:done\s+by|initiated\s+by)\s+you\b',
    r'\bwill\s+never\s+ask\s+for\b',
    r'\btraining\s+(?:module|session|program)\b',
    r'\bnews\s+article\b',
    r'\bauthorities\s+(?:urge|warn|advise)\b',
    r'\bnearest\s+branch\b',
    # PATCH: additional bank-legitimacy meta patterns
    r'\bif\s+(?:not\s+)?(?:authorised|authorized)\s+by\s+you\b',
    r'\bcall\s+(?:our\s+)?(?:helpline|toll.?free|1800)\b',
    r'\bdo\s+not\s+share\s+(?:otp|pin|password)\s+with\s+anyone\b',
    r'\bwe\s+(?:will\s+)?never\s+(?:call|ask)\b',
    r'\bxxxx\d{4}\b',
    r'\bnever\s+ask\s+(?:for\s+)?(?:your\s+)?otp\b',
    r'\bpeople\s+need\s+to\s+know\b',
    r'\breal\s+police\s+will\s+never\b',
]
COMPILED_META = [re.compile(p, re.IGNORECASE) for p in META_INDICATORS]


def _load_model():
    global _clf, _vec
    if _clf is not None:
        return True
    with _model_lock:
        if _clf is not None:
            return True
        try:
            base = os.path.dirname(__file__) or "."
            with open(os.path.join(base, "model.pkl"), "rb") as f:
                _clf = pickle.load(f)
            with open(os.path.join(base, "vectorizer.pkl"), "rb") as f:
                _vec = pickle.load(f)
            return True
        except Exception:
            return False


threading.Thread(target=_load_model, daemon=True).start()


def preprocess(text: str) -> str:
    # PATCH: normalise Unicode lookalikes before any regex/dict matching
    import unicodedata
    text = unicodedata.normalize("NFKD", text)
    # Map common Cyrillic/Greek lookalikes to Latin equivalents
    _UNICODE_MAP = str.maketrans({
        '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
        '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
        '\u0410': 'A', '\u0415': 'E', '\u041e': 'O', '\u0420': 'P',
        '\u0421': 'C', '\u0423': 'Y', '\u0425': 'X',
    })
    text = text.translate(_UNICODE_MAP)
    text = text.encode("ascii", errors="ignore").decode("ascii")
    # Map common digit-for-letter substitutions (0→o, etc.) only adjacent to letters
    _LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "@": "a"})
    text = re.sub(r'(?<=[a-zA-Z])[0134@]|[0134@](?=[a-zA-Z])', lambda m: m.group().translate(_LEET), text)
    text = text.lower().strip()
    for wrong, right in STT_CORRECTIONS.items():
        text = text.replace(wrong, right)
    for hin, eng in HINGLISH_MAP.items():
        text = text.replace(hin, eng)
    words = text.split()
    words = [w for w in words if w not in STT_FILLERS]
    text = " ".join(words)
    text = re.sub(r'\bur\b', 'your', text)
    text = re.sub(r'\bpls\b', 'please', text)
    text = re.sub(r'\bbcoz\b', 'because', text)
    text = re.sub(r'\basap\b', 'as soon as possible', text)
    text = re.sub(r'\d{10,}', 'PHONENUMBER', text)
    # PATCH: normalise spoken number denominations → MONEY tokens
    _WORD_AMOUNTS = [
        (r'\b(one|two|three|four|five|six|seven|eight|nine|ten|'
         r'twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|'
         r'hundred|thousand|lakh|crore)\s+(thousand|lakh|crore|rupees?|dollars?)\b',
         'MONEY'),
        (r'\b(one|two|three|four|five|ten|twenty|fifty|hundred)\s+thousand\b', 'MONEY'),
        (r'\b\d+\s+(thousand|lakh|crore)\s+(rupees?|rs\.?)\b', 'MONEY'),
    ]
    for _pat, _rep in _WORD_AMOUNTS:
        text = re.sub(_pat, _rep, text, flags=re.IGNORECASE)
    text = re.sub(r'\brs\.?\s*[\d,]+', 'MONEY', text, flags=re.I)
    text = re.sub(r'\$\s*[\d,]+', 'MONEY', text)
    text = re.sub(r'\b\d{4,}\b', 'NUM', text)
    text = re.sub(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', 'EMAIL', text)
    text = re.sub(r'https?://\S+', 'URL', text)
    text = re.sub(r'[^\w\s]', ' ', text).strip()
    text = re.sub(r'\s+', ' ', text)
    return text


def classify_text(text: str) -> float:
    if not _load_model():
        return 0.5
    try:
        vec = _vec.transform([preprocess(text)])
        return float(_clf.predict_proba(vec)[0][1])
    except Exception:
        return 0.5


def _is_meta_discussion(text: str) -> bool:
    return any(p.search(text) for p in COMPILED_META)


def _vector_score(text: str) -> tuple:
    vs = _get_vs()
    if vs is None:
        return 0.0, {}
    try:
        result = vs.search(text, threshold=0.62)
        if result.get("verdict") == "SCAM":
            for r in result.get("reasons", []):
                m = re.search(r'(\d+\.?\d*)%', r)
                if m:
                    return float(m.group(1)) / 100.0, result
            return 0.75, result
        return 0.0, result
    except Exception:
        return 0.0, {}


# ═══════════════════════════════════════════════════════════
#  CONVERSATION FEATURE ENGINE
# ═══════════════════════════════════════════════════════════

# ── Relationship Detection ────────────────────────────────
_CASUAL_SIGNALS = re.compile(
    r'\b(bro|dude|hey|mate|buddy|yaar|pal|boss|man|bhai|friend)\b',
    re.IGNORECASE
)
_FORMAL_SIGNALS = re.compile(
    r'\b(sir|dear\s+customer|dear\s+sir|ma.?am|respected|greetings|valued\s+customer)\b',
    re.IGNORECASE
)
_AUTHORITY_CLAIMS = re.compile(
    r'\b(officer|inspector|department|ministry|cbi|ed|income\s+tax|cyber\s+cell|'
    r'police|government|official|rbi|sebi|narcotics|enforcement|authority|commissioner)\b',
    re.IGNORECASE
)
_IDENTITY_WEAK = re.compile(
    r'\b(i\s+am\s+calling\s+from|this\s+is\s+(?:a\s+)?(?:call|message)\s+from|'
    r'we\s+are\s+(?:from|the)|on\s+behalf\s+of)\b',
    re.IGNORECASE
)


def score_relationship(messages: list) -> tuple:
    """
    Returns (relationship_score 0→1, reasons[]).
    0 = known/trusted, 1 = unknown/suspicious.
    """
    other_text = " ".join(m["text"] for m in messages if m["role"] == "other")
    if not other_text:
        return 0.0, []

    reasons = []
    score = 0.5  # neutral baseline

    casual_hits = len(_CASUAL_SIGNALS.findall(other_text))
    formal_hits = len(_FORMAL_SIGNALS.findall(other_text))
    authority_hits = len(_AUTHORITY_CLAIMS.findall(other_text))
    weak_identity = bool(_IDENTITY_WEAK.search(other_text))

    # Casual signals → likely known person → reduce score
    if casual_hits >= 2:
        score -= 0.25
        reasons.append("Casual familiar tone suggests known contact")
    elif casual_hits == 1:
        score -= 0.10

    # Authority tone without casual → raise risk
    if authority_hits >= 2 and casual_hits == 0:
        score += 0.15
        reasons.append("Repeated authority language with no casual rapport signals")

    # Formal without prior context → unknown
    if formal_hits >= 1 and casual_hits == 0:
        score += 0.20
        reasons.append("Formal/impersonal tone from an unverified contact")

    # Authority claims → high risk — PATCH: reduce when no demand context
    _HAS_DEMAND = re.compile(
        r'\b(otp|pin|cvv|upi|neft|rtgs|send|transfer|pay|deposit|wire|share)\b',
        re.IGNORECASE
    )
    authority_has_demand = bool(_HAS_DEMAND.search(other_text))
    if authority_hits >= 1:
        if authority_has_demand:
            score += 0.35
            reasons.append("Caller claims to be a government/law-enforcement authority")
        else:
            score += 0.15
            reasons.append("Authority language detected — monitoring for demand signals")

    # Weak identity assertion
    if weak_identity:
        score += 0.15
        reasons.append("Unverified identity assertion detected")

    return min(max(score, 0.0), 1.0), reasons


# ── Money Intent Detection ────────────────────────────────
_MONEY_REQUEST = re.compile(
    r'(?:'
    # Pattern A — verb + financial noun (original core, verbs + nouns widened)
    r'\b(?:send|transfer|pay|deposit|wire|give|provide|need|want|require|lend|refund|'
    r'reimburse|settle|clear|arrange|collect|release|load|top.?up)\b.{0,30}'
    r'\b(?:money|amount|cash|funds|rupees?|rs\.?|inr|\$|usd|payment|fee|fine|'
    r'charge|penalty|balance|dues?|sum|total|back|advance|wallet)\b'
    r'|'
    # Pattern B — repayment / debt framing
    r'\b(?:give\s+back|pay\s+back|return\s+(?:the\s+)?money|paid\s+for|i\s+paid|'
    r'you\s+owe(?:\s+me)?|owe\s+(?:me|us)|money\s+back|get\s+(?:my|the)\s+money|'
    r'return\s+(?:my|the|your)\s+(?:money|amount|cash|dues?)|refund\s+(?:my|the|me)|'
    r'need\s+(?:it|that)\s+back|give\s+me\s+back)\b'
    r'|'
    # Pattern C — amount-first / implicit demand idioms
    r'\b(?:amount\s+(?:due|pending|owed|needed|of)|owing\s+(?:me|us)|'
    r'settle\s+(?:up|the\s+(?:amount|dues?|balance|debt))|'
    r'clear\s+(?:my|the|your)\s+(?:dues?|balance|debt)|'
    r'paid\s+(?:already|you|him|them|on\s+your\s+behalf)|'
    r'i\s+(?:have\s+)?already\s+paid|spent\s+(?:for|on)\s+you)\b'
    r')',
    re.IGNORECASE
)
_AMOUNT_PATTERN = re.compile(
    r'\b(rs\.?\s*[\d,]+|inr\s*[\d,]+|\$\s*[\d,]+|[\d,]+\s*(?:rupees?|dollars?|lakhs?|crores?))\b',
    re.IGNORECASE
)
_TRANSFER_METHODS = re.compile(
    r'\b(upi|neft|rtgs|imps|paytm|phonepe|googlepay|gpay|bank\s+transfer|wire\s+transfer|'
    r'account\s+number|ifsc|crypto|bitcoin)\b',
    re.IGNORECASE
)


def score_money_intent(messages: list) -> tuple:
    """Returns (money_score 0→1, reasons[])."""
    other_msgs = [m for m in messages if m["role"] == "other"]
    other_text = " ".join(m["text"] for m in other_msgs)

    if not other_text:
        return 0.0, []

    reasons = []
    score = 0.0

    request_hits = len(_MONEY_REQUEST.findall(other_text))
    amount_hits = len(_AMOUNT_PATTERN.findall(other_text))
    method_hits = len(_TRANSFER_METHODS.findall(other_text))

    # Repeated money requests across multiple turns
    turns_with_money = sum(
        1 for m in other_msgs
        if _MONEY_REQUEST.search(m["text"]) or _AMOUNT_PATTERN.search(m["text"])
    )

    if request_hits >= 1:
        score += 0.30
        reasons.append("Monetary request detected from other party")
    if request_hits >= 3:
        score += 0.20
        reasons.append("Repeated money demands across conversation")
    if amount_hits >= 1:
        score += 0.15
        reasons.append("Specific financial amount mentioned")
    if method_hits >= 1:
        score += 0.20
        reasons.append("Payment transfer method specified (UPI/NEFT/RTGS/crypto)")
    if turns_with_money >= 2:
        score += 0.15
        reasons.append("Multiple conversation turns involve financial requests")

    # Early money request: demand before rapport is established
    if request_hits >= 1 and len(messages) < 3:
        score += 0.20
        reasons.append("Money requested at conversation start — no rapport established")

    return min(score, 1.0), reasons 


# ── Escalation Detection ──────────────────────────────────
_URGENCY_WORDS = re.compile(
    r'\b(immediately|urgent|right\s+now|asap|as\s+soon\s+as\s+possible|within\s+\d+\s+(?:minutes?|hours?)'
    r'|before\s+(?:it\'?s?\s+too\s+late|midnight|tonight)|no\s+time|last\s+chance|final\s+notice)\b',
    re.IGNORECASE
)
_PRESSURE_WORDS = re.compile(
    r'\b(or\s+else|otherwise|consequences|serious\s+action|legal\s+action|arrest|warrant|'
    r'FIR|court|jail|freeze|blocked|suspended|cancelled|terminated)\b',
    re.IGNORECASE
)
_NEUTRAL_OPENERS = re.compile(
    r'\b(hello|hi|good\s+(?:morning|afternoon|evening)|how\s+are\s+you|hope\s+you\'?re)\b',
    re.IGNORECASE
)


def score_escalation(messages: list) -> tuple:
    """
    Detects progression: neutral → request → urgency → pressure/threat.
    Returns (escalation_score 0→1, reasons[]).
    """
    other_msgs = [m for m in messages if m["role"] == "other"]
    if len(other_msgs) < 2:
        return 0.0, []

    reasons = []
    score = 0.0

    # Phase tagging per message
    phases = []
    for m in other_msgs:
        t = m["text"]
        has_neutral = bool(_NEUTRAL_OPENERS.search(t))
        has_money = bool(_MONEY_REQUEST.search(t) or _AMOUNT_PATTERN.search(t))
        has_urgency = bool(_URGENCY_WORDS.search(t))
        has_pressure = bool(_PRESSURE_WORDS.search(t))

        if has_pressure:
            phases.append(3)
        elif has_urgency:
            phases.append(2)
        elif has_money:
            phases.append(1)
        elif has_neutral:
            phases.append(0)
        else:
            phases.append(0)

    # Detect escalating progression
    max_phase = max(phases)
    min_phase = min(phases)
    phase_range = max_phase - min_phase

    if phase_range >= 3:
        score = 0.95
        reasons.append("Severe escalation: conversation moved from friendly to threatening")
    elif phase_range >= 2:
        score = 0.70
        reasons.append("Significant escalation: urgency and pressure introduced mid-conversation")
    elif phase_range >= 1:
        score = 0.40
        reasons.append("Mild escalation: tone shifted toward urgency")

    # Direct threat presence
    if max_phase == 3:
        score = max(score, 0.75)
        reasons.append("Threats or legal pressure detected (arrest/warrant/FIR)")

    # Urgency without prior rapport (first message already urgent)
    if phases and phases[0] >= 2:
        score = max(score, 0.55)
        reasons.append("Conversation opened with immediate urgency — no rapport building")

    return min(score, 1.0), reasons


# ── Emotional Manipulation Detection ─────────────────────
_PANIC_WORDS = re.compile(
    r'\b(urgent|emergency|immediately|crisis|disaster|critical|panic|now|right\s+now|'
    r'today\s+only|expires?|deadline)\b',
    re.IGNORECASE
)
_GUILT_WORDS = re.compile(
    r'\b(please\s+help|i\s+need\s+you|only\s+you\s+can|trust\s+me|believe\s+me|'
    r'for\s+my\s+sake|i\'?m\s+begging|desperate|no\s+one\s+else)\b',
    re.IGNORECASE
)
_FEAR_WORDS = re.compile(
    r'\b(arrested?|jail|prison|blocked|frozen|suspended|seized|summons?|court|'
    r'criminal\s+case|FIR|chargesheet|penalty|blacklisted|locked)\b',
    re.IGNORECASE
)
_FLATTERY_WORDS = re.compile(
    r'\b(congratulations?|you\s+(?:have\s+)?won|lucky\s+winner|selected|chosen|'
    r'exclusive\s+offer|special\s+reward|prize)\b',
    re.IGNORECASE
)


def score_emotional_manipulation(messages: list) -> tuple:
    """Returns (emotion_score 0→1, reasons[])."""
    other_text = " ".join(m["text"] for m in messages if m["role"] == "other")
    if not other_text:
        return 0.0, []

    reasons = []
    score = 0.0

    panic_count = len(_PANIC_WORDS.findall(other_text))
    guilt_count = len(_GUILT_WORDS.findall(other_text))
    fear_count = len(_FEAR_WORDS.findall(other_text))
    flattery_count = len(_FLATTERY_WORDS.findall(other_text))

    if panic_count >= 3:
        score += 0.30
        reasons.append("High-frequency urgency language creating artificial panic")
    elif panic_count >= 1:
        score += 0.15
        reasons.append("Urgency language detected to pressure action")

    if guilt_count >= 1:
        score += 0.25
        reasons.append("Guilt/empathy manipulation detected ('only you can help')")

    if fear_count >= 2:
        score += 0.35
        reasons.append("Fear-inducing language: threats of arrest, account freeze, or legal action")
    elif fear_count >= 1:
        score += 0.15
        reasons.append("Fear language detected (arrest/blocking threats)")

    if flattery_count >= 1:
        score += 0.20
        reasons.append("Flattery/prize bait detected to lower guard")

    # Compound: fear + urgency = high manipulation
    if fear_count >= 1 and panic_count >= 2:
        score += 0.15
        reasons.append("Combination of fear and urgency — classic pressure manipulation")

    return min(score, 1.0), reasons


# ── Consistency / Anomaly Detection ──────────────────────
_KNOWS_ME_SIGNALS = re.compile(
    r'\b(your\s+name\s+is|i\s+know\s+you|we\s+(?:spoke|talked|met)|'
    r'as\s+per\s+your|your\s+(?:account|file|record|case))\b',
    re.IGNORECASE
)
_CLAIMS_AUTHORITY = re.compile(
    r'\b(cbi|ed|income\s+tax|police|government|rbi|sebi|court|ministry|department)\b',
    re.IGNORECASE
)
_ASKS_SECRECY = re.compile(
    r'\b(do\s+not\s+tell|keep\s+(?:this\s+)?(?:secret|confidential|between\s+us)|'
    r'don.t\s+(?:inform|tell|share\s+with)|without\s+telling\s+anyone|'
    r'stay\s+on\s+(?:the\s+)?call|do\s+not\s+(?:disconnect|hang\s+up))\b',
    re.IGNORECASE
)
_CONTEXT_SHIFT = re.compile(
    r'\b(by\s+the\s+way|actually|listen|wait|one\s+more\s+thing|'
    r'before\s+(?:i\s+go|we\s+end)|also\s+(?:need|want|require))\b',
    re.IGNORECASE
)
_FAKE_FAMILIARITY = re.compile(
    r'\b(we\s+met|remember\s+me|you\s+know\s+me|we\s+spoke\s+before|'
    r'i\s+(?:called|messaged)\s+you\s+(?:before|earlier|last\s+(?:week|month|time))|'
    # PATCH: event/platform-based familiarity gambits
    r'we\s+(?:were\s+)?(?:at|in)\s+the\s+same|'
    r'i\s+think\s+we\s+(?:know\s+each\s+other|met)|'
    r'(?:saw|spotted|noticed)\s+you\s+(?:at|in)|'
    r'connected\s+(?:at|through|via)|'
    r'mutual\s+(?:friend|contact|connection)|'
    r'(?:same\s+(?:batch|college|company|event|conference|school|seminar|club))|'
    r'we\s+spoke\s+earlier|'
    r'you\s+remember\s+me|'
    r'we\s+met\s+at|'
    r'i\s+was\s+(?:referred|introduced)\s+(?:to\s+you|by))\b',
    re.IGNORECASE
)


def score_anomaly(messages: list) -> tuple:
    """
    Detects behavioral inconsistencies and red-flag patterns.
    Returns (anomaly_score 0→1, reasons[]).
    """
    other_msgs = [m for m in messages if m["role"] == "other"]
    other_text = " ".join(m["text"] for m in other_msgs)
    me_msgs = [m for m in messages if m["role"] == "me"]

    if not other_text:
        return 0.0, []

    reasons = []
    score = 0.0

    has_authority = bool(_CLAIMS_AUTHORITY.search(other_text))
    has_money = bool(_MONEY_REQUEST.search(other_text) or _AMOUNT_PATTERN.search(other_text))
    knows_me = bool(_KNOWS_ME_SIGNALS.search(other_text))
    asks_secrecy = bool(_ASKS_SECRECY.search(other_text))
    context_shift = len(_CONTEXT_SHIFT.findall(other_text))

    fake_familiarity = bool(_FAKE_FAMILIARITY.search(other_text))

    if fake_familiarity:
        score += 0.30
        reasons.append("Unverified familiarity claim — asserting prior relationship without context")

    # Fake familiarity + financial request = high-signal social-engineering pattern
    if fake_familiarity and has_money:
        score += 0.25
        reasons.append("Familiarity claim followed by financial request — strong scam pattern")

    # Gradual trust-building: rapport established first, money asked later
    if fake_familiarity and has_money and len(other_msgs) > 2:
        reasons.append("Gradual trust-building followed by financial request detected")

    # Unknown person + money = core anomaly
    # PATCH: suppress anomaly bonus when strong casual rapport is present
    _CASUAL_PROXY = re.compile(
        r'\b(bro|dude|hey|mate|buddy|yaar|pal|boss|man|bhai|friend)\b', re.IGNORECASE
    )
    casual_proxy_hits = len(_CASUAL_PROXY.findall(other_text))
    if has_money and not knows_me and len(other_msgs) <= 3 and casual_proxy_hits < 2:
        score += 0.40
        reasons.append("Unverified person requesting money with minimal relationship context")
    elif has_money and not knows_me and len(other_msgs) <= 3 and casual_proxy_hits >= 2:
        score += 0.10
        reasons.append("Money request in casual context — low-risk familiarity signal")

    # Authority + money = high risk combination
    if has_authority and has_money:
        score += 0.40
        reasons.append("Authority claim combined with financial demand — common government impersonation pattern")

    # Secrecy requests
    if asks_secrecy:
        score += 0.35
        reasons.append("Secrecy/isolation tactic: instructed not to inform others or hang up")

    # Context shift mid-conversation (bait and switch)
    if context_shift >= 2:
        score += 0.20
        reasons.append("Sudden topic/context shift detected — possible bait-and-switch tactic")

    # One-sided conversation: other party dominates
    if len(other_msgs) > 0 and len(me_msgs) == 0:
        score += 0.10
        reasons.append("One-sided conversation — no response from user recorded")

    # Identity claimed without verification
    if has_authority and not knows_me:
        score += 0.20
        reasons.append("Authority identity claimed but no verifiable personal context established")

    return min(score, 1.0), reasons


# ── Conversation Score Aggregator ─────────────────────────
def compute_conversation_score(messages: list) -> tuple:
    """
    Returns (conversation_score 0→1, sub_scores dict, all_reasons list).
    Weights:
      relationship  0.25
      money         0.25
      escalation    0.20
      emotion       0.15
      anomaly       0.15
    """
    rel_score, rel_reasons = score_relationship(messages)
    mon_score, mon_reasons = score_money_intent(messages)
    esc_score, esc_reasons = score_escalation(messages)
    emo_score, emo_reasons = score_emotional_manipulation(messages)
    ano_score, ano_reasons = score_anomaly(messages)

    conv_score = (
        0.25 * rel_score +
        0.25 * mon_score +
        0.20 * esc_score +
        0.15 * emo_score +
        0.15 * ano_score
    )

    sub_scores = {
        "relationship": round(rel_score, 3),
        "money":        round(mon_score, 3),
        "escalation":   round(esc_score, 3),
        "emotion":      round(emo_score, 3),
        "anomaly":      round(ano_score, 3),
    }

    all_reasons = rel_reasons + mon_reasons + esc_reasons + emo_reasons + ano_reasons

    return min(conv_score, 1.0), sub_scores, all_reasons

# ═══════════════════════════════════════════════════════════
#  PHASE 4 — REAL-TIME ESCALATION / DE-ESCALATION TRACKING
# ═══════════════════════════════════════════════════════════

def _quick_risk_score(messages: list) -> float:
    """
    Lightweight per-step scorer used exclusively by compute_escalation.
    Uses ML + rules only — intentionally skips vector store and full
    conversation analysis to stay fast across N prefix evaluations.
    """
    if not messages:
        return 0.0
    flat       = " ".join(m["text"] for m in messages)
    other_only = " ".join(m["text"] for m in messages if m["role"] == "other")
    ml_s       = classify_text(flat)
    # PATCH: preprocess before rules
    preprocessed_other = preprocess(other_only) if other_only else ""
    rule_data  = rules.check(preprocessed_other) if preprocessed_other else None
    if rule_data:
        match_count = len(rule_data.get("matches", []))
        rule_s = min(0.40 + 0.15 * (match_count - 1), 1.0)
    else:
        rule_s = 0.0
    # PATCH: when ML is default, weight rules more heavily
    if ml_s == 0.5:
        return 0.30 * ml_s + 0.70 * rule_s
    return 0.70 * ml_s + 0.30 * rule_s


def compute_escalation(messages: list) -> tuple:
    """
    Tracks how risk evolves turn-by-turn across the conversation.

    Algorithm:
      1. Score every prefix messages[:i+1] with _quick_risk_score.
      2. Compare the final two step-scores (delta = current − previous).
      3. Classify trend:
           delta > +0.15  → ESCALATING
           delta < −0.15  → DE-ESCALATING
           otherwise      → STABLE

    Returns:
      trend (str)          : "ESCALATING" | "STABLE" | "DE-ESCALATING"
      current_score (float): risk score at the latest step (0→1)

    Edge cases:
      - 0 messages → ("STABLE", 0.0)
      - 1 message  → ("STABLE", score_of_that_message)
        (no prior step to compare; no trend yet)
    """
    n = len(messages)
    if n == 0:
        return "STABLE", 0.0
    if n == 1:
        return "STABLE", _quick_risk_score(messages)

    scores  = [_quick_risk_score(messages[:i + 1]) for i in range(n)]
    current = scores[-1]
    prev    = scores[-2]
    local_delta  = current - prev
    # PATCH: also measure global trajectory (first → last) to catch slow ramps
    global_delta = scores[-1] - scores[0]
    delta = max(local_delta, global_delta * 0.5)

    if delta > 0.15:
        trend = "ESCALATING"
    elif delta < -0.15:
        trend = "DE-ESCALATING"
    else:
        trend = "STABLE"

    return trend, current


# ═══════════════════════════════════════════════════════════
#  FINAL DECISION ENGINE — Conversation-Aware
# ═══════════════════════════════════════════════════════════

def analyze_conversation(messages: list) -> dict:
    """
    Full conversation analysis pipeline.
    messages: [{"role": "me"|"other", "text": "..."}]

    Final score formula:
      final = 0.4*ml + 0.2*rule + 0.1*vector + 0.3*conversation

    Verdicts:
      > 0.75 → SCAM
      > 0.45 → SUSPICIOUS
      else   → SAFE
    """
   # Flatten with explicit role tags for ML context
    flat_text = " ".join(
        f"[{m['role'].upper()}] {m['text']}" for m in messages
    )
    other_only = " ".join(m["text"] for m in messages if m["role"] == "other")

   # ── Layer 1: Rules (strictly on other-party text only) ─
    # PATCH: preprocess other_only before rules to catch STT phonetic bypasses
    preprocessed_other = preprocess(other_only) if other_only else ""
    rule_data = rules.check(preprocessed_other) if preprocessed_other else None
    if rule_data:
        match_count = len(rule_data.get("matches", []))
        raw_rule_score = min(0.40 + 0.15 * (match_count - 1), 1.0)
    else:
        raw_rule_score = 0.0

    # ── Layer 2: ML Classifier ────────────────────────────
    ml_score = classify_text(flat_text)

    # ── Layer 3: Vector ───────────────────────────────────
    vec_score, vec_data = _vector_score(flat_text)

    # ── Layer 4: Conversation Intelligence ───────────────
    # PATCH: preprocess messages for conversation scoring to catch STT bypasses
    preprocessed_messages = [
        {"role": m["role"], "text": preprocess(m["text"])} for m in messages
    ]
    conv_score, sub_scores, conv_reasons = compute_conversation_score(preprocessed_messages)

    # ── Meta-discussion guard ────────────────────────────
    me_text = " ".join(m["text"] for m in messages if m["role"] == "me")
    is_meta = _is_meta_discussion(me_text)  # only safe when user says it
    # PATCH: also detect protective/warning language in other's text
    is_meta = is_meta or _is_meta_discussion(other_only or "")
    other_denies_scam = bool(re.search(
        r'\b('
        r'this\s+is\s+not\s+a\s+scam|not\s+(?:a\s+)?fraud|'
        r'trust\s+me|i\s+am\s+legitimate|'
        r'i\s+am\s+(?:real|genuine|official|verified)|'
        r'this\s+is\s+(?:real|genuine|official|legitimate)|'
        r'it\s+is\s+not\s+(?:fraud|fake|a\s+scam)|'
        r'don.t\s+worry\s+(?:it.s|this\s+is)\s+(?:safe|legitimate|real)|'
        r'we\s+are\s+(?:a\s+)?(?:real|official|genuine|registered)'
        r')\b',
        other_only or "", re.IGNORECASE
    ))
    effective_rule_score = raw_rule_score
    if is_meta and ml_score < 0.60:
        conv_score = conv_score * 0.4  # PATCH: stronger suppression for meta
        effective_rule_score = raw_rule_score * 0.3
    elif ml_score < 0.30 and raw_rule_score >= 0.6:
        effective_rule_score = raw_rule_score * 0.6
    if other_denies_scam:
        # Scammer claiming innocence is itself a red flag
        # PATCH: use conv_reasons instead of undefined 'reasons' variable
        conv_reasons.append("Sender is explicitly denying scam — common manipulation tactic")
        conv_score = min(conv_score + 0.15, 1.0)

    # ── Final Score ───────────────────────────────────────
    # PATCH: When ML returns default 0.5 (model unavailable), redistribute
    # its weight to rules and conversation which have real signal
    ml_is_default = (ml_score == 0.5)
    if ml_is_default:
        # ML has no signal — rely on rules + conversation
        final_score = (
            0.10 * ml_score +
            0.45 * effective_rule_score +
            0.05 * vec_score +
            0.40 * conv_score
        )
    else:
        final_score = (
            0.35 * ml_score +
            0.30 * effective_rule_score +
            0.05 * vec_score +
            0.30 * conv_score
        )

    # ── Phase 4: Escalation Trend ─────────────────────────
    # Runs after final_score so it never influences the verdict,
    # only annotates the response with trajectory context.
    trend, trend_score = compute_escalation(messages)

    # ── Multi-tier Verdict ────────────────────────────────
    # PATCH: strong-signal overrides — if rules fired multiple times or
    # conv_score is very high, push verdict to SCAM even if final_score is borderline
    strong_rule_signal = (raw_rule_score >= 0.55)  # Requires 2+ rule matches
    strong_conv_signal = (conv_score >= 0.45)
    strong_ml_signal = (ml_score >= 0.80)
    # PATCH: direct rule override for multi-match scams (2+ strong patterns)
    # Only if meta-guard hasn't suppressed the rules
    multi_rule_override = (rule_data and len(rule_data.get("matches", [])) >= 2 and 
                           effective_rule_score >= 0.40)

    if final_score > 0.55 or multi_rule_override or \
       (final_score > 0.30 and (strong_rule_signal or strong_conv_signal)):
        verdict = "SCAM"
        if final_score > 0.75:
            conf = "HIGH"
        elif final_score > 0.60:
            conf = "HIGH" if (strong_rule_signal or strong_conv_signal) else "MEDIUM"
        else:
            conf = "MEDIUM"
    elif final_score > 0.25:
        verdict = "SUSPICIOUS"
        conf = "MEDIUM" if final_score > 0.40 else "LOW"
    else:
        verdict = "SAFE"
        conf = "HIGH" if final_score < 0.15 else "MEDIUM"

    # ── Breakdown string ──────────────────────────────────
    breakdown = (
        f"Risk Scores — ML: {ml_score:.2f} | Rules: {raw_rule_score:.2f} (eff: {effective_rule_score:.2f}) | "
        f"Vector: {vec_score:.2f} | Conversation: {conv_score:.2f} "
        f"[rel={sub_scores['relationship']:.2f}, money={sub_scores['money']:.2f}, "
        f"esc={sub_scores['escalation']:.2f}, emo={sub_scores['emotion']:.2f}, "
        f"ano={sub_scores['anomaly']:.2f}]"
    )

    # ── Build response ────────────────────────────────────
    if verdict in ("SCAM", "SUSPICIOUS"):
        reasons = []

        # Conversation intelligence reasons first (human-readable)
        if conv_reasons:
            reasons.extend(conv_reasons)

        # Rule reasons
        if rule_data and effective_rule_score > 0:
            for r in rule_data.get("reasons", []):
                if r not in reasons:
                    reasons.append(r)

        # Vector reasons
        if vec_data and vec_score > 0:
            for r in vec_data.get("reasons", []):
                if r not in reasons:
                    reasons.append(r)

        # ML fallback
        if not reasons:
            reasons.append(
                f"ML classifier detected suspicious patterns ({ml_score * 100:.1f}% probability)"
            )

        # Phase 4: dynamic trend reasons
        if trend == "ESCALATING":
            reasons.append("Risk increasing due to recent messages")
        elif trend == "DE-ESCALATING":
            reasons.append("Conversation risk decreasing")

        reasons.append(breakdown)

        # Actions
        actions = []

        if rule_data and effective_rule_score > 0:
            actions = rule_data.get("actions", [])
        elif vec_data:
            actions = vec_data.get("actions", [])
        if not actions:
            actions = [
                "Hang up or stop responding immediately.",
                "Do NOT share OTP, PIN, or transfer money.",
                "Call Cyber Crime Helpline: 1930",
                "Block and report this contact.",
            ]

        # When SUSPICIOUS + financial signal — override to verification-first actions.
        # "Proceed normally" is never appropriate when money is in scope.
        if verdict == "SUSPICIOUS" and (
            _MONEY_REQUEST.search(other_only or "") or
            _AMOUNT_PATTERN.search(other_only or "")
        ):
            actions = [
                "Verify the other party's identity through a separate, trusted channel.",
                "Do NOT transfer any money based solely on this conversation.",
                "Call back on a publicly listed / independently verified number.",
                "If pressured, contact Cyber Crime Helpline: 1930 immediately.",
            ]

        # Cluster
        cluster = (rule_data or {}).get(
            "cluster",
            (vec_data or {}).get("cluster", "BEHAVIORAL_DETECTION")
        )

        # Matches
        matches = list(set(
            vec_data.get("matches", []) +
            (rule_data.get("matches", []) if rule_data else [])
        ))

        # Provider
        provider_parts = []
        if conv_score >= 0.30:
            provider_parts.append("CONVERSATION")
        if rule_data and effective_rule_score > 0:
            provider_parts.append("RULES")
        if ml_score >= 0.50:
            provider_parts.append("ML")
        if vec_score > 0:
            provider_parts.append("VECTOR")

        return {
            "verdict": verdict,
            "confidence": conf,
            "cluster": cluster,
            "matches": matches,
            "reasons": reasons,
            "actions": actions,
            "provider": " + ".join(provider_parts) if provider_parts else "ML ENGINE",
            "trend": trend,
        }

    else:
        return {
            "verdict": "SAFE",
            "confidence": conf,
            "cluster": "SAFE",
            "matches": [],
            "reasons": [
                "No significant scam patterns detected across all analysis layers.",
                breakdown,
            ],
            "actions": [
                "Proceed normally.",
                "Stay vigilant for unverified requests or sudden urgency.",
            ],
            "provider": "MULTI-LAYER ENGINE",
            "trend": trend,
        }


# ═══════════════════════════════════════════════════════════
#  LEGACY ENTRY POINT — single flat text (backward compat)
# ═══════════════════════════════════════════════════════════

def analyze_text(text: str) -> dict:
    """
    Legacy single-text analysis.
    Wraps the flat text as a single 'other' message
    and runs through the full conversation pipeline.
    """
    messages = [{"role": "other", "text": text}]
    return analyze_conversation(messages)