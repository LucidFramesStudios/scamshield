"""
detector.py — Multi-layer scam detection engine (v4-lite).
Pipeline: Rule Engine → ML Classifier → Conversation Intelligence → Smart Aggregator

LITE MODE: Vector/embedding layer disabled for Render free tier stability.
"""
import os
import re
import pickle
import rules

# ── 1. Vector Store — DISABLED for lite deployment ────────
def _get_vs():
    return None


# ── 2. ML Model Loading (synchronous, no threading) ──────
_clf = None
_vec = None

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
    "you pee eye": "upi", "you pee i": "upi",
    "eye pee ess": "ips", "eye p s": "ips",
    "war rant": "warrant", "war-rant": "warrant",
    "non bail able": "non-bailable", "non bailable": "non-bailable",
    "bail able": "bailable",
    "otpee": "otp", "o t p": "otp", "o tp": "otp", "ot p": "otp",
    "c v v": "cvv", "see vee vee": "cvv",
    "girftari": "arrest", "giraftari": "arrest",
    "bhejo": "send", "band ho jayega": "will be blocked",
    "a count": "account", "pleese": "please", "reverify": "re-verify",
}

HINGLISH_MAP = {
    "sirji": "sir", "kripya": "please", "turant": "immediately",
    "paisa": "money", "suniye": "listen", "samjhiye": "understand",
    "aapka": "your", "police wale": "police",
    "paisa bhejo": "send money", "paise bhejo": "send money",
    "rupaye bhejo": "send rupees", "abhi bhejo": "send immediately",
    "girftari hogi": "arrest will happen", "giraftari hogi": "arrest will happen",
    "band ho jayega": "will be blocked", "band kar denge": "will block",
    "gir ftari": "arrest", "khata": "account", "khata band": "account blocked",
    "nahi batana": "do not tell", "darr": "fear", "dhamki": "threat",
    "kehra": "case", "jama karo": "deposit",
    "turant paisa": "send money immediately",
    "warna": "otherwise", "pareshaan": "distress",
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
    try:
        base = os.path.dirname(__file__) or "."
        with open(os.path.join(base, "model.pkl"), "rb") as f:
            _clf = pickle.load(f)
        with open(os.path.join(base, "vectorizer.pkl"), "rb") as f:
            _vec = pickle.load(f)
        print("[SYSTEM] ML model loaded.")
        return True
    except Exception as e:
        print(f"[SYSTEM] ML model not available: {e}")
        return False


# Load model eagerly at import (no threading — simpler, safer on Render)
_load_model()


def preprocess(text: str) -> str:
    import unicodedata
    text = unicodedata.normalize("NFKD", text)
    _UNICODE_MAP = str.maketrans({
        '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
        '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
        '\u0410': 'A', '\u0415': 'E', '\u041e': 'O', '\u0420': 'P',
        '\u0421': 'C', '\u0423': 'Y', '\u0425': 'X',
    })
    text = text.translate(_UNICODE_MAP)
    text = text.encode("ascii", errors="ignore").decode("ascii")
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
    """Vector search disabled in lite mode — always returns zero."""
    return 0.0, {}


# ═══════════════════════════════════════════════════════════
#  CONVERSATION FEATURE ENGINE
# ═══════════════════════════════════════════════════════════

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
    other_text = " ".join(m["text"] for m in messages if m["role"] == "other")
    if not other_text:
        return 0.0, []

    reasons = []
    score = 0.5

    casual_hits = len(_CASUAL_SIGNALS.findall(other_text))
    formal_hits = len(_FORMAL_SIGNALS.findall(other_text))
    authority_hits = len(_AUTHORITY_CLAIMS.findall(other_text))
    weak_identity = bool(_IDENTITY_WEAK.search(other_text))

    if casual_hits >= 2:
        score -= 0.25
        reasons.append("Casual familiar tone suggests known contact")
    elif casual_hits == 1:
        score -= 0.10

    if authority_hits >= 2 and casual_hits == 0:
        score += 0.15
        reasons.append("Repeated authority language with no casual rapport signals")

    if formal_hits >= 1 and casual_hits == 0:
        score += 0.20
        reasons.append("Formal/impersonal tone from an unverified contact")

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

    if weak_identity:
        score += 0.15
        reasons.append("Unverified identity assertion detected")

    return min(max(score, 0.0), 1.0), reasons


_MONEY_REQUEST = re.compile(
    r'(?:'
    r'\b(?:send|transfer|pay|deposit|wire|give|provide|need|want|require|lend|refund|'
    r'reimburse|settle|clear|arrange|collect|release|load|top.?up)\b.{0,30}'
    r'\b(?:money|amount|cash|funds|rupees?|rs\.?|inr|\$|usd|payment|fee|fine|'
    r'charge|penalty|balance|dues?|sum|total|back|advance|wallet)\b'
    r'|'
    r'\b(?:give\s+back|pay\s+back|return\s+(?:the\s+)?money|paid\s+for|i\s+paid|'
    r'you\s+owe(?:\s+me)?|owe\s+(?:me|us)|money\s+back|get\s+(?:my|the)\s+money|'
    r'return\s+(?:my|the|your)\s+(?:money|amount|cash|dues?)|refund\s+(?:my|the|me)|'
    r'need\s+(?:it|that)\s+back|give\s+me\s+back)\b'
    r'|'
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
    other_msgs = [m for m in messages if m["role"] == "other"]
    other_text = " ".join(m["text"] for m in other_msgs)

    if not other_text:
        return 0.0, []

    reasons = []
    score = 0.0

    request_hits = len(_MONEY_REQUEST.findall(other_text))
    amount_hits = len(_AMOUNT_PATTERN.findall(other_text))
    method_hits = len(_TRANSFER_METHODS.findall(other_text))

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

    if request_hits >= 1 and len(messages) < 3:
        score += 0.20
        reasons.append("Money requested at conversation start — no rapport established")

    return min(score, 1.0), reasons


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
    other_msgs = [m for m in messages if m["role"] == "other"]
    if len(other_msgs) < 2:
        return 0.0, []

    reasons = []
    score = 0.0

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

    if max_phase == 3:
        score = max(score, 0.75)
        reasons.append("Threats or legal pressure detected (arrest/warrant/FIR)")

    if phases and phases[0] >= 2:
        score = max(score, 0.55)
        reasons.append("Conversation opened with immediate urgency — no rapport building")

    return min(score, 1.0), reasons


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

    if fear_count >= 1 and panic_count >= 2:
        score += 0.15
        reasons.append("Combination of fear and urgency — classic pressure manipulation")

    return min(score, 1.0), reasons


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

    if fake_familiarity and has_money:
        score += 0.25
        reasons.append("Familiarity claim followed by financial request — strong scam pattern")

    if fake_familiarity and has_money and len(other_msgs) > 2:
        reasons.append("Gradual trust-building followed by financial request detected")

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

    if has_authority and has_money:
        score += 0.40
        reasons.append("Authority claim combined with financial demand — common government impersonation pattern")

    if asks_secrecy:
        score += 0.35
        reasons.append("Secrecy/isolation tactic: instructed not to inform others or hang up")

    if context_shift >= 2:
        score += 0.20
        reasons.append("Sudden topic/context shift detected — possible bait-and-switch tactic")

    if len(other_msgs) > 0 and len(me_msgs) == 0:
        score += 0.10
        reasons.append("One-sided conversation — no response from user recorded")

    if has_authority and not knows_me:
        score += 0.20
        reasons.append("Authority identity claimed but no verifiable personal context established")

    return min(score, 1.0), reasons


def compute_conversation_score(messages: list) -> tuple:
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
#  ESCALATION TRACKING
# ═══════════════════════════════════════════════════════════

def _quick_risk_score(messages: list) -> float:
    if not messages:
        return 0.0
    flat       = " ".join(m["text"] for m in messages)
    other_only = " ".join(m["text"] for m in messages if m["role"] == "other")
    ml_s       = classify_text(flat)
    preprocessed_other = preprocess(other_only) if other_only else ""
    rule_data  = rules.check(preprocessed_other) if preprocessed_other else None
    if rule_data:
        match_count = len(rule_data.get("matches", []))
        rule_s = min(0.40 + 0.15 * (match_count - 1), 1.0)
    else:
        rule_s = 0.0
    if ml_s == 0.5:
        return 0.30 * ml_s + 0.70 * rule_s
    return 0.70 * ml_s + 0.30 * rule_s


def compute_escalation(messages: list) -> tuple:
    n = len(messages)
    if n == 0:
        return "STABLE", 0.0
    if n == 1:
        return "STABLE", _quick_risk_score(messages)

    scores  = [_quick_risk_score(messages[:i + 1]) for i in range(n)]
    current = scores[-1]
    prev    = scores[-2]
    local_delta  = current - prev
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
#  FINAL DECISION ENGINE
# ═══════════════════════════════════════════════════════════

def analyze_conversation(messages: list) -> dict:
    flat_text = " ".join(
        f"[{m['role'].upper()}] {m['text']}" for m in messages
    )
    other_only = " ".join(m["text"] for m in messages if m["role"] == "other")

    # Layer 1: Rules
    preprocessed_other = preprocess(other_only) if other_only else ""
    rule_data = rules.check(preprocessed_other) if preprocessed_other else None
    if rule_data:
        match_count = len(rule_data.get("matches", []))
        raw_rule_score = min(0.40 + 0.15 * (match_count - 1), 1.0)
    else:
        raw_rule_score = 0.0

    # Layer 2: ML
    ml_score = classify_text(flat_text)

    # Layer 3: Vector — disabled
    vec_score, vec_data = 0.0, {}

    # Layer 4: Conversation Intelligence
    preprocessed_messages = [
        {"role": m["role"], "text": preprocess(m["text"])} for m in messages
    ]
    conv_score, sub_scores, conv_reasons = compute_conversation_score(preprocessed_messages)

    # Meta-discussion guard
    me_text = " ".join(m["text"] for m in messages if m["role"] == "me")
    is_meta = _is_meta_discussion(me_text)
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
        conv_score = conv_score * 0.4
        effective_rule_score = raw_rule_score * 0.3
    elif ml_score < 0.30 and raw_rule_score >= 0.6:
        effective_rule_score = raw_rule_score * 0.6
    if other_denies_scam:
        conv_reasons.append("Sender is explicitly denying scam — common manipulation tactic")
        conv_score = min(conv_score + 0.15, 1.0)

    # Final Score — adjusted weights (no vector)
    ml_is_default = (ml_score == 0.5)
    if ml_is_default:
        final_score = (
            0.10 * ml_score +
            0.50 * effective_rule_score +
            0.40 * conv_score
        )
    else:
        final_score = (
            0.40 * ml_score +
            0.30 * effective_rule_score +
            0.30 * conv_score
        )

    # Escalation Trend
    trend, trend_score = compute_escalation(messages)

    # Verdict
    strong_rule_signal = (raw_rule_score >= 0.55)
    strong_conv_signal = (conv_score >= 0.45)
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

    breakdown = (
        f"Risk Scores — ML: {ml_score:.2f} | Rules: {raw_rule_score:.2f} (eff: {effective_rule_score:.2f}) | "
        f"Vector: {vec_score:.2f} | Conversation: {conv_score:.2f} "
        f"[rel={sub_scores['relationship']:.2f}, money={sub_scores['money']:.2f}, "
        f"esc={sub_scores['escalation']:.2f}, emo={sub_scores['emotion']:.2f}, "
        f"ano={sub_scores['anomaly']:.2f}]"
    )

    if verdict in ("SCAM", "SUSPICIOUS"):
        reasons = []
        if conv_reasons:
            reasons.extend(conv_reasons)
        if rule_data and effective_rule_score > 0:
            for r in rule_data.get("reasons", []):
                if r not in reasons:
                    reasons.append(r)
        if not reasons:
            reasons.append(
                f"ML classifier detected suspicious patterns ({ml_score * 100:.1f}% probability)"
            )
        if trend == "ESCALATING":
            reasons.append("Risk increasing due to recent messages")
        elif trend == "DE-ESCALATING":
            reasons.append("Conversation risk decreasing")
        reasons.append(breakdown)

        actions = []
        if rule_data and effective_rule_score > 0:
            actions = rule_data.get("actions", [])
        if not actions:
            actions = [
                "Hang up or stop responding immediately.",
                "Do NOT share OTP, PIN, or transfer money.",
                "Call Cyber Crime Helpline: 1930",
                "Block and report this contact.",
            ]
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

        cluster = (rule_data or {}).get("cluster", "BEHAVIORAL_DETECTION")
        matches = list(set(rule_data.get("matches", []) if rule_data else []))

        provider_parts = []
        if conv_score >= 0.30:
            provider_parts.append("CONVERSATION")
        if rule_data and effective_rule_score > 0:
            provider_parts.append("RULES")
        if ml_score >= 0.50:
            provider_parts.append("ML")

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


def analyze_text(text: str) -> dict:
    messages = [{"role": "other", "text": text}]
    return analyze_conversation(messages)