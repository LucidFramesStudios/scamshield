"""
improvement_engine.py

For each failure pattern found by the evaluator, identify the root cause in
detector.py / rules.py and suggest the minimal targeted patch.

Rules:
  - DO NOT rewrite entire files
  - DO NOT introduce new libraries
  - Only modify scoring weights, regex patterns, or threshold values
  - Each patch targets ONE specific weakness bucket
"""

import json
from evaluator import compute_metrics, load_results, group_failures_by_weakness


# ─────────────────────────────────────────────────────────────
#  Patch Library — one entry per known weakness bucket
# ─────────────────────────────────────────────────────────────
#
#  Structure of each patch dict:
#    weakness    : matches the bucket label from evaluator.py
#    file        : target file (detector.py or rules.py)
#    issue       : 1–3 sentence root-cause explanation
#    before      : exact code snippet to replace (stripped of line numbers)
#    after       : replacement code
#    confidence  : how certain we are this patch helps (HIGH/MEDIUM/LOW)
#    test_cases  : representative test case names that will be fixed

PATCH_LIBRARY = [

    # ── False Positive: friend/family money ───────────────────
    {
        "weakness":   "FALSE_POSITIVE: friend/family money",
        "file":       "detector.py",
        "issue": (
            "score_anomaly() adds +0.40 for 'Unverified person requesting money with minimal "
            "relationship context' even when strong casual signals (bro/bhai/yaar/mate) are "
            "present in the same conversation. The anomaly scorer does not receive the "
            "relationship score as context, so it fires unconditionally whenever has_money=True "
            "and len(other_msgs)<=3. Fix: gate the anomaly bonus behind a relationship_score "
            "threshold so that conversations with established casual rapport are exempted."
        ),
        "confidence": "HIGH",
        "test_cases": [
            "FP_friend_casual_money",
            "FP_friend_loan_repayment",
            "FP_colleague_petty_cash",
            "FP_splitting_restaurant_bill",
        ],
        "before": """    # Unknown person + money = core anomaly
    if has_money and not knows_me and len(other_msgs) <= 3:
        score += 0.40
        reasons.append("Unverified person requesting money with minimal relationship context")""",
        "after": """    # Unknown person + money = core anomaly
    # PATCH: pass casual_hits into anomaly scorer so that well-established
    # casual rapport suppresses the anomaly bonus.  We proxy casual_hits by
    # re-running the casual signals pattern here (cheap single regex call).
    _CASUAL_PROXY = re.compile(
        r'\\b(bro|dude|hey|mate|buddy|yaar|pal|boss|man|bhai|friend)\\b', re.IGNORECASE
    )
    casual_proxy_hits = len(_CASUAL_PROXY.findall(other_text))
    if has_money and not knows_me and len(other_msgs) <= 3 and casual_proxy_hits < 2:
        score += 0.40
        reasons.append("Unverified person requesting money with minimal relationship context")
    elif has_money and not knows_me and len(other_msgs) <= 3 and casual_proxy_hits >= 2:
        # Casual relationship established — reduce to mild flag, not full anomaly
        score += 0.10
        reasons.append("Money request in casual context — low-risk familiarity signal")""",
    },

    # ── False Positive: legitimate bank alert ─────────────────
    {
        "weakness":   "FALSE_POSITIVE: legitimate bank alert",
        "file":       "detector.py",
        "issue": (
            "Genuine bank SMS messages contain 'immediately', account numbers, and money amounts "
            "that trigger rule and emotion scorers. The meta-indicator guard already handles "
            "'if not done by you' and 'will never ask for' patterns, but the rule engine runs "
            "on 'other_only' text BEFORE meta suppression is checked. "
            "Fix: add more bank-legitimacy meta patterns and reduce the effective_rule_score "
            "multiplier for meta contexts from 0.6 to 0.3."
        ),
        "confidence": "HIGH",
        "test_cases": [
            "FP_real_bank_otp_alert",
            "FP_real_bank_kyc_update",
            "EDGE_otp_in_scam_awareness_message",
        ],
        "before": """META_INDICATORS = [
    r'\\b(?:someone|they)\\s+tried\\s+to\\s+scam\\b',
    r'\\b(?:don.t|do\\s+not|never)\\s+(?:fall\\s+for|share|give)\\b',
    r'\\bit.s\\s+a\\s+scam\\b',
    r'\\bscam\\s+(?:alert|warning|awareness)\\b',
    r'\\breport\\s+(?:to|it|this)\\b',
    r'\\b(?:fake|fraud)\\s+(?:call|message|text)\\b',
    r'\\bif\\s+not\\s+(?:done\\s+by|initiated\\s+by)\\s+you\\b',
    r'\\bwill\\s+never\\s+ask\\s+for\\b',
    r'\\btraining\\s+(?:module|session|program)\\b',
    r'\\bnews\\s+article\\b',
    r'\\bauthorities\\s+(?:urge|warn|advise)\\b',
    r'\\bnearest\\s+branch\\b',
]""",
        "after": """META_INDICATORS = [
    r'\\b(?:someone|they)\\s+tried\\s+to\\s+scam\\b',
    r'\\b(?:don.t|do\\s+not|never)\\s+(?:fall\\s+for|share|give)\\b',
    r'\\bit.s\\s+a\\s+scam\\b',
    r'\\bscam\\s+(?:alert|warning|awareness)\\b',
    r'\\breport\\s+(?:to|it|this)\\b',
    r'\\b(?:fake|fraud)\\s+(?:call|message|text)\\b',
    r'\\bif\\s+not\\s+(?:done\\s+by|initiated\\s+by)\\s+you\\b',
    r'\\bwill\\s+never\\s+ask\\s+for\\b',
    r'\\btraining\\s+(?:module|session|program)\\b',
    r'\\bnews\\s+article\\b',
    r'\\bauthorities\\s+(?:urge|warn|advise)\\b',
    r'\\bnearest\\s+branch\\b',
    # PATCH: add bank-legitimacy patterns for genuine alert SMS
    r'\\bif\\s+(?:not\\s+)?(?:authorised|authorized)\\s+by\\s+you\\b',
    r'\\bcall\\s+(?:our\\s+)?(?:helpline|toll.?free|1800)\\b',
    r'\\bdo\\s+not\\s+share\\s+(?:otp|pin|password)\\s+with\\s+anyone\\b',
    r'\\bwe\\s+(?:will\\s+)?never\\s+(?:call|ask)\\b',
    r'\\bxxxx\\d{4}\\b',   # masked account number format used by real banks
]""",
    },

    # ── STT Miss: phonetic bypass ──────────────────────────────
    {
        "weakness":   "STT_MISS: phonetic bypass",
        "file":       "detector.py",
        "issue": (
            "STT_CORRECTIONS dict covers common OCR misspellings but not phonetic expansions "
            "like 'you pee eye' (UPI), 'eye pee ess' (IPS), or 'war rant' (warrant). "
            "Fix: add phonetic multi-word patterns to STT_CORRECTIONS and add a phonetic "
            "normalization pass that collapses common spoken-form expansions before regex matching."
        ),
        "confidence": "HIGH",
        "test_cases": [
            "STT_phonetic_upi_bypass",
            "STT_spaced_keyword_warrant",
            "STT_ips_phonetic_authority",
        ],
        "before": """STT_CORRECTIONS = {
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
}""",
        "after": """STT_CORRECTIONS = {
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
    "otpee": "otp",
    "o t p": "otp",
    "girftari": "arrest",
    "bhejo": "send",
    "band ho jayega": "will be blocked",
}""",
    },

    # ── STT Miss: Hinglish / regional language ─────────────────
    {
        "weakness":   "STT_MISS: Hinglish/regional language",
        "file":       "detector.py",
        "issue": (
            "HINGLISH_MAP maps only 8 common Hinglish words. Words like 'girftari' (arrest), "
            "'bhejo' (send/transfer), 'band karo' (block/cancel), 'pareshaan' (distress), "
            "'darr' (fear) remain untranslated and thus invisible to all regex detectors. "
            "Fix: expand HINGLISH_MAP with threat and money-related Hinglish vocabulary."
        ),
        "confidence": "HIGH",
        "test_cases": ["STT_hinglish_threat"],
        "before": """HINGLISH_MAP = {
    "sirji": "sir", "kripya": "please", "turant": "immediately",
    "paisa": "money", "suniye": "listen", "samjhiye": "understand",
    "aapka": "your", "police wale": "police",
}""",
        "after": """HINGLISH_MAP = {
    "sirji": "sir", "kripya": "please", "turant": "immediately",
    "paisa": "money", "suniye": "listen", "samjhiye": "understand",
    "aapka": "your", "police wale": "police",
    # PATCH: expanded Hinglish threat/money vocabulary
    "paisa bhejo": "send money",
    "paise bhejo": "send money",
    "bhejo": "send",
    "girftari": "arrest",
    "giraftari": "arrest",
    "band ho jayega": "will be blocked",
    "band kar denge": "will block",
    "gir ftari": "arrest",
    "rupaye bhejo": "send rupees",
    "abhi bhejo": "send immediately",
    "khata": "account",
    "khata band": "account blocked",
    "nahi batana": "do not tell",
    "darr": "fear",
    "dhamki": "threat",
    "kehra": "case",
    "jama karo": "deposit",
    "turant paisa": "send money immediately",
}""",
    },

    # ── STT Miss: character obfuscation (Unicode) ──────────────
    {
        "weakness":   "STT_MISS: character obfuscation",
        "file":       "detector.py",
        "issue": (
            "The preprocess() function does not normalise Unicode lookalike characters "
            "(e.g. Cyrillic 'а' \\u0430 used in place of Latin 'a', or digit '0' replacing 'o'). "
            "Scammers exploit this to bypass regex matching. "
            "Fix: add a Unicode normalization step using unicodedata.normalize('NFKD') and "
            "an ASCII transliteration fallback before applying STT_CORRECTIONS."
        ),
        "confidence": "MEDIUM",
        "test_cases": ["STT_unicode_lookalike_chars"],
        "before": """def preprocess(text: str) -> str:
    text = text.lower().strip()
    for wrong, right in STT_CORRECTIONS.items():
        text = text.replace(wrong, right)""",
        "after": """def preprocess(text: str) -> str:
    # PATCH: normalise Unicode lookalikes before any regex/dict matching
    import unicodedata
    # NFKD decomposition then re-encode as ASCII ignoring non-ASCII residue
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", errors="ignore").decode("ascii")
    # Also map common digit-for-letter substitutions used in obfuscation
    _LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "@": "a"})
    # Only apply leet substitutions when followed by letters (avoid amounts)
    import re as _re
    text = _re.sub(r'(?<=[a-z])[013@]|[013@](?=[a-z])', lambda m: m.group().translate(_LEET), text)
    text = text.lower().strip()
    for wrong, right in STT_CORRECTIONS.items():
        text = text.replace(wrong, right)""",
    },

    # ── STT Miss: numeric amounts as words ────────────────────
    {
        "weakness":   "STT_MISS: character obfuscation",
        "file":       "detector.py",
        "issue": (
            "Amounts spoken as English words ('ten thousand rupees', 'five lakh') are not "
            "matched by _AMOUNT_PATTERN which only looks for digits. This lowers money_score "
            "and can cause a SCAM to be classified as SUSPICIOUS or SAFE. "
            "Fix: add a word-to-digit normalisation map in preprocess() for common financial "
            "denominations before _AMOUNT_PATTERN is applied."
        ),
        "confidence": "MEDIUM",
        "test_cases": ["STT_numeric_amount_obfuscated"],
        "before": r"""    text = re.sub(r'\brs\.?\s*[\d,]+', 'MONEY', text, flags=re.I)
    text = re.sub(r'\$\s*[\d,]+', 'MONEY', text)
    text = re.sub(r'\b\d{4,}\b', 'NUM', text)""",
        "after": """    # PATCH: normalise spoken number denominations → digit tokens
    _WORD_AMOUNTS = [
        (r'\\b(one|two|three|four|five|six|seven|eight|nine|ten|'
         r'twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|'
         r'hundred|thousand|lakh|crore)\\s+(thousand|lakh|crore|rupees?|dollars?)\\b',
         'MONEY'),
        (r'\\b(one|two|three|four|five|ten|twenty|fifty)\\s+thousand\\b', 'MONEY'),
        (r'\\b\\d+\\s+(thousand|lakh|crore)\\s+(rupees?|rs\\.?)\\b', 'MONEY'),
    ]
    for _pat, _rep in _WORD_AMOUNTS:
        text = re.sub(_pat, _rep, text, flags=re.IGNORECASE)
    text = re.sub(r'\\brs\\.?\\s*[\\d,]+', 'MONEY', text, flags=re.I)
    text = re.sub(r'\\$\\s*[\\d,]+', 'MONEY', text)
    text = re.sub(r'\\b\\d{4,}\\b', 'NUM', text)""",
    },

    # ── SCAM Miss: fake familiarity ───────────────────────────
    {
        "weakness":   "SCAM_MISS: fake familiarity pattern",
        "file":       "detector.py",
        "issue": (
            "_FAKE_FAMILIARITY regex in score_anomaly() matches explicit prior-meeting claims "
            "('we met', 'remember me') but misses vague event-based familiarity openers "
            "like 'we were at the same X event' or 'I think we know each other from Y' "
            "which are hallmarks of pig-butchering and romance scams. "
            "Fix: extend _FAKE_FAMILIARITY to cover event/platform-based familiarity claims."
        ),
        "confidence": "HIGH",
        "test_cases": [
            "SCAM_fake_familiarity_delayed_ask",
            "SCAM_romantic_pig_butchering",
        ],
        "before": """_FAKE_FAMILIARITY = re.compile(
    r'\\b(we\\s+met|remember\\s+me|you\\s+know\\s+me|we\\s+spoke\\s+before|'
    r'i\\s+(?:called|messaged)\\s+you\\s+(?:before|earlier|last\\s+(?:week|month|time)))\\b',
    re.IGNORECASE
)""",
        "after": """_FAKE_FAMILIARITY = re.compile(
    r'\\b(we\\s+met|remember\\s+me|you\\s+know\\s+me|we\\s+spoke\\s+before|'
    r'i\\s+(?:called|messaged)\\s+you\\s+(?:before|earlier|last\\s+(?:week|month|time))|'
    # PATCH: event/platform-based familiarity gambits
    r'we\\s+(?:were\\s+)?(?:at|in)\\s+the\\s+same|'
    r'i\\s+think\\s+we\\s+(?:know\\s+each\\s+other|met)|'
    r'(?:saw|spotted|noticed)\\s+you\\s+(?:at|in)|'
    r'connected\\s+(?:at|through|via)|'
    r'mutual\\s+(?:friend|contact|connection)|'
    r'(?:same\\s+(?:batch|college|company|event|conference|school))|'
    r'i\\s+was\\s+(?:referred|introduced)\\s+(?:to\\s+you|by))\\b',
    re.IGNORECASE
)""",
    },

    # ── SCAM Miss: corporate/invoice scam ────────────────────
    {
        "weakness":   "SCAM_MISS: corporate/invoice scam",
        "file":       "rules.py",
        "issue": (
            "rules.py has no patterns for business/invoice fraud vocabulary: "
            "'overdue invoice', 'pending payment', 'wire transfer details', "
            "'legal notice', 'service suspension'. These are core BEC (Business Email "
            "Compromise) signals that currently reach the model layer only (low weight). "
            "Fix: add targeted rules for corporate fraud patterns."
        ),
        "confidence": "HIGH",
        "test_cases": [
            "SCAM_corporate_invoice_fraud",
            "SCAM_job_offer_registration_fee",
        ],
        "before": """RULES = [
    (r'\\botp\\b',                              "OTP sharing request detected"),""",
        "after": """RULES = [
    (r'\\botp\\b',                              "OTP sharing request detected"),
    # PATCH: business/corporate fraud patterns
    (r'\\boverdue\\s+(?:invoice|payment|amount)\\b',  "Overdue invoice pressure tactic detected"),
    (r'\\bwire\\s+transfer\\s+details\\b',             "Wire transfer details push detected"),
    (r'\\blegal\\s+notice\\b',                         "Legal notice threat detected"),
    (r'\\bservice\\s+suspension\\b',                   "Service suspension threat detected"),
    (r'\\bsecurity\\s+deposit\\b',                     "Upfront security deposit demand detected"),
    (r'\\bregistration\\s+fee\\b',                     "Fake registration fee detected"),
    (r'\\brefundable\\s+(?:deposit|fee|amount)\\b',    "Fake refundable deposit scam detected"),
    (r'\\bshare\\s+(?:the\\s+)?screenshot\\b',         "Screenshot sharing request detected"),
    (r'\\bpay\\s+(?:a\\s+)?(?:refundable|small)\\s+(?:fee|deposit|amount)\\b',
                                                       "Advance fee demand detected"),""",
    },

    # ── SCAM Miss: denial tactic ──────────────────────────────
    {
        "weakness":   "SCAM_MISS: denial-as-amplifier",
        "file":       "detector.py",
        "issue": (
            "The `other_denies_scam` amplifier in analyze_conversation() references a "
            "variable `reasons` before it is defined in the SAFE branch path, which causes "
            "a NameError at runtime and silently falls back. Additionally the denial pattern "
            "only matches 'this is not a scam' and misses 'i am legitimate', 'trust me, "
            "this is real', 'it is not fraud' variants. "
            "Fix: broaden the denial regex and ensure conv_score amplification happens "
            "unconditionally before reasons list is built."
        ),
        "confidence": "HIGH",
        "test_cases": ["EDGE_scammer_denies_being_scammer"],
        "before": """    other_denies_scam = bool(re.search(
        r'\\b(this\\s+is\\s+not\\s+a\\s+scam|not\\s+fraud|trust\\s+me|i\\s+am\\s+legitimate)\\b',
        other_only or "", re.IGNORECASE
    ))""",
        "after": """    other_denies_scam = bool(re.search(
        r'\\b('
        r'this\\s+is\\s+not\\s+a\\s+scam|not\\s+(?:a\\s+)?fraud|'
        r'trust\\s+me|i\\s+am\\s+legitimate|'
        # PATCH: additional denial variants
        r'i\\s+am\\s+(?:real|genuine|official|verified)|'
        r'this\\s+is\\s+(?:real|genuine|official|legitimate)|'
        r'it\\s+is\\s+not\\s+(?:fraud|fake|a\\s+scam)|'
        r'don.t\\s+worry\\s+(?:it.s|this\\s+is)\\s+(?:safe|legitimate|real)|'
        r'we\\s+are\\s+(?:a\\s+)?(?:real|official|genuine|registered)'
        r')\\b',
        other_only or "", re.IGNORECASE
    ))""",
    },

    # ── Boundary: authority without financial demand ───────────
    {
        "weakness":   "BOUNDARY: authority without demand",
        "file":       "detector.py",
        "issue": (
            "score_relationship() adds +0.35 for any authority claim regardless of "
            "whether a financial demand or OTP request follows. This causes incomplete "
            "scam scripts (authority claim only, no demand) to score too high and "
            "real authority contacts (police requesting witness statement) to be over-flagged. "
            "Fix: halve the authority relationship score when no money or OTP signal is "
            "present in the same conversation."
        ),
        "confidence": "MEDIUM",
        "test_cases": [
            "BOUND_incomplete_authority_no_demand",
            "EDGE_police_real_request_for_statement",
        ],
        "before": """    # Authority claims → high risk
    if authority_hits >= 1:
        score += 0.35
        reasons.append("Caller claims to be a government/law-enforcement authority")""",
        "after": """    # Authority claims → high risk — but only amplify fully when combined
    # with money or OTP signals (detected later in pipeline via anomaly scorer).
    # PATCH: use lighter weight when authority claim appears without demand context.
    _HAS_DEMAND = re.compile(
        r'\\b(otp|pin|cvv|upi|neft|rtgs|send|transfer|pay|deposit|wire|share)\\b',
        re.IGNORECASE
    )
    authority_has_demand = bool(_HAS_DEMAND.search(other_text))
    if authority_hits >= 1:
        if authority_has_demand:
            score += 0.35
            reasons.append("Caller claims to be a government/law-enforcement authority")
        else:
            score += 0.15
            reasons.append("Authority language detected — monitoring for demand signals")""",
    },

    # ── Evolution: SAFE→SCAM slow ramp missed ─────────────────
    {
        "weakness":   "EVOLUTION: SAFE→SCAM transition missed",
        "file":       "detector.py",
        "issue": (
            "compute_escalation() compares only the final two step-scores (delta = "
            "current − previous). In slow-ramp pig-butchering scams the delta between "
            "turn N-1 and N is modest even though the overall trajectory is strongly "
            "ESCALATING. Fix: also compare the earliest and latest step scores "
            "(global delta) and use max(local_delta, global_delta/2) as the "
            "classification signal so long-horizon escalation is not missed."
        ),
        "confidence": "MEDIUM",
        "test_cases": [
            "EVO_safe_to_scam_gradual",
            "SCAM_fake_familiarity_delayed_ask",
        ],
        "before": """    scores  = [_quick_risk_score(messages[:i + 1]) for i in range(n)]
    current = scores[-1]
    prev    = scores[-2]
    delta   = current - prev

    if delta > 0.15:
        trend = "ESCALATING"
    elif delta < -0.15:
        trend = "DE-ESCALATING"
    else:
        trend = "STABLE" """,
        "after": """    scores  = [_quick_risk_score(messages[:i + 1]) for i in range(n)]
    current = scores[-1]
    prev    = scores[-2]
    local_delta  = current - prev
    # PATCH: also measure global trajectory (first → last) to catch slow ramps
    global_delta = scores[-1] - scores[0]
    # Use whichever signal is stronger, but weight global at 50%
    delta = max(local_delta, global_delta * 0.5)

    if delta > 0.15:
        trend = "ESCALATING"
    elif delta < -0.15:
        trend = "DE-ESCALATING"
    else:
        trend = "STABLE" """,
    },

    # ── False Positive: context-dependent keyword (PIN) ────────
    {
        "weakness":   "FALSE_POSITIVE: context-dependent keyword",
        "file":       "rules.py",
        "issue": (
            "The rule r'\\bpin\\b' fires on WiFi PIN, ATM PIN set-by-user, game PIN, "
            "and other benign uses. 'PIN' alone is too broad without surrounding context. "
            "Fix: tighten the rule to require a possession/sharing verb or credential context "
            "nearby (share your PIN, enter PIN, provide PIN) before flagging."
        ),
        "confidence": "HIGH",
        "test_cases": ["EDGE_pin_in_safe_gaming_context"],
        "before": """    (r'\\bpin\\b',                              "PIN solicitation detected"),""",
        "after": """    # PATCH: require share/provide/give verb near PIN to avoid WiFi/gaming FP
    (r'\\b(?:share|give|provide|send|tell|enter|submit)\\s+(?:your\\s+)?pin\\b',
                                                       "PIN solicitation detected"),
    (r'\\bpin\\s+(?:number|code)\\b',                 "PIN code solicitation detected"),""",
    },
]


# ─────────────────────────────────────────────────────────────
#  Matching engine
# ─────────────────────────────────────────────────────────────

def patches_for_weaknesses(weakness_labels: list) -> list:
    """
    Given a list of weakness bucket labels (from evaluator.group_failures_by_weakness),
    return the relevant patches from PATCH_LIBRARY.
    """
    matched = []
    seen    = set()
    for label in weakness_labels:
        for patch in PATCH_LIBRARY:
            if patch["weakness"] == label and patch["weakness"] not in seen:
                matched.append(patch)
                seen.add(patch["weakness"])
    # Also append any patches for weaknesses not explicitly listed (catch-all)
    for patch in PATCH_LIBRARY:
        if patch["weakness"] not in seen:
            matched.append(patch)
            seen.add(patch["weakness"])
    return matched


# ─────────────────────────────────────────────────────────────
#  Pretty printer
# ─────────────────────────────────────────────────────────────

def format_patch(patch: dict) -> str:
    lines = []
    lines.append(f"\n{'═' * 66}")
    lines.append(f"FILE   : {patch['file']}")
    lines.append(f"TARGET : {patch['weakness']}")
    lines.append(f"CONF   : {patch['confidence']}")
    lines.append(f"\nISSUE:")
    # Word-wrap issue text at 80 chars
    words = patch["issue"].split()
    line  = "  "
    for w in words:
        if len(line) + len(w) > 78:
            lines.append(line)
            line = "  " + w + " "
        else:
            line += w + " "
    if line.strip():
        lines.append(line)
    lines.append(f"\nFIXES TEST CASES:")
    for tc in patch.get("test_cases", []):
        lines.append(f"  • {tc}")
    lines.append(f"\nSUGGESTED PATCH:")
    lines.append(f"\n  BEFORE:\n")
    for bl in patch["before"].splitlines():
        lines.append(f"    {bl}")
    lines.append(f"\n  AFTER:\n")
    for al in patch["after"].splitlines():
        lines.append(f"    {al}")
    return "\n".join(lines)


def print_all_patches(patches: list):
    print(f"\n{'═' * 66}")
    print(f"  IMPROVEMENT ENGINE — {len(patches)} Suggested Patches")
    print(f"{'═' * 66}")
    for i, patch in enumerate(patches, 1):
        print(f"\n[Patch {i}/{len(patches)}]")
        print(format_patch(patch))
    print(f"\n{'═' * 66}\n")


# ─────────────────────────────────────────────────────────────
#  Main entry point
# ─────────────────────────────────────────────────────────────

def generate_improvements(
    results_file: str = "test_results.json",
    top_n_patches: int = 10,
) -> list:
    """
    Load results, identify weakness buckets from failures,
    match patches, print them, and return the list.
    """
    try:
        results  = load_results(results_file)
        metrics  = compute_metrics(results)
        failures = metrics["all_failures"]

        if not failures:
            print("\n  ✓ No failures — no patches needed.")
            return []

        weakness_map = group_failures_by_weakness(failures)
        active_weaknesses = list(weakness_map.keys())

        # Prioritise: most failures first
        active_weaknesses.sort(key=lambda w: -len(weakness_map[w]))

        patches = patches_for_weaknesses(active_weaknesses)[:top_n_patches]
        print_all_patches(patches)

        # Persist suggestions
        output = []
        for p in patches:
            output.append({
                "file":       p["file"],
                "weakness":   p["weakness"],
                "confidence": p["confidence"],
                "issue":      p["issue"],
                "test_cases": p["test_cases"],
                "before":     p["before"],
                "after":      p["after"],
            })
        with open("patch_suggestions.json", "w") as f:
            json.dump(output, f, indent=2)
        print("  Patches saved → patch_suggestions.json")
        return patches

    except FileNotFoundError:
        print(f"  [ERROR] {results_file} not found. Run test_runner first.")
        return []


if __name__ == "__main__":
    generate_improvements()