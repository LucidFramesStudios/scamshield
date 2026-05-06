import re

RULES = [
    (r'\botp\b',                              "OTP sharing request detected"),
    # PATCH: business/corporate fraud patterns
    (r'\boverdue\s+(?:invoice|payment|amount)\b',  "Overdue invoice pressure tactic detected"),
    (r'\b(?:pending|outstanding)\s+(?:invoice|payment|dues?|amount)\b', "Outstanding payment demand detected"),
    (r'\bwire\s+transfer\s+details\b',             "Wire transfer details push detected"),
    (r'\blegal\s+notice\b',                         "Legal notice threat detected"),
    (r'\bservice\s+suspension\b',                   "Service suspension threat detected"),
    (r'\bsecurity\s+deposit\b',                     "Upfront security deposit demand detected"),
    (r'\bregistration\s+fee\b',                     "Fake registration fee detected"),
    (r'\brefundable\s+(?:deposit|fee|amount)\b',    "Fake refundable deposit scam detected"),
    (r'\bshare\s+(?:the\s+)?screenshot\b',          "Screenshot sharing request detected"),
    (r'\bpay\s+(?:a\s+)?(?:refundable|small)\s+(?:fee|deposit|amount)\b',
                                                     "Advance fee demand detected"),
    (r'\bbank\s+details?\s+(?:changed|updated)\b',  "Bank details change fraud detected"),
    (r'\b(?:invoice|payment)\s+(?:is\s+)?(?:\d+\s+days?\s+)?overdue\b', "Overdue payment pressure detected"),
    (r'\bsettle\s+(?:the\s+)?(?:amount|outstanding|dues?)\b', "Settlement demand detected"),
    (r'\breturn\s+(?:the\s+)?(?:excess|extra)\s+(?:money|amount)\b', "Fake overpayment return demand detected"),
    (r'\bsend\s+money\b',                     "Money transfer demand detected"),
    (r'\bsend\s+me\s+(?:money|rs\.?\s*[\d,]+|MONEY|the\s+(?:money|amount))\b', "Money transfer demand detected"),
    (r'\btransfer\s+money\b',                 "Money transfer demand detected"),
    (r'\bpay\s+now\b',                        "Urgent payment demand detected"),
    (r'\burgent\s+payment\b',                 "Urgent payment demand detected"),
    (r'\bupi\b',                              "UPI transfer request detected"),
    (r'\brtgs\b',                             "RTGS transfer request detected"),
    (r'\bneft\b',                             "NEFT transfer request detected"),
    (r'\bwire\s+transfer\b',                  "Wire transfer demand detected"),
    (r'\bdo\s+not\s+tell\b',                  "Secrecy/isolation tactic detected"),
    (r'\bdigital\s+arrest\b',                 "Digital arrest threat detected"),
    (r'\bstay\s+on\s+(?:the\s+)?call\b',      "Call-hold isolation tactic detected"),
    (r'\bdo\s+not\s+(?:disconnect|hang\s+up)\b', "Forced call retention detected"),
    (r'\bwarrant\b',                          "False warrant threat detected"),
    (r'\bsafe\s+(?:harbor|vault|account)\b',  "Fake safe account scam detected"),
    # PATCH: require share/provide/give verb near PIN to avoid WiFi/gaming FP
    (r'\b(?:share|give|provide|send|tell|enter|submit)\s+(?:your\s+)?pin\b',
                                                       "PIN solicitation detected"),
    (r'\bpin\s+(?:number|code)\b',                 "PIN code solicitation detected"),
    (r'\bcvv\b',                              "CVV solicitation detected"),
    (r'\bshare\s+(?:your|the)\s+(?:otp|pin|cvv|password|account|details?|credentials?)\b', "Credential sharing request detected"),
    (r'\bshare\s+your\b',                     "Credential sharing request detected"),
    (r'\bclick\s+(?:the\s+)?link\b',          "Phishing link push detected"),
    (r'\bverify\s+(?:your\s+)?kyc\b',         "KYC phishing detected"),
    (r'\bpay\s+(?:the\s+)?fine\b',            "Fake fine payment scam detected"),
    (r'\bsettle\s+(?:the\s+)?matter\b',       "Extortion/settlement demand detected"),
    (r'\bimmediate\s+arrest\b',               "Immediate arrest threat detected"),
    (r'\bnon.?bailable\b',                    "Non-bailable warrant threat detected"),
    (r'\bescrow\s+account\b',                 "Fake escrow scam detected"),
    (r'\bprocessing\s+fee\b',                 "Fake fee demand detected"),
    (r'\bclearance\s+fee\b',                  "Fake clearance fee detected"),
    (r'\brelease\s+fee\b',                    "Fake release fee detected"),
    # PATCH: additional high-signal scam patterns
    (r'\bfile\s+(?:an?\s+)?fir\b',            "FIR threat detected"),
    (r'\bfir\s+(?:against|filed|registered|lodged)\b', "FIR threat detected"),
    (r'\b(?:will\s+be\s+|face\s+|under\s+)arrest(?:ed)?\b', "Arrest threat detected"),
    (r'\baccount\s+(?:will\s+be\s+|has\s+been\s+)?(?:block|suspend|freez|deactivat|seal|flag|compromis)', "Account blocking threat detected"),
    (r'\bpolice\s+complaint\b',               "Police complaint threat detected"),
    (r'\bguaranteed\s+(?:returns?|profit|income)\b', "Fake guaranteed returns scam detected"),
    (r'\b(?:invest|deposit)\b.{0,30}\b(?:crypto|bitcoin|trading\s+platform)\b', "Crypto investment scam detected"),
    (r'\b(?:crypto|bitcoin|trading)\b.{0,30}\b(?:deposit|invest|start)\b', "Crypto investment scam detected"),
    (r'\bdeposit\s+(?:rs\.?\s*[\d,]+|money|amount|the\s+amount)\b', "Deposit demand detected"),
    (r'\bsend\s+(?:rs\.?\s*[\d,]+|the\s+(?:money|amount|payment))\b', "Direct payment demand detected"),
    (r'\btransfer\s+(?:rs\.?\s*[\d,]+|the\s+(?:money|amount|funds))\b', "Transfer demand detected"),
    (r'\b(?:pay|send|transfer|deposit)\b.{0,20}\b(?:immediately|urgent|right\s+now)\b', "Urgent payment pressure detected"),
    (r'\b(?:immediately|urgent|right\s+now)\b.{0,20}\b(?:pay|send|transfer|deposit)\b', "Urgent payment pressure detected"),
    (r'\byou\s+(?:have\s+been|are)\s+(?:selected|chosen|shortlisted)\b', "Selection bait detected"),
    (r'\b(?:connection|sim(?:\s+card)?|number|account)\s+(?:will\s+be\s+|has\s+been\s+)?(?:disconnect|deactivat|terminat|cancel)', "Disconnection threat detected"),
]

COMPILED = [(re.compile(p, re.IGNORECASE), msg) for p, msg in RULES]

ACTIONS = [
    "Hang up immediately.",
    "Do NOT send money or share OTP/PIN.",
    "Call Cyber Crime Helpline: 1930",
    "Block this number and report it.",
]

def check(text: str) -> dict | None:
    triggered = []
    for pattern, msg in COMPILED:
        if pattern.search(text):
            if msg not in triggered:
                triggered.append(msg)

    if triggered:
        return {
            "verdict": "SCAM",
            "confidence": "HIGH",
            "cluster": "RULE_ENGINE",
            "matches": triggered,
            "reasons": triggered,
            "actions": ACTIONS,
        }
    return None