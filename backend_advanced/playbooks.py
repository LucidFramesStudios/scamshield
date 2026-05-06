PLAYBOOKS = {
    "AUTHORITY_IMPERSONATION": {
        "verdict": "SCAM",
        "confidence": "HIGH",
        "reasons": ["Semantic match: Sender is impersonating law enforcement, customs, or government officials."],
        "actions": ["Do not trust the caller ID.", "Hang up immediately.", "Contact the official department directly using a verified number."]
    },
    "URGENT_FINANCIAL": {
        "verdict": "SCAM",
        "confidence": "HIGH",
        "reasons": ["Semantic match: High-pressure financial demand or OTP theft pattern detected."],
        "actions": ["Never share your OTP or PIN.", "Do not authorize any RTGS/UPI transfers.", "Call your bank immediately to secure your account."]
    }
}

SAFE_PLAYBOOK = {
    "verdict": "SAFE",
    "confidence": "LOW",
    "reasons": ["No semantic match to known high-risk scam vectors found in local database."],
    "actions": ["Proceed normally.", "Always remain vigilant for unverified requests."]
}