"""
conversation_generator.py
Generates structured adversarial test cases for ScamShield.
Each case: name, category, messages, expected_verdict, expected_trend, explanation.

Probes known weak-spots in detector.py v4:
  - Anomaly scorer fires on legitimate friend money requests
  - STT phonetic variants bypass rule regex
  - Gradual familiarity scams (low escalation score due to slow ramp)
  - Authority + no-money conversations over-triggering
  - Emotional manipulation by real relatives vs scammer mimicry
"""

# ─────────────────────────────────────────────────────────────
#  A. FALSE POSITIVES — must resolve SAFE
# ─────────────────────────────────────────────────────────────

FALSE_POSITIVES = [
    {
        "name": "FP_friend_casual_money",
        "category": "false_positive",
        "subcategory": "friend_money",
        "messages": [
            {"role": "other", "text": "Hey bro, you around?"},
            {"role": "me",    "text": "Yeah man, what's up?"},
            {"role": "other", "text": "Dude I'm at the petrol pump and my UPI is acting up. Can you send 500? I'll pay you back tonight."},
            {"role": "me",    "text": "Sure, sending now."},
            {"role": "other", "text": "Thanks bhai, you're a lifesaver."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Genuine friend UPI request. Casual tone (bro/bhai/dude), small amount, "
            "mutual conversation, no urgency pressure. Anomaly scorer may misfire on "
            "'unverified person + money' despite strong casual signals."
        ),
    },
    {
        "name": "FP_family_emergency_transfer",
        "category": "false_positive",
        "subcategory": "family_money",
        "messages": [
            {"role": "other", "text": "Beta it's mom. I'm at the hospital with Nana."},
            {"role": "me",    "text": "Oh no, what happened?"},
            {"role": "other", "text": "He fell. The admission requires Rs 8000 right now. Can you transfer it to my PhonePe? I'll explain everything when I'm home."},
            {"role": "me",    "text": "Transferring now. Is he okay?"},
            {"role": "other", "text": "He's stable. Thank you so much. Come when you can."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Genuine family emergency. Hospital context, emotional but logical tone, "
            "specific amount, mutual dialogue, follow-up concern. Should not be SCAM. "
            "Fear/panic words + money may cause false positive."
        ),
    },
    {
        "name": "FP_real_bank_otp_alert",
        "category": "false_positive",
        "subcategory": "real_bank_alert",
        "messages": [
            {"role": "other", "text": "SBI Alert: Your account XXXX1234 has been debited Rs 12,000 on 04-Jul. If not done by you, call 1800-1234 immediately."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Legitimate bank debit SMS. Contains 'immediately' and 'account' and money amount "
            "but also has 'if not done by you' meta-indicator. Rule and emotional scorers "
            "may over-fire on urgency + amount."
        ),
    },
    {
        "name": "FP_office_reimbursement_request",
        "category": "false_positive",
        "subcategory": "office_payment",
        "messages": [
            {"role": "other", "text": "Hi, this is Priya from Finance. Can you submit your travel reimbursement claim by EOD?"},
            {"role": "me",    "text": "Sure, how do I submit it?"},
            {"role": "other", "text": "Just fill the form on the intranet portal and attach bills. Amount due to you is Rs 3,400."},
            {"role": "me",    "text": "Done, submitted."},
            {"role": "other", "text": "Great, it'll be credited to your account within 3 working days."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Routine office reimbursement. The money flows TO the user, not FROM. "
            "Formal tone may trigger relationship scorer incorrectly."
        ),
    },
    {
        "name": "FP_colleague_petty_cash",
        "category": "false_positive",
        "subcategory": "friend_money",
        "messages": [
            {"role": "other", "text": "Hey, remember you owe me 200 from lunch last week?"},
            {"role": "me",    "text": "Oh yeah totally forgot, sorry!"},
            {"role": "other", "text": "No worries, just send it on GPay when you get a chance."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Legitimate debt repayment reminder. 'You owe me' triggers money-intent scorer "
            "and GPay triggers transfer-method pattern despite this being benign."
        ),
    },
    {
        "name": "FP_friend_loan_repayment",
        "category": "false_positive",
        "subcategory": "friend_money",
        "messages": [
            {"role": "other", "text": "Yaar, I need to pay my rent by tonight. Can you lend me Rs 5000? I'll return it Monday for sure."},
            {"role": "me",    "text": "Okay fine, sending on NEFT."},
            {"role": "other", "text": "You're a legend bhai. Thank you."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Friendly loan request with casual tone (yaar/bhai). NEFT + Rs 5000 + tonight "
            "will likely trigger rule engine and urgency scorer. Should remain SAFE."
        ),
    },
    {
        "name": "FP_scam_awareness_discussion",
        "category": "false_positive",
        "subcategory": "meta_discussion",
        "messages": [
            {"role": "other", "text": "Did you see that viral scam where they fake a digital arrest and demand OTP?"},
            {"role": "me",    "text": "Yes, my uncle almost fell for it! They threatened a warrant too."},
            {"role": "other", "text": "People need to know — real police will never ask you to stay on call or send money. It's a scam alert."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Anti-scam awareness discussion quoting scam tactics. Contains 'OTP', 'warrant', "
            "'digital arrest' in a meta-discussion context. Meta-indicator guard should fire."
        ),
    },
    {
        "name": "FP_real_bank_kyc_update",
        "category": "false_positive",
        "subcategory": "real_bank_alert",
        "messages": [
            {"role": "other", "text": "Dear Customer, your KYC documents are due for renewal. Please visit the nearest branch or login to netbanking. We will never ask for your OTP or PIN."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Official bank KYC notice with explicit safety disclaimer. 'Nearest branch' is a "
            "meta-indicator. 'OTP' and 'KYC' will fire rules despite the protective framing."
        ),
    },
    {
        "name": "FP_splitting_restaurant_bill",
        "category": "false_positive",
        "subcategory": "friend_money",
        "messages": [
            {"role": "other", "text": "Okay I paid the whole bill, Rs 1800 for 4 of us so everyone owes me 450."},
            {"role": "me",    "text": "Sure sending on UPI now."},
            {"role": "other", "text": "Got it, thanks man!"},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Bill splitting among friends. Contains UPI + money amount. Should be safe "
            "given the social context and mutual tone."
        ),
    },
    {
        "name": "FP_gig_worker_payment_followup",
        "category": "false_positive",
        "subcategory": "office_payment",
        "messages": [
            {"role": "other", "text": "Hi, I'm Ravi the plumber who came yesterday. The payment of Rs 2200 is still pending."},
            {"role": "me",    "text": "Sorry about that, I'll transfer it now."},
            {"role": "other", "text": "You can send it to my PhonePe number 9876543210. Thanks."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Legitimate payment for services rendered. Contains PhonePe, phone number, "
            "amount. Anomaly scorer may flag unknown person + money request."
        ),
    },
]


# ─────────────────────────────────────────────────────────────
#  B. ADVANCED SCAM PATTERNS — must resolve SCAM
# ─────────────────────────────────────────────────────────────

ADVANCED_SCAMS = [
    {
        "name": "SCAM_fake_familiarity_delayed_ask",
        "category": "advanced_scam",
        "subcategory": "familiarity",
        "messages": [
            {"role": "other", "text": "Hey, this is Suresh! We met at Rahul's wedding last year, remember?"},
            {"role": "me",    "text": "Oh hey! Yes I think so, how are you?"},
            {"role": "other", "text": "Doing well! Settled in Pune now. How's family?"},
            {"role": "me",    "text": "All good, thanks!"},
            {"role": "other", "text": "Great to reconnect. Listen, I'm in a bit of a bind — stuck at the airport, wallet stolen. Could you do me a big favour and send Rs 3000 on UPI? I'll return it as soon as I'm back."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": (
            "Classic fake familiarity + delayed financial ask. Builds rapport over several turns "
            "before pivoting to request. Anomaly + familiarity detectors should catch this."
        ),
    },
    {
        "name": "SCAM_authority_otp_extraction",
        "category": "advanced_scam",
        "subcategory": "authority",
        "messages": [
            {"role": "other", "text": "I am calling from RBI Cyber Fraud Division. We have detected suspicious transactions on your account."},
            {"role": "me",    "text": "What kind of transactions?"},
            {"role": "other", "text": "Your account has been used to purchase items from Kolkata. To verify your identity, I need you to share the OTP sent to your registered mobile."},
            {"role": "me",    "text": "I just got an OTP..."},
            {"role": "other", "text": "Yes that is our security verification. Please share it immediately or your account will be blocked."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": (
            "Authority impersonation + OTP extraction + account freeze threat. "
            "All major signals present: authority claim, OTP request, urgency, fear."
        ),
    },
    {
        "name": "SCAM_emotional_family_impersonation",
        "category": "advanced_scam",
        "subcategory": "emotional",
        "messages": [
            {"role": "other", "text": "Hello, I'm calling from Apollo Hospital. Are you related to Mr. Ajay Sharma?"},
            {"role": "me",    "text": "Yes, he's my father. Is everything okay?"},
            {"role": "other", "text": "He's been admitted after a road accident. He's in the ICU. We need Rs 50,000 immediately for emergency surgery."},
            {"role": "me",    "text": "Oh god. Can I speak to him?"},
            {"role": "other", "text": "He's unconscious right now. Please transfer the amount to this account immediately: NEFT to HDFC Bank, account 12345678, IFSC HDFC0001234. Every minute counts."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": (
            "Hospital impersonation scam targeting family emergency emotion. Contains NEFT, "
            "account number, IFSC, extreme urgency, and fear of loss of life."
        ),
    },
    {
        "name": "SCAM_corporate_invoice_fraud",
        "category": "advanced_scam",
        "subcategory": "corporate",
        "messages": [
            {"role": "other", "text": "Hi, this is from Infosys Vendor Relations. We have a pending invoice INV-2024-1187 from your organization."},
            {"role": "me",    "text": "I'm not aware of this invoice. Can you resend details?"},
            {"role": "other", "text": "Of course. Invoice is for Rs 2,40,000 for Q3 consulting services. Payment is 30 days overdue."},
            {"role": "me",    "text": "Let me check with finance."},
            {"role": "other", "text": "Please process it today to avoid a legal notice and service suspension. Wire transfer details attached."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": (
            "Business email compromise / fake vendor invoice. Legal threat + urgency + large amount. "
            "Wire transfer trigger + legal notice = strong scam pattern."
        ),
    },
    {
        "name": "SCAM_digital_arrest_isolation",
        "category": "advanced_scam",
        "subcategory": "authority",
        "messages": [
            {"role": "other", "text": "This is CBI officer Rakesh Sharma. A parcel in your name has been seized carrying narcotics."},
            {"role": "me",    "text": "That's impossible, I haven't sent any parcel."},
            {"role": "other", "text": "We are initiating a digital arrest. You must stay on this call and not contact anyone until the investigation is complete."},
            {"role": "me",    "text": "Should I call a lawyer?"},
            {"role": "other", "text": "Do NOT tell anyone or you will be arrested immediately. To settle this matter and close the FIR, you must pay Rs 1,50,000 as a security deposit."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": (
            "Full digital arrest scam. CBI impersonation, secrecy demand, immediate arrest threat, "
            "FIR, financial settlement demand. Maximum signal across all detectors."
        ),
    },
    {
        "name": "SCAM_lottery_advance_fee",
        "category": "advanced_scam",
        "subcategory": "flattery",
        "messages": [
            {"role": "other", "text": "Congratulations! You have been selected as the lucky winner of Rs 25,00,000 in the KBC National Lottery."},
            {"role": "me",    "text": "Really? I didn't register for any lottery."},
            {"role": "other", "text": "Your number was auto-selected from TRAI database. To release your prize money, a processing fee of Rs 5,000 must be paid first."},
            {"role": "me",    "text": "Why do I need to pay?"},
            {"role": "other", "text": "It's a mandatory clearance fee as per RBI guidelines. Pay via UPI and the prize will be credited within 2 hours."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": (
            "Lottery advance-fee scam. Flattery opener, authority claim (RBI), clearance fee, "
            "UPI payment request. Classic pattern."
        ),
    },
    {
        "name": "SCAM_job_offer_registration_fee",
        "category": "advanced_scam",
        "subcategory": "corporate",
        "messages": [
            {"role": "other", "text": "Hi, I'm HR from Amazon. Your profile was shortlisted for a Work From Home role paying Rs 45,000/month."},
            {"role": "me",    "text": "Interesting, tell me more."},
            {"role": "other", "text": "You just need to pay a refundable security deposit of Rs 2,499 to register and we will process your joining immediately."},
            {"role": "me",    "text": "Why is a deposit needed?"},
            {"role": "other", "text": "It's required by Amazon's HR policy for remote employees. Pay via PhonePe to 9988776655 and share the screenshot."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": (
            "Fake job scam with registration fee. Upfront payment + share screenshot tactic. "
            "PhonePe number + deposit = red flags."
        ),
    },
    {
        "name": "SCAM_insurance_refund_overpayment",
        "category": "advanced_scam",
        "subcategory": "authority",
        "messages": [
            {"role": "other", "text": "This is LIC Customer Care. We have processed a refund of Rs 18,000 to your account but due to a technical error, Rs 80,000 was credited instead."},
            {"role": "me",    "text": "I don't see any credit in my account."},
            {"role": "other", "text": "It will reflect in 10 minutes. You need to return the excess Rs 62,000 immediately via NEFT to avoid legal action."},
            {"role": "me",    "text": "Should I wait for it to reflect first?"},
            {"role": "other", "text": "No, the reversal must be done within 30 minutes or your account will be frozen and a police complaint filed."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": (
            "Overpayment refund scam. NEFT + account freeze threat + legal action + urgency. "
            "High escalation from refund story to freeze threat."
        ),
    },
    {
        "name": "SCAM_customs_package_clearance",
        "category": "advanced_scam",
        "subcategory": "authority",
        "messages": [
            {"role": "other", "text": "Customs Department India. A package registered under your Aadhaar has been held at the airport."},
            {"role": "me",    "text": "I'm not expecting any package."},
            {"role": "other", "text": "The parcel contains foreign currency and banned items. You must pay a release fee of Rs 12,000 to avoid criminal charges."},
            {"role": "me",    "text": "Can I come in person?"},
            {"role": "other", "text": "In-person visits are suspended due to an active investigation. Pay via UPI and share your Aadhaar and PAN for verification."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": (
            "Customs impersonation scam. Release fee + document phishing + UPI request. "
            "Authority + money + secrecy cluster."
        ),
    },
    {
        "name": "SCAM_romantic_pig_butchering",
        "category": "advanced_scam",
        "subcategory": "familiarity",
        "messages": [
            {"role": "other", "text": "Hi, sorry to message out of the blue — I think we were at the same startup event in Bangalore?"},
            {"role": "me",    "text": "Maybe! Which one?"},
            {"role": "other", "text": "SaaS Summit 2023. You were wearing a blue jacket. I'm Lisa, I work in fintech investments."},
            {"role": "me",    "text": "I was there! Nice to connect."},
            {"role": "other", "text": "I've been making really good returns on a crypto platform lately. You should try it — you just need to deposit $200 to start. I can guide you personally."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": (
            "Pig-butchering intro. Builds vague familiarity, then pitches investment requiring "
            "upfront crypto deposit. Delayed ask after establishing rapport."
        ),
    },
]


# ─────────────────────────────────────────────────────────────
#  C. BOUNDARY CASES — verdict may be SAFE or SUSPICIOUS
# ─────────────────────────────────────────────────────────────

BOUNDARY_CASES = [
    {
        "name": "BOUND_vague_polite_money_request",
        "category": "boundary",
        "subcategory": "vague",
        "messages": [
            {"role": "other", "text": "Hi, I hope this is fine to ask. Is there any chance you could help me out financially? It's a difficult time."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Very vague request, no amount, no method, no urgency. Polite tone. "
            "Should not trigger SCAM — at most SUSPICIOUS due to money framing."
        ),
    },
    {
        "name": "BOUND_incomplete_authority_no_demand",
        "category": "boundary",
        "subcategory": "authority_no_demand",
        "messages": [
            {"role": "other", "text": "This is a call from TRAI. Your mobile number has been flagged for misuse."},
            {"role": "me",    "text": "What does that mean?"},
            {"role": "other", "text": "An investigation is underway. You will receive an official notice within 48 hours."},
        ],
        "expected_verdict": "SUSPICIOUS",
        "expected_trend": "STABLE",
        "explanation": (
            "Authority claim but no direct financial demand yet. Incomplete scam script. "
            "Should land SUSPICIOUS, not SCAM — no money, no OTP, just a setup."
        ),
    },
    {
        "name": "BOUND_mixed_safe_and_risky",
        "category": "boundary",
        "subcategory": "mixed_signals",
        "messages": [
            {"role": "other", "text": "Hey man, long time! Hope you're well."},
            {"role": "me",    "text": "Yeah all good, you?"},
            {"role": "other", "text": "Things are okay. Actually I wanted to check — did you by any chance notice a transaction of Rs 500 from your UPI account that you didn't make?"},
        ],
        "expected_verdict": "SUSPICIOUS",
        "expected_trend": "STABLE",
        "explanation": (
            "Starts casual, then pivots to a suspicious transaction query. "
            "Could be genuine alert or phishing setup. Mixed signals = SUSPICIOUS."
        ),
    },
    {
        "name": "BOUND_urgent_real_medical_no_money",
        "category": "boundary",
        "subcategory": "urgency_no_demand",
        "messages": [
            {"role": "other", "text": "Emergency! Call me back ASAP. It's about dad."},
            {"role": "me",    "text": "What happened??"},
            {"role": "other", "text": "He's okay now, was having chest pains. At the hospital. Come when you can."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Genuine family emergency with no financial ask. Urgency words present but "
            "resolves without money request. Should not be SCAM."
        ),
    },
    {
        "name": "BOUND_formal_unknown_sender_no_demand",
        "category": "boundary",
        "subcategory": "formal_unknown",
        "messages": [
            {"role": "other", "text": "Dear Sir, I am reaching out on behalf of a mutual connection who suggested I contact you regarding a potential business collaboration."},
            {"role": "me",    "text": "I see, what kind of collaboration?"},
            {"role": "other", "text": "We are a technology firm exploring partnerships in your sector. Could we schedule a call this week?"},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Cold outreach without financial demand. Formal tone may trigger relationship scorer "
            "but no money, OTP, or authority claim present."
        ),
    },
    {
        "name": "BOUND_single_urgency_word_no_context",
        "category": "boundary",
        "subcategory": "vague",
        "messages": [
            {"role": "other", "text": "Please respond urgently regarding your account."},
        ],
        "expected_verdict": "SUSPICIOUS",
        "expected_trend": "STABLE",
        "explanation": (
            "Minimal message with urgency + account keyword but no specifics. "
            "Insufficient for SCAM, clearly odd enough for SUSPICIOUS."
        ),
    },
    {
        "name": "BOUND_known_colleague_odd_request",
        "category": "boundary",
        "subcategory": "mixed_signals",
        "messages": [
            {"role": "other", "text": "Hi, it's Arun from your office. Quick favour — can you transfer Rs 1000 to this new account? Our usual payment system is down."},
            {"role": "me",    "text": "Why not wait for the system?"},
            {"role": "other", "text": "It's urgent for the vendor. Please do it now, I'll sort the paperwork."},
        ],
        "expected_verdict": "SUSPICIOUS",
        "expected_trend": "STABLE",
        "explanation": (
            "Colleague asking for unusual side-channel payment with urgency and promise to fix "
            "paperwork later. Classic Business Email Compromise setup. SUSPICIOUS is correct."
        ),
    },
    {
        "name": "BOUND_part_scam_part_safe",
        "category": "boundary",
        "subcategory": "mixed_signals",
        "messages": [
            {"role": "other", "text": "Hi, this is Amazon. Your Prime subscription has been renewed for Rs 4,999."},
            {"role": "me",    "text": "I didn't authorise this."},
            {"role": "other", "text": "To cancel and get a refund, please call our helpline. We will never ask for your OTP or bank details."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Fake or real Amazon renewal notice that includes a genuine safety disclaimer. "
            "Meta-indicator should suppress false positive."
        ),
    },
]


# ─────────────────────────────────────────────────────────────
#  D. EVOLUTION SCENARIOS
# ─────────────────────────────────────────────────────────────

EVOLUTION_CASES = [
    {
        "name": "EVO_safe_to_scam_gradual",
        "category": "evolution",
        "subcategory": "safe_to_scam",
        "messages": [
            {"role": "other", "text": "Hey! How have you been? It's been ages."},
            {"role": "me",    "text": "All good! You?"},
            {"role": "other", "text": "Great. Just moved to a new city. Life is exciting!"},
            {"role": "me",    "text": "That's wonderful, which city?"},
            {"role": "other", "text": "Hyderabad. Say, I've been investing in this new app and making really good returns. You should check it out."},
            {"role": "me",    "text": "What kind of returns?"},
            {"role": "other", "text": "About 30% monthly. Very safe. You just need to deposit Rs 5000 to start. Share your UPI and I'll guide you."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": (
            "Conversation starts warm and friendly (SAFE), gradually pivots to investment pitch "
            "requiring upfront payment. ESCALATING trend + SCAM verdict expected."
        ),
    },
    {
        "name": "EVO_scam_to_safe_caller_backs_down",
        "category": "evolution",
        "subcategory": "scam_to_safe",
        "messages": [
            {"role": "other", "text": "Your SIM card will be deactivated in 2 hours unless you verify your Aadhaar by sharing the OTP."},
            {"role": "me",    "text": "I'm going to report this number to TRAI."},
            {"role": "other", "text": "Okay okay, I'm sorry. This was a training simulation for our company. No need to report."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "DE-ESCALATING",
        "explanation": (
            "Scam opener but caller backs down when challenged. Verdict should still be SCAM "
            "based on the initial message. Trend should be DE-ESCALATING. "
            "Scammer denial ('training simulation') is itself a manipulation tactic."
        ),
    },
    {
        "name": "EVO_gradual_escalation_four_phases",
        "category": "evolution",
        "subcategory": "escalating",
        "messages": [
            {"role": "other", "text": "Good morning. Hope you are doing well."},
            {"role": "me",    "text": "Good morning!"},
            {"role": "other", "text": "We noticed some activity on your account. Nothing serious yet."},
            {"role": "me",    "text": "Okay, what kind of activity?"},
            {"role": "other", "text": "Transactions of Rs 45,000 to an unknown account. You need to verify this immediately."},
            {"role": "me",    "text": "I didn't do this."},
            {"role": "other", "text": "Then your account may have been compromised. Share your OTP to freeze it before the culprit withdraws more. Or we will have to file an FIR."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": (
            "Textbook 4-phase escalation: neutral greeting → vague concern → money amount → "
            "OTP demand + FIR threat. Full escalation range (phases 0→3)."
        ),
    },
    {
        "name": "EVO_suspicious_resolves_safe",
        "category": "evolution",
        "subcategory": "safe_to_safe",
        "messages": [
            {"role": "other", "text": "Hi, I'm calling about your car insurance renewal."},
            {"role": "me",    "text": "Okay, go ahead."},
            {"role": "other", "text": "Your policy expires next month. I can share a renewal link from our official website."},
            {"role": "me",    "text": "Please email it to me instead of sharing a link on call."},
            {"role": "other", "text": "Of course, no problem. We will email it to your registered address. We never ask for OTP on calls."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Insurance call that seems initially suspicious but resolves safely with proper "
            "redirection and explicit 'never ask OTP' assurance."
        ),
    },
    {
        "name": "EVO_stable_high_risk_no_escalation",
        "category": "evolution",
        "subcategory": "stable_scam",
        "messages": [
            {"role": "other", "text": "Send me the OTP. Your account will be blocked if not done in 10 minutes."},
            {"role": "me",    "text": "Which bank?"},
            {"role": "other", "text": "HDFC. Share OTP immediately or account is suspended."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": (
            "Scam that opens at maximum intensity with no escalation — already threatening from "
            "the first message. Trend should be STABLE (uniformly high risk)."
        ),
    },
]


# ─────────────────────────────────────────────────────────────
#  E. STT NOISE / PHONETIC DISTORTION CASES
# ─────────────────────────────────────────────────────────────

STT_NOISE_CASES = [
    {
        "name": "STT_phonetic_upi_bypass",
        "category": "stt_noise",
        "subcategory": "phonetic",
        "messages": [
            {"role": "other", "text": "Send me two thousand rupees on you pee eye. It's urgent."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": (
            "Phonetic spelling of UPI ('you pee eye'). Rule engine looks for \\bupi\\b which "
            "will not match. STT correction dict doesn't cover this variant."
        ),
    },
    {
        "name": "STT_broken_grammar_otp_request",
        "category": "stt_noise",
        "subcategory": "broken_grammar",
        "messages": [
            {"role": "other", "text": "your a count suspend happen. send otpee for reverify pleese."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": (
            "Severely broken grammar with phonetic OTP variant ('otpee'). "
            "Rule \\botp\\b may not match 'otpee'."
        ),
    },
    {
        "name": "STT_hinglish_threat",
        "category": "stt_noise",
        "subcategory": "hinglish",
        "messages": [
            {"role": "other", "text": "Aapka account band ho jayega. Turant paisa bhejo warna girftari hogi."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": (
            "Pure Hinglish threat: 'account will be closed, send money immediately or arrest'. "
            "HINGLISH_MAP maps 'turant' → 'immediately' and 'paisa' → 'money' but "
            "'girftari' (arrest) and 'bhejo' (send) are unmapped."
        ),
    },
    {
        "name": "STT_spaced_keyword_warrant",
        "category": "stt_noise",
        "subcategory": "phonetic",
        "messages": [
            {"role": "other", "text": "We have a war rant issued in your name. Non bail able charges apply."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": (
            "STT-inserted spaces inside keywords: 'war rant' and 'bail able'. "
            "Regex \\bwarrant\\b and \\bnon.?bailable\\b won't match with spaces inserted."
        ),
    },
    {
        "name": "STT_numeric_amount_obfuscated",
        "category": "stt_noise",
        "subcategory": "obfuscation",
        "messages": [
            {"role": "other", "text": "Transfer ten thousand rupees to this account number five five five zero via NEFT today."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": (
            "Amount given as words not digits ('ten thousand'). Amount pattern regex looks for "
            "digit patterns. NEFT rule should still fire but amount won't be extracted."
        ),
    },
    {
        "name": "STT_ips_phonetic_authority",
        "category": "stt_noise",
        "subcategory": "phonetic",
        "messages": [
            {"role": "other", "text": "I am eye pee ess officer Sharma. You are under digital arrest. Do not disconnect."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": (
            "IPS officer claim spoken phonetically ('eye pee ess'). Authority claim detector "
            "looks for 'officer' (present) but not 'eye pee ess' = IPS variant."
        ),
    },
    {
        "name": "STT_filler_words_diluted_scam",
        "category": "stt_noise",
        "subcategory": "filler",
        "messages": [
            {"role": "other", "text": "So um basically like your uh account has been like flagged and uh you need to uh share the uh otp like right now basically."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": (
            "Heavy filler injection around OTP + account + right now keywords. "
            "STT_FILLERS removes 'uh', 'um', 'like', 'basically' in preprocess. "
            "Remaining text should still be caught."
        ),
    },
    {
        "name": "STT_unicode_lookalike_chars",
        "category": "stt_noise",
        "subcategory": "obfuscation",
        "messages": [
            {"role": "other", "text": "Sh\u0430re your 0TP n0w. Acс0unt will be bl0cked."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": (
            "Cyrillic lookalike characters substituted ('а' for 'a', 'с' for 'c') and zero "
            "for 'o'. Regex won't match 'sh\u0430re' or '0TP'. Unicode normalization missing."
        ),
    },
]


# ─────────────────────────────────────────────────────────────
#  F. EXTRA EDGE CASES (single-message, high-signal)
# ─────────────────────────────────────────────────────────────

EDGE_CASES = [
    {
        "name": "EDGE_empty_but_valid_request",
        "category": "edge",
        "subcategory": "minimal",
        "messages": [
            {"role": "other", "text": "Share your CVV."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": "Single CVV solicitation. Rule engine must catch this immediately.",
    },
    {
        "name": "EDGE_safe_money_flow_to_user",
        "category": "edge",
        "subcategory": "reverse_flow",
        "messages": [
            {"role": "other", "text": "Hi, I'm sending you Rs 2000 as promised. Please confirm your UPI ID."},
            {"role": "me",    "text": "It's myname@upi"},
            {"role": "other", "text": "Sent! Please confirm receipt."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Money flowing TO the user. Asking for UPI ID to send (not receive) money. "
            "Anomaly scorer may still flag UPI + money mention."
        ),
    },
    {
        "name": "EDGE_only_me_messages",
        "category": "edge",
        "subcategory": "minimal",
        "messages": [
            {"role": "me", "text": "Hello?"},
            {"role": "me", "text": "Anyone there?"},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": "No 'other' messages at all. Should default to SAFE with no signal.",
    },
    {
        "name": "EDGE_single_word_threats",
        "category": "edge",
        "subcategory": "minimal",
        "messages": [
            {"role": "other", "text": "Warrant. Arrest. FIR. Pay. Now."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": (
            "Extreme keyword stuffing in a terse message. Multiple rule hits in five words."
        ),
    },
    {
        "name": "EDGE_safe_job_offer_no_money",
        "category": "edge",
        "subcategory": "safe_corporate",
        "messages": [
            {"role": "other", "text": "Hi, I'm a recruiter from Tata Consultancy. Your profile looks great for a role we have open. Would you be interested in a call?"},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "Legitimate recruiter outreach. No money, no urgency, no OTP. "
            "Formal tone should not push into SUSPICIOUS."
        ),
    },
    {
        "name": "EDGE_otp_in_scam_awareness_message",
        "category": "edge",
        "subcategory": "meta",
        "messages": [
            {"role": "other", "text": "Scam alert: Never share your OTP or UPI PIN with anyone claiming to be from your bank."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "OTP + UPI in a warning message. Meta-indicator 'scam alert' should suppress "
            "the rule triggers."
        ),
    },
    {
        "name": "EDGE_police_real_request_for_statement",
        "category": "edge",
        "subcategory": "authority_legitimate",
        "messages": [
            {"role": "other", "text": "This is Inspector Mehta from Bandra Police Station. You were listed as a witness in a case. We'd like you to come in to give a statement at your convenience."},
        ],
        "expected_verdict": "SUSPICIOUS",
        "expected_trend": "STABLE",
        "explanation": (
            "Potentially real police request for witness statement. No money or OTP. "
            "SUSPICIOUS acceptable; SCAM would be a false positive."
        ),
    },
    {
        "name": "EDGE_pin_in_safe_gaming_context",
        "category": "edge",
        "subcategory": "context_dependent",
        "messages": [
            {"role": "other", "text": "Hey, what's the PIN for the WiFi at your place? Coming over tonight."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": (
            "PIN solicitation in clearly safe social context. Rule \\bpin\\b will fire. "
            "Should not be SCAM."
        ),
    },
    {
        "name": "EDGE_long_conversation_low_risk",
        "category": "edge",
        "subcategory": "long_benign",
        "messages": [
            {"role": "other", "text": "Hi! How are you doing?"},
            {"role": "me",    "text": "Good thanks, you?"},
            {"role": "other", "text": "Great! Planning to visit Goa next month."},
            {"role": "me",    "text": "Oh nice! Which part?"},
            {"role": "other", "text": "Probably North Goa. Any recommendations?"},
            {"role": "me",    "text": "Arambol beach is lovely and less touristy."},
            {"role": "other", "text": "Perfect, I'll check it out. Thanks!"},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": "Long benign conversation. No risk signals anywhere. Clean SAFE.",
    },
    {
        "name": "EDGE_scammer_denies_being_scammer",
        "category": "edge",
        "subcategory": "denial_tactic",
        "messages": [
            {"role": "other", "text": "I am calling from the ED. Send Rs 50,000 immediately to avoid arrest."},
            {"role": "me",    "text": "This sounds like a scam."},
            {"role": "other", "text": "This is not a scam. I am legitimate. Trust me. Pay now or face consequences."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": (
            "Scammer explicitly denies being a scam. 'This is not a scam' + 'trust me' "
            "should trigger the denial-tactic amplifier in detector.py."
        ),
    },
]


# ─────────────────────────────────────────────────────────────
#  G. ADDITIONAL ADVERSARIAL CASES (Phase 2 expansion)
# ─────────────────────────────────────────────────────────────

ADVERSARIAL_CASES = [
    # ── Multi-turn manipulation: familiarity → trust → money ──
    {
        "name": "ADV_slow_burn_college_friend",
        "category": "advanced_scam",
        "subcategory": "familiarity",
        "messages": [
            {"role": "other", "text": "Hey! We were in the same batch at IIT, right? 2018?"},
            {"role": "me",    "text": "Hmm maybe, what's your name?"},
            {"role": "other", "text": "It's Vikram! We sat together in the DSA elective. How have you been?"},
            {"role": "me",    "text": "Oh nice, doing well thanks!"},
            {"role": "other", "text": "Great to reconnect! Listen, I'm stuck abroad and my cards aren't working. Could you transfer Rs 10,000 to my UPI? I'll send it right back once I'm home."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": "Fake college familiarity → rapport building → money demand via UPI.",
    },
    {
        "name": "ADV_we_spoke_earlier_scam",
        "category": "advanced_scam",
        "subcategory": "familiarity",
        "messages": [
            {"role": "other", "text": "Hi, we spoke earlier about your investment portfolio. You remember me, right?"},
            {"role": "me",    "text": "I think so..."},
            {"role": "other", "text": "Great! So the mutual fund I mentioned has limited slots. You need to deposit Rs 25,000 today as a security deposit to lock your spot."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": "Fake prior-conversation claim + investment scam + security deposit demand.",
    },
    {
        "name": "ADV_same_event_crypto",
        "category": "advanced_scam",
        "subcategory": "familiarity",
        "messages": [
            {"role": "other", "text": "We were at the same seminar last month in Delhi, weren't we?"},
            {"role": "me",    "text": "Which seminar?"},
            {"role": "other", "text": "The fintech one. I've been doing really well with crypto trading since. Want me to guide you? Just deposit $500 to start."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": "Same-event familiarity gambit → crypto investment pitch with upfront deposit.",
    },

    # ── Corporate / BEC scams ──
    {
        "name": "ADV_vendor_bank_change",
        "category": "advanced_scam",
        "subcategory": "corporate",
        "messages": [
            {"role": "other", "text": "Hi, this is from Vendor Payments at TCS. Our bank details have changed due to an internal restructuring."},
            {"role": "me",    "text": "Okay, what are the new details?"},
            {"role": "other", "text": "Please update our account for all future payments. New NEFT details: ICICI Bank, account 9876543210, IFSC ICIC0001234. The outstanding payment of Rs 4,50,000 should be routed here immediately."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": "BEC vendor bank detail change scam. Large amount + urgency + new account details.",
    },
    {
        "name": "ADV_invoice_legal_threat",
        "category": "advanced_scam",
        "subcategory": "corporate",
        "messages": [
            {"role": "other", "text": "This is a final reminder regarding invoice INV-2025-4412. The outstanding payment of Rs 1,80,000 is now 45 days overdue."},
            {"role": "me",    "text": "I don't recall this invoice."},
            {"role": "other", "text": "Failure to settle the amount within 24 hours will result in a legal notice and service suspension. Wire transfer details enclosed."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": "Fake overdue invoice + legal notice threat + wire transfer demand.",
    },
    {
        "name": "ADV_hr_training_fee",
        "category": "advanced_scam",
        "subcategory": "corporate",
        "messages": [
            {"role": "other", "text": "Congratulations! You have been selected for a premium remote job at Google paying Rs 80,000/month."},
            {"role": "me",    "text": "Really? What's the process?"},
            {"role": "other", "text": "Just pay a registration fee of Rs 3,499 to confirm your slot. This is refundable after your first month. Send to PhonePe 9911223344 and share the screenshot."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": "Fake job offer with registration fee + screenshot sharing demand.",
    },

    # ── Emotional urgency + panic ──
    {
        "name": "ADV_kidnapping_ransom",
        "category": "advanced_scam",
        "subcategory": "emotional",
        "messages": [
            {"role": "other", "text": "We have your son. If you want to see him alive, transfer Rs 5,00,000 to this account immediately."},
            {"role": "me",    "text": "What? Who is this?"},
            {"role": "other", "text": "Do not call the police or tell anyone. Transfer the money within 1 hour or face the consequences. NEFT to SBI account 1122334455."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": "Virtual kidnapping ransom scam. Extreme panic + secrecy + NEFT demand.",
    },
    {
        "name": "ADV_hospital_surgery_urgent",
        "category": "advanced_scam",
        "subcategory": "emotional",
        "messages": [
            {"role": "other", "text": "This is Dr. Kapoor from Medanta Hospital. Your relative has been in a severe accident."},
            {"role": "me",    "text": "Oh god, who?"},
            {"role": "other", "text": "I cannot share details on phone. But immediate surgery is needed. Transfer Rs 2,00,000 to hospital account via RTGS right now. Every minute counts."},
            {"role": "me",    "text": "Can I come there?"},
            {"role": "other", "text": "There's no time. Pay now or we cannot proceed. Do not tell other family members as it may cause panic."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": "Fake hospital scam with RTGS demand + secrecy + extreme urgency.",
    },
    {
        "name": "ADV_electricity_disconnect_panic",
        "category": "advanced_scam",
        "subcategory": "authority",
        "messages": [
            {"role": "other", "text": "This is MSEDCL. Your electricity bill of Rs 12,340 is overdue. Your connection will be disconnected within 2 hours."},
            {"role": "me",    "text": "I paid my bill last month."},
            {"role": "other", "text": "Our system shows pending. To prevent disconnection, pay now via UPI to this number: 8899776655. Share the screenshot for confirmation."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": "Fake utility disconnection scam + UPI payment to personal number + screenshot.",
    },

    # ── STT phonetic expansion tests ──
    {
        "name": "ADV_stt_otpee_account_suspend",
        "category": "stt_noise",
        "subcategory": "phonetic",
        "messages": [
            {"role": "other", "text": "Your a count is suspend. Send otpee now for verify or account will be block."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": "Phonetic 'otpee' + broken grammar 'a count' + urgency.",
    },
    {
        "name": "ADV_stt_you_pee_eye_transfer",
        "category": "stt_noise",
        "subcategory": "phonetic",
        "messages": [
            {"role": "other", "text": "Transfer five thousand rupees on you pee eye immediately or face arrest."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": "Phonetic UPI + word amount + arrest threat.",
    },
    {
        "name": "ADV_stt_war_rant_threat",
        "category": "stt_noise",
        "subcategory": "phonetic",
        "messages": [
            {"role": "other", "text": "A war rant has been issued. You face non bail able charges. Pay the fine immediately."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "STABLE",
        "explanation": "STT-spaced 'war rant' and 'bail able' + fine demand.",
    },

    # ── Confusing SAFE cases ──
    {
        "name": "ADV_safe_friend_birthday_money",
        "category": "false_positive",
        "subcategory": "friend_money",
        "messages": [
            {"role": "other", "text": "Hey dude! Happy birthday man!"},
            {"role": "me",    "text": "Thanks bro!"},
            {"role": "other", "text": "I'm sending you 2000 on GPay as a gift. What's your UPI ID?"},
            {"role": "me",    "text": "It's myname@oksbi, thanks yaar!"},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": "Friend sending birthday money TO user. Casual tone, UPI + money mention should not trigger SCAM.",
    },
    {
        "name": "ADV_safe_real_police_fir",
        "category": "false_positive",
        "subcategory": "authority_legitimate",
        "messages": [
            {"role": "other", "text": "This is Sub-Inspector Patil from Cyber Crime Unit. We are investigating a fraud complaint filed by you last week."},
            {"role": "me",    "text": "Yes, I filed the complaint."},
            {"role": "other", "text": "We need you to visit the station with your documents. No payment is required. Our reference number is CYB/2025/1234."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": "Real police follow-up on user's own complaint. 'No payment required' is a key safe signal.",
    },
    {
        "name": "ADV_safe_delivery_otp",
        "category": "false_positive",
        "subcategory": "real_bank_alert",
        "messages": [
            {"role": "other", "text": "Your Amazon order #ABC-1234 is out for delivery. The delivery person may ask for an OTP to confirm delivery. This is standard procedure."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": "Legitimate delivery OTP notification. Contains 'OTP' but in safe delivery context.",
    },
    {
        "name": "ADV_safe_roommate_rent",
        "category": "false_positive",
        "subcategory": "friend_money",
        "messages": [
            {"role": "other", "text": "Hey buddy, rent is due tomorrow. Your share is Rs 15,000. Can you send it to the landlord's NEFT account?"},
            {"role": "me",    "text": "Sure, sending tonight."},
            {"role": "other", "text": "Cool thanks man!"},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": "Roommate rent reminder. Large amount + NEFT but clear casual context.",
    },

    # ── Digital arrest variants ──
    {
        "name": "ADV_digital_arrest_aadhaar",
        "category": "advanced_scam",
        "subcategory": "authority",
        "messages": [
            {"role": "other", "text": "Your Aadhaar has been linked to money laundering. This is the Enforcement Directorate."},
            {"role": "me",    "text": "That's not possible."},
            {"role": "other", "text": "You are under digital arrest. Stay on the call. Do not disconnect or tell anyone."},
            {"role": "me",    "text": "What do I need to do?"},
            {"role": "other", "text": "Transfer Rs 3,00,000 to a safe harbor account to clear your name. Use RTGS. Share your PIN for verification."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": "Full digital arrest scam with ED impersonation + safe harbor + PIN + RTGS + secrecy.",
    },

    # ── Investment / ponzi ──
    {
        "name": "ADV_guaranteed_returns_scam",
        "category": "advanced_scam",
        "subcategory": "flattery",
        "messages": [
            {"role": "other", "text": "Exclusive offer for selected investors. Guaranteed 50% returns in 30 days on our AI trading platform."},
            {"role": "me",    "text": "That sounds too good to be true."},
            {"role": "other", "text": "We are SEBI registered. You have been chosen from a premium list. Deposit Rs 1,00,000 to start. Limited slots — act now."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": "Fake SEBI registration + guaranteed returns + urgency + large deposit demand.",
    },

    # ── Boundary: suspicious but not full scam ──
    {
        "name": "ADV_boundary_insurance_call",
        "category": "boundary",
        "subcategory": "mixed_signals",
        "messages": [
            {"role": "other", "text": "Hi, I'm calling from LIC about your matured policy. You have Rs 2,50,000 ready for withdrawal."},
            {"role": "me",    "text": "Which policy?"},
            {"role": "other", "text": "Policy number ending 5678. Please verify your identity. Can you confirm your date of birth and PAN number?"},
        ],
        "expected_verdict": "SUSPICIOUS",
        "expected_trend": "STABLE",
        "explanation": "Could be real or fake insurance call. PAN request without payment demand. SUSPICIOUS is appropriate.",
    },

    # ── KYC phishing ──
    {
        "name": "ADV_kyc_link_phishing",
        "category": "advanced_scam",
        "subcategory": "authority",
        "messages": [
            {"role": "other", "text": "Dear customer, your KYC is expired. Verify your KYC immediately by clicking the link below or your account will be blocked."},
            {"role": "me",    "text": "Which bank?"},
            {"role": "other", "text": "State Bank of India. Click the link now: http://sbi-kyc-update.xyz. Enter your account number, password and OTP."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": "KYC phishing with fake link + OTP + password + account credential harvesting.",
    },

    # ── Overpayment return scam ──
    {
        "name": "ADV_overpayment_return",
        "category": "advanced_scam",
        "subcategory": "authority",
        "messages": [
            {"role": "other", "text": "Sir, we accidentally credited Rs 1,50,000 to your account instead of Rs 15,000. Please return the excess money immediately."},
            {"role": "me",    "text": "I don't see any credit."},
            {"role": "other", "text": "It will reflect soon. You must return the excess amount via NEFT right now or we will file a police complaint."},
        ],
        "expected_verdict": "SCAM",
        "expected_trend": "ESCALATING",
        "explanation": "Overpayment return scam with police threat + NEFT demand + urgency.",
    },

    # ── Safe corporate ──
    {
        "name": "ADV_safe_actual_vendor_invoice",
        "category": "false_positive",
        "subcategory": "office_payment",
        "messages": [
            {"role": "other", "text": "Hi, this is Rajan from CloudTech Solutions. Just a reminder that invoice CT-2025-089 for Rs 45,000 is due next week."},
            {"role": "me",    "text": "Thanks for the reminder. I'll process it through our normal payment cycle."},
            {"role": "other", "text": "Perfect, no rush. Happy to send a copy to your finance team if needed."},
        ],
        "expected_verdict": "SAFE",
        "expected_trend": "STABLE",
        "explanation": "Legitimate vendor invoice reminder. No urgency, no threats, normal business tone.",
    },
]


# ─────────────────────────────────────────────────────────────
#  MASTER ASSEMBLER
# ─────────────────────────────────────────────────────────────

def get_all_cases():
    """Return complete test suite (~80-100 cases)."""
    all_cases = (
        FALSE_POSITIVES
        + ADVANCED_SCAMS
        + BOUNDARY_CASES
        + EVOLUTION_CASES
        + STT_NOISE_CASES
        + EDGE_CASES
        + ADVERSARIAL_CASES
    )
    # Assign sequential IDs
    for i, case in enumerate(all_cases):
        case["id"] = i + 1
    return all_cases


def get_cases_by_category(category: str):
    return [c for c in get_all_cases() if c["category"] == category]


def get_case_summary():
    cases = get_all_cases()
    from collections import Counter
    cats   = Counter(c["category"] for c in cases)
    verdicts = Counter(c["expected_verdict"] for c in cases)
    return {
        "total":    len(cases),
        "by_category": dict(cats),
        "by_expected_verdict": dict(verdicts),
    }


if __name__ == "__main__":
    summary = get_case_summary()
    print(f"Total cases: {summary['total']}")
    print(f"By category: {summary['by_category']}")
    print(f"By verdict:  {summary['by_expected_verdict']}")
    for c in get_all_cases():
        print(f"  [{c['id']:02d}] {c['name']:<50s} → {c['expected_verdict']}")