"""
data_generator.py — Adversarial scam/safe sample generator (v2).
Produces 2400+ samples across 4 categories with realistic mutations.
Categories:
  1. Obvious scams (authority threats, payment demands)
  2. Subtle scams (no threats, social engineering, slow burn)
  3. Safe but scam-like (real bank alerts, IT emails, official comms)
  4. Emotional/social manipulation (romance, guilt, family emergency)
"""
import random
import re
import json
import itertools

random.seed(42)

# ═══════════════════════════════════════════════════════════════
#  VOCABULARY POOLS
# ═══════════════════════════════════════════════════════════════

AUTHORITY_ROLES = [
    "CBI officer", "DCP", "Customs officer", "TRAI officer",
    "RBI official", "Cyber Crime DSP", "Income Tax inspector",
    "Enforcement Directorate officer", "Sub-Inspector",
    "Senior Superintendent", "Narcotics Bureau chief",
]
AGENCIES = [
    "CBI", "Mumbai Police", "Income Tax Department", "TRAI",
    "Narcotics Control Bureau", "Enforcement Directorate",
    "Reserve Bank of India", "SEBI", "Delhi Police Cyber Cell",
]
OFFENCES = [
    "money laundering", "drug trafficking", "hawala transactions",
    "cybercrime under IT Act 66D", "tax evasion", "terror financing",
    "FEMA violation", "identity theft", "fraudulent KYC submissions",
]
DEMANDS = [
    "Pay Rs {amount} immediately to avoid arrest.",
    "Transfer Rs {amount} to safe harbor account.",
    "Pay clearance fee of Rs {amount}.",
    "Deposit Rs {amount} into the escrow account provided.",
    "Wire Rs {amount} via NEFT to the account I will share.",
    "Send Rs {amount} through UPI to verify your identity.",
]
THREATS = [
    "You will be arrested within {hours} hours.",
    "Your account will be frozen.",
    "Digital arrest has been initiated against you.",
    "A non-bailable warrant has been issued in your name.",
    "Your passport will be suspended immediately.",
    "FIR number {fir} has been filed. Surrender or face arrest.",
]
FINANCIAL_OPENERS = [
    "Congratulations! You won Rs {amount}.",
    "Your KYC has expired. Account blocked in 24 hours.",
    "You have a tax refund of Rs {amount}.",
    "Your SBI account will be deactivated. Update KYC now.",
    "Unclaimed insurance payout of Rs {amount} in your name.",
    "RBI has flagged your account. Immediate verification needed.",
]
FINANCIAL_HOOKS = [
    "Click the link and enter OTP.",
    "Pay Rs {fee} processing fee to release amount.",
    "Share your CVV to verify.",
    "Enter your PIN to confirm identity.",
    "Send OTP received on your phone.",
    "Transfer Rs {fee} as refundable security deposit.",
]

# ── Subtle scam components (no overt threats) ──────────────
SUBTLE_OPENERS = [
    "Hi, this is {name} from {company} customer support.",
    "We noticed unusual activity on your account ending {last4}.",
    "Your recent transaction of Rs {amount} is being reviewed.",
    "This is a courtesy call regarding your {product} application.",
    "We are upgrading your account security. Need quick verification.",
    "Your {service} subscription renewal failed. Please update payment.",
]
SUBTLE_HOOKS = [
    "Can you confirm the OTP we just sent?",
    "I need your registered mobile number to pull up your account.",
    "Please share the last 4 digits of your card for verification.",
    "We'll send a verification link. Please click and complete the process.",
    "For security, please share the code you just received via SMS.",
    "Can you verify your date of birth and mother's maiden name?",
    "I'm going to share a link for you to reset your credentials.",
]
SUBTLE_NAMES = ["Rahul", "Priya", "Amit", "Neha", "Vikram", "Sneha", "Rajesh"]
SUBTLE_COMPANIES = [
    "HDFC Bank", "SBI", "Airtel", "Jio", "Amazon", "Flipkart",
    "Paytm", "PhonePe", "Google Pay", "ICICI Bank", "Axis Bank",
]
SUBTLE_PRODUCTS = ["credit card", "home loan", "FD", "insurance policy", "mutual fund"]
SUBTLE_SERVICES = ["Netflix", "Hotstar", "Amazon Prime", "Spotify", "YouTube Premium"]

# ── Emotional / social manipulation ────────────────────────
EMOTIONAL_OPENERS = [
    "Hey, it's me. I'm in serious trouble and I can't tell anyone else.",
    "I've been in an accident and I need money urgently for the hospital.",
    "Papa collapsed. We need Rs {amount} for the ICU deposit RIGHT NOW.",
    "I'm stuck at the airport, my wallet got stolen. Can you send money?",
    "Please don't tell anyone but I got scammed and need money to fix it.",
    "I met someone online and they need help. I just need to send them Rs {amount}.",
    "Your son has been detained. Send Rs {amount} bail money or he stays in jail.",
    "This is an emergency. Your daughter's phone is off and she owes hospital fees.",
]
EMOTIONAL_ESCALATIONS = [
    "Please don't tell mom and dad about this.",
    "I'm begging you, time is running out.",
    "If you don't help me now, something terrible will happen.",
    "I promise I'll pay you back. Just send it now.",
    "They said if I don't pay in 1 hour they'll file a case.",
    "I know this sounds crazy but please just trust me.",
    "You're the only person I can ask. Everyone else said no.",
    "Stay on the call with me. Don't disconnect.",
]
EMOTIONAL_PAYMENT = [
    "Send it to this UPI: {upi_id}",
    "Transfer via Google Pay to {phone}",
    "NEFT to account {acc_no}, IFSC {ifsc}",
    "Just send Rs {amount} to my friend's account, I'll explain later.",
    "Buy a gift card worth Rs {amount} and share the code with me.",
]

# ── BEC / Corporate scam ──────────────────────────────────
BEC_TEMPLATES = [
    "Hi {name}, this is {ceo}. I need you to process a wire transfer of Rs {amount} to a vendor urgently. Keep this confidential until the deal closes.",
    "{name}, please purchase {count} gift cards worth Rs {amount} each for client appreciation. Send me the codes. Don't loop in anyone else.",
    "Hey {name}, the payment to {vendor} bounced. Can you resend Rs {amount} to this new account? Need it done before EOD.",
    "This is {ceo} texting from my personal number. Process Rs {amount} to the account I'm sharing. Finance already approved it.",
    "{name}, our {vendor} invoice is overdue. Transfer Rs {amount} immediately to avoid service disruption. I'll send account details.",
]
CEO_NAMES = ["Rajiv Sir", "the CFO", "Mr. Sharma", "Anil", "Deepak from finance"]
VENDOR_NAMES = ["TechServe Solutions", "CloudPro", "DataSync Inc", "vendor ABC"]
EMPLOYEE_NAMES = ["Priya", "Amit", "Sneha", "Rohan", "Kavitha"]

# ── Safe but scam-like (legitimate communications) ─────────
SAFE_BANK_ALERTS = [
    "Your HDFC account {acc} was debited Rs {amount} on {date}. If not done by you, call 18002026161.",
    "SBI Alert: Rs {amount} credited to your account ending {last4} via NEFT. Ref: {ref}.",
    "ICICI: Your credit card ending {last4} was charged Rs {amount} at {merchant}. SMS BLOCK to 9215676766 if not you.",
    "Axis Bank: Your FD of Rs {amount} matures on {date}. Visit branch or net banking to renew.",
    "RBI update: UPI transaction limit revised to Rs 5,00,000 for select categories effective {date}.",
    "Your EMI of Rs {amount} for loan ending {last4} is due on {date}. Ensure sufficient balance.",
]
SAFE_IT_EMAILS = [
    "Hi team, we're rolling out mandatory password rotation next Monday. Please update via the internal portal.",
    "Reminder: Complete your annual cybersecurity training by {date}. Link on the intranet.",
    "IT Advisory: Phishing attempts targeting our domain detected. Do not click suspicious links. Report to security@company.com.",
    "VPN maintenance scheduled for Saturday 2 AM to 6 AM. Plan accordingly.",
    "Your Jira ticket PROJ-{num} has been assigned to {name}. Please review.",
    "The deployment to staging environment completed successfully. Build #{num} is ready for QA.",
]
SAFE_GOVT_MSGS = [
    "UIDAI: Your Aadhaar details have been successfully updated. If not initiated by you, visit uidai.gov.in.",
    "Income Tax Dept: Your ITR for AY {year} has been processed. Refund of Rs {amount} initiated to your bank account.",
    "EPFO: Your PF contribution for {month} has been credited. Check balance on epfindia.gov.in.",
    "DigiLocker: Document '{doc}' has been issued to your account. Access at digilocker.gov.in.",
    "Passport Seva: Your application {ref} is under review. Expected processing time: 30 days.",
    "IRCTC: PNR {pnr} confirmed. Train {train} on {date} from {src} to {dst}.",
]
SAFE_PERSONAL = [
    "Hey, can you share the updated TDS certificate by Friday?",
    "Mom, I got placed at {company} with {salary} LPA! So happy!",
    "Getting CORS errors when fetching from backend. Ideas?",
    "The AWS bill for {month} came to ${aws_amount}. We should optimize.",
    "Does anyone know a good dermatologist near {city}?",
    "Your {service} order is out for delivery. ETA 8 PM.",
    "Meeting rescheduled to 3 PM. Can you update the calendar invite?",
    "Happy birthday! Wishing you all the best this year.",
    "The WiFi password for the guest network is sunshine2024.",
    "Please review the PR before tomorrow's standup.",
    "Can you pick up groceries on the way home? We need milk and eggs.",
    "Traffic is terrible on the highway. Taking the metro instead.",
    "The plumber is coming at 4 PM. Can someone be home?",
    "I renewed our Netflix subscription. Family plan is Rs 649/month now.",
    "Your Swiggy order has been delivered. Rate your experience.",
]
SAFE_PROFESSIONAL = [
    "Hi {name}, please find attached the Q{q} financial report for your review.",
    "The board meeting is confirmed for {date} at 10 AM. Agenda attached.",
    "Reminder: Your performance review is scheduled for next {day}.",
    "Please process the vendor payment for invoice INV-{num}. Amount: Rs {amount}. Already approved by finance.",
    "The client demo went well. They want a follow-up call next week.",
    "Your leave request for {date} has been approved by your manager.",
    "The new office WiFi credentials are in the shared doc. Please update.",
]

# ── Value pools ────────────────────────────────────────────
AMOUNTS = ["5,000", "25,000", "1,00,000", "2,50,000", "3,500", "15,000", "50,000", "75,000", "10,000", "8,500"]
SMALL_AMOUNTS = ["500", "999", "1,200", "2,000", "3,500"]
HOURS = ["1", "2", "4", "6", "12"]
FIR_NUMBERS = ["2847/2024", "1093/2025", "4521/2024", "7832/2025"]
LAST4 = ["3847", "9021", "5567", "1234", "7788", "4455"]
DATES = ["15-Jan-2025", "03-Feb-2025", "22-Mar-2025", "10-Apr-2025", "01-May-2025"]
MONTHS = ["January", "February", "March", "April", "Q3", "Q4", "last month"]
COMPANIES = ["TCS", "Infosys", "Wipro", "Amazon", "Google", "Flipkart", "Razorpay"]
CITIES = ["Mumbai", "Delhi", "Bangalore", "Pune", "Hyderabad", "Chennai"]
SERVICES = ["Zomato", "Swiggy", "Amazon", "Blinkit", "BigBasket", "Dunzo"]
MERCHANTS = ["Amazon.in", "Flipkart", "Myntra", "BookMyShow", "MakeMyTrip", "Uber"]
DOCS_POOL = ["Driving License", "PAN Card", "Aadhaar", "Marksheet"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
UPI_IDS = ["scammer@ybl", "helpdesk.verify@oksbi", "urgent.pay@paytm", "safe.transfer@axl"]
PHONE_NUMBERS = ["9876543210", "8765432109", "7654321098", "9988776655"]
ACC_NUMBERS = ["1234567890", "9876543210", "5566778899", "1122334455"]
IFSC_CODES = ["HDFC0001234", "SBIN0005678", "ICIC0009012", "UTIB0003456"]
TRAIN_NUMBERS = ["12345 Rajdhani", "22222 Shatabdi", "16789 Duronto"]
PNR_NUMBERS = ["4512389076", "2345678901", "8765432109"]

def _pick(lst): return random.choice(lst)


# ═══════════════════════════════════════════════════════════════
#  MUTATION ENGINE
# ═══════════════════════════════════════════════════════════════

def _inject_urgency(text: str) -> str:
    urgency = [
        " Act immediately.", " Time is running out.", " Do not delay.",
        " This is very urgent.", " Respond within 10 minutes.",
        " Failure to comply will result in action.", " Last warning.",
    ]
    return text.rstrip(".") + "." + _pick(urgency)

def _break_grammar(text: str) -> str:
    replacements = [
        ("immediately", "immidiately"), ("Your", "Ur"), ("your", "ur"),
        ("please", "pls"), ("Please", "Pls"), ("because", "bcoz"),
        ("account", "acnt"), ("transfer", "trnsfr"), ("money", "mny"),
        ("number", "numbr"), ("payment", "paymt"), ("receive", "recieve"),
        ("verification", "verifcation"), ("immediately", "immediatly"),
    ]
    for orig, garbled in replacements:
        if orig in text and random.random() > 0.6:
            text = text.replace(orig, garbled, 1)
    return text

def _add_stt_noise(text: str) -> str:
    """Simulate speech-to-text transcription errors."""
    stt_errors = [
        ("warrant", "warant"), ("arrested", "arested"), ("account", "acount"),
        ("transfer", "transfor"), ("immediately", "immediate lee"),
        ("digital", "dijital"), ("officer", "offcer"), ("department", "depart meant"),
        ("verification", "very fi cation"), ("suspicious", "suspishus"),
        ("processing", "prosessing"), ("criminal", "crimnal"),
        ("authority", "athority"), ("payment", "pay meant"),
        ("government", "goverment"), ("fraudulent", "frodulent"),
        ("compliance", "complience"), ("investigation", "investgation"),
    ]
    for orig, garbled in stt_errors:
        if orig.lower() in text.lower() and random.random() > 0.5:
            text = re.sub(re.escape(orig), garbled, text, count=1, flags=re.I)
    # Add random filler words (STT artifacts)
    if random.random() > 0.7:
        fillers = [" uh ", " um ", " like ", " you know ", " basically "]
        words = text.split()
        if len(words) > 5:
            pos = random.randint(2, len(words) - 2)
            words.insert(pos, _pick(fillers).strip())
            text = " ".join(words)
    return text

def _shuffle_words(text: str) -> str:
    words = text.split()
    if len(words) > 6:
        s = random.randint(2, len(words) // 3)
        segment = words[s:s + 3]
        random.shuffle(segment)
        words[s:s + 3] = segment
    return " ".join(words)

def _add_typos(text: str) -> str:
    """Random character-level typos."""
    if random.random() > 0.5:
        return text
    words = text.split()
    if len(words) < 3:
        return text
    idx = random.randint(1, len(words) - 1)
    w = words[idx]
    if len(w) > 3:
        op = random.choice(["swap", "drop", "double"])
        pos = random.randint(1, len(w) - 2)
        if op == "swap" and pos < len(w) - 1:
            w = w[:pos] + w[pos + 1] + w[pos] + w[pos + 2:]
        elif op == "drop":
            w = w[:pos] + w[pos + 1:]
        elif op == "double":
            w = w[:pos] + w[pos] + w[pos:]
        words[idx] = w
    return " ".join(words)

def _hinglish_mix(text: str) -> str:
    """Add Hindi/Hinglish words common in Indian scam calls."""
    mixes = [
        ("Sir", "Sirji"), ("please", "kripya"), ("immediately", "turant"),
        ("money", "paisa"), ("Listen", "Suniye"), ("understand", "samjhiye"),
        ("Your", "Aapka"), ("police", "police wale"),
    ]
    for eng, hin in mixes:
        if eng in text and random.random() > 0.6:
            text = text.replace(eng, hin, 1)
    return text

def _apply_mutations(text: str, scam: bool = True) -> str:
    """Apply a random subset of mutations."""
    mutations = []
    if scam:
        if random.random() < 0.35: mutations.append(_inject_urgency)
        if random.random() < 0.30: mutations.append(_break_grammar)
        if random.random() < 0.25: mutations.append(_add_stt_noise)
        if random.random() < 0.15: mutations.append(_shuffle_words)
        if random.random() < 0.20: mutations.append(_add_typos)
        if random.random() < 0.20: mutations.append(_hinglish_mix)
    else:
        if random.random() < 0.15: mutations.append(_add_stt_noise)
        if random.random() < 0.10: mutations.append(_add_typos)
    for mut in mutations:
        text = mut(text)
    return text


# ═══════════════════════════════════════════════════════════════
#  CATEGORY 1: OBVIOUS SCAMS
# ═══════════════════════════════════════════════════════════════

def _make_authority_scam() -> str:
    text = (
        f"I am {_pick(AUTHORITY_ROLES)} from {_pick(AGENCIES)}. "
        f"Your Aadhaar is linked to {_pick(OFFENCES)}. "
        f"{_pick(THREATS).format(hours=_pick(HOURS), fir=_pick(FIR_NUMBERS))} "
        f"{_pick(DEMANDS).format(amount=_pick(AMOUNTS))}"
    )
    return _apply_mutations(text, scam=True)

def _make_financial_scam() -> str:
    text = (
        f"{_pick(FINANCIAL_OPENERS).format(amount=_pick(AMOUNTS))} "
        f"{_pick(FINANCIAL_HOOKS).format(fee=_pick(SMALL_AMOUNTS))}"
    )
    if random.random() < 0.3:
        text = f"I am {_pick(AUTHORITY_ROLES)}. " + text
    return _apply_mutations(text, scam=True)

def _make_digital_arrest() -> str:
    templates = [
        "This is {role} from {agency}. You are under digital arrest. Do not disconnect this call. Do not tell anyone. Transfer Rs {amount} to clear your name.",
        "Digital arrest warrant issued. Case number {fir}. Stay on the call. Any attempt to disconnect will be treated as non-cooperation. Transfer Rs {amount} immediately.",
        "Your phone and bank accounts are under surveillance as part of digital arrest proceedings. Cooperate by transferring Rs {amount} to the safe vault account.",
    ]
    text = _pick(templates).format(
        role=_pick(AUTHORITY_ROLES), agency=_pick(AGENCIES),
        amount=_pick(AMOUNTS), fir=_pick(FIR_NUMBERS)
    )
    return _apply_mutations(text, scam=True)


# ═══════════════════════════════════════════════════════════════
#  CATEGORY 2: SUBTLE SCAMS (no overt threats)
# ═══════════════════════════════════════════════════════════════

def _make_subtle_scam() -> str:
    opener = _pick(SUBTLE_OPENERS).format(
        name=_pick(SUBTLE_NAMES), company=_pick(SUBTLE_COMPANIES),
        last4=_pick(LAST4), amount=_pick(AMOUNTS),
        product=_pick(SUBTLE_PRODUCTS), service=_pick(SUBTLE_SERVICES),
    )
    hook = _pick(SUBTLE_HOOKS)
    text = f"{opener} {hook}"
    return _apply_mutations(text, scam=True)

def _make_bec_scam() -> str:
    text = _pick(BEC_TEMPLATES).format(
        name=_pick(EMPLOYEE_NAMES), ceo=_pick(CEO_NAMES),
        amount=_pick(AMOUNTS), count=random.randint(5, 20),
        vendor=_pick(VENDOR_NAMES),
    )
    return _apply_mutations(text, scam=True)

def _make_slow_burn_scam() -> str:
    """Multi-turn slow burn — starts innocent, escalates."""
    phases = [
        [
            "Hi, I'm calling from {company} regarding your account.",
            "We've noticed some irregularity and wanted to help you secure your account.",
            "For verification, can you confirm the OTP I just triggered to your phone?",
        ],
        [
            "Hello, this is the fraud prevention team at {company}.",
            "Good news — we've blocked a suspicious transaction on your account.",
            "To complete the reversal, I'll need you to share the verification code sent to your phone.",
        ],
        [
            "Sir/Ma'am, your {product} application has been pre-approved.",
            "We just need to verify some details to process it.",
            "Please share the 6-digit code we sent. It's just for identity confirmation.",
        ],
    ]
    phase = _pick(phases)
    text = " ".join(phase).format(
        company=_pick(SUBTLE_COMPANIES), product=_pick(SUBTLE_PRODUCTS)
    )
    return _apply_mutations(text, scam=True)

def _make_refund_scam() -> str:
    templates = [
        "Hi, you are eligible for a refund of Rs {amount} from {company}. To process, please install the app I'm sending and share your screen so I can guide you.",
        "We overcharged you Rs {amount} on your last {product} bill. I'll initiate the refund now. Just open the link and enter your UPI PIN when prompted.",
        "Your {company} order was cancelled but the refund failed. Please share your bank details so we can process it manually.",
    ]
    text = _pick(templates).format(
        amount=_pick(AMOUNTS), company=_pick(SUBTLE_COMPANIES),
        product=_pick(SUBTLE_PRODUCTS)
    )
    return _apply_mutations(text, scam=True)


# ═══════════════════════════════════════════════════════════════
#  CATEGORY 3: SAFE BUT SCAM-LIKE
# ═══════════════════════════════════════════════════════════════

def _make_safe_bank_alert() -> str:
    text = _pick(SAFE_BANK_ALERTS).format(
        acc="XX" + _pick(LAST4), amount=_pick(AMOUNTS),
        date=_pick(DATES), last4=_pick(LAST4),
        ref="NEFT" + str(random.randint(100000, 999999)),
        merchant=_pick(MERCHANTS),
    )
    return _apply_mutations(text, scam=False)

def _make_safe_it_email() -> str:
    text = _pick(SAFE_IT_EMAILS).format(
        date=_pick(DATES), num=str(random.randint(1000, 9999)),
        name=_pick(SUBTLE_NAMES),
    )
    return _apply_mutations(text, scam=False)

def _make_safe_govt_msg() -> str:
    text = _pick(SAFE_GOVT_MSGS).format(
        year="2025-26", amount=_pick(SMALL_AMOUNTS),
        month=_pick(MONTHS), doc=_pick(DOCS_POOL),
        ref="PSK" + str(random.randint(100000, 999999)),
        pnr=_pick(PNR_NUMBERS), train=_pick(TRAIN_NUMBERS),
        date=_pick(DATES), src=_pick(CITIES), dst=_pick(CITIES),
    )
    return _apply_mutations(text, scam=False)

def _make_safe_personal() -> str:
    text = _pick(SAFE_PERSONAL).format(
        company=_pick(COMPANIES), salary=str(random.randint(5, 30)),
        month=_pick(MONTHS), aws_amount=str(random.randint(100, 9999)),
        city=_pick(CITIES), service=_pick(SERVICES),
    )
    return _apply_mutations(text, scam=False)

def _make_safe_professional() -> str:
    text = _pick(SAFE_PROFESSIONAL).format(
        name=_pick(SUBTLE_NAMES), q=random.randint(1, 4),
        date=_pick(DATES), day=_pick(DAYS),
        num=str(random.randint(1000, 9999)),
        amount=_pick(AMOUNTS),
    )
    return _apply_mutations(text, scam=False)

# Hard negatives — safe text that contains trigger words
def _make_hard_negative() -> str:
    templates = [
        "Reminder: Never share your OTP with anyone. HDFC Bank will never ask for it.",
        "Mom, someone tried to scam me today! They asked me to pay a fine. I didn't fall for it.",
        "Just completed the cybersecurity training. The module on digital arrest scams was eye-opening.",
        "FYI: If anyone calls claiming to be from CBI and asks for money, it's a scam. Report to 1930.",
        "The RBI has issued a circular warning about fake UPI refund scams. Be careful.",
        "I work at the fraud prevention desk at {company}. Genuine calls from us will never ask for your PIN.",
        "My friend lost Rs {amount} to a warrant scam last week. These fraudsters are getting smarter.",
        "News article: Digital arrest scams on the rise. Authorities urge public to hang up on suspicious calls.",
        "Please verify your KYC at your nearest {company} branch. Do not share details over phone.",
        "Setting up wire transfer for vendor payment as approved in yesterday's meeting. Account details on file.",
        "Can you send money to the caterer for the office party? His UPI is on the shared sheet.",
        "The processing fee for the visa application is Rs {amount}. Pay on the official portal only.",
        "Paid the clearance fee at customs for the shipment. Receipt attached.",
        "Got the OTP for the Domino's order. Pizza in 30 mins!",
        "Transfer money from savings to FD? The interest rate is better right now.",
    ]
    text = _pick(templates).format(
        company=_pick(SUBTLE_COMPANIES), amount=_pick(AMOUNTS)
    )
    return _apply_mutations(text, scam=False)


# ═══════════════════════════════════════════════════════════════
#  CATEGORY 4: EMOTIONAL / SOCIAL MANIPULATION
# ═══════════════════════════════════════════════════════════════

def _make_emotional_scam() -> str:
    opener = _pick(EMOTIONAL_OPENERS).format(amount=_pick(AMOUNTS))
    escalation = _pick(EMOTIONAL_ESCALATIONS)
    payment = _pick(EMOTIONAL_PAYMENT).format(
        upi_id=_pick(UPI_IDS), phone=_pick(PHONE_NUMBERS),
        acc_no=_pick(ACC_NUMBERS), ifsc=_pick(IFSC_CODES),
        amount=_pick(AMOUNTS),
    )
    text = f"{opener} {escalation} {payment}"
    return _apply_mutations(text, scam=True)

def _make_romance_scam() -> str:
    templates = [
        "I know we just met online but I feel a deep connection with you. I'm stuck in {city} and need Rs {amount} for my flight back. I promise I'll pay you back when we meet.",
        "Baby, I'm in the hospital and my insurance doesn't cover it. Can you send Rs {amount}? I'll transfer it back as soon as I'm out. You're the only one I trust.",
        "I have a great investment opportunity but I need Rs {amount} to get started. We can double it in a week. Trust me, I've done this before.",
        "I'm sending you a gift package from abroad. The customs charges are Rs {amount}. Can you pay and I'll reimburse you?",
    ]
    text = _pick(templates).format(city=_pick(CITIES), amount=_pick(AMOUNTS))
    return _apply_mutations(text, scam=True)

def _make_guilt_scam() -> str:
    templates = [
        "You promised to help me and now you're backing out? I thought you were a good person. Just send Rs {amount}.",
        "If something happens to me because you didn't help, it's on your conscience. Send Rs {amount} now.",
        "I helped you when you needed it. Now I need Rs {amount} urgently. Don't be like this.",
        "My child is sick and I have no one else to turn to. Rs {amount} for medicines. Please, I'm desperate.",
    ]
    text = _pick(templates).format(amount=_pick(AMOUNTS))
    return _apply_mutations(text, scam=True)

# Safe emotional (not scams)
def _make_safe_emotional() -> str:
    templates = [
        "I'm going through a really tough time. Can we talk?",
        "Mom is in the hospital but the insurance is covering it. Just wanted to let you know.",
        "Lost my wallet today. Already blocked the cards. What a day.",
        "Feeling overwhelmed at work. The deadline is killing me.",
        "Had an argument with my roommate about money. So stressful.",
        "My car broke down on the highway. AAA is on the way though.",
        "Grandpa isn't doing well. Keeping him in our prayers.",
        "I need help urgently — with this Python bug. It's driving me crazy!",
    ]
    return _pick(templates)


# ═══════════════════════════════════════════════════════════════
#  MAIN GENERATOR
# ═══════════════════════════════════════════════════════════════

def generate(n_total: int = 2400) -> list[dict]:
    samples = []

    # Category 1: Obvious scams (~25%)
    n_obvious = int(n_total * 0.25)
    generators_obvious = [_make_authority_scam, _make_financial_scam, _make_digital_arrest]
    for i in range(n_obvious):
        gen = generators_obvious[i % len(generators_obvious)]
        samples.append({"text": gen(), "label": 1})

    # Category 2: Subtle scams (~20%)
    n_subtle = int(n_total * 0.20)
    generators_subtle = [_make_subtle_scam, _make_bec_scam, _make_slow_burn_scam, _make_refund_scam]
    for i in range(n_subtle):
        gen = generators_subtle[i % len(generators_subtle)]
        samples.append({"text": gen(), "label": 1})

    # Category 3: Safe but scam-like (~30%)
    n_safe_tricky = int(n_total * 0.30)
    generators_safe = [
        _make_safe_bank_alert, _make_safe_it_email, _make_safe_govt_msg,
        _make_safe_personal, _make_safe_professional, _make_hard_negative,
    ]
    for i in range(n_safe_tricky):
        gen = generators_safe[i % len(generators_safe)]
        samples.append({"text": gen(), "label": 0})

    # Category 4: Emotional manipulation (~15% scam + 10% safe emotional)
    n_emotional_scam = int(n_total * 0.15)
    generators_emotional_scam = [_make_emotional_scam, _make_romance_scam, _make_guilt_scam]
    for i in range(n_emotional_scam):
        gen = generators_emotional_scam[i % len(generators_emotional_scam)]
        samples.append({"text": gen(), "label": 1})

    n_safe_emotional = int(n_total * 0.10)
    for _ in range(n_safe_emotional):
        samples.append({"text": _make_safe_emotional(), "label": 0})

    random.shuffle(samples)
    return samples


if __name__ == "__main__":
    data = generate(2400)
    with open("dataset.json", "w") as f:
        json.dump(data, f, indent=2)

    scam_count = sum(1 for d in data if d["label"] == 1)
    safe_count = sum(1 for d in data if d["label"] == 0)
    print(f"Generated {len(data)} samples: {scam_count} scam, {safe_count} safe")
    print("Saved to dataset.json")