from embeddings import get_embedding, cosine_similarity

DATASET = [
    # Authority Scams
    {"text": "This is Deputy Commissioner Rajesh Sharma calling from CBI headquarters New Delhi. Your Aadhaar number has been used in a drug trafficking case. You must cooperate or face immediate arrest.", "cluster": "AUTHORITY_SCAM"},
    {"text": "I am Inspector General from Mumbai Crime Branch. A parcel intercepted at Mumbai airport containing 2 kilograms of drugs is registered under your name. You will be arrested within 2 hours.", "cluster": "AUTHORITY_SCAM"},
    {"text": "Namaskar, this is calling from Delhi Police Cyber Cell. Your mobile number is linked to a hawala transaction of 47 lakh rupees. Kindly do the needful immediately or warrant will be issued.", "cluster": "AUTHORITY_SCAM"},
    {"text": "This is IPS officer Vikram Singh from Central Bureau of Investigation. Your bank account is under surveillance for money laundering. You must transfer all funds to Safe Harbor Vault for protection.", "cluster": "AUTHORITY_SCAM"},
    {"text": "I am calling from Customs Department of India. A courier parcel in your name from China is blocked at IGI Airport. It contains illegal substances. You have to pay release fee or police will visit.", "cluster": "AUTHORITY_SCAM"},
    {"text": "This is Enforcement Directorate officer speaking. FEMA violation detected in your account. Rs 8 lakh penalty or immediate arrest. Do not disconnect call or we will send team to your address.", "cluster": "AUTHORITY_SCAM"},
    {"text": "Your mobile SIM is being misused for terror funding activities. This is NIA officer calling. All your numbers will be blocked in 2 hours. Press 9 to connect to nodal officer now.", "cluster": "AUTHORITY_SCAM"},
    {"text": "Namaste, I am IAS officer Pradeep Mishra from Ministry of Finance. Your PAN card is suspended due to suspicious ITR filing. Kindly cooperate or income tax raid will be conducted at your premises.", "cluster": "AUTHORITY_SCAM"},
    {"text": "This is TRAI officer. Your mobile number is going to be disconnected permanently in 2 hours due to illegal activities. Press 1 to speak to officer and save your connection.", "cluster": "AUTHORITY_SCAM"},
    {"text": "CBI has registered FIR number 7742/2024 against your name for cyberfraud of Rs 12 lakh. I am officer Deepak Verma. You must give statement via video call or face non-bailable warrant.", "cluster": "AUTHORITY_SCAM"},
    {"text": "This is calling from GST department head office. Your business GST number has been flagged for tax evasion of 23 lakh. Pay immediately or we will seize your business accounts.", "cluster": "AUTHORITY_SCAM"},
    {"text": "Mumbai Police Cyber Crime Division is speaking. Your Aadhaar is linked to 14 fake bank accounts used for online fraud. Cooperate immediately or you will be taken into digital arrest.", "cluster": "AUTHORITY_SCAM"},
    {"text": "I am Senior Superintendent of Police from Kolkata. A complaint has been filed against you for sending obscene messages. Settle this matter before it goes to court. Pay fine of Rs 50,000.", "cluster": "AUTHORITY_SCAM"},
    {"text": "This is officer from Supreme Court of India legal department. Non-bailable warrant has been issued against your name. You must appear virtually or send your representative immediately.", "cluster": "AUTHORITY_SCAM"},
    {"text": "Calling from Narcotics Control Bureau. Package with your Aadhaar details found with 500 grams of methamphetamine at Chennai port. This is cognizable offence. Pay settlement or face 10 years imprisonment.", "cluster": "AUTHORITY_SCAM"},
    {"text": "I am DCP Suresh Kumar from Economic Offences Wing. Your savings account at SBI is linked to Ponzi scheme. Account will be seized in 3 hours. Transfer savings to RBI protected vault immediately.", "cluster": "AUTHORITY_SCAM"},
    {"text": "This is calling from Income Tax Department raid team. We are outside your premises. Your ITR mismatch shows income of 45 lakh undisclosed. Pay 30 percent penalty online to avoid arrest.", "cluster": "AUTHORITY_SCAM"},
    {"text": "RBI officer speaking. Your bank account has been flagged under Prevention of Money Laundering Act. To protect your funds transfer them to government escrow account immediately.", "cluster": "AUTHORITY_SCAM"},
    {"text": "This is cyber crime police station Hyderabad. Your IP address has been used to send 840 spam messages for fraud lottery scheme. You will be booked under IT Act Section 66D.", "cluster": "AUTHORITY_SCAM"},
    {"text": "Calling from CBI New Delhi. Your name and photo found in prostitution racket FIR. This is very serious case. Pay Rs 2 lakh compromise fee and matter will be closed without going to media.", "cluster": "AUTHORITY_SCAM"},
    {"text": "Sir, I am IPS officer from central bureau. Your Aadhaar has been linked to drug shipment. You must cooperate or we will come to your house with warrant.", "cluster": "AUTHORITY_SCAM"},
    {"text": "Namaskar, I am officer from TRAI. Your number is being used by terrorists. We are initiating digital arrest. Please stay on call and do not talk to anyone including family members.", "cluster": "AUTHORITY_SCAM"},
    {"text": "This is DIG rank officer Ratan Lal from CBI Intelligence wing. We have evidence your mobile was used to access dark web content. Cooperate now or we proceed with hard arrest.", "cluster": "AUTHORITY_SCAM"},
    {"text": "Hello I am calling from Delhi High Court. Contempt of court notice issued against your PAN number. Pay challan of Rs 75,000 through online mode only before 5 PM today.", "cluster": "AUTHORITY_SCAM"},
    {"text": "This is Customs and Excise officer from Chennai. Your courier parcel from Dubai has been seized. It contains undeclared gold biscuits worth 14 lakh. Pay import duty or face smuggling charges.", "cluster": "AUTHORITY_SCAM"},
    {"text": "This is officer from Cyber Police Maharashtra. Your WhatsApp has been used to spread fake news causing communal tension. This is non-bailable. Pay Rs 1 lakh or face 3 years jail.", "cluster": "AUTHORITY_SCAM"},
    {"text": "CBI officer speaking. We have intercepted your call logs showing conversation with known criminal Dawood network. You are under surveillance. Report to nearest CBI office within 2 hours.", "cluster": "AUTHORITY_SCAM"},
    {"text": "This is SEBI enforcement officer. Your demat account shows 48 suspicious transactions. Account will be sealed. Pay regulatory penalty of Rs 1.2 lakh to avoid criminal proceedings.", "cluster": "AUTHORITY_SCAM"},
    {"text": "This is cybercrime DSP from Bengaluru. Your email ID has been used to send threatening emails to a minister. This is criminal conspiracy charge. Surrender digitally or team will visit.", "cluster": "AUTHORITY_SCAM"},
    {"text": "Sir this is UIDAI helpline. Your Aadhaar biometric data has been compromised. Lock your biometric immediately by paying Rs 499 through our secure link to prevent misuse.", "cluster": "AUTHORITY_SCAM"},
    {"text": "This is from Ministry of Home Affairs verification department. Your passport has been flagged for fake documents at embassy. Pay verification fee of Rs 3,500 to restore passport validity.", "cluster": "AUTHORITY_SCAM"},
    {"text": "I am calling from SBI head office fraud department. Your account will be freeze within 1 hour. Kindly do the needful and verify your KYC by clicking the link sent to you immediately.", "cluster": "AUTHORITY_SCAM"},
    {"text": "This is officer from Interpol India division. International arrest warrant issued against your passport number. Pay bail security of Rs 75,000 to government account to avoid extradition.", "cluster": "AUTHORITY_SCAM"},
    {"text": "National Cyber Crime Reporting Portal officer. Your IMEI is blacklisted. Reactivate by paying Rs 2,500 through government payment link.", "cluster": "AUTHORITY_SCAM"},
    {"text": "I am from finance ministry. Your PAN number shows foreign remittance violation. Settle the matter with us privately before we escalate to court.", "cluster": "AUTHORITY_SCAM"},
    # Financial Scams
    {"text": "Congratulations! You have won the KBC lottery of Rs 25 lakh. To claim your prize you must first pay a processing fee of Rs 5,000 and GST charges to release your winning amount.", "cluster": "FINANCIAL_SCAM"},
    {"text": "Your SBI account KYC is expired. Your account will be blocked in 24 hours. Click the link below and update your KYC details including Aadhaar, PAN and debit card number immediately.", "cluster": "FINANCIAL_SCAM"},
    {"text": "You have been selected as a premium customer. To unlock your exclusive benefits please purchase Rs 10,000 in Amazon gift cards and share the codes with our team.", "cluster": "FINANCIAL_SCAM"},
    {"text": "Invest in our guaranteed scheme and get 40 percent monthly returns. Thousands of investors are already earning. Send Rs 50,000 to get started. 100 percent safe government backed.", "cluster": "FINANCIAL_SCAM"},
    {"text": "I am Sophia from London. I am sending you a gift package from UK but customs is asking for clearance fee of Rs 8,000. Please help me send the money.", "cluster": "FINANCIAL_SCAM"},
    {"text": "Your computer is infected with 7 viruses. I am calling from Microsoft support. Please install our remote tool and pay Rs 2,999 annual protection plan to fix immediately.", "cluster": "FINANCIAL_SCAM"},
    {"text": "Work from home earn Rs 50,000 per month. No experience needed. Just pay Rs 1,500 registration fee and Rs 2,000 for training kit. Thousands already working successfully.", "cluster": "FINANCIAL_SCAM"},
    {"text": "Your Paytm KYC is incomplete. Your wallet will be blocked tonight. Call our KYC officer and share your Aadhaar number and OTP to complete verification immediately.", "cluster": "FINANCIAL_SCAM"},
    {"text": "Your mobile number has been selected in Jio lucky draw. You have won iPhone 15 and Rs 1 lakh cash. Pay Rs 1,800 courier charge to receive your prize.", "cluster": "FINANCIAL_SCAM"},
    {"text": "This is LIC officer calling. You are eligible for Rs 74,000 policy bonus refund. Share your account details and OTP received on mobile for instant transfer to your account.", "cluster": "FINANCIAL_SCAM"},
    {"text": "Join our trading group and make $500 daily with bitcoin. Our AI algorithm has 94 percent win rate. Deposit minimum $200 USDT to activate your trading account now.", "cluster": "FINANCIAL_SCAM"},
    {"text": "Grandma it is me your grandson Tyler. I am in jail in Mexico and need $3,000 bail money via Western Union right away. Please do not tell mom and dad about this.", "cluster": "FINANCIAL_SCAM"},
    {"text": "Earn $800 per day reshipping packages from home. No experience needed. Pay $250 starter kit fee and we will send you your first assignment within 24 hours.", "cluster": "FINANCIAL_SCAM"},
    {"text": "Your Bank of America online account shows unauthorized wire transfer of $8,900. Contact our fraud department immediately by calling this number and provide your account number and PIN.", "cluster": "FINANCIAL_SCAM"},
    {"text": "This is your bank calling. We detected suspicious activity on your account. Please verify your card number, expiry date and CVV to stop the transaction immediately.", "cluster": "FINANCIAL_SCAM"},
    {"text": "You have a pending tax refund of Rs 14,500. To receive it click the link and enter your bank account number and ATM PIN for direct credit within 24 hours.", "cluster": "FINANCIAL_SCAM"},
    # Safe
    {"text": "Hi this is Meena from accounts. Can you please share the updated TDS certificates for Q4? Auditors need them before Friday end of day for the annual accounts finalization process.", "cluster": "SAFE"},
    {"text": "The AWS bill for last month came to $4,200. It is higher than usual due to the data migration project. Engineering team please optimize the unused EC2 instances to bring costs down.", "cluster": "SAFE"},
    {"text": "Does anyone know a good pediatrician near Whitefield Bangalore? My son has had a mild fever for 2 days and I want to get him checked.", "cluster": "SAFE"},
    {"text": "The client signed off on the final design mockups. We can now proceed to development sprint. Engineering team please attend the kickoff call on Monday 10 AM.", "cluster": "SAFE"},
    {"text": "Hi there, checking if our team meeting scheduled for 3 PM is still on. I have another call that can potentially conflict. Please confirm so I can send the right calendar invite update.", "cluster": "SAFE"},
    {"text": "Good news everyone. We crossed 100,000 users on the app today! Thank you to every team member who made this milestone possible. Celebratory cake in the cafeteria at 4 PM.", "cluster": "SAFE"},
    {"text": "Mom, I got placed at TCS with a package of 7 LPA. Final round was yesterday and the offer letter just came. Starting date is June 15.", "cluster": "SAFE"},
    {"text": "Your Zomato order from Mainland China is out for delivery. Estimated arrival 8:45 PM. If you have any special instructions for the delivery partner please add them in the order notes.", "cluster": "SAFE"},
    {"text": "I need to connect a React frontend with a Node Express backend. Getting CORS errors when trying to fetch data. How do I set up proper CORS headers on the server side?", "cluster": "SAFE"},
    {"text": "Hi team, the vendor has agreed to extend the contract for another 6 months at the same rate. Legal will circulate the amendment for signatures by Thursday.", "cluster": "SAFE"},
]

CLUSTER_PLAYBOOKS = {
    "AUTHORITY_SCAM": {
        "verdict": "SCAM",
        "confidence": "HIGH",
        "reasons": [
            "Caller is impersonating law enforcement or government officials.",
            "Uses fear tactics: threats of arrest, warrant, or account seizure.",
        ],
        "actions": [
            "Hang up immediately.",
            "No government agency demands payment over phone.",
            "Call 1930 (Cyber Crime Helpline).",
            "Verify by calling the official agency's published number.",
        ],
    },
    "FINANCIAL_SCAM": {
        "verdict": "SCAM",
        "confidence": "HIGH",
        "reasons": [
            "High-pressure financial demand or credential theft pattern detected.",
            "Offer too good to be true, or urgent payment / fee required.",
        ],
        "actions": [
            "Never share OTP, PIN, or card details.",
            "Do not pay any 'processing fee' to claim prizes.",
            "Call 1930 (Cyber Crime Helpline).",
            "Block and report this number.",
        ],
    },
    "SAFE": {
        "verdict": "SAFE",
        "confidence": "HIGH",
        "reasons": ["Matches known safe conversation patterns."],
        "actions": ["Proceed normally.", "Remain vigilant for unexpected requests."],
    },
}

SAFE_RESULT = {
    "verdict": "SAFE",
    "confidence": "LOW",
    "cluster": "UNKNOWN",
    "matches": [],
    "reasons": ["No threat patterns found in semantic database."],
    "actions": ["Proceed normally.", "Remain vigilant for unverified requests."],
}

print("[SYSTEM] Computing baseline vectors for Semantic Database...")
STORED_VECTORS = []
for item in DATASET:
    STORED_VECTORS.append({
        "text": item["text"],
        "cluster": item["cluster"],
        "embedding": get_embedding(item["text"]),
    })
print(f"[SYSTEM] Vector Database ready with {len(STORED_VECTORS)} patterns.")


def search(query_text: str, threshold: float = 0.62, top_k: int = 3) -> dict:
    query_emb = get_embedding(query_text)

    scored = []
    for item in STORED_VECTORS:
        score = cosine_similarity(query_emb, item["embedding"])
        scored.append((score, item))

    scored.sort(key=lambda x: x[0], reverse=True)
    top = scored[:top_k]
    best_score, best_item = top[0]

    print(
        f"[VECTOR] Top match: '{best_item['text'][:60]}...' "
        f"| Score: {best_score:.2f} | Cluster: {best_item['cluster']}"
    )

    if best_score < threshold or best_item["cluster"] == "SAFE":
        result = dict(SAFE_RESULT)
        result["matches"] = [item["text"][:80] for _, item in top if _ >= 0.40]
        return result

    playbook = dict(CLUSTER_PLAYBOOKS.get(best_item["cluster"], CLUSTER_PLAYBOOKS["SAFE"]))
    top_matches = [
        item["text"][:80]
        for score, item in top
        if score >= threshold and item["cluster"] != "SAFE"
    ]

    return {
        "verdict": playbook["verdict"],
        "confidence": playbook["confidence"],
        "cluster": best_item["cluster"],
        "matches": top_matches,
        "reasons": playbook["reasons"] + [f"Semantic similarity: {best_score * 100:.1f}%"],
        "actions": playbook["actions"],
    }