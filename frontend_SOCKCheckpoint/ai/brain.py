from ai.prompts import SOC_PROMPT

def think(message: str):
    text = message.lower()

    if "loan" in text:
        return {
            "summary": "Possible financial scam detected.",
            "risk": 82,
            "category": "Financial Fraud",
            "mitre": "T1566",
            "response": "Investigate sender before responding."
        }

    if "password" in text:
        return {
            "summary": "Credential theft attempt detected.",
            "risk": 91,
            "category": "Credential Phishing",
            "mitre": "T1566.002",
            "response": "Reset password immediately."
        }

    if "bitcoin" in text:
        return {
            "summary": "Possible cryptocurrency scam.",
            "risk": 88,
            "category": "Crypto Fraud",
            "mitre": "T1583",
            "response": "Block sender and preserve evidence."
        }

    return {
        "summary": "No significant threat detected.",
        "risk": 10,
        "category": "Safe",
        "mitre": None,
        "response": "No action required."
    }