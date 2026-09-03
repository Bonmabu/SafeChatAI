from datetime import datetime


THREAT_INTEL_DB = {
    "iocs": [],
    "incidents": []
}


def enrich_iocs(iocs):
    results = []

    for ioc in iocs:
        now = datetime.utcnow().isoformat()

        results.append({
            "ioc": ioc,
            "type": "unknown",
            "reputation": "unknown",
            "risk_score": 50,
            "sources": "SafeChat AI",
            "first_seen": now,
            "checked_at": now
        })

    THREAT_INTEL_DB["iocs"].extend(results)

    return results

def analyze_iocs(iocs):

    risk = "LOW"

    if len(iocs) > 5:
        risk = "HIGH"

    if len(iocs) > 10:
        risk = "CRITICAL"

    return {
        "count": len(iocs),
        "risk": risk,
        "iocs": iocs
    }


def enrich_incident(message):
    import re

    iocs = re.findall(
        r"(?:https?://\S+|(?:\d{1,3}\.){3}\d{1,3}|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})",
        message
    )
    return enrich_iocs(iocs)
def detect_campaign(category=None, message=None, risk_score=0, *args, **kwargs):

    text = f"{category} {message}".lower()

    if "phishing" in text or "bank" in text or "verify" in text:
        return "Credential Harvesting Campaign"

    if "malware" in text or "download" in text or "payload" in text:
        return "Malware Distribution Campaign"

    if "fraud" in text or "payment" in text or "money" in text:
        return "Financial Fraud Campaign"

    if risk_score and float(risk_score) >= 80:
        return "High Risk Unknown Campaign"

    return "Unknown Campaign"

