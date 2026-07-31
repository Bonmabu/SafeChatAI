from datetime import datetime


def generate_copilot_analysis(
    category,
    risk_score,
    message,
    status
):
    actions = []

    if risk_score >= 80:
        severity = "CRITICAL"
        actions = [
            "Block detected indicators",
            "Escalate to SOC Level 2",
            "Investigate affected user/session"
        ]

    elif risk_score >= 50:
        severity = "HIGH"
        actions = [
            "Monitor activity",
            "Collect additional evidence",
            "Assign analyst review"
        ]

    else:
        severity = "LOW"
        actions = [
            "Log event",
            "Continue monitoring"
        ]

    return {
        "summary": f"{category} threat detected with {severity} risk",
        "severity": severity,
        "risk_score": risk_score,
        "recommended_actions": actions,
        "analyst_note": (
            f"AI analysis: {category} activity detected. "
            f"Message pattern requires review."
        ),
        "generated_at": datetime.utcnow().isoformat()
    }


def explain_incident(incident):
    return {
        "incident_id": incident.get("id"),
        "explanation": (
            f"This incident involves {incident.get('category')} "
            f"with risk score {incident.get('risk_score')}."
        ),
        "recommendation": "Review indicators and apply containment actions."
    }
def soc_copilot(
    category=None,
    risk_score=0,
    message="",
    status=""
):
    return {
        "category": category,
        "risk_score": risk_score,
        "status": status,
        "message": message,
        "recommendation": [
            "Review threat indicators",
            "Check affected user activity",
            "Escalate based on severity"
        ]
    }