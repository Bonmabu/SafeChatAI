from datetime import datetime

from ai.investigation_agent import investigate_incident


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
            f"This incident involves "
            f"{incident.get('category', 'Unknown')} activity."
        ),
        "recommendation": (
            "Review indicators and apply containment actions."
        )
    }


def soc_copilot(query, incidents=None, iocs=None):
    """
    Phase 39 Copilot entry point.

    Routes incident-focused questions through the
    Investigation Agent while preserving the existing
    Copilot response contract.
    """

    incidents = incidents or []
    iocs = iocs or []

    query_text = str(query or "").strip()

    if not incidents:
        return {
            "agent": "SafeChat Investigation Agent",
            "action": "investigate",
            "status": "no_incidents",
            "answer": "No incidents are currently available for investigation.",
            "findings": [],
            "recommendations": [
                "Continue monitoring incoming security events."
            ]
        }

    query_lower = query_text.lower()

    candidates = incidents

    # Prefer explicit incident ID when supplied.
    for incident in incidents:
        incident_id = str(incident.get("id", ""))

        if incident_id and incident_id in query_text:
            candidates = [incident]
            break

    # Otherwise prioritize active/high-risk incidents.
    if candidates == incidents:
        active = [
            incident
            for incident in incidents
            if str(
                incident.get("status", "")
            ).upper() in {"OPEN", "INVESTIGATING", "ACTIVE"}
        ]

        if active:
            candidates = active

    # Prefer critical/high-risk incident when the query asks
    # about investigation, threats, or critical activity.
    if any(
        term in query_lower
        for term in (
            "investigate",
            "incident",
            "threat",
            "critical",
            "attack",
            "suspicious",
        )
    ):
        candidates = sorted(
            candidates,
            key=lambda item: float(
                item.get(
                    "risk_score",
                    item.get("score", 0)
                ) or 0
            ),
            reverse=True
        )

    incident = candidates[0]

    investigation = investigate_incident(
        incident,
        incidents=incidents,
        iocs=iocs
    )

    return {
        "agent": investigation["agent"],
        "action": "investigate",
        "status": "completed",
        "answer": (
            f"Investigation completed for incident "
            f"{investigation.get('incident_id')}. "
            f"{len(investigation.get('findings', []))} findings identified."
        ),
        "investigation": investigation,
        "findings": investigation["findings"],
        "evidence": investigation["evidence"],
        "recommendations": investigation["recommended_actions"],
        "confidence": investigation["confidence"],
    }
