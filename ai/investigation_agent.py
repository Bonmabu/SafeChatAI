from datetime import datetime


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalize(value):
    return str(value or "").strip().lower()


def investigate_incident(incident, incidents=None, iocs=None):
    """
    Phase 39 — AI Investigation Agent.

    Performs deterministic investigation over existing SOC data:
    incident -> related activity -> IOC context -> findings -> actions.
    """

    incidents = incidents or []
    iocs = iocs or []

    incident_id = incident.get("id")
    category = incident.get("category", "Unknown")
    score = _safe_float(
        incident.get("risk_score", incident.get("score", 0))
    )
    status = str(incident.get("status", "OPEN"))
    mitre = incident.get("mitre") or incident.get("mitre_technique")

    incident_category = _normalize(category)

    affected_users = incident.get("affected_users", []) or []
    affected_devices = incident.get("affected_devices", []) or []
    event_count = int(_safe_float(incident.get("event_count", 0)))

    related_incidents = []

    for item in incidents:
        if not isinstance(item, dict):
            continue

        if incident_id is not None and item.get("id") == incident_id:
            continue

        item_category = _normalize(item.get("category"))

        if (
            item_category == incident_category
            and incident_category not in {"", "safe", "unknown"}
        ):
            related_incidents.append(item)

    related_iocs = []

    for ioc in iocs:
        if not isinstance(ioc, dict):
            continue

        ioc_category = _normalize(
            ioc.get("category")
            or ioc.get("type")
            or ioc.get("threat_type")
        )

        if (
            ioc_category == incident_category
            or incident_category in ioc_category
            or ioc_category in incident_category
        ):
            related_iocs.append(ioc)

    findings = []
    evidence = []

    if score >= 80:
        findings.append(
            "High-risk activity requires immediate investigation."
        )
        evidence.append("Risk score is at or above the critical threshold.")

    elif score >= 50:
        findings.append(
            "Suspicious activity requires analyst review."
        )
        evidence.append("Risk score exceeds the investigation threshold.")

    else:
        findings.append(
            "Risk level is currently below the investigation threshold."
        )

    if related_incidents:
        findings.append(
            f"{len(related_incidents)} related incident(s) "
            f"share the same threat category."
        )
        evidence.append("Related historical incident activity detected.")

    if related_iocs:
        findings.append(
            f"{len(related_iocs)} related IOC record(s) "
            f"were identified."
        )
        evidence.append("IOC intelligence is available for correlation.")

    if affected_users:
        findings.append(
            f"{len(affected_users)} affected user(s) "
            f"are associated with the campaign."
        )
        evidence.append("Campaign identity scope is available.")

    if affected_devices:
        findings.append(
            f"{len(affected_devices)} affected device(s) "
            f"are associated with the campaign."
        )
        evidence.append("Campaign device scope is available.")

    if event_count > 1:
        findings.append(
            f"The campaign contains {event_count} correlated security events."
        )
        evidence.append("Multiple security events establish campaign activity.")

    if mitre:
        findings.append(
            f"MITRE ATT&CK mapping identified: {mitre}."
        )
        evidence.append("MITRE technique metadata is present.")

    if status.upper() in {"OPEN", "INVESTIGATING", "ACTIVE"}:
        findings.append(
            "Incident remains active and should remain in the investigation queue."
        )

    if score >= 80:
        priority = "IMMEDIATE"
        actions = [
            "Review the incident and correlated events immediately.",
            "Validate all associated indicators of compromise.",
            "Investigate affected users, devices, and sessions.",
            "Apply containment according to SOC policy.",
        ]
    elif score >= 50:
        priority = "HIGH"
        actions = [
            "Review correlated incidents and indicators.",
            "Validate the available evidence.",
            "Monitor affected entities for additional activity.",
            "Escalate if the threat score increases.",
        ]
    else:
        priority = "NORMAL"
        actions = [
            "Continue monitoring.",
            "Retain available evidence for future correlation.",
        ]

    confidence = 55

    if related_incidents:
        confidence += 10

    if related_iocs:
        confidence += 10

    if mitre:
        confidence += 10

    if score >= 80:
        confidence += 10

    confidence = min(99, confidence)

    return {
        "agent": "SafeChat Investigation Agent",
        "agent_version": "1.0",
        "status": "completed",
        "investigation_id": (
            f"INV-{incident_id}"
            if incident_id is not None
            else f"INV-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        ),
        "incident_id": incident_id,
        "category": category,
        "risk_score": score,
        "severity": (
            "CRITICAL"
            if score >= 80
            else "HIGH"
            if score >= 50
            else "LOW"
        ),
        "priority": priority,
        "confidence": confidence,
        "related_incidents": len(related_incidents),
        "related_iocs": len(related_iocs),
        "affected_users": len(affected_users),
        "affected_devices": len(affected_devices),
        "event_count": event_count,
        "mitre": mitre,
        "findings": findings,
        "evidence": evidence,
        "recommended_actions": actions,
        "generated_at": datetime.utcnow().isoformat(),
    }

