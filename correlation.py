from datetime import datetime, timedelta
import uuid

# Active campaigns
ATTACK_CAMPAIGNS = []

# Correlation window
CORRELATION_WINDOW = timedelta(minutes=30)


def correlate_event(event):
    """
    Correlates an event with an existing campaign
    or creates a new campaign.
    """

    now = datetime.now()

    username = event.get("username", "")
    hostname = event.get("hostname", "")
    source_ip = event.get("source_ip", "")

    for campaign in ATTACK_CAMPAIGNS:

        if now - campaign["last_seen"] > CORRELATION_WINDOW:
            continue

        if (
            username
            and username == campaign["username"]
        ) or (
            hostname
            and hostname == campaign["hostname"]
        ) or (
            source_ip
            and source_ip == campaign["source_ip"]
        ):

            campaign["events"].append(event)
            campaign["last_seen"] = now

            update_campaign(campaign)

            return campaign

    campaign = {
        "id": str(uuid.uuid4())[:8],
        "created": now,
        "last_seen": now,
        "username": username,
        "hostname": hostname,
        "source_ip": source_ip,
        "events": [event],
        "severity": event["score"],
        "campaign": event["category"],
        "stage": event["stage"],
        "confidence": event["confidence"]
    }

    ATTACK_CAMPAIGNS.append(campaign)

    return campaign


def update_campaign(campaign):

    categories = {
        e["category"]
        for e in campaign["events"]
    }

    stages = {
        e["stage"]
        for e in campaign["events"]
    }

    highest = max(
        e["score"]
        for e in campaign["events"]
    )

    campaign["severity"] = highest

    campaign["stage"] = " → ".join(stages)

    if (
        "Cloud Compromise" in categories
        and "Active Directory Attack" in categories
        and "Lateral Movement" in categories
        and "Ransomware" in categories
    ):
        campaign["campaign"] = "Enterprise Ransomware"

    elif (
        "Business Email Compromise" in categories
        and "Data Exfiltration" in categories
    ):
        campaign["campaign"] = "Business Email Fraud"

    elif (
        "Password Spraying" in categories
        and "Privilege Escalation" in categories
    ):
        campaign["campaign"] = "Account Takeover"

    elif (
        "Privilege Escalation" in categories
        and "Data Leak" in categories
    ):
        campaign["campaign"] = "Insider Data Theft"

    campaign["confidence"] = min(
        99,
        highest + len(categories)
    )


def get_campaigns():

    return ATTACK_CAMPAIGNS