from datetime import datetime

CAMPAIGNS = {}
MITRE_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]


def detect_campaign(event):
    """
    event = {
        "category": ...,
        "score": ...,
        "stage": ...,
        "mitre": ...,
        "confidence": ...,
        "source_ip": ...,
        "hostname": ...,
        "username": ...
    }
    """

    category = event.get("category", "Unknown")
    score = event.get("score", 0)
    stage = event.get("stage", "")
    mitre = event.get("mitre", "")
    confidence = event.get("confidence", 0)

    source_ip = event.get("source_ip", "unknown")
    hostname = event.get("hostname", "unknown")
    username = event.get("username", "unknown")

    now = datetime.utcnow().isoformat()

    # Campaign key
    key = f"{source_ip}:{hostname}:{category}"

    if key not in CAMPAIGNS:

        CAMPAIGNS[key] = {

            "id": f"CAM-{len(CAMPAIGNS)+1:05d}",

            "campaign": category,

            "status": "Active",

            "start_time": now,

            "last_seen": now,

            "severity": score,

            "confidence": confidence,

            "events": [],

            "users": [],

            "hosts": [],

            "ips": [],

            "mitre": [],

            "kill_chain": []
        }

    c = CAMPAIGNS[key]

    c["last_seen"] = now
    c["severity"] = max(c["severity"], score)
    c["confidence"] = max(c["confidence"], confidence)

    if username not in c["users"]:
        c["users"].append(username)

    if hostname not in c["hosts"]:
        c["hosts"].append(hostname)

    if source_ip not in c["ips"]:
        c["ips"].append(source_ip)

    if mitre and mitre not in c["mitre"]:
        c["mitre"].append(mitre)

    if stage and stage not in c["kill_chain"]:

        c["kill_chain"].append(stage)

        c["kill_chain"].sort(
        key=lambda x: MITRE_ORDER.index(x)
        if x in MITRE_ORDER else 999
    )

    c["events"].append({
        "time": now,
        "category": category,
        "score": score,
        "stage": stage,
        "mitre": mitre
    })

    return c


def get_campaigns():
    return list(CAMPAIGNS.values())


def get_campaign(campaign_id):

    for campaign in CAMPAIGNS.values():
        if campaign["id"] == campaign_id:
            return campaign

    return None


def close_campaign(campaign_id):

    campaign = get_campaign(campaign_id)

    if campaign:
        campaign["status"] = "Closed"

    return campaign