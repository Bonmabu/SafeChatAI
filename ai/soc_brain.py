from datetime import datetime

SOC_BRAIN = {
    "history": [],
    "patterns": {},
    "campaigns": {}
}


def analyze_pattern(category, score, corr_id):

    if category not in SOC_BRAIN["patterns"]:
        SOC_BRAIN["patterns"][category] = {
            "count": 0,
            "avg_score": 0
        }

    p = SOC_BRAIN["patterns"][category]

    p["count"] += 1

    p["avg_score"] = (
        (p["avg_score"] * (p["count"] - 1) + score)
        / p["count"]
    )

    SOC_BRAIN["history"].append({
        "category": category,
        "score": score,
        "corr_id": corr_id,
        "time": datetime.utcnow().isoformat()
    })

    if len(SOC_BRAIN["history"]) > 100:
        SOC_BRAIN["history"] = SOC_BRAIN["history"][-100:]

    return p


def predict_next_attack():

    if not SOC_BRAIN["patterns"]:
        return None

    highest = max(
        SOC_BRAIN["patterns"].items(),
        key=lambda x: x[1]["count"]
    )

    return {
        "predicted_category": highest[0],
        "confidence": min(100, highest[1]["count"] * 10)
    }
from collections import Counter

def executive_reasoning(summary, graph):
    nodes = graph.get("nodes", [])

    categories = [n.get("category", "Unknown") for n in nodes]
    top = Counter(categories).most_common(5)

    security = summary.get("security_score", 100)
    critical = summary.get("critical_threats", 0)
    incidents = summary.get("open_incidents", 0)

    findings = []

    if security < 25:
        findings.append("SOC health is critical.")

    if critical > 20:
        findings.append(f"{critical} critical threats detected.")

    if incidents > 10:
        findings.append(f"{incidents} incidents require investigation.")

    return {
        "summary": " ".join(findings),
        "top_threats": top,
        "confidence": min(99, 60 + critical)
    }

