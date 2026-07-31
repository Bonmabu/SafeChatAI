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
        "confidence": min(99, 60 + critical),
    }
from collections import Counter

def executive_reasoning(summary, graph):
    nodes = graph.get("nodes", [])

    categories = [
        n.get("category", "Unknown")
        for n in nodes
    ]

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