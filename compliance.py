from datetime import datetime

COMPLIANCE_FRAMEWORKS = [
    "ISO 27001",
    "NIST CSF",
    "SOC 2",
    "PCI DSS",
    "GDPR"
]

def compliance_summary():
    return {
        "generated": datetime.utcnow().isoformat(),
        "score": 87,
        "status": "Compliant",
        "frameworks": COMPLIANCE_FRAMEWORKS,
        "controls": {
            "implemented": 87,
            "pending": 13
        }
    }