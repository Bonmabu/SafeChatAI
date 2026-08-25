from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8")

routes = r'''

# ============================================================
# CUSTOMER DASHBOARD COMPATIBILITY ROUTES
# ============================================================

@app.get("/soc-summary")
def soc_summary():
    return {
        "total_scans": get_total_scans(),
        "total_alerts": get_total_alerts(),
        "total_incidents": get_total_incidents(),
        "open_incidents": get_open_incident_count(),
        "status": "operational"
    }


@app.get("/customer/dashboard")
def customer_dashboard(user=Depends(get_current_user)):
    return {
        "total_scans": get_total_scans(),
        "total_alerts": get_total_alerts(),
        "total_incidents": get_total_incidents(),
        "open_incidents": get_open_incident_count(),
        "status": "operational"
    }


@app.get("/customer/iocs")
def customer_iocs(user=Depends(get_current_user)):
    return IOC_DATABASE


@app.get("/threat-dna")
def threat_dna():
    try:
        from threat_dna import get_threat_dna

        dna = get_threat_dna()

        if isinstance(dna, dict):
            return {
                "fingerprints": dna.get("fingerprints", [])
            }

        if isinstance(dna, list):
            return {
                "fingerprints": dna
            }

        return {"fingerprints": []}

    except Exception as e:
        print("THREAT DNA ERROR:", e)
        return {"fingerprints": []}
'''

required = [
    '@app.get("/soc-summary")',
    '@app.get("/customer/dashboard")',
    '@app.get("/customer/iocs")',
    '@app.get("/threat-dna")'
]

missing = [x for x in required if x not in text]

if missing:
    path.write_text(text.rstrip() + routes + "\n", encoding="utf-8", newline="\n")
    print("Added missing routes:")
    for x in missing:
        print("  " + x)
else:
    print("All four routes already exist. Nothing changed.")
