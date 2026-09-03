from pathlib import Path
import re
import shutil
from datetime import datetime

path = Path("main.py")

# Backup current working file
backup = Path(f"main.py.before_decision_fix_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

pattern = re.compile(
    r'@app\.get\("/executive/decision"\)\s*'
    r'def executive_decision\(\):.*?'
    r'(?=@app\.get\("/executive/priority-queue"\))',
    re.S
)

replacement = '''@app.get("/executive/decision")
def executive_decision():

    kpi = get_executive_kpis()

    # Enterprise risk remains the overall enterprise risk metric.
    risk = float(kpi.get("enterprise_risk", 0) or 0)

    # Determine the executive top threat from actual high-risk incidents.
    # Safe/low-risk events must never become the executive top threat.
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT category, COUNT(*) AS total
        FROM incidents
        WHERE risk_score >= 70
          AND category IS NOT NULL
          AND category != 'Safe'
        GROUP BY category
        ORDER BY total DESC, MAX(risk_score) DESC
        LIMIT 1
    """)

    threat_row = cursor.fetchone()

    conn.close()

    if threat_row is not None:
        try:
            top = threat_row["category"]
        except (KeyError, IndexError, TypeError):
            try:
                top = threat_row[0]
            except (KeyError, IndexError, TypeError):
                top = "No active high-risk threat"
    else:
        top = "No active high-risk threat"

    # Executive risk decision.
    if risk >= 75:
        level = "Critical"
        recommendation = (
            "Immediate executive intervention required. "
            "Prioritize high-risk incidents."
        )
        change = "Increasing"

    elif risk >= 50:
        level = "High"
        recommendation = (
            "Review active threats and accelerate remediation."
        )
        change = "Elevated"

    elif risk >= 25:
        level = "Medium"
        recommendation = (
            "Monitor threat activity and review security controls."
        )
        change = "Stable"

    else:
        level = "Low"
        recommendation = (
            "Security posture is healthy. Continue monitoring."
        )
        change = "Improving"

    return {
        "level": level,
        "top_threat": top,
        "risk_change": change,
        "recommendation": recommendation,
        "enterprise_risk": round(risk, 2)
    }

'''

match = pattern.search(text)

if not match:
    print("ERROR: executive_decision block was not found.")
    print("No changes made.")
else:
    text = text[:match.start()] + replacement + text[match.end():]
    path.write_text(text, encoding="utf-8", newline="\n")
    print("SUCCESS: executive_decision logic repaired.")
    print(f"Backup created: {backup.name}")
