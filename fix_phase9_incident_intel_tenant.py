from pathlib import Path

path = Path(r".\main.py")
text = path.read_text(encoding="utf-8")

old = '''@app.get("/customer/incidents/{incident_id}/intel", dependencies=[Depends(require_customer_access)])
def incident_intel(incident_id:int):

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT threat_intel
        FROM incidents
        WHERE id=?
        """,
        (incident_id,)
    )

    row = cursor.fetchone()

    conn.close()

    if not row:
        return {
            "error":"Incident not found"
        }

    return {
        "incident_id":incident_id,
        "intel":json.loads(row["threat_intel"] or "[]")
    }'''

new = '''@app.get("/customer/incidents/{incident_id}/intel")
def incident_intel(
    incident_id: int,
    tenant_id: str = Depends(get_customer_tenant)
):

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT threat_intel
            FROM incidents
            WHERE id=?
              AND tenant_id=?
            """,
            (incident_id, tenant_id)
        )

        row = cursor.fetchone()

    finally:
        conn.close()

    if not row:
        return {
            "error": "Incident not found"
        }

    return {
        "incident_id": incident_id,
        "intel": json.loads(row["threat_intel"] or "[]")
    }'''

if old not in text:
    raise SystemExit(
        "STOP: Expected incident-intel block was not found. No changes made."
    )

text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("Customer incident intelligence is now tenant-scoped.")
