from pathlib import Path

path = Path(r".\main.py")
text = path.read_text(encoding="utf-8")

old = '''@app.put("/customer/incidents/{incident_id}", dependencies=[Depends(require_customer_access)])
def update_customer_incident(
    incident_id: int,
    payload: CustomerIncidentUpdate
):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE incidents
        SET status = ?
        WHERE id = ?
    """, (
        payload.status,
        incident_id
    ))

    conn.commit()
    conn.close()

    return {
        "success": True,
        "incident_id": incident_id,
        "status": payload.status
    }'''

new = '''@app.put("/customer/incidents/{incident_id}")
def update_customer_incident(
    incident_id: int,
    payload: CustomerIncidentUpdate,
    tenant_id: str = Depends(get_customer_tenant)
):
    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE incidents
            SET status = ?
            WHERE id = ?
              AND tenant_id = ?
        """, (
            payload.status,
            incident_id,
            tenant_id
        ))

        updated = cursor.rowcount
        conn.commit()

    finally:
        conn.close()

    if updated == 0:
        raise HTTPException(
            status_code=404,
            detail="Incident not found for this tenant."
        )

    return {
        "success": True,
        "incident_id": incident_id,
        "status": payload.status
    }'''

if old not in text:
    raise SystemExit(
        "STOP: Expected customer incident update block was not found exactly. No changes made."
    )

text = text.replace(old, new, 1)

path.write_text(
    text,
    encoding="utf-8",
    newline="\n"
)

print("Customer incident update is now tenant-scoped.")
