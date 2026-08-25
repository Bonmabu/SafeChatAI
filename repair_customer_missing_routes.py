from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8")

marker = "# ============================================================\n# CUSTOMER DASHBOARD COMPATIBILITY ROUTES"

insert = r'''
# ============================================================
# CUSTOMER DASHBOARD MISSING COMPATIBILITY ROUTES
# ============================================================

@app.get("/incidents")
def get_incidents():
    """
    Customer dashboard incident feed.
    Uses the existing incident database/query infrastructure when
    available and always returns a JSON array expected by React.
    """
    try:
        if "get_recent_incidents" in globals():
            data = get_recent_incidents()
            return data if isinstance(data, list) else []

        if "get_incidents_db" in globals():
            data = get_incidents_db()
            return data if isinstance(data, list) else []

        return []
    except Exception as e:
        print("INCIDENTS ERROR:", e)
        return []


@app.get("/customer/attack-trend")
def customer_attack_trend():
    """
    Customer dashboard attack trend.
    Returns a stable array for the Recharts trend component.
    """
    try:
        incidents = get_incidents()

        if not isinstance(incidents, list):
            incidents = []

        trend = {}

        for incident in incidents:
            timestamp = (
                incident.get("created_at")
                or incident.get("timestamp")
                or incident.get("detected_at")
            )

            if not timestamp:
                continue

            day = str(timestamp)[:10]
            trend[day] = trend.get(day, 0) + 1

        return [
            {
                "date": day,
                "attacks": count
            }
            for day, count in sorted(trend.items())
        ]

    except Exception as e:
        print("ATTACK TREND ERROR:", e)
        return []


@app.websocket("/ws/soc")
async def websocket_soc(websocket: WebSocket):
    """
    Customer SOC live event stream.
    """
    await manager.connect(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# ============================================================
# CUSTOMER IOC ARRAY COMPATIBILITY
# ============================================================

def _customer_ioc_array():
    result = []

    try:
        for category, values in IOC_DATABASE.items():

            if not isinstance(values, dict):
                continue

            for value, metadata in values.items():

                item = {
                    "ioc": value,
                    "value": value,
                    "type": category,
                }

                if isinstance(metadata, dict):
                    item.update(metadata)

                result.append(item)

    except Exception as e:
        print("IOC ARRAY ERROR:", e)

    return result


'''
if marker not in text:
    raise SystemExit("ERROR: CUSTOMER DASHBOARD COMPATIBILITY ROUTES marker not found.")

# Insert the new routes immediately before the existing compatibility block.
text = text.replace(marker, insert + marker, 1)

# Replace the existing customer_iocs return.
old = '''@app.get("/customer/iocs")
def customer_iocs(user=Depends(get_current_user)):
    return IOC_DATABASE
'''

new = '''@app.get("/customer/iocs")
def customer_iocs(user=Depends(get_current_user)):
    return _customer_ioc_array()
'''

if old not in text:
    raise SystemExit("ERROR: Existing /customer/iocs route not found.")

text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("Customer Dashboard routes repaired.")
print("Added:")
print("  /incidents")
print("  /customer/attack-trend")
print("  /ws/soc")
print("Fixed:")
print("  /customer/iocs -> array")
