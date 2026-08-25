from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8")

marker = "# ============================================================\n# CUSTOMER DASHBOARD MISSING COMPATIBILITY ROUTES"

if marker not in text:
    raise SystemExit("ERROR: compatibility route marker not found")

route = r'''
# ============================================================
# SOC AI STREAM - CUSTOMER THREAT ANALYSIS
# ============================================================

@app.post("/soc-ai-stream")
async def soc_ai_stream(payload: dict, user=Depends(get_current_user)):

    text_value = str(payload.get("text") or "").strip()

    if not text_value:
        return {
            "success": False,
            "error": "Text is required."
        }

    username = payload.get("username") or "unknown"
    hostname = payload.get("hostname") or "unknown"
    source_ip = payload.get("source_ip") or "unknown"

    try:
        # ----------------------------------------------------
        # Existing SafeChat AI threat classifier
        # ----------------------------------------------------
        classification = classify_threat(text_value)

        if isinstance(classification, dict):
            category = (
                classification.get("category")
                or classification.get("threat")
                or classification.get("type")
                or "Unknown"
            )

            score = float(
                classification.get("score")
                or classification.get("risk_score")
                or 0
            )

            stage = classification.get("stage") or "Unknown"
            mitre = classification.get("mitre") or ""

        else:
            category = str(classification or "Unknown")
            score = 0
            stage = "Unknown"
            mitre = ""

        # ----------------------------------------------------
        # IOC extraction
        # ----------------------------------------------------
        try:
            iocs = extract_iocs(text_value)
        except Exception as e:
            print("SOC AI IOC ERROR:", e)
            iocs = {}

        # ----------------------------------------------------
        # Persist/update IOC intelligence
        # ----------------------------------------------------
        try:
            if iocs:
                update_ioc_database(iocs)
        except Exception as e:
            print("SOC AI IOC DATABASE ERROR:", e)

        # ----------------------------------------------------
        # Correlation / Attack Graph
        # ----------------------------------------------------
        correlation_id = generate_correlation_key(
            category,
            text_value
        )

        node_id = f"{category}:{correlation_id}"

        graph = add_graph_node(
            node_id=node_id,
            category=category,
            score=score,
            stage=stage,
            mitre=mitre
        )

        # Connect this attack to the previous live attack.
        previous_node = graph.get("last_node")

        if previous_node and previous_node != node_id:
            add_graph_edge(
                previous_node,
                node_id,
                category="CORRELATED_ATTACK"
            )

        # Re-read graph after possible edge creation.
        graph = ATTACK_GRAPH

        # ----------------------------------------------------
        # Risk level
        # ----------------------------------------------------
        if score >= 90:
            risk_level = "Critical"
        elif score >= 75:
            risk_level = "High"
        elif score >= 50:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # ----------------------------------------------------
        # Live Attack Graph event
        # ----------------------------------------------------
        live_node = {
            "id": node_id,
            "category": category,
            "score": score,
            "max_score": score,
            "stage": stage,
            "mitre": mitre,
            "count": graph["nodes"].get(
                node_id,
                {}
            ).get("count", 1),
            "correlation_id": correlation_id,
            "source_ip": source_ip,
            "hostname": hostname,
            "username": username
        }

        event = {
            "type": "attack_graph_live",
            "timestamp": now_ts(),
            "correlation_id": correlation_id,
            "node": live_node,
            "links": graph.get("edges", [])
        }

        await manager.broadcast(event)

        # ----------------------------------------------------
        # Dashboard update
        # ----------------------------------------------------
        await manager.broadcast({
            "type": "dashboard_update",
            "timestamp": now_ts(),
            "data": {
                "category": category,
                "score": score,
                "risk_level": risk_level
            }
        })

        # ----------------------------------------------------
        # Customer-facing AI response
        # ----------------------------------------------------
        summary = (
            f"{category} detected with a {risk_level} risk level "
            f"(score {score:.0f}/100)."
        )

        recommendations = [
            "Review the detected activity and associated indicators.",
            "Investigate the affected account, host, and source IP.",
            "Correlate related events in the Attack Graph."
        ]

        if risk_level in ("Critical", "High"):
            recommendations.insert(
                0,
                "Escalate this event for immediate SOC investigation."
            )

        return {
            "success": True,
            "reply": summary,
            "data": {
                "summary": summary,
                "analysis": summary,
                "category": category,
                "score": score,
                "risk_level": risk_level,
                "level": risk_level,
                "stage": stage,
                "mitre": mitre,
                "iocs": iocs,
                "correlation_id": correlation_id,
                "username": username,
                "hostname": hostname,
                "source_ip": source_ip,
                "actions": recommendations,
                "recommendations": recommendations,
                "node": live_node
            }
        }

    except Exception as e:
        print("SOC AI STREAM ERROR:", repr(e))

        return {
            "success": False,
            "error": "SOC AI analysis failed.",
            "detail": str(e)
        }


'''

text = text.replace(marker, route + "\n" + marker, 1)

path.write_text(text, encoding="utf-8", newline="\n")

print("Added /soc-ai-stream successfully.")
