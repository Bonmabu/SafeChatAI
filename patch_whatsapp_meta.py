from pathlib import Path
import re

path = Path(".\main.py")
text = path.read_text(encoding="utf-8")

# ------------------------------------------------------------
# 1. Ensure Request is imported
# ------------------------------------------------------------
if "from fastapi import Request" not in text:
    if "from fastapi import " in text:
        text = text.replace(
            "from fastapi import ",
            "from fastapi import Request, ",
            1
        )
    else:
        text = "from fastapi import Request\n" + text

# ------------------------------------------------------------
# 2. Add WhatsApp provider configuration
# ------------------------------------------------------------
anchor = 'SECRET_KEY = os.getenv("SECRET_KEY")'

config = '''WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
WHATSAPP_APP_SECRET = os.getenv("WHATSAPP_APP_SECRET", "")
WHATSAPP_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")

'''

if "WHATSAPP_VERIFY_TOKEN = os.getenv" not in text:
    if anchor not in text:
        raise RuntimeError("Could not find SECRET_KEY configuration anchor.")
    text = text.replace(anchor, config + anchor, 1)

# ------------------------------------------------------------
# 3. Add Meta webhook immediately after /whatsapp/analyze
# ------------------------------------------------------------
if '@app.get("/whatsapp/webhook")' not in text:

    marker = '@app.post("/whatsapp/analyze")'
    start = text.find(marker)

    if start == -1:
        raise RuntimeError('Could not find existing /whatsapp/analyze endpoint.')

    next_route = text.find("\n@app.", start + len(marker))

    if next_route == -1:
        insertion_point = len(text)
    else:
        insertion_point = next_route

    webhook = r'''

# ============================================================
# META WHATSAPP CLOUD API WEBHOOK
# ============================================================

@app.get("/whatsapp/webhook")
def whatsapp_webhook_verify(
    hub_mode: str | None = None,
    hub_verify_token: str | None = None,
    hub_challenge: str | None = None
):
    """
    Meta webhook verification endpoint.

    Meta sends:
      hub.mode
      hub.verify_token
      hub.challenge

    FastAPI converts the underscore parameters from the query string.
    """

    if hub_mode == "subscribe" and hub_verify_token == WHATSAPP_VERIFY_TOKEN:
        return int(hub_challenge or "0")

    raise HTTPException(
        status_code=403,
        detail="WhatsApp webhook verification failed."
    )


@app.post("/whatsapp/webhook")
async def whatsapp_webhook(request: Request):
    """
    Receives inbound WhatsApp Cloud API messages from Meta,
    extracts text messages, and sends them through the existing
    SafeChat AI threat-classification + ML pipeline.
    """

    payload = await request.json()

    results = []

    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})

            for message in value.get("messages", []):

                message_type = message.get("type")

                # SafeChat currently analyzes text messages.
                if message_type != "text":
                    results.append({
                        "message_id": message.get("id"),
                        "status": "ignored",
                        "reason": f"Unsupported message type: {message_type}"
                    })
                    continue

                text_body = (
                    message.get("text", {})
                    .get("body", "")
                    .strip()
                )

                if not text_body:
                    continue

                sender = message.get("from")
                message_id = message.get("id")
                timestamp = message.get("timestamp")

                category, score, stage, mitre, confidence, matches = (
                    classify_threat(text_body)
                )

                try:
                    ml_result = predict(text_body)
                except Exception as exc:
                    ml_result = {
                        "status": "Unavailable",
                        "score": 0,
                        "category": "Unknown",
                        "explanation": str(exc)
                    }

                result = {
                    "source": "whatsapp_cloud",
                    "message_id": message_id,
                    "sender": sender,
                    "timestamp": timestamp,
                    "tenant_id": "demo",
                    "text": text_body,
                    "category": category,
                    "score": score,
                    "status": calculate_status(score),
                    "stage": stage,
                    "mitre": mitre,
                    "confidence": confidence,
                    "matches": matches,
                    "ml": ml_result
                }

                results.append(result)

    return {
        "success": True,
        "source": "whatsapp_cloud",
        "messages_received": len(results),
        "results": results
    }

'''

    text = text[:insertion_point] + webhook + text[insertion_point:]

path.write_text(text, encoding="utf-8", newline="\n")

print("WhatsApp Meta webhook integration added.")
