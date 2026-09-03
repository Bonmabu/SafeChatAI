from pathlib import Path

path = Path(".\main.py")
text = path.read_text(encoding="utf-8")

old = '''    payload = await request.json()

    results = []'''

new = '''    body = await request.body()

    signature = request.headers.get("X-Hub-Signature-256", "")

    if WHATSAPP_APP_SECRET:
        expected = "sha256=" + hmac.new(
            WHATSAPP_APP_SECRET.encode("utf-8"),
            body,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected):
            raise HTTPException(
                status_code=403,
                detail="Invalid WhatsApp webhook signature."
            )

    payload = await request.json()

    results = []'''

if old not in text:
    raise RuntimeError("Webhook payload block was not found.")

if 'request.headers.get("X-Hub-Signature-256"' in text:
    print("Signature validation already present.")
else:
    text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8", newline="\n")
    print("WhatsApp webhook signature validation added.")
