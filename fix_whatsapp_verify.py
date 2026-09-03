from pathlib import Path

path = Path(".\main.py")
text = path.read_text(encoding="utf-8")

old = '''@app.get("/whatsapp/webhook")
def whatsapp_webhook_verify(
    hub_mode: str | None = None,
    hub_verify_token: str | None = None,
    hub_challenge: str | None = None
):'''

new = '''@app.get("/whatsapp/webhook")
def whatsapp_webhook_verify(
    hub_mode: str | None = Query(None, alias="hub.mode"),
    hub_verify_token: str | None = Query(None, alias="hub.verify_token"),
    hub_challenge: str | None = Query(None, alias="hub.challenge")
):'''

if old not in text:
    raise RuntimeError("Expected WhatsApp webhook verification block was not found.")

text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8", newline="\n")
print("Meta webhook query aliases fixed.")
