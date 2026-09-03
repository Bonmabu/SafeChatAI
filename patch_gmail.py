from pathlib import Path

path = Path(".\main.py")
text = path.read_text(encoding="utf-8")

anchor = "from fastapi import"

if "from googleapiclient.discovery import build as gmail_build" not in text:
    text = text.replace(
        anchor,
        "from googleapiclient.discovery import build as gmail_build\n"
        "from google.oauth2.credentials import Credentials\n"
        "from google.auth.transport.requests import Request\n\n"
        + anchor,
        1
    )

anchor = "class EmailWebhookRequest(BaseModel):"

gmail_code = '''
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
GMAIL_TOKEN_FILE = Path("gmail_token.json")


def get_gmail_service():
    if not GMAIL_TOKEN_FILE.exists():
        raise HTTPException(
            status_code=503,
            detail="Gmail is not connected. Run connect_gmail.py first."
        )

    creds = Credentials.from_authorized_user_file(
        str(GMAIL_TOKEN_FILE),
        GMAIL_SCOPES
    )

    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        GMAIL_TOKEN_FILE.write_text(
            creds.to_json(),
            encoding="utf-8"
        )

    if not creds.valid:
        raise HTTPException(
            status_code=503,
            detail="Gmail authorization is invalid or expired."
        )

    return gmail_build(
        "gmail",
        "v1",
        credentials=creds
    )


@app.get("/gmail/status")
def gmail_status():
    service = get_gmail_service()
    profile = service.users().getProfile(userId="me").execute()

    return {
        "success": True,
        "connected": True,
        "email": profile.get("emailAddress"),
        "messages_total": profile.get("messagesTotal", 0),
    }


'''

if "def get_gmail_service():" not in text:
    text = text.replace(anchor, gmail_code + anchor, 1)

path.write_text(text, encoding="utf-8")
print("main.py Gmail integration patch applied.")
