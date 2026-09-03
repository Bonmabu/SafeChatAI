from dotenv import load_dotenv
import os
from google_auth_oauthlib.flow import InstalledAppFlow

load_dotenv(".env")

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

flow = InstalledAppFlow.from_client_config(
    {
        "installed": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    },
    SCOPES,
)

creds = flow.run_local_server(
    port=8081,
    access_type="offline",
    prompt="consent",
)

with open("gmail_token.json", "w", encoding="utf-8") as f:
    f.write(creds.to_json())

print("GMAIL TOKEN SAVED")
print("FILE: gmail_token.json")
