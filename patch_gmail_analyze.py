from pathlib import Path

path = Path(".\main.py")
text = path.read_text(encoding="utf-8")

anchor = '@app.get("/gmail/status")'

gmail_analyze_code = r'''
@app.get("/gmail/analyze")
def gmail_analyze(
    max_results: int = 10,
    q: str | None = None,
    user=Depends(get_current_user)
):
    max_results = max(1, min(max_results, 50))

    service = get_gmail_service()

    request = service.users().messages().list(
        userId="me",
        maxResults=max_results,
        q=q
    )

    message_list = request.execute().get("messages", [])

    results = []

    for item in message_list:
        message = service.users().messages().get(
            userId="me",
            id=item["id"],
            format="metadata",
            metadataHeaders=["From", "To", "Subject", "Date"]
        ).execute()

        headers = {
            h["name"].lower(): h["value"]
            for h in message.get("payload", {}).get("headers", [])
        }

        sender = headers.get("from")
        recipient = headers.get("to")
        subject = headers.get("subject")
        date = headers.get("date")
        snippet = message.get("snippet", "")

        analysis_text = "\n".join(
            part for part in [
                subject,
                sender,
                snippet
            ] if part
        )

        category, score, stage, mitre, confidence, matches = classify_threat(
            analysis_text
        )

        try:
            ml_result = predict(analysis_text)
        except Exception as exc:
            ml_result = {
                "status": "Unavailable",
                "score": 0,
                "category": "Unknown",
                "explanation": str(exc)
            }

        results.append({
            "message_id": item["id"],
            "thread_id": message.get("threadId"),
            "date": date,
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "snippet": snippet,
            "category": category,
            "score": score,
            "status": calculate_status(score),
            "stage": stage,
            "mitre": mitre,
            "confidence": confidence,
            "matches": matches,
            "ml": ml_result
        })

    return {
        "success": True,
        "source": "gmail",
        "count": len(results),
        "results": results
    }


'''

if 'def gmail_analyze(' not in text:
    text = text.replace(anchor, gmail_analyze_code + anchor, 1)

path.write_text(text, encoding="utf-8")
print("main.py Gmail inbox analysis endpoint added.")
