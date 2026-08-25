from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8-sig")

if '@app.get("/executive/users")' in text:
    print("executive_users endpoint already exists. No changes made.")
    raise SystemExit(0)

marker = '@app.get("/executive-ai")'

endpoint = '''@app.get("/executive/users")
def executive_users():

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            username,
            full_name,
            email,
            role,
            tenant_id,
            created_at
        FROM users
        ORDER BY created_at DESC
    """)

    users = []

    for row in cursor.fetchall():
        user = dict(row)

        # Do not expose passwords or authentication tokens
        user["active"] = any(
            session_user
            and session_user.get("username") == user["username"]
            for session_user in ACTIVE_SESSIONS.values()
        )

        users.append(user)

    conn.close()

    return {
        "total_users": len(users),
        "users": users
    }


'''

pos = text.find(marker)

if pos < 0:
    raise SystemExit(
        'ERROR: @app.get("/executive-ai") marker not found. main.py NOT changed.'
    )

text = text[:pos] + endpoint + text[pos:]

path.write_text(text, encoding="utf-8", newline="\n")

print("SUCCESS: exact historical /executive/users endpoint restored.")
