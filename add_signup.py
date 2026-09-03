from pathlib import Path

path = Path(".\main.py")
text = path.read_text(encoding="utf-8")

marker = '@app.post("/login")'

if 'class SignupRequest(BaseModel):' in text:
    print("Signup model already exists.")
elif marker not in text:
    raise SystemExit("ERROR: login route marker not found.")
else:
    block = '''class SignupRequest(BaseModel):
    username: str
    password: str
    full_name: str | None = None
    email: str | None = None


@app.post("/signup")
def signup(request: SignupRequest):
    username = request.username.strip()
    password = request.password

    if not username or not password:
        raise HTTPException(
            status_code=400,
            detail="Username and password are required."
        )

    if len(password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 6 characters."
        )

    conn = get_conn()

    try:
        cursor = conn.cursor()

        cursor.execute(
            db_sql("""
                SELECT id
                FROM users
                WHERE username = ?
                LIMIT 1
            """),
            (username,)
        )

        if cursor.fetchone():
            raise HTTPException(
                status_code=409,
                detail="Username already exists."
            )

        if request.email:
            cursor.execute(
                db_sql("""
                    SELECT id
                    FROM users
                    WHERE email = ?
                    LIMIT 1
                """),
                (request.email.strip(),)
            )

            if cursor.fetchone():
                raise HTTPException(
                    status_code=409,
                    detail="Email already exists."
                )

        password_hash = hash_password(password)

        cursor.execute(
            db_sql("""
                INSERT INTO users (
                    username,
                    full_name,
                    email,
                    password_hash,
                    role,
                    tenant_id,
                    status,
                    is_active,
                    session_version
                )
                VALUES (?, ?, ?, ?, 'customer', 'demo', 'active', 1, 1)
            """),
            (
                username,
                request.full_name,
                request.email.strip() if request.email else None,
                password_hash
            )
        )

        conn.commit()

        user_id = cursor.lastrowid

        token = create_access_token(
            {
                "sub": username,
                "user_id": user_id,
                "role": "customer",
                "tenant_id": "demo",
                "session_version": 1
            }
        )

        return {
            "success": True,
            "message": "Signup successful",
            "token": token,
            "role": "customer",
            "tenant_id": "demo",
            "user_id": user_id
        }

    finally:
        conn.close()


'''

    text = text.replace(marker, block + marker, 1)
    path.write_text(text, encoding="utf-8")
    print("Added POST /signup successfully.")
