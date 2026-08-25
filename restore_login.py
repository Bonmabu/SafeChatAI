from pathlib import Path

path = Path("main.py")
text = path.read_text(encoding="utf-8")

if "def create_access_token" in text:
    print("STOP: create_access_token already exists.")
    raise SystemExit(0)

if '@app.post("/login")' in text:
    print("STOP: /login already exists.")
    raise SystemExit(0)

marker = "def check_permission(role: str, action: str):"

position = text.find(marker)

if position == -1:
    print("ERROR: Could not find the authentication insertion point.")
    raise SystemExit(1)

backup = Path("main.py.before-login-restore")
backup.write_text(text, encoding="utf-8")

auth_code = '''def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire})
    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(request: LoginRequest):

    conn = get_conn()
    cursor = conn.cursor()

    try:
        cursor.execute(
            db_sql("""
                SELECT
                    id,
                    username,
                    password_hash,
                    role,
                    tenant_id,
                    status,
                    is_active,
                    session_version,
                    password_reset_required
                FROM users
                WHERE username = ?
            """),
            (request.username,)
        )

        user = cursor.fetchone()

        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password."
            )

        user = dict(user)

        if not user.get("is_active", 1):
            raise HTTPException(
                status_code=403,
                detail="Account is inactive."
            )

        if str(user.get("status", "active")).upper() != "ACTIVE":
            raise HTTPException(
                status_code=403,
                detail="Account is not active."
            )

        if not verify_password(
            request.password,
            user["password_hash"]
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password."
            )

        token = create_access_token({
            "sub": user["username"],
            "user_id": user["id"],
            "role": user["role"],
            "tenant_id": user["tenant_id"],
            "session_version": user.get("session_version", 0)
        })

        return {
            "success": True,
            "message": "Login successful",
            "token": token,
            "access_token": token,
            "token_type": "bearer",
            "username": user["username"],
            "role": user["role"],
            "tenant_id": user["tenant_id"],
            "password_reset_required": bool(
                user.get("password_reset_required", 0)
            )
        }

    finally:
        conn.close()


'''

text = text[:position] + auth_code + text[position:]

path.write_text(text, encoding="utf-8", newline="\n")

print("SUCCESS: Login/JWT authentication restored.")
print("Backup created:", backup)