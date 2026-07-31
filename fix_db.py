import sqlite3

conn = sqlite3.connect("safechat.db")  # adjust if your db name is different
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE incidents ADD COLUMN priority TEXT;")
    print("COLUMN ADDED SUCCESSFULLY")
except Exception as e:
    print("ERROR:", e)

conn.commit()
conn.close()