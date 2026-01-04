from fastapi import FastAPI, Header, HTTPException
import sqlite3
from datetime import datetime

app = FastAPI()

DB_FILE = "iot.db"
DEVICE_TOKEN = "DEV_TEST_123"

# ---------- DB INIT ----------
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_token TEXT PRIMARY KEY,
            device_state TEXT,
            updated_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------- API ----------
@app.get("/")
def root():
    return {"status": "server running with db"}

# USER / APP sends command
@app.post("/send_command")
def send_command(command: str, authorization: str = Header(None)):
    if authorization != DEVICE_TOKEN:
        raise HTTPException(status_code=401)

    if command not in ["ON", "OFF"]:
        raise HTTPException(status_code=400)

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO devices (device_token, device_state, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(device_token)
        DO UPDATE SET device_state=?, updated_at=?
    """, (
        DEVICE_TOKEN,
        command,
        datetime.utcnow().isoformat(),
        command,
        datetime.utcnow().isoformat()
    ))

    conn.commit()
    conn.close()

    return {"status": "stored", "command": command}

# ESP32 polls command
@app.get("/device/command")
def get_command(authorization: str = Header(None)):
    if authorization != DEVICE_TOKEN:
        raise HTTPException(status_code=401)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT device_state FROM devices WHERE device_token=?",
        (DEVICE_TOKEN,)
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        return {"command": "OFF"}

    return {"command": row["device_state"]}
