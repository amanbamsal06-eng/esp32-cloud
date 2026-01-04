from fastapi import FastAPI, Header, HTTPException
from datetime import datetime, timedelta
import secrets
import os
from supabase import create_client

# -------------------------------------------------
# SUPABASE SETUP
# -------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Supabase env vars not set")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# -------------------------------------------------
# FASTAPI APP
# -------------------------------------------------
app = FastAPI()

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def generate_token():
    return secrets.token_hex(32)

def authenticate(token: str):
    if not token:
        raise HTTPException(status_code=401, detail="TOKEN_REQUIRED")

    res = supabase.table("devices").select("*").eq(
        "device_token", token
    ).eq("active", True).single().execute()

    if not res.data:
        raise HTTPException(status_code=401, detail="INVALID_TOKEN")

    if res.data["token_expiry"]:
        if datetime.fromisoformat(res.data["token_expiry"]) < datetime.utcnow():
            raise HTTPException(status_code=401, detail="TOKEN_EXPIRED")

    return res.data

# -------------------------------------------------
# HEALTH CHECK
# -------------------------------------------------
@app.get("/")
def root():
    return {"status": "server running with supabase api"}

# -------------------------------------------------
# DEVICE PROVISIONING
# -------------------------------------------------
@app.post("/provision")
def provision(device_id: str):
    existing = supabase.table("devices").select("device_id").eq(
        "device_id", device_id
    ).execute()

    if existing.data:
        raise HTTPException(400, detail="DEVICE_ALREADY_EXISTS")

    token = generate_token()

    supabase.table("devices").insert({
        "device_id": device_id,
        "device_token": token,
        "device_state": "OFF",
        "token_expiry": (datetime.utcnow() + timedelta(days=30)).isoformat(),
        "active": True,
        "updated_at": datetime.utcnow().isoformat()
    }).execute()

    return {
        "device_id": device_id,
        "device_token": token,
        "expires_in_days": 30
    }

# -------------------------------------------------
# SEND COMMAND
# -------------------------------------------------
@app.post("/send_command")
def send_command(command: str, authorization: str = Header(None)):
    if command not in ["ON", "OFF"]:
        raise HTTPException(400, detail="INVALID_COMMAND")

    device = authenticate(authorization)

    supabase.table("devices").update({
        "device_state": command,
        "updated_at": datetime.utcnow().isoformat()
    }).eq("device_id", device["device_id"]).execute()

    return {"status": "stored", "command": command}

# -------------------------------------------------
# DEVICE POLL
# -------------------------------------------------
@app.get("/device/command")
def get_command(authorization: str = Header(None)):
    device = authenticate(authorization)
    return {"command": device["device_state"]}

# -------------------------------------------------
# TOKEN REFRESH
# -------------------------------------------------
@app.post("/refresh_token")
def refresh_token(device_id: str, authorization: str = Header(None)):
    device = authenticate(authorization)

    if device["device_id"] != device_id:
        raise HTTPException(401, detail="INVALID_REFRESH_REQUEST")

    new_token = generate_token()

    supabase.table("devices").update({
        "device_token": new_token,
        "token_expiry": (datetime.utcnow() + timedelta(days=30)).isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }).eq("device_id", device_id).execute()

    return {
        "device_token": new_token,
        "expires_in_days": 30
    }

# -------------------------------------------------
# REVOKE DEVICE
# -------------------------------------------------
@app.post("/revoke_device")
def revoke_device(device_id: str):
    supabase.table("devices").update({
        "active": False,
        "updated_at": datetime.utcnow().isoformat()
    }).eq("device_id", device_id).execute()

    return {"status": "device_revoked"}
