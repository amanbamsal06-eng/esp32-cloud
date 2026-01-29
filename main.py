import os
import json
import time
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from fastapi import FastAPI, Depends, HTTPException, Header, status, Request, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from pydantic import BaseModel
from supabase import create_client, Client
import redis.asyncio as redis
import paho.mqtt.client as mqtt
from jose import JWTError, jwt

# --- 1. SECURE CONFIGURATION ---
# IMPORTANT: Add 'ADMIN_API_KEY' to your Render environment variables!
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "change-this-to-a-32-char-random-string")
ADMIN_KEY_HEADER = APIKeyHeader(name="X-Admin-Key", auto_error=True)

JWT_SECRET = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"

# Database Connections
supabase: Client = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_SERVICE_KEY"))
redis_client = redis.from_url(os.getenv("UPSTASH_REDIS_URL"), decode_responses=True)

# MQTT v5 Manager
class MQTTManager:
    def __init__(self):
        self.client = mqtt.Client(protocol=mqtt.MQTTv5)
        user = os.getenv("MQTT_USER")
        pw = os.getenv("MQTT_PASSWORD")
        if user and pw: self.client.username_pw_set(user, pw)
    
    def start(self):
        self.client.connect_async(os.getenv("MQTT_BROKER", "broker.emqx.io"), 1883)
        self.client.loop_start()

    def send(self, device_id: str, action: str):
        topic = f"iot/{device_id}/cmd"
        self.client.publish(topic, json.dumps({"action": action, "ts": int(time.time())}), qos=1)

mqtt_node = MQTTManager()

# --- 2. LIFECYCLE & APP ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    mqtt_node.start()
    await redis_client.ping()
    yield
    mqtt_node.client.loop_stop()
    await redis_client.close()

app = FastAPI(title="Hardened IoT Hub 2026", lifespan=lifespan)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ==========================================
# --- 3. SECURITY DEPENDENCIES ---
# ==========================================

async def validate_admin(api_key: str = Depends(admin_key_header)):
    """Locks the /admin routes so only YOU can use them."""
    if api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized Admin Access")
    return api_key

async def validate_passport(token: str = Depends(oauth2_scheme)):
    """Verifies JWT signature AND checks the Redis Blacklist."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        dev_id = payload.get("sub")
        # Hot Layer Check: Is the device banned?
        if await redis_client.exists(f"blacklist:{dev_id}"):
            raise HTTPException(status_code=403, detail="Device access revoked.")
        return dev_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Passport Expired/Invalid")

# ==========================================
# --- 4. SECURE API ENDPOINTS ---
# ==========================================

# --- A. ADMIN CRUD (CURL Only) ---
@app.post("/v1/admin/devices", dependencies=[Depends(validate_admin)])
async def register_device(device_id: str, secret: str):
    """Registers a new device into the system securely."""
    supabase.table("devices").insert({"device_id": device_id, "hardware_secret": secret}).execute()
    return {"status": "success", "device": device_id}

@app.post("/v1/admin/unban/{device_id}", dependencies=[Depends(validate_admin)])
async def unban(device_id: str):
    """Clears a device from the blacklist so it can re-provision."""
    await redis_client.delete(f"blacklist:{device_id}")
    return {"status": f"Device {device_id} is now welcome back."}

# --- B. PROVISIONING (The Birth) ---
@app.post("/v1/provision")
async def provision(device_id: str, secret: str):
    """Verifies hardware secret and starts a new session."""
    res = supabase.table("devices").select("*").eq("device_id", device_id).single().execute()
    if not res.data or res.data['hardware_secret'] != secret:
        raise HTTPException(status_code=401, detail="Hardware rejected.")

    # Generate a unique version for this session
    session_ver = str(uuid.uuid4())
    supabase.table("devices").update({"refresh_token_ver": session_ver}).eq("device_id", device_id).execute()

    access = jwt.encode({"sub": device_id, "scope": "access", "exp": datetime.utcnow() + timedelta(minutes=60)}, JWT_SECRET)
    refresh = jwt.encode({"sub": device_id, "scope": "refresh", "ver": session_ver, "exp": datetime.utcnow() + timedelta(days=365)}, JWT_SECRET)
    
    return {"access_token": access, "refresh_token": refresh}

# --- C. REFRESH WITH ROTATION (The Hacker Trap) ---
@app.post("/v1/refresh")
async def refresh_passport(refresh_token: str = Header(...)):
    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[ALGORITHM])
        dev_id = payload.get("sub")
        token_ver = payload.get("ver")

        # 1. Check if this token version is still the "current" one in SQL
        res = supabase.table("devices").select("refresh_token_ver").eq("device_id", dev_id).single().execute()
        if not res.data or res.data['refresh_token_ver'] != token_ver:
            # REUSE DETECTED: Someone (hacker or old client) tried to use an old token
            await redis_client.set(f"blacklist:{dev_id}", "true", ex=86400)
            raise HTTPException(status_code=403, detail="Security Breach: Token Reuse Detected. Banned.")

        # 2. ROTATE: Generate NEW tokens and a NEW version
        new_ver = str(uuid.uuid4())
        supabase.table("devices").update({"refresh_token_ver": new_ver}).eq("device_id", dev_id).execute()

        new_acc = jwt.encode({"sub": dev_id, "scope": "access", "exp": datetime.utcnow() + timedelta(minutes=60)}, JWT_SECRET)
        new_ref = jwt.encode({"sub": dev_id, "scope": "refresh", "ver": new_ver, "exp": datetime.utcnow() + timedelta(days=365)}, JWT_SECRET)

        return {"access_token": new_acc, "refresh_token": new_ref}
    except JWTError:
        raise HTTPException(status_code=401, detail="Session Expired")

# --- D. ALEXA & HEARTBEAT ---
@app.post("/v1/heartbeat")
async def heartbeat(state: Dict[str, Any], dev_id: str = Depends(validate_passport)):
    await redis_client.hset(f"device:{dev_id}:state", mapping={k: str(v) for k, v in state.items()})
    return {"status": "ok"}

@app.post("/v1/alexa/smart-home")
async def alexa_gateway(request: Request, bg: BackgroundTasks):
    data = await request.json()
    header = data["directive"]["header"]
    eid = data["directive"]["endpoint"]["endpointId"]
    action = "ON" if header["name"] == "TurnOn" else "OFF"
    
    mqtt_node.send(eid, action)
    bg.add_task(lambda: supabase.table("commands").insert({"device_id": eid, "action": action}).execute())
    
    return {"event": {"header": {"namespace": "Alexa", "name": "Response", "messageId": header["messageId"] + "-R", "payloadVersion": "3"}, "endpoint": {"endpointId": eid}, "payload": {}}}
