import os
import json
import time
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager  # <--- THIS WAS MISSING!

# Third-party imports
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Header, status, Request, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from pydantic import BaseModel
from supabase import create_client, Client
import redis.asyncio as redis
import paho.mqtt.client as mqtt
from jose import JWTError, jwt

# ==========================================
# --- 1. SECURE CONFIGURATION ---
# ==========================================
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "change-this-in-render-settings")
ADMIN_KEY_HEADER = APIKeyHeader(name="X-Admin-Key", auto_error=True)

JWT_SECRET = os.getenv("JWT_SECRET_KEY", "very-secret-token-key")
ALGORITHM = "HS256"

# Database Connections
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
UPSTASH_REDIS_URL = os.getenv("UPSTASH_REDIS_URL")

# Clients
supabase  = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
redis_client = redis.from_url(UPSTASH_REDIS_URL, decode_responses=True)

# MQTT Manager
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
    # Startup logic
    mqtt_node.start()
    await redis_client.ping()
    yield
    # Shutdown logic
    mqtt_node.client.loop_stop()
    await redis_client.close()

app = FastAPI(title="Hardened IoT Hub 2026", lifespan=lifespan)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ==========================================
# --- 3. SECURITY DEPENDENCIES ---
# ==========================================

async def validate_admin(api_key: str = Depends(ADMIN_KEY_HEADER)):
    if api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized Admin Access")
    return api_key

async def validate_passport(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        dev_id = payload.get("sub")
        if await redis_client.exists(f"blacklist:{dev_id}"):
            raise HTTPException(status_code=403, detail="Device access revoked.")
        return dev_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Passport Expired/Invalid")

# ==========================================
# --- 4. SECURE API ENDPOINTS ---
# ==========================================

@app.post("/v1/admin/devices", dependencies=[Depends(validate_admin)])
async def register_device(device_id: str, secret: str):
    supabase.table("devices").insert({"device_id": device_id, "hardware_secret": secret}).execute()
    return {"status": "success", "device": device_id}

@app.post("/v1/admin/unban/{device_id}", dependencies=[Depends(validate_admin)])
async def unban(device_id: str):
    await redis_client.delete(f"blacklist:{device_id}")
    return {"status": f"Device {device_id} is un-banned."}

@app.post("/v1/provision")
async def provision(device_id: str, secret: str):
    res = supabase.table("devices").select("*").eq("device_id", device_id).single().execute()
    if not res.data or res.data['hardware_secret'] != secret:
        raise HTTPException(status_code=401, detail="Hardware rejected.")

    session_ver = str(uuid.uuid4())
    supabase.table("devices").update({"refresh_token_ver": session_ver}).eq("device_id", device_id).execute()

    access = jwt.encode({"sub": device_id, "scope": "access", "exp": datetime.utcnow() + timedelta(minutes=60)}, JWT_SECRET)
    refresh = jwt.encode({"sub": device_id, "scope": "refresh", "ver": session_ver, "exp": datetime.utcnow() + timedelta(days=365)}, JWT_SECRET)
    
    return {"access_token": access, "refresh_token": refresh}

@app.post("/v1/refresh")
async def refresh_passport(refresh_token: str = Header(...)):
    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[ALGORITHM])
        dev_id = payload.get("sub")
        token_ver = payload.get("ver")

        res = supabase.table("devices").select("refresh_token_ver").eq("device_id", dev_id).single().execute()
        if not res.data or res.data['refresh_token_ver'] != token_ver:
            await redis_client.set(f"blacklist:{dev_id}", "true", ex=86400)
            raise HTTPException(status_code=403, detail="Token Reuse Detected. Banned.")

        new_ver = str(uuid.uuid4())
        supabase.table("devices").update({"refresh_token_ver": new_ver}).eq("device_id", dev_id).execute()

        new_acc = jwt.encode({"sub": dev_id, "scope": "access", "exp": datetime.utcnow() + timedelta(minutes=60)}, JWT_SECRET)
        new_ref = jwt.encode({"sub": dev_id, "scope": "refresh", "ver": new_ver, "exp": datetime.utcnow() + timedelta(days=365)}, JWT_SECRET)

        return {"access_token": new_acc, "refresh_token": new_ref}
    except JWTError:
        raise HTTPException(status_code=401, detail="Session Expired")

@app.post("/v1/heartbeat")
async def heartbeat(state: Dict[str, Any], dev_id: str = Depends(validate_passport)):
    await redis_client.hset(f"device:{dev_id}:state", mapping={k: str(v) for k, v in state.items()})
    return {"status": "ok"}

@app.post("/v1/alexa/smart-home")
async def alexa_gateway(request: Request, bg: BackgroundTasks):
    data = await request.json()
    header = data["directive"]["header"]
    eid = data["directive"]["endpoint"]["endpointId"]
    
    if header["namespace"] == "Alexa.Discovery":
        # Discovery Logic
        return {"event": {"header": {"namespace": "Alexa.Discovery", "name": "Discover.Response", "payloadVersion": "3"}, "payload": {"endpoints": [{"endpointId": eid, "friendlyName": "IoT Device", "displayCategories": ["LIGHT"], "capabilities": [{"type": "AlexaInterface", "interface": "Alexa.PowerController", "version": "3"}]}]}}}

    action = "ON" if header["name"] == "TurnOn" else "OFF"
    mqtt_node.send(eid, action)
    bg.add_task(lambda: supabase.table("commands").insert({"device_id": eid, "action": action}).execute())
    
    return {"event": {"header": {"namespace": "Alexa", "name": "Response", "messageId": header["messageId"] + "-R", "payloadVersion": "3"}, "endpoint": {"endpointId": eid}, "payload": {}}}

@app.get("/health")
async def health():
    return {"status": "online"}
