import os
import json
import time
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from contextlib import asynccontextmanager

# Third-party imports
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Header, status, Request, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from supabase import create_client, Client as SupabaseClient
import redis.asyncio as redis
import paho.mqtt.client as mqtt
from jose import JWTError, jwt

# ==========================================
# --- 1. CONFIGURATION (Environment Vars) ---
# ==========================================
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-long-production-secret")
ALGORITHM = "HS256"

# Database & Broker Config (From Render Dashboard)
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
UPSTASH_REDIS_URL = os.getenv("UPSTASH_REDIS_URL")

MQTT_BROKER = os.getenv("MQTT_BROKER", "broker.emqx.io")
MQTT_PORT = int(os.getenv("MQTT_PORT", 1883))
MQTT_USER = os.getenv("MQTT_USER")
MQTT_PASS = os.getenv("MQTT_PASS")

# Logger Setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("IOT_GATEWAY")

# ==========================================
# --- 2. DATABASE & MQTT CLIENTS ---
# ==========================================
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
redis_client = redis.from_url(UPSTASH_REDIS_URL, decode_responses=True)

class MQTTService:
    def __init__(self):
        self.client = mqtt.Client(protocol=mqtt.MQTTv5)
        if MQTT_USER and MQTT_PASS:
            self.client.username_pw_set(MQTT_USER, MQTT_PASS)

    def start(self):
        self.client.connect_async(MQTT_BROKER, MQTT_PORT)
        self.client.loop_start()

    def publish_cmd(self, device_id: str, action: str, val: Any = None):
        topic = f"iot/{device_id}/cmd"
        payload = json.dumps({"action": action, "value": val, "ts": int(time.time())})
        return self.client.publish(topic, payload, qos=1)

mqtt_service = MQTTService()

# ==========================================
# --- 3. MODELS & SECURITY ---
# ==========================================
class DeviceModel(BaseModel):
    device_id: str
    hardware_secret: str
    device_name: Optional[str] = "New Device"

class HeartbeatModel(BaseModel):
    state: Dict[str, Any]

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_token(device_id: str, scope: str, expire_days: int = 0, expire_mins: int = 60):
    expire = datetime.utcnow() + (timedelta(days=expire_days) if expire_days else timedelta(minutes=expire_mins))
    return jwt.encode({"sub": device_id, "scope": scope, "exp": expire}, JWT_SECRET_KEY, algorithm=ALGORITHM)

async def validate_passport(token: str = Depends(oauth2_scheme)) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        device_id = payload.get("sub")
        if await redis_client.exists(f"blacklist:{device_id}"):
            raise HTTPException(status_code=403, detail="Banned")
        return device_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid Token")

# ==========================================
# --- 4. MAIN APP & LIFECYCLE ---
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    mqtt_service.start()
    await redis_client.ping()
    logger.info("Enterprise IoT Gateway Online.")
    yield
    mqtt_service.client.loop_stop()
    await redis_client.close()

app = FastAPI(title="Enterprise IoT Gateway", lifespan=lifespan)

# ==========================================
# --- 5. ROUTES (CURL & ALEXA) ---
# ==========================================

# --- [ADMIN] CURL Endpoints (Read/Update Code) ---

@app.get("/v1/admin/devices")
async def list_devices():
    """Read all devices from Supabase (Cold Layer)"""
    res = supabase.table("devices").select("*").execute()
    return res.data

@app.post("/v1/admin/devices")
async def add_device(device: DeviceModel):
    """Insert a new device into the registry via CURL"""
    res = supabase.table("devices").insert({
        "device_id": device.device_id,
        "hardware_secret": device.hardware_secret,
        "device_name": device.device_name
    }).execute()
    return {"status": "created", "data": res.data}

@app.delete("/v1/admin/devices/{device_id}")
async def delete_device(device_id: str):
    """Delete a device and blacklist it in Redis instantly"""
    supabase.table("devices").delete().eq("device_id", device_id).execute()
    await redis_client.set(f"blacklist:{device_id}", "true")
    return {"status": "deleted_and_blacklisted"}

# --- [DEVICE] IoT Logic ---

@app.post("/v1/provision")
async def provision(data: DeviceModel):
    res = supabase.table("devices").select("*").eq("device_id", data.device_id).single().execute()
    if not res.data or res.data['hardware_secret'] != data.hardware_secret:
        raise HTTPException(status_code=401, detail="Auth Failed")
    
    return {
        "access_token": create_token(data.device_id, "access"),
        "refresh_token": create_token(data.device_id, "refresh", expire_days=365)
    }

@app.post("/v1/heartbeat")
async def heartbeat(data: HeartbeatModel, device_id: str = Depends(validate_passport)):
    """Update Hot Layer (Upstash Redis)"""
    key = f"device:{device_id}:state"
    mapping = {k: str(v) for k, v in data.state.items()}
    mapping["last_seen"] = str(int(time.time()))
    await redis_client.hset(key, mapping=mapping)
    await redis_client.expire(key, 3600)
    return {"status": "synced"}

# --- [ALEXA] Smart Home integration ---

@app.post("/v1/alexa/smart-home")
async def alexa_handler(request: Request, bg: BackgroundTasks):
    body = await request.json()
    header = body["directive"]["header"]
    endpoint_id = body["directive"]["endpoint"]["endpointId"]
    
    # 1. Dispatch Command via MQTT
    action = "ON" if header["name"] == "TurnOn" else "OFF"
    mqtt_service.publish_cmd(endpoint_id, action)
    
    # 2. Log to SQL in background
    bg.add_task(lambda: supabase.table("commands").insert({"device_id": endpoint_id, "action": action}).execute())

    return {
        "event": {
            "header": {"namespace": "Alexa", "name": "Response", "messageId": header["messageId"] + "-R", "payloadVersion": "3"},
            "endpoint": {"endpointId": endpoint_id},
            "payload": {}
        }
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}
