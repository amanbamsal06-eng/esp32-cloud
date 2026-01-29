


import os
import json
import logging
import secrets
from datetime import datetime
from typing import Dict, Any, Optional

from fastapi import FastAPI, Header, HTTPException, Depends, Security, status
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
from supabase import create_client, Client
import paho.mqtt.client as mqtt
from dotenv import load_dotenv

load_dotenv()

# -------------------------------------------------
# LOGGING & CONFIG
# -------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Essential Environment Variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
MQTT_BROKER = os.getenv("MQTT_BROKER", "broker.hivemq.com")
MQTT_PORT = int(os.getenv("MQTT_PORT", 1883))
MQTT_USER = os.getenv("MQTT_USER")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD")

# Security Keys
# This key is for your UI/Admin to talk to this API
API_KEY = os.getenv("INTERNAL_API_KEY", "change-me-in-production")
API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# -------------------------------------------------
# INITIALIZATION
# -------------------------------------------------
if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Critical Error: Supabase credentials missing.")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Initialize MQTT with specific clean-session settings for production
mqtt_client = mqtt.Client(client_id="fastapi_iot_manager", clean_session=True)
if MQTT_USER and MQTT_PASSWORD:
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info("Connected to MQTT Broker successfully.")
    else:
        logger.error(f"MQTT Connection failed with code {rc}")

mqtt_client.on_connect = on_connect
mqtt_client.connect_async(MQTT_BROKER, MQTT_PORT, 60)
mqtt_client.loop_start()

app = FastAPI(title="Production IoT Gateway")

# -------------------------------------------------
# MODELS
# -------------------------------------------------
class Command(BaseModel):
    command: str
    relay: Optional[int] = 1
    value: Optional[bool] = None
    extra: Optional[Dict[str, Any]] = None

class DeviceStateUpdate(BaseModel):
    device_id: str
    state: Dict[str, Any]

# -------------------------------------------------
# SECURITY DEPENDENCIES
# -------------------------------------------------

async def validate_api_key(header_key: str = Security(api_key_header)):
    """Verifies the request comes from an authorized admin/app."""
    if header_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Could not validate API Key"
        )
    return header_key

async def verify_device_access(device_id: str, device_token: str = Header(...)):
    """Verifies that the device_id matches the provided device_token."""
    res = supabase.table("devices").select("device_token").eq("device_id", device_id).single().execute()
    
    if not res.data or res.data.get("device_token") != device_token:
        logger.warning(f"Unauthorized access attempt for device: {device_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Device Token or ID"
        )
    return res.data

# -------------------------------------------------
# ENDPOINTS
# -------------------------------------------------

@app.post("/provision", dependencies=[Depends(validate_api_key)])
def provision_device(device_id: str):
    """Registers a new device. Only callable by Admin/App with API Key."""
    existing = supabase.table("devices").select("*").eq("device_id", device_id).execute()
    
    if existing.data:
        return {"status": "exists", "device_token": existing.data[0]["device_token"]}

    token = secrets.token_hex(24)
    new_device = {
        "device_id": device_id,
        "device_token": token,
        "is_online": False,
        "config": {"mqtt_topic_cmd": f"home/devices/{device_id}/cmd"}
    }
    
    supabase.table("devices").insert(new_device).execute()
    return {"status": "created", "device_token": token}

@app.post("/command/{device_id}", dependencies=[Depends(validate_api_key)])
def send_command(
    device_id: str, 
    cmd: Command, 
    device_token: str = Header(...)  # <--- This requires 'device-token' in the header
):
    """
    Sends a command via MQTT. 
    Checks:
    1. API Key (Admin Access)
    2. Device Token (Specific Device Access)
    """
    
    # 1. Fetch the device from Supabase to check the token
    res = supabase.table("devices").select("device_token").eq("device_id", device_id).single().execute()
    
    if not res.data:
        raise HTTPException(status_code=404, detail="Device not found")

    # 2. AUTH CHECK: Does the token in the header match the token in the DB?
    if res.data.get("device_token") != device_token:
        logger.warning(f"Unauthorized command attempt for device {device_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid Device Token"
        )

    # 3. If auth passes, proceed to MQTT
    topic = f"home/devices/{device_id}/cmd"
    payload = cmd.dict(exclude_none=True)
    
    result = mqtt_client.publish(topic, json.dumps(payload), qos=1)
    
    if result.rc != mqtt.MQTT_ERR_SUCCESS:
        raise HTTPException(status_code=500, detail="MQTT Broker unreachable")

    return {
        "status": "dispatched", 
        "device_id": device_id, 
        "authorized": True
    }

@app.post("/heartbeat")
def heartbeat(update: DeviceStateUpdate, device_token: str = Header(...)):
    """
    Device sends status. 
    Protected by Device Token (X-Device-Token in header).
    """
    # Validate token manually for this specific route
    res = supabase.table("devices").select("device_token").eq("device_id", update.device_id).single().execute()
    
    if not res.data or res.data["device_token"] != device_token:
        raise HTTPException(status_code=401, detail="Unauthorized Device")

    payload = {
        "is_online": True,
        "last_heartbeat": datetime.utcnow().isoformat(),
        "device_state": update.state
    }
    
    supabase.table("devices").update(payload).eq("device_id", update.device_id).execute()
    return {"status": "recorded"}

@app.get("/device/{device_id}", dependencies=[Depends(validate_api_key)])
def get_status(device_id: str):
    res = supabase.table("devices").select("*").eq("device_id", device_id).single().execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="Not found")
    return res.data
