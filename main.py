from fastapi import FastAPI, Header, HTTPException, Body
from pydantic import BaseModel
from typing import Dict, Any, Optional
import os
import json
import time
from datetime import datetime
from supabase import create_client, Client
import paho.mqtt.client as mqtt
from dotenv import load_dotenv

load_dotenv()

# -------------------------------------------------
# CONFIGURATION
# -------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

print(f"DEBUG: SUPABASE_URL is {'SET' if SUPABASE_URL else 'MISSING'}")
print(f"DEBUG: SUPABASE_KEY is {'SET' if SUPABASE_KEY else 'MISSING'}")

MQTT_BROKER = os.getenv("MQTT_BROKER", "broker.hivemq.com")
MQTT_PORT = int(os.getenv("MQTT_PORT", 1883))
MQTT_USER = os.getenv("MQTT_USER")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("WARNING: SUPABASE_URL or SUPABASE_KEY not set. API will fail.")

# -------------------------------------------------
# SUPABASE CLIENT
# -------------------------------------------------
if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Supabase env vars not set")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# -------------------------------------------------
# MQTT CLIENT
# -------------------------------------------------
mqtt_client = mqtt.Client()

if MQTT_USER and MQTT_PASSWORD:
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASSWORD)

def on_connect(client, userdata, flags, rc):
    print(f"Connected to MQTT Broker with result code {rc}")

mqtt_client.on_connect = on_connect

try:
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
    mqtt_client.loop_start()
except Exception as e:
    print(f"Failed to connect to MQTT broker: {e}")

# -------------------------------------------------
# FASTAPI APP
# -------------------------------------------------
app = FastAPI(title="IoT Device Manager")

# -------------------------------------------------
# MODELS
# -------------------------------------------------
class DeviceProvision(BaseModel):
    device_id: str

class Command(BaseModel):
    command: str
    relay: Optional[int] = 1
    value: Optional[bool] = None
    extra: Optional[Dict[str, Any]] = None

class DeviceStateUpdate(BaseModel):
    device_id: str
    state: Dict[str, Any]

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def get_device(device_id: str):
    try:
        res = supabase.table("devices").select("*").eq("device_id", device_id).single().execute()
        return res.data
    except Exception:
        return None

def update_device_online_status(device_id: str, is_online: bool):
    try:
        supabase.table("devices").update({
            "is_online": is_online,
            "last_heartbeat": datetime.utcnow().isoformat()
        }).eq("device_id", device_id).execute()
    except Exception as e:
        print(f"Error updating status: {e}")

# -------------------------------------------------
# ENDPOINTS
# -------------------------------------------------

@app.get("/")
def root():
    return {"status": "online", "service": "IoT Manager"}

@app.post("/provision")
def provision_device(data: DeviceProvision):
    """Register a new device or return existing credentials"""
    existing = get_device(data.device_id)
    if existing:
        return {
            "status": "exists", 
            "device_token": existing["device_token"],
            "config": existing.get("config", {})
        }
    
    # Generate a simple token (in production use a better secret)
    import secrets
    token = secrets.token_hex(16)
    
    new_device = {
        "device_id": data.device_id,
        "device_token": token,
        "is_online": True,
        "config": {
            "mqtt_broker": MQTT_BROKER,
            "mqtt_port": MQTT_PORT,
            "mqtt_topic_cmd": f"home/devices/{data.device_id}/cmd"
        }
    }
    
    res = supabase.table("devices").insert(new_device).execute()
    return {"status": "created", "device_token": token, "config": new_device["config"]}

@app.post("/command/{device_id}")
def send_command(device_id: str, cmd: Command):
    """Send command to device via MQTT and update DB"""
    
    # 1. Update Supabase (Optimistic update)
    # We might want to store the desired state
    
    # 2. Publish to MQTT
    topic = f"home/devices/{device_id}/cmd"
    payload = {
        "command": cmd.command,
        "relay": cmd.relay,
        "value": cmd.value,
        ** (cmd.extra or {})
    }
    
    info = mqtt_client.publish(topic, json.dumps(payload), qos=1)
    
    if info.rc != mqtt.MQTT_ERR_SUCCESS:
        raise HTTPException(status_code=500, detail="Failed to publish to MQTT")
        
    return {"status": "sent", "topic": topic, "payload": payload}

@app.post("/heartbeat")
def heartbeat(update: DeviceStateUpdate):
    """Device sends heartbeat with current state"""
    
    data = {
        "is_online": True,
        "last_heartbeat": datetime.utcnow().isoformat(),
        "device_state": update.state
    }
    
    try:
        supabase.table("devices").update(data).eq("device_id", update.device_id).execute()
        
        # Check if there are pending config updates? (Simple version: just return ok)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/device/{device_id}")
def get_device_status(device_id: str):
    device = get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device
