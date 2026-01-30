# ==========================================
# IoT Home Automation Hub - Production Server (Optimized)
# Stack: FastAPI + Supabase + Redis + MQTT + Alexa
# ==========================================

import os
import json
import time
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from contextlib import asynccontextmanager

# Third-party imports
from fastapi import FastAPI, Depends, HTTPException, Header, Request, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from pydantic import BaseModel
from supabase import create_client, Client
import redis.asyncio as redis
import paho.mqtt.client as mqtt
from jose import JWTError, jwt

# ==========================================
# LOGGING SETUP
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==========================================
# CONFIGURATION & SECRETS
# ==========================================
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "change-this-in-render-settings")
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "very-secret-token-key")
ALGORITHM = "HS256"

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
UPSTASH_REDIS_URL = os.getenv("UPSTASH_REDIS_URL")

MQTT_BROKER = os.getenv("MQTT_BROKER", "broker.emqx.io")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_USER = os.getenv("MQTT_USER")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD")

# ==========================================
# DATABASE & CACHE CLIENTS
# ==========================================
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
redis_client = redis.from_url(UPSTASH_REDIS_URL, decode_responses=True)

# ==========================================
# MQTT MANAGER
# ==========================================
class MQTTManager:
    def __init__(self):
        self.client = mqtt.Client(protocol=mqtt.MQTTv5)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message
        
        if MQTT_USER and MQTT_PASSWORD:
            self.client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    
    def _on_connect(self, client, userdata, flags, rc, properties=None):
        logger.info(f"✅ MQTT Connected: {rc}")
        self.client.subscribe("iot/+/status")
    
    def _on_disconnect(self, client, userdata, rc, properties=None):
        logger.warning(f"⚠️ MQTT Disconnected: {rc}")
    
    def _on_message(self, client, userdata, msg):
        try:
            device_id = msg.topic.split('/')[1]
            payload = json.loads(msg.payload.decode())
            logger.info(f"📥 Device {device_id} status: {payload}")
        except Exception as e:
            logger.error(f"MQTT message parse error: {e}")
    
    def start(self):
        try:
            self.client.connect_async(MQTT_BROKER, MQTT_PORT, keepalive=60)
            self.client.loop_start()
            logger.info(f"🚀 MQTT started on {MQTT_BROKER}:{MQTT_PORT}")
        except Exception as e:
            logger.error(f"❌ MQTT connection failed: {e}")
    
    def publish_state_update(self, device_id: str, state: Dict[str, Any]):
        """Notify ESP8266 of state change via MQTT"""
        topic = f"iot/{device_id}/state"
        payload = json.dumps(state)
        result = self.client.publish(topic, payload, qos=1)
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            logger.info(f"📤 State update sent to {device_id}")
        else:
            logger.error(f"❌ MQTT publish failed for {device_id}")

mqtt_manager = MQTTManager()

# ==========================================
# FASTAPI LIFECYCLE
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🟢 Starting IoT Hub...")
    mqtt_manager.start()
    await redis_client.ping()
    logger.info("✅ Server ready")
    yield
    logger.info("🔴 Shutting down...")
    mqtt_manager.client.loop_stop()
    await redis_client.close()

app = FastAPI(title="IoT Home Automation Hub", version="3.0", lifespan=lifespan)

# ==========================================
# SECURITY
# ==========================================
ADMIN_KEY_HEADER = APIKeyHeader(name="X-Admin-Key", auto_error=True)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def validate_admin(api_key: str = Depends(ADMIN_KEY_HEADER)):
    if api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized")
    return api_key

# This function runs BEFORE the endpoint handler
async def validate_device_token(token: str = Depends(oauth2_scheme)):
    """
    This dependency function extracts and validates JWT token
    It runs automatically when endpoint has: device_id: str = Depends(validate_device_token)
    """
    try:
        # Step 1: Decode the JWT token
        payload = jwt.decode(
            token,                    # The token from Authorization header
            JWT_SECRET,               # Secret key to verify signature
            algorithms=[ALGORITHM]    # HS256
        )
        
        # Token decoded successfully - now payload looks like:
        # {"sub": "esp8266_001", "scope": "access", "exp": 1738276800}
        
        # Step 2: Extract device_id
        device_id = payload.get("sub")
        if not device_id:
            raise HTTPException(status_code=401, detail="Invalid token: no device_id")
        
        # Step 3: Check if token expired (jwt.decode already checks this, but just in case)
        exp = payload.get("exp")
        if exp and exp < int(time.time()):
            raise HTTPException(status_code=401, detail="Token expired")
        
        # Step 4: Check if device is blacklisted
        is_banned = await redis_client.exists(f"blacklist:{device_id}")
        if is_banned:
            logger.warning(f"🚫 Banned device tried to access: {device_id}")
            raise HTTPException(status_code=403, detail="Device access revoked")
        
        # Step 5: All checks passed - return device_id
        logger.debug(f"✅ Token validated for device: {device_id}")
        return device_id
        
    except jwt.ExpiredSignatureError:
        logger.error("❌ Token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError as e:
        logger.error(f"❌ JWT validation failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")

# ==========================================
# PYDANTIC MODELS
# ==========================================
class DeviceRegister(BaseModel):
    device_id: str
    secret: str
    name: Optional[str] = None
    num_relays: int = 4

class ProvisionRequest(BaseModel):
    device_id: str
    secret: str

class RelayUpdate(BaseModel):
    state: bool  # true = ON, false = OFF
    timer_minutes: Optional[int] = None  # Auto turn off/on after X minutes

class AlexaRequest(BaseModel):
    directive: Dict[str, Any]

# ==========================================
# 🔧 ADMIN ENDPOINTS
# ==========================================
@app.post("/v1/admin/devices", dependencies=[Depends(validate_admin)])
async def register_device(req: DeviceRegister):
    """Register new device"""
    try:
        # Store in Supabase (permanent registry)
        supabase.table("devices").insert({
            "device_id": req.device_id,
            "hardware_secret": req.secret,
            "name": req.name or req.device_id,
            "num_relays": req.num_relays,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        # Initialize state in Redis
        initial_state = {
            "relays": json.dumps({f"relay{i+1}": {"state": False, "timer_end": None} for i in range(req.num_relays)}),
            "online": "false",
            "num_relays": req.num_relays
        }
        await redis_client.hset(f"device:{req.device_id}:state", mapping=initial_state)
        
        logger.info(f"✅ Device registered: {req.device_id}")
        return {"status": "success", "device_id": req.device_id}
    except Exception as e:
        logger.error(f"❌ Registration failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/v1/admin/devices/{device_id}", dependencies=[Depends(validate_admin)])
async def ban_device(device_id: str):
    await redis_client.set(f"blacklist:{device_id}", "banned", ex=86400*365)
    return {"status": "banned"}

@app.post("/v1/admin/unban/{device_id}", dependencies=[Depends(validate_admin)])
async def unban_device(device_id: str):
    await redis_client.delete(f"blacklist:{device_id}")
    return {"status": "unbanned"}

# ==========================================
# 🔐 DEVICE AUTHENTICATION
# ==========================================
@app.post("/v1/provision")
async def provision_device(req: ProvisionRequest):
    try:
        res = supabase.table("devices").select("*").eq("device_id", req.device_id).single().execute()
        if not res.data or res.data.get('hardware_secret') != req.secret:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        session_ver = str(uuid.uuid4())
        supabase.table("devices").update({
            "refresh_token_ver": session_ver,
            "last_provision": datetime.utcnow().isoformat()
        }).eq("device_id", req.device_id).execute()
        
        access_token = jwt.encode({
            "sub": req.device_id,
            "scope": "access",
            "exp": datetime.utcnow() + timedelta(hours=1)
        }, JWT_SECRET, algorithm=ALGORITHM)
        
        refresh_token = jwt.encode({
            "sub": req.device_id,
            "scope": "refresh",
            "ver": session_ver,
            "exp": datetime.utcnow() + timedelta(days=365)
        }, JWT_SECRET, algorithm=ALGORITHM)
        
        logger.info(f"🔑 Provisioned: {req.device_id}")
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": 3600,
            "mqtt_broker": MQTT_BROKER,
            "mqtt_port": MQTT_PORT
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Provision error: {e}")
        raise HTTPException(status_code=500, detail="Provisioning failed")

@app.post("/v1/refresh")
async def refresh_token(refresh_token: str = Header(..., alias="Authorization")):
    try:
        token = refresh_token.replace("Bearer ", "")
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        device_id = payload.get("sub")
        token_ver = payload.get("ver")
        
        res = supabase.table("devices").select("refresh_token_ver").eq("device_id", device_id).single().execute()
        if not res.data or res.data['refresh_token_ver'] != token_ver:
            await redis_client.set(f"blacklist:{device_id}", "token_reuse", ex=86400)
            logger.critical(f"🚨 TOKEN REUSE: {device_id}")
            raise HTTPException(status_code=403, detail="Token reuse detected")
        
        new_ver = str(uuid.uuid4())
        supabase.table("devices").update({"refresh_token_ver": new_ver}).eq("device_id", device_id).execute()
        
        new_access = jwt.encode({"sub": device_id, "scope": "access", "exp": datetime.utcnow() + timedelta(hours=1)}, JWT_SECRET, algorithm=ALGORITHM)
        new_refresh = jwt.encode({"sub": device_id, "scope": "refresh", "ver": new_ver, "exp": datetime.utcnow() + timedelta(days=365)}, JWT_SECRET, algorithm=ALGORITHM)
        
        return {"access_token": new_access, "refresh_token": new_refresh, "expires_in": 3600}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==========================================
# 📡 DEVICE COMMUNICATION (OPTIMIZED)
# ==========================================
@app.post("/v1/ping")
async def device_ping(device_id: str = Depends(validate_device_token)):
    """Lightweight heartbeat - just mark device online"""
    timestamp = int(time.time())
    await redis_client.setex(f"device:{device_id}:online", 300, "true")  # 5 min TTL
    await redis_client.hset(f"device:{device_id}:state", "last_seen", timestamp)
    logger.debug(f"💓 Ping from {device_id}")
    return {"status": "ok", "server_time": timestamp}

@app.get("/v1/device/{device_id}/state")
async def get_device_state(
    device_id: str,
    requester: str = Depends(validate_device_token)  # Any authenticated device can query
):
    """Get current state of device from Redis"""
    state = await redis_client.hgetall(f"device:{device_id}:state")
    if not state:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Check if online
    is_online = await redis_client.exists(f"device:{device_id}:online")
    
    return {
        "device_id": device_id,
        "online": bool(is_online),
        "relays": json.loads(state.get("relays", "{}")),
        "last_seen": state.get("last_seen"),
        "num_relays": int(state.get("num_relays", 4))
    }

@app.post("/v1/device/{device_id}/relay/{relay_id}")
async def update_relay(
    device_id: str,
    relay_id: str,  # e.g., "relay1", "relay2"
    update: RelayUpdate,
    requester: str = Depends(validate_device_token)  # Can be admin OR device
):
    """
    Update relay state (called by admin, Alexa, or ESP8266 itself)
    Changes are saved to Redis and pushed to ESP8266 via MQTT
    """
    # Get current state from Redis
    current_state = await redis_client.hget(f"device:{device_id}:state", "relays")
    if not current_state:
        raise HTTPException(status_code=404, detail="Device not found")
    
    relays = json.loads(current_state)
    if relay_id not in relays:
        raise HTTPException(status_code=400, detail=f"Relay {relay_id} not found")
    
    # Calculate timer end time if timer is set
    timer_end = None
    if update.timer_minutes:
        timer_end = int(time.time()) + (update.timer_minutes * 60)
    
    # Update relay state
    relays[relay_id] = {
        "state": update.state,
        "timer_end": timer_end,
        "updated_at": int(time.time()),
        "updated_by": requester
    }
    
    # Save to Redis
    await redis_client.hset(f"device:{device_id}:state", "relays", json.dumps(relays))
    
    # Notify ESP8266 via MQTT
    mqtt_manager.publish_state_update(device_id, {
        "relay_id": relay_id,
        "state": update.state,
        "timer_end": timer_end
    })
    
    # Log to Supabase (audit trail)
    supabase.table("commands").insert({
        "device_id": device_id,
        "command": {"relay": relay_id, "state": update.state, "timer_minutes": update.timer_minutes},
        "source": requester,
        "timestamp": datetime.utcnow().isoformat()
    }).execute()
    
    logger.info(f"🔧 {requester} updated {device_id}/{relay_id} → {update.state}")
    
    return {
        "status": "updated",
        "device_id": device_id,
        "relay_id": relay_id,
        "state": update.state,
        "timer_end": timer_end
    }

# ==========================================
# 🗣️ ALEXA INTEGRATION
# ==========================================
@app.post("/v1/alexa/smart-home")
async def alexa_smart_home(req: AlexaRequest, bg: BackgroundTasks):
    try:
        directive = req.directive
        header = directive["header"]
        namespace = header["namespace"]
        name = header["name"]
        
        # Discovery
        if namespace == "Alexa.Discovery":
            devices_res = supabase.table("devices").select("device_id, name, num_relays").execute()
            endpoints = []
            for device in devices_res.data:
                endpoints.append({
                    "endpointId": device["device_id"],
                    "friendlyName": device.get("name", device["device_id"]),
                    "description": f"Smart Switch with {device.get('num_relays', 4)} relays",
                    "manufacturerName": "HomeAutomation",
                    "displayCategories": ["SWITCH"],
                    "capabilities": [{
                        "type": "AlexaInterface",
                        "interface": "Alexa.PowerController",
                        "version": "3",
                        "properties": {
                            "supported": [{"name": "powerState"}],
                            "proactivelyReported": False,
                            "retrievable": True
                        }
                    }]
                })
            return {
                "event": {
                    "header": {"namespace": "Alexa.Discovery", "name": "Discover.Response", "payloadVersion": "3", "messageId": str(uuid.uuid4())},
                    "payload": {"endpoints": endpoints}
                }
            }
        
        # Power Control
        if namespace == "Alexa.PowerController":
            endpoint_id = directive["endpoint"]["endpointId"]
            action = name == "TurnOn"
            
            # Check online
            is_online = await redis_client.exists(f"device:{endpoint_id}:online")
            if not is_online:
                return {
                    "event": {
                        "header": {"namespace": "Alexa", "name": "ErrorResponse", "messageId": str(uuid.uuid4()), "payloadVersion": "3"},
                        "payload": {"type": "ENDPOINT_UNREACHABLE", "message": "Device offline"}
                    }
                }
            
            # Update relay1 (default for Alexa single-relay control)
            current_state = await redis_client.hget(f"device:{endpoint_id}:state", "relays")
            relays = json.loads(current_state)
            relays["relay1"]["state"] = action
            relays["relay1"]["updated_at"] = int(time.time())
            await redis_client.hset(f"device:{endpoint_id}:state", "relays", json.dumps(relays))
            
            # Notify device
            mqtt_manager.publish_state_update(endpoint_id, {"relay_id": "relay1", "state": action})
            
            logger.info(f"🗣️ Alexa: {endpoint_id}/relay1 → {action}")
            
            return {
                "event": {
                    "header": {"namespace": "Alexa", "name": "Response", "messageId": str(uuid.uuid4()), "payloadVersion": "3"},
                    "endpoint": {"endpointId": endpoint_id},
                    "payload": {}
                },
                "context": {
                    "properties": [{
                        "namespace": "Alexa.PowerController",
                        "name": "powerState",
                        "value": "ON" if action else "OFF",
                        "timeOfSample": datetime.utcnow().isoformat() + "Z",
                        "uncertaintyInMilliseconds": 500
                    }]
                }
            }
        
        raise HTTPException(status_code=400, detail="Unsupported directive")
    except Exception as e:
        logger.error(f"❌ Alexa error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ==========================================
# 🩺 HEALTH & MONITORING
# ==========================================
@app.get("/health")
async def health_check():
    checks = {"redis": False, "mqtt": mqtt_manager.client.is_connected(), "supabase": False}
    try:
        await redis_client.ping()
        checks["redis"] = True
    except: pass
    try:
        supabase.table("devices").select("count", count="exact").limit(1).execute()
        checks["supabase"] = True
    except: pass
    return {"status": "healthy" if all(checks.values()) else "degraded", "services": checks, "timestamp": int(time.time())}

@app.get("/v1/devices/online")
async def get_online_devices(admin_key: str = Depends(validate_admin)):
    """Get list of currently online devices"""
    devices = supabase.table("devices").select("device_id, name").execute()
    online_devices = []
    for device in devices.data:
        is_online = await redis_client.exists(f"device:{device['device_id']}:online")
        if is_online:
            state = await redis_client.hgetall(f"device:{device['device_id']}:state")
            online_devices.append({
                "device_id": device["device_id"],
                "name": device.get("name"),
                "relays": json.loads(state.get("relays", "{}")),
                "last_seen": state.get("last_seen")
            })
    return {"online_count": len(online_devices), "devices": online_devices}

@app.get("/")
async def root():
    return {
        "service": "IoT Home Automation Hub",
        "version": "3.0",
        "features": ["Redis-first state", "Lightweight ping", "Real-time MQTT sync", "Timer support"],
        "endpoints": {
            "ping": "/v1/ping",
            "state": "/v1/device/{id}/state",
            "relay": "/v1/device/{id}/relay/{relay_id}",
            "online": "/v1/devices/online"
        }
    }
