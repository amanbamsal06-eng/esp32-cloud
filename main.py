# ==========================================
# IoT Home Automation Hub - Production Server
# Stack: FastAPI + Supabase + Redis + MQTT + Alexa
# ==========================================

import os
import json
import time
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager

# Third-party imports
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Header, status, Request, BackgroundTasks
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
# MQTT MANAGER WITH RELIABILITY
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
        # Subscribe to all device status updates
        self.client.subscribe("iot/+/status")
    
    def _on_disconnect(self, client, userdata, rc, properties=None):
        logger.warning(f"⚠️ MQTT Disconnected: {rc}")
    
    def _on_message(self, client, userdata, msg):
        try:
            device_id = msg.topic.split('/')[1]
            payload = json.loads(msg.payload.decode())
            logger.info(f"📥 Device {device_id} status: {payload}")
            # Could update Redis/Supabase here with device responses
        except Exception as e:
            logger.error(f"Message parse error: {e}")
    
    def start(self):
        try:
            self.client.connect_async(MQTT_BROKER, MQTT_PORT, keepalive=60)
            self.client.loop_start()
            logger.info(f"🚀 MQTT Manager started on {MQTT_BROKER}:{MQTT_PORT}")
        except Exception as e:
            logger.error(f"❌ MQTT connection failed: {e}")
    
    def send_command(self, device_id: str, command: Dict[str, Any]):
        topic = f"iot/{device_id}/cmd"
        payload = json.dumps({**command, "ts": int(time.time())})
        result = self.client.publish(topic, payload, qos=1)
        
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            logger.error(f"❌ MQTT publish failed for {device_id}")
            raise HTTPException(status_code=503, detail="Command delivery failed")
        
        logger.info(f"📤 Sent to {device_id}: {command}")

mqtt_manager = MQTTManager()

# ==========================================
# FASTAPI LIFECYCLE
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 🟢 STARTUP
    logger.info("🟢 Starting IoT Hub Server...")
    mqtt_manager.start()
    await redis_client.ping()
    logger.info("✅ Redis connected")
    logger.info("✅ Server ready")
    
    yield
    
    # 🔴 SHUTDOWN
    logger.info("🔴 Shutting down...")
    mqtt_manager.client.loop_stop()
    await redis_client.close()
    logger.info("👋 Goodbye")

app = FastAPI(
    title="IoT Home Automation Hub",
    version="2.0",
    lifespan=lifespan
)

# ==========================================
# SECURITY DEPENDENCIES
# ==========================================
ADMIN_KEY_HEADER = APIKeyHeader(name="X-Admin-Key", auto_error=True)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def validate_admin(api_key: str = Depends(ADMIN_KEY_HEADER)):
    if api_key != ADMIN_API_KEY:
        logger.warning("🚨 Unauthorized admin attempt")
        raise HTTPException(status_code=403, detail="Unauthorized Admin Access")
    return api_key

async def validate_device_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        device_id = payload.get("sub")
        
        # Check if device is blacklisted
        if await redis_client.exists(f"blacklist:{device_id}"):
            logger.warning(f"🚫 Blocked device attempted access: {device_id}")
            raise HTTPException(status_code=403, detail="Device access revoked")
        
        return device_id
    except JWTError as e:
        logger.error(f"🔐 Token validation failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid/Expired Token")

# ==========================================
# PYDANTIC MODELS
# ==========================================
class DeviceRegister(BaseModel):
    device_id: str
    secret: str

class ProvisionRequest(BaseModel):
    device_id: str
    secret: str

class HeartbeatPayload(BaseModel):
    relays: Dict[str, bool]  # e.g., {"relay1": true, "relay2": false}
    uptime: int
    wifi_rssi: Optional[int] = None
    free_heap: Optional[int] = None

class AlexaRequest(BaseModel):
    directive: Dict[str, Any]

# ==========================================
# 🔧 ADMIN ENDPOINTS
# ==========================================
@app.post("/v1/admin/devices", dependencies=[Depends(validate_admin)])
async def register_device(req: DeviceRegister):
    """Register a new ESP8266 device with hardware secret"""
    try:
        supabase.table("devices").insert({
            "device_id": req.device_id,
            "hardware_secret": req.secret,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        logger.info(f"✅ Device registered: {req.device_id}")
        return {"status": "success", "device_id": req.device_id}
    except Exception as e:
        logger.error(f"❌ Registration failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/v1/admin/devices/{device_id}", dependencies=[Depends(validate_admin)])
async def ban_device(device_id: str):
    """Ban a device (blacklist)"""
    await redis_client.set(f"blacklist:{device_id}", "banned", ex=86400*365)
    logger.warning(f"🚫 Device banned: {device_id}")
    return {"status": "banned", "device_id": device_id}

@app.post("/v1/admin/unban/{device_id}", dependencies=[Depends(validate_admin)])
async def unban_device(device_id: str):
    """Remove device from blacklist"""
    await redis_client.delete(f"blacklist:{device_id}")
    logger.info(f"✅ Device unbanned: {device_id}")
    return {"status": "unbanned", "device_id": device_id}

# ==========================================
# 🔐 DEVICE AUTHENTICATION
# ==========================================
@app.post("/v1/provision")
async def provision_device(req: ProvisionRequest):
    """ESP8266 first boot: exchange hardware secret for JWT tokens"""
    try:
        # Verify device exists and secret matches
        res = supabase.table("devices").select("*").eq("device_id", req.device_id).single().execute()
        
        if not res.data or res.data.get('hardware_secret') != req.secret:
            logger.warning(f"🚨 Invalid provision attempt: {req.device_id}")
            raise HTTPException(status_code=401, detail="Invalid device credentials")
        
        # Create new session version (for refresh token rotation)
        session_ver = str(uuid.uuid4())
        supabase.table("devices").update({
            "refresh_token_ver": session_ver,
            "last_provision": datetime.utcnow().isoformat()
        }).eq("device_id", req.device_id).execute()
        
        # Generate tokens
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
    """Refresh access token using refresh token"""
    try:
        # Remove "Bearer " prefix if present
        token = refresh_token.replace("Bearer ", "")
        
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        device_id = payload.get("sub")
        token_ver = payload.get("ver")
        
        # Verify token version matches DB (detect token reuse attacks)
        res = supabase.table("devices").select("refresh_token_ver").eq("device_id", device_id).single().execute()
        
        if not res.data or res.data['refresh_token_ver'] != token_ver:
            # Token reuse detected - ban device
            await redis_client.set(f"blacklist:{device_id}", "token_reuse", ex=86400)
            logger.critical(f"🚨 TOKEN REUSE DETECTED: {device_id} - BANNED")
            raise HTTPException(status_code=403, detail="Security violation: Token reuse detected")
        
        # Generate new tokens with new version
        new_ver = str(uuid.uuid4())
        supabase.table("devices").update({
            "refresh_token_ver": new_ver
        }).eq("device_id", device_id).execute()
        
        new_access = jwt.encode({
            "sub": device_id,
            "scope": "access",
            "exp": datetime.utcnow() + timedelta(hours=1)
        }, JWT_SECRET, algorithm=ALGORITHM)
        
        new_refresh = jwt.encode({
            "sub": device_id,
            "scope": "refresh",
            "ver": new_ver,
            "exp": datetime.utcnow() + timedelta(days=365)
        }, JWT_SECRET, algorithm=ALGORITHM)
        
        logger.info(f"🔄 Token refreshed: {device_id}")
        return {
            "access_token": new_access,
            "refresh_token": new_refresh,
            "expires_in": 3600
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    except Exception as e:
        logger.error(f"❌ Refresh error: {e}")
        raise HTTPException(status_code=500, detail="Token refresh failed")

# ==========================================
# 📡 DEVICE COMMUNICATION
# ==========================================
@app.post("/v1/heartbeat")
async def device_heartbeat(
    payload: HeartbeatPayload,
    device_id: str = Depends(validate_device_token)
):
    """ESP8266 sends state every 60 seconds"""
    try:
        timestamp = int(time.time())
        
        # Store current state in Redis (with 5-minute TTL)
        state_data = {
            "relays": json.dumps(payload.relays),
            "uptime": payload.uptime,
            "wifi_rssi": payload.wifi_rssi or -100,
            "free_heap": payload.free_heap or 0,
            "last_seen": timestamp
        }
        
        await redis_client.hset(f"device:{device_id}:state", mapping={k: str(v) for k, v in state_data.items()})
        await redis_client.expire(f"device:{device_id}:state", 300)
        
        # Quick last-seen marker
        await redis_client.set(f"device:{device_id}:last_seen", timestamp, ex=86400)
        
        logger.debug(f"💓 Heartbeat from {device_id}: uptime={payload.uptime}s")
        
        return {
            "status": "ok",
            "server_time": timestamp,
            "next_heartbeat": 60
        }
    except Exception as e:
        logger.error(f"❌ Heartbeat error for {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Heartbeat processing failed")

@app.post("/v1/command/{device_id}")
async def send_device_command(
    device_id: str,
    action: str,
    relay: Optional[int] = None,
    admin_key: str = Depends(validate_admin)
):
    """Admin: Send command to ESP8266 via MQTT"""
    try:
        # Check if device is online (heartbeat within last 5 minutes)
        last_seen = await redis_client.get(f"device:{device_id}:last_seen")
        if not last_seen or (int(time.time()) - int(last_seen)) > 300:
            raise HTTPException(status_code=503, detail="Device is offline")
        
        command = {"action": action}
        if relay is not None:
            command["relay"] = relay
        
        mqtt_manager.send_command(device_id, command)
        
        # Log command to database
        supabase.table("commands").insert({
            "device_id": device_id,
            "command": command,
            "source": "admin",
            "timestamp": datetime.utcnow().isoformat()
        }).execute()
        
        return {"status": "sent", "command": command}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Command failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ==========================================
# 🗣️ ALEXA SMART HOME INTEGRATION
# ==========================================
@app.post("/v1/alexa/smart-home")
async def alexa_smart_home(req: AlexaRequest, bg: BackgroundTasks):
    """Alexa Smart Home Skill endpoint"""
    try:
        directive = req.directive
        header = directive["header"]
        namespace = header["namespace"]
        name = header["name"]
        
        # === DISCOVERY ===
        if namespace == "Alexa.Discovery" and name == "Discover":
            # Fetch all registered devices
            devices_res = supabase.table("devices").select("device_id, name, capabilities").execute()
            
            endpoints = []
            for device in devices_res.data:
                endpoints.append({
                    "endpointId": device["device_id"],
                    "friendlyName": device.get("name", f"Smart Switch {device['device_id']}"),
                    "description": "ESP8266 Smart Relay",
                    "manufacturerName": "HomeAutomation",
                    "displayCategories": ["SWITCH"],
                    "capabilities": [
                        {
                            "type": "AlexaInterface",
                            "interface": "Alexa.PowerController",
                            "version": "3",
                            "properties": {
                                "supported": [{"name": "powerState"}],
                                "proactivelyReported": False,
                                "retrievable": True
                            }
                        },
                        {
                            "type": "AlexaInterface",
                            "interface": "Alexa.EndpointHealth",
                            "version": "3",
                            "properties": {
                                "supported": [{"name": "connectivity"}],
                                "proactivelyReported": False,
                                "retrievable": True
                            }
                        }
                    ]
                })
            
            logger.info(f"🔍 Alexa Discovery: {len(endpoints)} devices")
            return {
                "event": {
                    "header": {
                        "namespace": "Alexa.Discovery",
                        "name": "Discover.Response",
                        "payloadVersion": "3",
                        "messageId": str(uuid.uuid4())
                    },
                    "payload": {"endpoints": endpoints}
                }
            }
        
        # === POWER CONTROL ===
        if namespace == "Alexa.PowerController":
            endpoint_id = directive["endpoint"]["endpointId"]
            action = "ON" if name == "TurnOn" else "OFF"
            
            # Check if device is online
            last_seen = await redis_client.get(f"device:{endpoint_id}:last_seen")
            if not last_seen or (int(time.time()) - int(last_seen)) > 300:
                logger.warning(f"⚠️ Alexa command to offline device: {endpoint_id}")
                return {
                    "event": {
                        "header": {
                            "namespace": "Alexa",
                            "name": "ErrorResponse",
                            "messageId": str(uuid.uuid4()),
                            "payloadVersion": "3"
                        },
                        "payload": {
                            "type": "ENDPOINT_UNREACHABLE",
                            "message": "Device is offline or not responding"
                        }
                    }
                }
            
            # Send MQTT command
            mqtt_manager.send_command(endpoint_id, {"action": action, "source": "alexa"})
            
            # Log command in background
            bg.add_task(
                lambda: supabase.table("commands").insert({
                    "device_id": endpoint_id,
                    "command": {"action": action},
                    "source": "alexa",
                    "timestamp": datetime.utcnow().isoformat()
                }).execute()
            )
            
            logger.info(f"🗣️ Alexa command: {endpoint_id} → {action}")
            
            # Response with state context
            return {
                "event": {
                    "header": {
                        "namespace": "Alexa",
                        "name": "Response",
                        "messageId": str(uuid.uuid4()),
                        "payloadVersion": "3"
                    },
                    "endpoint": {"endpointId": endpoint_id},
                    "payload": {}
                },
                "context": {
                    "properties": [{
                        "namespace": "Alexa.PowerController",
                        "name": "powerState",
                        "value": action,
                        "timeOfSample": datetime.utcnow().isoformat() + "Z",
                        "uncertaintyInMilliseconds": 500
                    }]
                }
            }
        
        # Unsupported directive
        logger.warning(f"⚠️ Unsupported Alexa directive: {namespace}.{name}")
        raise HTTPException(status_code=400, detail="Unsupported directive")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Alexa handler error: {e}")
        raise HTTPException(status_code=500, detail="Alexa processing failed")

# ==========================================
# 🩺 HEALTH & STATUS
# ==========================================
@app.get("/health")
async def health_check():
    """Service health check"""
    checks = {
        "redis": False,
        "mqtt": mqtt_manager.client.is_connected(),
        "supabase": False
    }
    
    # Test Redis
    try:
        await redis_client.ping()
        checks["redis"] = True
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
    
    # Test Supabase
    try:
        supabase.table("devices").select("count", count="exact").limit(1).execute()
        checks["supabase"] = True
    except Exception as e:
        logger.error(f"Supabase health check failed: {e}")
    
    all_healthy = all(checks.values())
    status_code = 200 if all_healthy else 503
    
    return {
        "status": "healthy" if all_healthy else "degraded",
        "services": checks,
        "timestamp": int(time.time()),
        "version": "2.0"
    }

@app.get("/")
async def root():
    return {
        "service": "IoT Home Automation Hub",
        "version": "2.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "admin": "/v1/admin/*",
            "device": "/v1/provision, /v1/heartbeat",
            "alexa": "/v1/alexa/smart-home"
        }
    }
