from fastapi import FastAPI, Header, HTTPException
from sqlalchemy import create_engine, Column, String, Boolean, TIMESTAMP
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timedelta
import secrets
import os

# -------------------------------------------------
# DATABASE SETUP
# -------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# -------------------------------------------------
# DEVICE TABLE
# -------------------------------------------------
class Device(Base):
    __tablename__ = "devices"

    device_id = Column(String, primary_key=True)
    device_token = Column(String, unique=True, nullable=False)
    device_state = Column(String, default="OFF")
    token_expiry = Column(TIMESTAMP)
    active = Column(Boolean, default=True)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# -------------------------------------------------
# FASTAPI APP
# -------------------------------------------------
app = FastAPI()

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def get_db():
    return SessionLocal()

def generate_token():
    return secrets.token_hex(32)

def authenticate(db, token: str):
    device = db.query(Device).filter(
        Device.device_token == token,
        Device.active == True
    ).first()

    if not device:
        raise HTTPException(status_code=401, detail="INVALID_TOKEN")

    if device.token_expiry and device.token_expiry < datetime.utcnow():
        raise HTTPException(status_code=401, detail="TOKEN_EXPIRED")

    return device

# -------------------------------------------------
# HEALTH CHECK
# -------------------------------------------------
@app.get("/")
def root():
    return {"status": "server running with postgres"}

# -------------------------------------------------
# DEVICE PROVISIONING (FIRST TIME ONLY)
# -------------------------------------------------
@app.post("/provision")
def provision(device_id: str):
    db = get_db()

    existing = db.query(Device).filter(Device.device_id == device_id).first()
    if existing:
        raise HTTPException(400, detail="DEVICE_ALREADY_EXISTS")

    token = generate_token()

    device = Device(
        device_id=device_id,
        device_token=token,
        token_expiry=datetime.utcnow() + timedelta(days=30)
    )

    db.add(device)
    db.commit()
    db.close()

    return {
        "device_id": device_id,
        "device_token": token,
        "expires_in_days": 30
    }

# -------------------------------------------------
# SEND COMMAND (APP / USER)
# -------------------------------------------------
@app.post("/send_command")
def send_command(
    command: str,
    authorization: str = Header(None)
):
    if command not in ["ON", "OFF"]:
        raise HTTPException(400, detail="INVALID_COMMAND")

    db = get_db()
    device = authenticate(db, authorization)

    device.device_state = command
    device.updated_at = datetime.utcnow()
    db.commit()
    db.close()

    return {"status": "stored", "command": command}

# -------------------------------------------------
# DEVICE POLL COMMAND (ESP32 / ESP8266)
# -------------------------------------------------
@app.get("/device/command")
def get_command(
    authorization: str = Header(None)
):
    db = get_db()
    device = authenticate(db, authorization)
    state = device.device_state
    db.close()

    return {"command": state}

# -------------------------------------------------
# TOKEN REFRESH (SECURE ROTATION)
# -------------------------------------------------
@app.post("/refresh_token")
def refresh_token(
    device_id: str,
    authorization: str = Header(None)
):
    db = get_db()

    device = db.query(Device).filter(
        Device.device_token == authorization,
        Device.device_id == device_id,
        Device.active == True
    ).first()

    if not device:
        raise HTTPException(status_code=401, detail="INVALID_REFRESH_REQUEST")

    new_token = generate_token()

    device.device_token = new_token
    device.token_expiry = datetime.utcnow() + timedelta(days=30)
    device.updated_at = datetime.utcnow()

    db.commit()
    db.close()

    return {
        "device_token": new_token,
        "expires_in_days": 30
    }

# -------------------------------------------------
# DEVICE REVOKE (ADMIN / SECURITY)
# -------------------------------------------------
@app.post("/revoke_device")
def revoke_device(device_id: str):
    db = get_db()
    device = db.query(Device).filter(Device.device_id == device_id).first()

    if not device:
        raise HTTPException(404)

    device.active = False
    db.commit()
    db.close()

    return {"status": "device_revoked"}
