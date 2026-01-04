from fastapi import FastAPI, Header, HTTPException, Depends
from sqlalchemy import create_engine, Column, String, Boolean, TIMESTAMP
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from datetime import datetime, timedelta
import secrets
import os

# -------------------------------------------------
# DATABASE SETUP
# -------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=3,
    max_overflow=5
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

# -------------------------------------------------
# DEVICE TABLE (must already exist in Supabase)
# -------------------------------------------------
class Device(Base):
    __tablename__ = "devices"

    device_id = Column(String, primary_key=True)
    device_token = Column(String, unique=True, nullable=False)
    device_state = Column(String, default="OFF")
    token_expiry = Column(TIMESTAMP)
    active = Column(Boolean, default=True)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow)

# ❌ DO NOT auto-create tables in prod
# Base.metadata.create_all(bind=engine)

# -------------------------------------------------
# FASTAPI APP
# -------------------------------------------------
app = FastAPI()

# -------------------------------------------------
# DB DEPENDENCY
# -------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def generate_token():
    return secrets.token_hex(32)

def authenticate(db: Session, token: str):
    if not token:
        raise HTTPException(status_code=401, detail="TOKEN_REQUIRED")

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
# DEVICE PROVISIONING (FIRST TIME)
# -------------------------------------------------
@app.post("/provision")
def provision(device_id: str, db: Session = Depends(get_db)):
    existing = db.query(Device).filter(Device.device_id == device_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="DEVICE_ALREADY_EXISTS")

    token = generate_token()

    device = Device(
        device_id=device_id,
        device_token=token,
        token_expiry=datetime.utcnow() + timedelta(days=30),
        updated_at=datetime.utcnow()
    )

    db.add(device)
    db.commit()

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
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    if command not in ["ON", "OFF"]:
        raise HTTPException(status_code=400, detail="INVALID_COMMAND")

    device = authenticate(db, authorization)

    device.device_state = command
    device.updated_at = datetime.utcnow()
    db.commit()

    return {"status": "stored", "command": command}

# -------------------------------------------------
# DEVICE POLL COMMAND (ESP)
# -------------------------------------------------
@app.get("/device/command")
def get_command(
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    device = authenticate(db, authorization)
    return {"command": device.device_state}

# -------------------------------------------------
# TOKEN REFRESH
# -------------------------------------------------
@app.post("/refresh_token")
def refresh_token(
    device_id: str,
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
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

    return {
        "device_token": new_token,
        "expires_in_days": 30
    }

# -------------------------------------------------
# DEVICE REVOKE (ADMIN)
# -------------------------------------------------
@app.post("/revoke_device")
def revoke_device(device_id: str, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.device_id == device_id).first()

    if not device:
        raise HTTPException(status_code=404, detail="DEVICE_NOT_FOUND")

    device.active = False
    device.updated_at = datetime.utcnow()
    db.commit()

    return {"status": "device_revoked"}
