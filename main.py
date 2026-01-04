from fastapi import FastAPI, Header, HTTPException

app = FastAPI()

# temporary in-memory store
DEVICE_TOKEN = "DEV_TEST_123"
device_state = "OFF"

@app.get("/")
def root():
    return {"status": "server running"}

# App / user sends command
@app.post("/send_command")
def send_command(command: str, authorization: str = Header(None)):
    global device_state
    if authorization != DEVICE_TOKEN:
        raise HTTPException(status_code=401)

    if command not in ["ON", "OFF"]:
        raise HTTPException(status_code=400)

    device_state = command
    return {"status": "stored", "command": device_state}

# ESP32 polls this
@app.get("/device/command")
def get_command(authorization: str = Header(None)):
    if authorization != DEVICE_TOKEN:
        raise HTTPException(status_code=401)

    return {"command": device_state}