from fastapi import FastAPI, Header, HTTPException

app = FastAPI()

DEVICE_TOKEN = "DEV_TEST_123"

@app.get("/")
def root():
    return {"status": "server running"}

@app.get("/device/command")
def get_command(authorization: str = Header(None)):
    if authorization != DEVICE_TOKEN:
        raise HTTPException(status_code=401)
    return {"command": "OFF"}
    
