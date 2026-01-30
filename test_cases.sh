#!/bin/bash

SERVER="https://esp32-cloud.onrender.com"
ADMIN_KEY="change-this-in-render-settings"
DEVICE_ID="esp8266_test_$(date +%s)"
DEVICE_SECRET="test_secret_123"

echo "🧪 Testing IoT Hub API..."
echo "Device ID: $DEVICE_ID"
echo ""

# 1. Register device
echo "1️⃣ Registering device..."
REGISTER_RESPONSE=$(curl -s -X POST "$SERVER/v1/admin/devices" \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -d "{\"device_id\":\"$DEVICE_ID\",\"secret\":\"$DEVICE_SECRET\",\"name\":\"Test Device\",\"num_relays\":4}")
echo "$REGISTER_RESPONSE"
echo ""

# 2. Provision
echo "2️⃣ Provisioning..."
PROVISION_RESPONSE=$(curl -s -X POST "$SERVER/v1/provision" \
  -H "Content-Type: application/json" \
  -d "{\"device_id\":\"$DEVICE_ID\",\"secret\":\"$DEVICE_SECRET\"}")
echo "$PROVISION_RESPONSE"
echo ""

# Extract access token (POSIX-compatible way)
ACCESS_TOKEN=$(echo "$PROVISION_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$ACCESS_TOKEN" ]; then
    echo "❌ Failed to get access token"
    exit 1
fi

# Show first 30 chars (POSIX-compatible way)
TOKEN_PREVIEW=$(echo "$ACCESS_TOKEN" | cut -c1-30)
echo "✅ Got access token: ${TOKEN_PREVIEW}..."
echo ""

# 3. Ping
echo "3️⃣ Sending ping..."
PING_RESPONSE=$(curl -s -X POST "$SERVER/v1/ping" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
echo "$PING_RESPONSE"
echo ""

# 4. Get state
echo "4️⃣ Getting device state..."
STATE_RESPONSE=$(curl -s "$SERVER/v1/device/$DEVICE_ID/state" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
echo "$STATE_RESPONSE"
echo ""

# 5. Turn ON relay1
echo "5️⃣ Turning ON relay1..."
RELAY1_ON=$(curl -s -X POST "$SERVER/v1/device/$DEVICE_ID/relay/relay1" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"state": true}')
echo "$RELAY1_ON"
echo ""

# 6. Turn ON relay2 with timer
echo "6️⃣ Turning ON relay2 with 5-minute timer..."
RELAY2_ON=$(curl -s -X POST "$SERVER/v1/device/$DEVICE_ID/relay/relay2" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"state": true, "timer_minutes": 5}')
echo "$RELAY2_ON"
echo ""

# 7. Check state again
echo "7️⃣ Checking updated state..."
STATE_UPDATED=$(curl -s "$SERVER/v1/device/$DEVICE_ID/state" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
echo "$STATE_UPDATED"
echo ""

# 8. Turn OFF relay1
echo "8️⃣ Turning OFF relay1..."
RELAY1_OFF=$(curl -s -X POST "$SERVER/v1/device/$DEVICE_ID/relay/relay1" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"state": false}')
echo "$RELAY1_OFF"
echo ""

# 9. Get online devices
echo "9️⃣ Getting online devices..."
ONLINE_DEVICES=$(curl -s "$SERVER/v1/devices/online" \
  -H "X-Admin-Key: $ADMIN_KEY")
echo "$ONLINE_DEVICES"
echo ""

echo "✅ All tests complete!"
echo ""
echo "Summary:"
echo "- Device ID: $DEVICE_ID"
echo "- Access Token: ${TOKEN_PREVIEW}..."
echo "- Tested: Register, Provision, Ping, State, Relay Control, Online Check"
