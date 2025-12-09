#!/bin/bash
set -e

# Configuration
BASE_DIR="committee-setup"
KEY_SERVER_OBJ_ID="${KEY_SERVER_OBJ_ID:-0x20f0896f7271bb7289bb14dca35046090357f4e928b99302cb633a0af39797aa}"
NETWORK="${NETWORK:-Testnet}"

# Member addresses (placeholder - replace with actual addresses)
MEMBER_ADDRESS_1="${MEMBER_ADDRESS_1:-0x1111111111111111111111111111111111111111111111111111111111111111}"
MEMBER_ADDRESS_2="${MEMBER_ADDRESS_2:-0x2222222222222222222222222222222222222222222222222222222222222222}"
MEMBER_ADDRESS_3="${MEMBER_ADDRESS_3:-0x3333333333333333333333333333333333333333333333333333333333333333}"

# Placeholder master shares (32-byte hex values - replace with actual DKG output)
MASTER_SHARE_1="${MASTER_SHARE_1:-0x208cd48a92430eb9f90482291e5552e07aebc335d84b7b6371a58ebedd6ed036}"
MASTER_SHARE_2="${MASTER_SHARE_2:-0x308cd48a92430eb9f90482291e5552e07aebc335d84b7b6371a58ebedd6ed037}"
MASTER_SHARE_3="${MASTER_SHARE_3:-0x408cd48a92430eb9f90482291e5552e07aebc335d84b7b6371a58ebedd6ed038}"

# Server ports
HTTP_PORT_1=2024
HTTP_PORT_2=2025
HTTP_PORT_3=2026

METRICS_PORT_1=9184
METRICS_PORT_2=9185
METRICS_PORT_3=9186

echo "Setting up committee servers..."
echo "================================"

# Create base directory
mkdir -p "$BASE_DIR"

# Create config file for server 1
cat > "$BASE_DIR/config-1.yaml" <<EOF
network: $NETWORK

server_mode: !Committee
  member_address: '$MEMBER_ADDRESS_1'
  key_server_obj_id: '$KEY_SERVER_OBJ_ID'
  committee_state: !Active

metrics_host_port: $METRICS_PORT_1
sdk_version_requirement: '>=0.4.5'
rgp_update_interval: '60s'
allowed_staleness: '2m'
session_key_ttl_max: '30m'
EOF

# Create config file for server 2
cat > "$BASE_DIR/config-2.yaml" <<EOF
network: $NETWORK

server_mode: !Committee
  member_address: '$MEMBER_ADDRESS_2'
  key_server_obj_id: '$KEY_SERVER_OBJ_ID'
  committee_state: !Active

metrics_host_port: $METRICS_PORT_2
sdk_version_requirement: '>=0.4.5'
rgp_update_interval: '60s'
allowed_staleness: '2m'
session_key_ttl_max: '30m'
EOF

# Create config file for server 3
cat > "$BASE_DIR/config-3.yaml" <<EOF
network: $NETWORK

server_mode: !Committee
  member_address: '$MEMBER_ADDRESS_3'
  key_server_obj_id: '$KEY_SERVER_OBJ_ID'
  committee_state: !Active

metrics_host_port: $METRICS_PORT_3
sdk_version_requirement: '>=0.4.5'
rgp_update_interval: '60s'
allowed_staleness: '2m'
session_key_ttl_max: '30m'
EOF

# Write master share files for reference
echo "$MASTER_SHARE_1" > "$BASE_DIR/master_share_v0_server1.txt"
echo "$MASTER_SHARE_2" > "$BASE_DIR/master_share_v0_server2.txt"
echo "$MASTER_SHARE_3" > "$BASE_DIR/master_share_v0_server3.txt"

echo "✓ Configuration files created in $BASE_DIR/"
echo "✓ Config files: config-1.yaml, config-2.yaml, config-3.yaml"
echo "✓ Master shares written to master_share_v0_server*.txt files"
echo ""
echo "Server Configuration:"
echo "  Server 1: HTTP port $HTTP_PORT_1, Metrics port $METRICS_PORT_1"
echo "  Server 2: HTTP port $HTTP_PORT_2, Metrics port $METRICS_PORT_2"
echo "  Server 3: HTTP port $HTTP_PORT_3, Metrics port $METRICS_PORT_3"
echo ""

# Create a helper script to start all servers
cat > "$BASE_DIR/start-servers.sh" <<'SCRIPT_EOF'
#!/bin/bash

# This script starts all three committee servers
# Run this from the seal repository root directory

BASE_DIR="committee-setup"

# Load master shares
MASTER_SHARE_1=$(cat "$BASE_DIR/master_share_v0_server1.txt")
MASTER_SHARE_2=$(cat "$BASE_DIR/master_share_v0_server2.txt")
MASTER_SHARE_3=$(cat "$BASE_DIR/master_share_v0_server3.txt")

echo "Starting committee servers..."
echo "Press Ctrl+C to stop all servers"
echo ""

# Start server 1 in background
echo "Starting server 1 on port 2024..."
CONFIG_PATH="$BASE_DIR/config-1.yaml" \
  MASTER_SHARE_V0="$MASTER_SHARE_1" \
  KEY_SERVER_HOST_PORT="0.0.0.0:2024" \
  cargo run --bin key-server > "$BASE_DIR/server1.log" 2>&1 &
SERVER1_PID=$!

# Start server 2 in background
echo "Starting server 2 on port 2025..."
CONFIG_PATH="$BASE_DIR/config-2.yaml" \
  MASTER_SHARE_V0="$MASTER_SHARE_2" \
  KEY_SERVER_HOST_PORT="0.0.0.0:2025" \
  cargo run --bin key-server > "$BASE_DIR/server2.log" 2>&1 &
SERVER2_PID=$!

# Start server 3 in background
echo "Starting server 3 on port 2026..."
CONFIG_PATH="$BASE_DIR/config-3.yaml" \
  MASTER_SHARE_V0="$MASTER_SHARE_3" \
  KEY_SERVER_HOST_PORT="0.0.0.0:2026" \
  cargo run --bin key-server > "$BASE_DIR/server3.log" 2>&1 &
SERVER3_PID=$!

echo ""
echo "All servers started!"
echo "  Server 1 PID: $SERVER1_PID (HTTP: 2024, Metrics: 9184)"
echo "  Server 2 PID: $SERVER2_PID (HTTP: 2025, Metrics: 9185)"
echo "  Server 3 PID: $SERVER3_PID (HTTP: 2026, Metrics: 9186)"
echo ""
echo "Logs:"
echo "  tail -f $BASE_DIR/server1.log"
echo "  tail -f $BASE_DIR/server2.log"
echo "  tail -f $BASE_DIR/server3.log"
echo ""
echo "Health checks:"
echo "  curl http://localhost:2024/health"
echo "  curl http://localhost:2025/health"
echo "  curl http://localhost:2026/health"
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Stopping all servers..."
    kill $SERVER1_PID $SERVER2_PID $SERVER3_PID 2>/dev/null
    echo "All servers stopped."
    exit 0
}

trap cleanup INT TERM

# Wait for all background processes
wait
SCRIPT_EOF

chmod +x "$BASE_DIR/start-servers.sh"

echo "To start all servers, run:"
echo "  ./$BASE_DIR/start-servers.sh"
echo ""
echo "Or start them individually:"
echo ""
echo "# Server 1:"
echo "CONFIG_PATH=$BASE_DIR/config-1.yaml \\"
echo "  MASTER_SHARE_V0=$MASTER_SHARE_1 \\"
echo "  KEY_SERVER_HOST_PORT=0.0.0.0:$HTTP_PORT_1 \\"
echo "  cargo run --bin key-server"
echo ""
echo "# Server 2:"
echo "CONFIG_PATH=$BASE_DIR/config-2.yaml \\"
echo "  MASTER_SHARE_V0=$MASTER_SHARE_2 \\"
echo "  KEY_SERVER_HOST_PORT=0.0.0.0:$HTTP_PORT_2 \\"
echo "  cargo run --bin key-server"
echo ""
echo "# Server 3:"
echo "CONFIG_PATH=$BASE_DIR/config-3.yaml \\"
echo "  MASTER_SHARE_V0=$MASTER_SHARE_3 \\"
echo "  KEY_SERVER_HOST_PORT=0.0.0.0:$HTTP_PORT_3 \\"
echo "  cargo run --bin key-server"
echo ""
echo "Note: Replace the placeholder values in config files and master shares"
echo "      with actual values from your DKG process before production use."
