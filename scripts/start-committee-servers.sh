#!/bin/bash
# Script to start 3 mock committee key servers and 1 aggregator server

# Check for help command
if [[ "$1" == "help" || "$1" == "--help" || "$1" == "-h" ]]; then
  echo "Usage: $0 [COMMAND]"
  echo ""
  echo "Commands:"
  echo "  (none)    Start all servers (3 key servers + 1 aggregator)"
  echo "  stop      Stop all running servers"
  echo "  help      Show this help message"
  echo ""
  echo "Server ports:"
  echo "  Key Server 0: http://localhost:2024"
  echo "  Key Server 1: http://localhost:2025"
  echo "  Key Server 2: http://localhost:2026"
  echo "  Aggregator:   http://localhost:2027"
  exit 0
fi

# Check for stop command
if [[ "$1" == "stop" || "$1" == "--stop" ]]; then
  echo "Stopping all servers..."
  pkill -9 -f "key-server|aggregator-server" 2>/dev/null || true

  # Kill any processes on the ports we use
  for port in 2024 2025 2026 2027; do
    lsof -ti:$port | xargs kill -9 2>/dev/null || true
  done

  echo "All servers stopped."
  exit 0
fi

# Cleanup any existing servers
echo "Cleaning up existing servers..."
pkill -9 -f "key-server|aggregator-server" 2>/dev/null || true
sleep 2

# Kill any processes on the ports we need
for port in 2024 2025 2026 2027; do
  lsof -ti:$port | xargs kill -9 2>/dev/null || true
done
sleep 1
echo "Cleanup complete."
echo ""

# Configuration
KEY_SERVER_OBJ="0x56eee177d0e3d544354616610d3e06edd65a10f47f0056d111e4d241d70c1969"
NETWORK="testnet"
MEMBER_0="0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d"
MEMBER_1="0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6"
MEMBER_2="0x223762117ab21a439f0f3f3b0577e838b8b26a37d9a1723a4be311243f4461b9"
MASTER_SHARE_0="0x698ca99c5ec36e1fa961e904fd50c3c3f16200f7de834704568468c5c6eaa718"
MASTER_SHARE_1="0x48ac97099f342e37cb5680334b3e3c7ab7c0a4f1bd4735f0934074d7cf1cfaf2"
MASTER_SHARE_2="0x27cc8476dfa4ee4fed4b1761992bb5317e1f48eb9c0b24dccffc80e9d74f4ecc"

# Create config files
echo "Creating config files..."

cat > crates/key-server/key-server-config-0.yaml <<EOF
network: Testnet

node_url: https://fullnode.testnet.sui.io:443

server_mode: !Committee
  member_address: '$MEMBER_0'
  key_server_obj_id: '$KEY_SERVER_OBJ'
  committee_state: !Active

metrics_host_port: 9184
EOF

cat > crates/key-server/key-server-config-1.yaml <<EOF
network: Testnet

node_url: https://fullnode.testnet.sui.io:443

server_mode: !Committee
  member_address: '$MEMBER_1'
  key_server_obj_id: '$KEY_SERVER_OBJ'
  committee_state: !Active

metrics_host_port: 9185
EOF

cat > crates/key-server/key-server-config-2.yaml <<EOF
network: Testnet

node_url: https://fullnode.testnet.sui.io:443

server_mode: !Committee
  member_address: '$MEMBER_2'
  key_server_obj_id: '$KEY_SERVER_OBJ'
  committee_state: !Active

metrics_host_port: 9186
EOF

echo "Config files created."
echo "Starting 3 key servers..."

# Start server 0 on port 2024
RUST_LOG=error \
  PORT=2024 \
  CONFIG_PATH=crates/key-server/key-server-config-0.yaml \
  MASTER_SHARE_V0=$MASTER_SHARE_0 \
  cargo run --bin key-server 2>&1 | sed 's/^/[SERVER-0] /' &
PID_0=$!
echo "Server 0 started on http://localhost:2024 (PID: $PID_0)"

# Start server 1 on port 2025
RUST_LOG=error \
  PORT=2025 \
  CONFIG_PATH=crates/key-server/key-server-config-1.yaml \
  MASTER_SHARE_V0=$MASTER_SHARE_1 \
  cargo run --bin key-server 2>&1 | sed 's/^/[SERVER-1] /' &
PID_1=$!
echo "Server 1 started on http://localhost:2025 (PID: $PID_1)"

# Start server 2 on port 2026
RUST_LOG=error \
  PORT=2026 \
  CONFIG_PATH=crates/key-server/key-server-config-2.yaml \
  MASTER_SHARE_V0=$MASTER_SHARE_2 \
  cargo run --bin key-server 2>&1 | sed 's/^/[SERVER-2] /' &
PID_2=$!
echo "Server 2 started on http://localhost:2026 (PID: $PID_2)"

# Start aggregator server on port 2027
RUST_LOG=error \
  PORT=2027 \
  NETWORK=$NETWORK \
  KEY_SERVER_OBJ_ID=$KEY_SERVER_OBJ \
  cargo run --bin aggregator-server 2>&1 | sed 's/^/[AGGREGATOR] /' &
PID_AGG=$!
echo "Aggregator started on http://localhost:2027 (PID: $PID_AGG)"

echo ""
echo "All servers started!"
echo "  - Key Server 0: http://localhost:2024 (PID: $PID_0)"
echo "  - Key Server 1: http://localhost:2025 (PID: $PID_1)"
echo "  - Key Server 2: http://localhost:2026 (PID: $PID_2)"
echo "  - Aggregator:   http://localhost:2027 (PID: $PID_AGG)"
echo ""
echo "Waiting for servers to be ready..."

# Function to check health endpoint
check_health() {
  local port=$1
  local name=$2
  local max_attempts=60
  local attempt=0

  while [ $attempt -lt $max_attempts ]; do
    if curl -s -f "http://localhost:$port/health" > /dev/null 2>&1; then
      echo "✓ $name is ready"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done

  echo "✗ $name failed to start (timeout after ${max_attempts}s)"
  return 1
}

# Check all servers
check_health 2024 "Key Server 0" &
check_health 2025 "Key Server 1" &
check_health 2026 "Key Server 2" &
check_health 2027 "Aggregator" &

# Wait for all health checks to complete
wait

echo ""
echo "All servers are ready!"
echo ""
echo "To stop all servers, run:"
echo "  ./scripts/start-committee-servers.sh stop"
echo ""
echo "Or manually:"
echo "  kill $PID_0 $PID_1 $PID_2 $PID_AGG"
