#!/bin/bash
# Script to start committee key servers and 1 aggregator server
#
# Usage:
#   ./start-committee-servers.sh <version> <key_server_obj_id> <server_list>
#   ./start-committee-servers.sh stop
#
# Example:
#   ./start-committee-servers.sh 0 0x0688650cf0b28882e607ae43df1e95e769f9b2f689cf90d68c715b3e08e28c70 \
#     "0x1edd...:0x3a9a...:2024,0x3af3...:0x35a8...:2025"

# Change to the seal repository root directory (where Cargo.toml is)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEAL_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SEAL_ROOT" || exit 1

echo "Running from: $(pwd)"
echo ""

# Check for help command
if [[ "$1" == "help" || "$1" == "--help" || "$1" == "-h" ]]; then
  echo "Usage: $0 [COMMAND|VERSION KEY_SERVER_OBJ_ID SERVER_LIST]"
  echo ""
  echo "Commands:"
  echo "  stop      Stop all running servers"
  echo "  help      Show this help message"
  echo ""
  echo "Parameters:"
  echo "  VERSION              Master share version (e.g., 0, 1, 2)"
  echo "  KEY_SERVER_OBJ_ID    Key server object ID (0x...)"
  echo "  SERVER_LIST          Comma-separated list: member_address:master_share:port"
  echo ""
  echo "Example:"
  echo "  $0 0 0x0688650cf... \"0x1edd...:0x3a9a...:2024,0x3af3...:0x35a8...:2025\""
  echo ""
  echo "Default server ports:"
  echo "  Key Server 0: http://localhost:2024"
  echo "  Key Server 1: http://localhost:2025"
  echo "  Aggregator:   http://localhost:3000"
  exit 0
fi

# Check for stop command
if [[ "$1" == "stop" || "$1" == "--stop" ]]; then
  echo "Stopping all servers..."
  pkill -9 -f "key-server|aggregator-server" 2>/dev/null || true

  # Kill any processes on the ports we use
  for port in 2024 2025 3000; do
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
for port in 2024 2025 3000; do
  lsof -ti:$port | xargs kill -9 2>/dev/null || true
done
sleep 1
echo "Cleanup complete."
echo ""

# Parse arguments or use defaults
VERSION="${1:-0}"
KEY_SERVER_OBJ_ID="${2:-0x0688650cf0b28882e607ae43df1e95e769f9b2f689cf90d68c715b3e08e28c70}"
SERVER_LIST="${3:-0x1edd19be21bacb19c30e7dfcc3a1a270effd8c9c24e9dfbd1c99156597efab9e:0x3a9a68b226d13c1cb4dd71c21c0cc433fe3673ed962ea0a6d47f9b96e15d8043:2024,0x3af3e4522a8a821dbc50c9dec6a5ad0fa62abc51a66d30f6e298e0d690b07e7b:0x35a81e05c0990668aa3fa6f92e7c25d36e59533a398d99055a49bcbae9c561f0:2025}"
NETWORK="Testnet"

# Parse server list into arrays
IFS=',' read -ra SERVERS <<< "$SERVER_LIST"
MEMBER_ADDRS=()
MASTER_SHARES=()
PORTS=()

for server_entry in "${SERVERS[@]}"; do
  IFS=':' read -ra PARTS <<< "$server_entry"
  if [ ${#PARTS[@]} -ne 3 ]; then
    echo "Error: Invalid server entry format: $server_entry"
    echo "Expected format: member_address:master_share:port"
    exit 1
  fi
  MEMBER_ADDRS+=("${PARTS[0]}")
  MASTER_SHARES+=("${PARTS[1]}")
  PORTS+=("${PARTS[2]}")
done

NUM_SERVERS=${#MEMBER_ADDRS[@]}
echo "Configuration:"
echo "  Version: V${VERSION}"
echo "  Key Server Object ID: ${KEY_SERVER_OBJ_ID}"
echo "  Number of servers: ${NUM_SERVERS}"
echo ""

# Create config files
echo "Creating config files..."

for i in "${!MEMBER_ADDRS[@]}"; do
  METRICS_PORT=$((9184 + i))
  cat > crates/key-server/key-server-config-${i}.yaml <<EOF
network: ${NETWORK}

node_url: https://fullnode.testnet.sui.io:443

server_mode: !Committee
  member_address: '${MEMBER_ADDRS[$i]}'
  key_server_obj_id: '${KEY_SERVER_OBJ_ID}'
  committee_state: !Active

metrics_host_port: ${METRICS_PORT}
EOF
  echo "  Created key-server-config-${i}.yaml for port ${PORTS[$i]}"
done

cat > crates/aggregator-server/aggregator-config-test.yaml <<EOF
network: ${NETWORK}
key_server_object_id: '${KEY_SERVER_OBJ_ID}'
EOF
echo "  Created aggregator-config-test.yaml"

echo "Config files created."
echo "Starting ${NUM_SERVERS} key servers..."

# Start all key servers
SERVER_PIDS=()
for i in "${!MEMBER_ADDRS[@]}"; do
  PORT="${PORTS[$i]}"

  env RUST_LOG=info \
    PORT="${PORT}" \
    CONFIG_PATH="crates/key-server/key-server-config-${i}.yaml" \
    "MASTER_SHARE_V${VERSION}=${MASTER_SHARES[$i]}" \
    cargo run --bin key-server 2>&1 | sed "s/^/[SERVER-${i}] /" &

  PID=$!
  SERVER_PIDS+=($PID)
  echo "Server ${i} started on http://localhost:${PORT} (PID: ${PID})"
done

# Start aggregator server on port 3000
RUST_LOG=info \
  PORT=3000 \
  CONFIG_PATH=crates/aggregator-server/aggregator-config-test.yaml \
  cargo run --bin aggregator-server 2>&1 | sed 's/^/[AGGREGATOR] /' &
PID_AGG=$!
echo "Aggregator started on http://localhost:3000 (PID: $PID_AGG)"

echo ""
echo "All servers started!"
for i in "${!MEMBER_ADDRS[@]}"; do
  echo "  - Key Server ${i}: http://localhost:${PORTS[$i]} (PID: ${SERVER_PIDS[$i]})"
done
echo "  - Aggregator:      http://localhost:3000 (PID: $PID_AGG)"
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

# Check all key servers
for i in "${!PORTS[@]}"; do
  check_health "${PORTS[$i]}" "Key Server ${i}" &
done

# Check aggregator
check_health 3000 "Aggregator" &

# Wait for all health checks to complete
wait

echo ""
echo "All servers are ready!"
echo ""
echo "To stop all servers, run:"
echo "  ./scripts/start-committee-servers.sh stop"
echo ""
echo "Or manually:"
ALL_PIDS="${SERVER_PIDS[@]} $PID_AGG"
echo "  kill $ALL_PIDS"
