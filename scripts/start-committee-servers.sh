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
  echo "  $0 0 0x0688650cf... \"0x1edd...:0x3a9a...:2024,0x3af3...:0x35a8...:2025,0x2237...:0x45b9...:2026\""
  echo ""
  echo "Default server ports:"
  echo "  Key Server 0: http://localhost:2024"
  echo "  Key Server 1: http://localhost:2025"
  echo "  Key Server 2: http://localhost:2026"
  echo "  Aggregator:   http://localhost:3000"
  exit 0
fi

# Check for stop command
if [[ "$1" == "stop" || "$1" == "--stop" ]]; then
  echo "Stopping all servers..."
  pkill -9 -f "key-server|aggregator-server" 2>/dev/null || true

  # Kill any processes on the ports we use
  for port in 2024 2025 2026 3000; do
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
for port in 2024 2025 2026 3000; do
  lsof -ti:$port | xargs kill -9 2>/dev/null || true
done
sleep 1
echo "Cleanup complete."
echo ""

# Parse arguments or use defaults
VERSION="${1:-0}"
KEY_SERVER_OBJ_ID="${2:-0xc8a3c59a48b6cce0c0f1b16f9ad1b9baada89202f7fda20876a1332a05016aa0}"
SERVER_LIST="${3:-0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d:0x3584544a57d15a1df016d94c366cb097c366a97ae2f72ecd20564c8c93dac609:2024,0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6:0x24af25480d76e19b26c27ec0a37f07dfda90fdf8b410eff14d52aac127ead94a:2025,0x223762117ab21a439f0f3f3b0577e838b8b26a37d9a1723a4be311243f4461b9:0x13d9f645c31c69185d6e243510915f27f1bb5276852ab1157a4f08f5bbfaec8b:2026}"
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

aggregator_version_requirement: '>=0.5.14'

metrics_host_port: ${METRICS_PORT}
EOF
  echo "  Created key-server-config-${i}.yaml for port ${PORTS[$i]}"
done

cat > crates/key-server/src/aggregator/aggregator-config-test.yaml <<EOF
network: !${NETWORK}
node_url: https://fullnode.testnet.sui.io:443
key_server_object_id: '${KEY_SERVER_OBJ_ID}'
ts_sdk_version_requirement: '>=0.4.5'

api_credentials:
  server1:
    api_key_name: examplename
    api_key: examplekey
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
  CONFIG_PATH=crates/key-server/src/aggregator/aggregator-config-test.yaml \
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
