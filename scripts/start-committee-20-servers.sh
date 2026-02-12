#!/bin/bash
# Script to start 20 committee key servers and 1 aggregator server
#
# Usage:
#   ./start-committee-20-servers.sh <version> <key_server_obj_id> <server_list>
#   ./start-committee-20-servers.sh stop
#
# Example:
#   ./start-committee-20-servers.sh 0 0x8a0e2e09a4c5255336d234b11014642b350634f07d07df6fc4c17bf07430c872 \
#     "0x0cef...:0x7239...:2024,0x15ef...:0x5ae8...:2025,..."

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
  echo "  status    Check status of all running servers"
  echo "  stop      Stop all running servers"
  echo "  help      Show this help message"
  echo ""
  echo "Parameters:"
  echo "  VERSION              Master share version (e.g., 0, 1, 2)"
  echo "  KEY_SERVER_OBJ_ID    Key server object ID (0x...)"
  echo "  SERVER_LIST          Comma-separated list: member_address:master_share:port"
  echo ""
  echo "Example:"
  echo "  $0 0 0x8a0e2e09a4c5255336d234b11014642b350634f07d07df6fc4c17bf07430c872 \\"
  echo "    \"0x0cef...:0x7239...:2024,0x15ef...:0x5ae8...:2025,0x271c...:0x4f6e...:2026\""
  echo ""
  echo "Default server ports:"
  echo "  Key Servers 0-19: http://localhost:2024-2043"
  echo "  Aggregator:       http://localhost:3000"
  exit 0
fi

# Check for status command
if [[ "$1" == "status" || "$1" == "--status" ]]; then
  echo "Checking server status..."
  echo ""

  # Check aggregator
  echo "=== Aggregator ==="
  AGGREGATOR_UP=false
  if curl -s -f http://localhost:3000/health > /dev/null 2>&1; then
    echo "✓ Aggregator (http://localhost:3000) - UP"
    AGGREGATOR_UP=true
  else
    echo "✗ Aggregator (http://localhost:3000) - DOWN"
  fi
  echo ""

  # Check all 20 key servers
  echo "=== Key Servers ==="
  UP_COUNT=0
  DOWN_COUNT=0

  for port in {2024..2043}; do
    i=$((port - 2024))
    if curl -s -f "http://localhost:${port}/health" > /dev/null 2>&1; then
      echo "✓ Server ${i} (http://localhost:${port}) - UP"
      ((UP_COUNT++))
    else
      echo "✗ Server ${i} (http://localhost:${port}) - DOWN"
      ((DOWN_COUNT++))
    fi
  done

  echo ""
  echo "=== Summary ==="
  TOTAL_UP=$UP_COUNT
  if [ "$AGGREGATOR_UP" = true ]; then
    ((TOTAL_UP++))
  fi
  echo "Total Servers UP: ${TOTAL_UP}/21 (1 Aggregator + 20 Key Servers)"
  echo "Key Servers UP: ${UP_COUNT}/20"
  echo "Key Servers DOWN: ${DOWN_COUNT}/20"

  if [ "$AGGREGATOR_UP" = true ] && [ $DOWN_COUNT -eq 0 ]; then
    echo "✓ All servers are running!"
    exit 0
  else
    echo "⚠ Some servers are not responding"
    exit 1
  fi
fi

# Check for stop command
if [[ "$1" == "stop" || "$1" == "--stop" ]]; then
  echo "Stopping all servers..."
  pkill -9 -f "key-server|aggregator-server" 2>/dev/null || true

  # Kill any processes on the ports we use
  for port in {2024..2043} 3000; do
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
for port in {2024..2043} 3000; do
  lsof -ti:$port | xargs kill -9 2>/dev/null || true
done
sleep 1
echo "Cleanup complete."
echo ""

# Parse arguments or use defaults from the 20/20 committee setup
VERSION="${1:-0}"
KEY_SERVER_OBJ_ID="${2:-0x8a0e2e09a4c5255336d234b11014642b350634f07d07df6fc4c17bf07430c872}"
SERVER_LIST="${3:-0x0ceffe3ba385abe7a11f535e3428ae2ff4508eb4b6d370b829318b0d901c1152:0x72392027c9c324a304cc35f13b6e2e66a6bc6f6bc9845fb78708745c584e5914:2024,0x15ef03731c612580a2c604696da996641d0426c80a202b92f97beb7e55ceccae:0x5ae82e12772fb102a0d6d91668a5799766093c40e9ba48493969330aa180fdb2:2025,0x271c3b8f29569652d20b9a18b1de628dae8bae43d46ba6c7b43968451710bae3:0x4f6ebd09abd1955e430d5aa6ab63437336a2672eabf4dff9ca98fe84808ce90c:2026,0x3c703fcef8a951d873e8347d1cdef0cd27e67323b6a1224f82d36d9ba2646269:0x67befc5bf47ce4765cdd4bc1045f9e1882e4078fdfaa02381c729e1c4d8077ff:2027,0x3fedeecd471d5bcba57eb542ed9dffe6556cb39ff2a96903d176343720271783:0x1ef21ba47fd1a8ba7852ee921d7af4c657b5e5ac4446ead4aa24e2e896106888:2028,0x46d8593c7f4e166c1eb9b8a710c573b6a4a68fc8336c5502a378491294b33d41:0x412e9d0de23a49d8afb3cfae02aac6f51abee9f5fd1e7d172f59b7d6a09e9563:2029,0x4c337121425049467206484b28986b9a2451b75367ed535a7685f047efb08888:0x696547a6e8e64fdd4b2d90360fad84d9bd07f3e5d8a2ef371e9a5f0aa74cb5df:2030,0x4cfc213c9d593493f207d085ae471b2a8f92e27338e5081bee72ec7d6d3f9a80:0x13e810a4d5679643e63a1c61ecba33734200790770bf332c6a5840200ac35bfd:2031,0x517024b07435eb2466d50226070af215932e6b7bc1d11f5f9a871835fa0f5404:0x63f17cccb11786a3be809c2a11c50b51cb06c2ac17134a97c898c5c6c738336c:2032,0x522c2901051b29dbe369fee0df577fb55bf23beb261d8c2c6ae9c032f778782d:0x6ae8460789371098a09af19c8477b8c5bcdf3edd8f4f0905048c48fa4259d8c1:2033,0x53dbf0f11dab2b549f41d22df1e1e627e5fb30c4fe8b38cf8edd0324738998b7:0x0eb1680f1e292b1542b1804e15bd79b5146d3e3f598f64f2922a734a88b87ffe:2034,0x58ced33704a6bf48c22782ef577c74234732c11e53a556e062feb6d79eff1b74:0x69e365cdda5361dd3fb591d9793564bd9d91f09e2c4bb13bff36fee0cb6c670d:2035,0x65db887e741dcc283bccf9ba2e0c9299703bc396126ba672ba5d7c19d0a26a2c:0x0051c865dc47fa9b25622e891c559db42d1645427a69e42858c309a0c444418f:2036,0x79a81c8f8838c0e52819445f2aeaf50be535f9eb62461aa5120b0d423e463b67:0x5e46729d754ffa07d3ddf3f3a73aee8083c0a819588e932391ca88d9a3ce3ce6:2037,0x7c92760e35a6019fd22d184f50a17cde561ec56975525e00f8765ddfa7f313d2:0x3efd8e29656e3a692af13635e90c634d402b398e685a5c785035e7751621b8af:2038,0x80495858eb94281f1f2c90536e2d77cc56e473d686ffe9c308b319a665288531:0x337b30b1688cecb48d6f4002a3e4077ff300ac2ebb3fbe7f61fc6f252b5e1c33:2039,0x979578f86bac45626ec7696054bf9a7505545d03f9d373671c2fcfdfd9da35b3:0x110111312248b4c0c796c523381fe1956e8aa382002c310c24ad1871a5530775:2040,0xa2aea96e9d16f026074456dee88a8b02bd68f2ce0d12997614424d6ecb8182ce:0x6c9b5a9555213cdef7ce74156bdc8b5f519597fa47b32535ea2f353cf5ef3c79:2041,0xaf31a3fbd658163f03741890b8ca1189b5c73e9ad8be9b95a0fe697f237062b2:0x480d2104b2cae45d84568f0ef688cf35bea3448291a2e233f6544449e954d89f:2042,0xc1ba9b2a4608c387a168610f586ccbe45e21aea2d614cc2f0263742dffe88089:0x5c385b07a73fca4812765fb09b42e32c5d56179d7fdd7efd98116050d2d0e869:2043}"
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
echo "  Committee ID: 0x289302c9f01a2a828947f1e27cd98438b8da9c9a5cced2a74c36057593d398b5"
echo ""

# Create config files
echo "Creating config files..."

for i in "${!MEMBER_ADDRS[@]}"; do
  METRICS_PORT=$((9184 + i))
  cat > crates/key-server/key-server-config-${i}.local.yaml <<EOF
network: ${NETWORK}

node_url: https://fullnode.testnet.sui.io:443

server_mode: !Committee
  member_address: '${MEMBER_ADDRS[$i]}'
  key_server_obj_id: '${KEY_SERVER_OBJ_ID}'
  committee_state: !Active

metrics_host_port: ${METRICS_PORT}
EOF
  echo "  Created key-server-config-${i}.local.yaml for port ${PORTS[$i]}"
done

cat > crates/key-server/src/aggregator/aggregator-config-test.local.yaml <<EOF
network: !${NETWORK}
node_url: https://fullnode.testnet.sui.io:443
key_server_object_id: '${KEY_SERVER_OBJ_ID}'

api_credentials:
  server-0:
    api_key_name: x-api-key
    api_key: dummy-key-0
  server-1:
    api_key_name: x-api-key
    api_key: dummy-key-1
  server-2:
    api_key_name: x-api-key
    api_key: dummy-key-2
  server-3:
    api_key_name: x-api-key
    api_key: dummy-key-3
  server-4:
    api_key_name: x-api-key
    api_key: dummy-key-4
  server-5:
    api_key_name: x-api-key
    api_key: dummy-key-5
  server-6:
    api_key_name: x-api-key
    api_key: dummy-key-6
  server-7:
    api_key_name: x-api-key
    api_key: dummy-key-7
  server-8:
    api_key_name: x-api-key
    api_key: dummy-key-8
  server-9:
    api_key_name: x-api-key
    api_key: dummy-key-9
  server-10:
    api_key_name: x-api-key
    api_key: dummy-key-10
  server-11:
    api_key_name: x-api-key
    api_key: dummy-key-11
  server-12:
    api_key_name: x-api-key
    api_key: dummy-key-12
  server-13:
    api_key_name: x-api-key
    api_key: dummy-key-13
  server-14:
    api_key_name: x-api-key
    api_key: dummy-key-14
  server-15:
    api_key_name: x-api-key
    api_key: dummy-key-15
  server-16:
    api_key_name: x-api-key
    api_key: dummy-key-16
  server-17:
    api_key_name: x-api-key
    api_key: dummy-key-17
  server-18:
    api_key_name: x-api-key
    api_key: dummy-key-18
  server-19:
    api_key_name: x-api-key
    api_key: dummy-key-19
EOF
echo "  Created aggregator-config-test.local.yaml"

echo "Config files created."
echo "Starting ${NUM_SERVERS} key servers..."

# Start all key servers
SERVER_PIDS=()
for i in "${!MEMBER_ADDRS[@]}"; do
  PORT="${PORTS[$i]}"

  env RUST_LOG=info \
    PORT="${PORT}" \
    CONFIG_PATH="crates/key-server/key-server-config-${i}.local.yaml" \
    "MASTER_SHARE_V${VERSION}=${MASTER_SHARES[$i]}" \
    ./target/release/key-server 2>&1 | sed "s/^/[SERVER-${i}] /" &

  PID=$!
  SERVER_PIDS+=($PID)
  echo "Server ${i} started on http://localhost:${PORT} (PID: ${PID})"
done

# Start aggregator server on port 3000
RUST_LOG=info \
  PORT=3000 \
  CONFIG_PATH=crates/key-server/src/aggregator/aggregator-config-test.local.yaml \
  ./target/release/aggregator-server 2>&1 | sed 's/^/[AGGREGATOR] /' &
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
echo "  ./scripts/start-committee-20-servers.sh stop"
echo ""
echo "Or manually:"
ALL_PIDS="${SERVER_PIDS[@]} $PID_AGG"
echo "  kill $ALL_PIDS"
