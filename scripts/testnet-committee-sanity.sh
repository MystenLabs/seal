#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

CLI=(cargo run --quiet --bin seal-committee-cli --)
STATE_ROOT="${STATE_ROOT:-testnet-committee-sanity-state}"
NETWORK="testnet"

ADDR0="${ADDR0:-0x00ba1ae103cf43b2017796914b20cfbed32fc78b43d506583cd2383af18ef739}"
ADDR1="${ADDR1:-0x393bddd124a05a95859579d635d46ef20e5be802362d5bbd86999e2c845bf153}"
ADDR2="${ADDR2:-0xb39cb0c9c979921bf1d63c3c6df20765b9c7c21b1ae9445ab42931f6e1b45c66}"
ADDR3="${ADDR3:-0xb44e7d66b338fbdf6c06f4d075c23869cd174e5ea6facb87248288daf192ed5f}"

if [[ -z "$STATE_ROOT" || "$STATE_ROOT" == "/" || "$STATE_ROOT" == "." ]]; then
    printf 'Refusing unsafe STATE_ROOT value: %s\n' "$STATE_ROOT" >&2
    exit 1
fi

log() {
    printf '\n== %s ==\n' "$*"
}

cleanup_state() {
    if [[ "${KEEP_STATE:-0}" == "1" ]]; then
        printf 'Keeping temporary state root: %s\n' "$STATE_ROOT"
        return 0
    fi
    rm -rf "$STATE_ROOT"
    printf 'Cleaned up %s\n' "$STATE_ROOT"
}

trap cleanup_state EXIT

run_unsigned_and_sign() {
    local label="$1"
    shift

    log "$label: build unsigned transaction"
    local output
    if ! output=$("${CLI[@]}" "$@" --unsigned 2>&1); then
        printf '%s\n' "$output"
        return 1
    fi
    printf '%s\n' "$output"

    local tx_bytes
    tx_bytes=$(printf '%s\n' "$output" | awk 'found { print; exit } /Unsigned transaction bytes/ { found=1 }')
    if [[ -z "$tx_bytes" ]]; then
        printf 'Could not find unsigned transaction bytes in command output for %s.\n' "$label" >&2
        return 1
    fi

    log "$label: sign-and-execute"
    "${CLI[@]}" sign-and-execute --tx-bytes "$tx_bytes"
}

yaml_scalar() {
    local file="$1"
    local key="$2"
    awk -v k="${key}:" '$1 == k { print $2; exit }' "$file"
}

require_yaml_scalar() {
    local file="$1"
    local key="$2"
    local value
    value=$(yaml_scalar "$file" "$key")
    if [[ -z "$value" ]]; then
        printf 'Missing %s in %s.\n' "$key" "$file" >&2
        return 1
    fi
    printf '%s\n' "$value"
}

extract_key_server_obj_id() {
    awk -F': ' '/KEY_SERVER_OBJ_ID:/ { print $2; exit } /Key Server Object ID:/ { print $2; exit }'
}

wait_for_key_server_obj_id() {
    local state_dir="$1"
    local key_server_obj_id=""
    local output

    for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
        output=$("${CLI[@]}" check-committee -s "$state_dir")
        printf '%s\n' "$output"
        key_server_obj_id=$(printf '%s\n' "$output" | extract_key_server_obj_id)
        if [[ -n "$key_server_obj_id" ]]; then
            printf '%s\n' "$key_server_obj_id"
            return 0
        fi
        sleep 5
    done

    printf 'Committee in %s did not expose KEY_SERVER_OBJ_ID after waiting.\n' "$state_dir" >&2
    return 1
}

write_fresh_config() {
    local file="$1"
    cat > "$file" <<EOF
init-params:
  NETWORK: Testnet
  THRESHOLD: 2
  MEMBERS:
    - ${ADDR0}
    - ${ADDR1}
    - ${ADDR2}
EOF
}

write_rotation_config() {
    local file="$1"
    local key_server_obj_id="$2"
    cat > "$file" <<EOF
init-params:
  NETWORK: Testnet
  THRESHOLD: 3
  MEMBERS:
    - ${ADDR1}
    - ${ADDR0}
    - ${ADDR2}
    - ${ADDR3}

init-rotation-params:
  KEY_SERVER_OBJ_ID: ${key_server_obj_id}
EOF
}

copy_config_to_members() {
    local source_config="$1"
    shift
    local dir
    for dir in "$@"; do
        mkdir -p "$dir"
        cp "$source_config" "$dir/dkg.yaml"
    done
}

copy_messages() {
    local messages_dir="$1"
    shift
    rm -rf "$messages_dir"
    mkdir -p "$messages_dir"
    local state_dir
    for state_dir in "$@"; do
        cp "$state_dir"/message_*.json "$messages_dir"/
    done
}

prepare_upgrade_package() {
    local package_dir="$1"
    local move_copy_dir
    move_copy_dir="$(dirname "$package_dir")"
    rm -rf "$move_copy_dir"
    mkdir -p "$move_copy_dir"
    cp -R move/. "$move_copy_dir"/

    cat >> "$package_dir/sources/committee.move" <<'EOF'

/// Testnet sanity marker used only from scripts/testnet-committee-sanity.sh.
public fun sanity_upgrade_marker(): u64 {
    42
}
EOF
}

log "Switch wallet env to testnet"
sui client switch --env testnet

log "Check wallet gas"
for address in "$ADDR0" "$ADDR1" "$ADDR2" "$ADDR3"; do
    "${CLI[@]}" --active-address "$address" gas
done

log "Reset local sanity state"
rm -rf "$STATE_ROOT"
mkdir -p "$STATE_ROOT"

fresh0="$STATE_ROOT/fresh-0"
fresh1="$STATE_ROOT/fresh-1"
fresh2="$STATE_ROOT/fresh-2"
mkdir -p "$fresh0" "$fresh1" "$fresh2"
write_fresh_config "$fresh0/dkg.yaml"

log "Fresh DKG: publish and initialize committee"
"${CLI[@]}" --active-address "$ADDR0" publish-and-init -s "$fresh0"
copy_config_to_members "$fresh0/dkg.yaml" "$fresh1" "$fresh2"
fresh_committee_id=$(require_yaml_scalar "$fresh0/dkg.yaml" "COMMITTEE_ID")
printf 'Fresh COMMITTEE_ID=%s\n' "$fresh_committee_id"

fresh_addresses=("$ADDR0" "$ADDR1" "$ADDR2")
fresh_dirs=("$fresh0" "$fresh1" "$fresh2")
fresh_urls=("http://localhost:4000" "http://localhost:4001" "http://localhost:4002")
fresh_names=("sanity-fresh-0" "sanity-fresh-1" "sanity-fresh-2")

for i in 0 1 2; do
    run_unsigned_and_sign \
        "Fresh DKG register member ${i}" \
        --active-address "${fresh_addresses[$i]}" \
        genkey-and-register \
        -s "${fresh_dirs[$i]}" \
        -u "${fresh_urls[$i]}" \
        -n "${fresh_names[$i]}"
done

log "Fresh DKG: check registration"
"${CLI[@]}" check-committee -s "$fresh0"

for i in 0 1 2; do
    log "Fresh DKG: create message member ${i}"
    "${CLI[@]}" --active-address "${fresh_addresses[$i]}" create-message -s "${fresh_dirs[$i]}"
done

fresh_messages="$STATE_ROOT/fresh-messages"
copy_messages "$fresh_messages" "$fresh0" "$fresh1" "$fresh2"

for i in 0 1 2; do
    run_unsigned_and_sign \
        "Fresh DKG propose member ${i}" \
        --active-address "${fresh_addresses[$i]}" \
        process-all-and-propose \
        -s "${fresh_dirs[$i]}" \
        -m "$fresh_messages"
done

log "Fresh DKG: wait for finalized key server"
fresh_check_output=$("${CLI[@]}" check-committee -s "$fresh0")
printf '%s\n' "$fresh_check_output"
fresh_key_server_obj_id=$(printf '%s\n' "$fresh_check_output" | extract_key_server_obj_id)
if [[ -z "$fresh_key_server_obj_id" ]]; then
    fresh_key_server_obj_id=$(wait_for_key_server_obj_id "$fresh0" | tail -n 1)
fi
printf 'Fresh KEY_SERVER_OBJ_ID=%s\n' "$fresh_key_server_obj_id"

share0=$(require_yaml_scalar "$fresh0/dkg.yaml" "MASTER_SHARE_V0")
share1=$(require_yaml_scalar "$fresh1/dkg.yaml" "MASTER_SHARE_V0")
share2=$(require_yaml_scalar "$fresh2/dkg.yaml" "MASTER_SHARE_V0")
printf 'Fresh MASTER_SHARE_V0 %s=%s\n' "$ADDR0" "$share0"
printf 'Fresh MASTER_SHARE_V0 %s=%s\n' "$ADDR1" "$share1"
printf 'Fresh MASTER_SHARE_V0 %s=%s\n' "$ADDR2" "$share2"

rot0="$STATE_ROOT/rotation-0"
rot1="$STATE_ROOT/rotation-1"
rot2="$STATE_ROOT/rotation-2"
rot3="$STATE_ROOT/rotation-3"
mkdir -p "$rot0" "$rot1" "$rot2" "$rot3"
write_rotation_config "$rot0/dkg.yaml" "$fresh_key_server_obj_id"

log "Rotation: initialize committee"
"${CLI[@]}" --active-address "$ADDR0" init-rotation -s "$rot0"
copy_config_to_members "$rot0/dkg.yaml" "$rot1" "$rot2" "$rot3"
rotation_committee_id=$(require_yaml_scalar "$rot0/dkg.yaml" "COMMITTEE_ID")
printf 'Rotation COMMITTEE_ID=%s\n' "$rotation_committee_id"

rotation_addresses=("$ADDR1" "$ADDR0" "$ADDR2" "$ADDR3")
rotation_dirs=("$rot0" "$rot1" "$rot2" "$rot3")
rotation_urls=("http://localhost:4100" "http://localhost:4101" "http://localhost:4102" "http://localhost:4103")
rotation_names=("sanity-rotation-0" "sanity-rotation-1" "sanity-rotation-2" "sanity-rotation-3")

for i in 0 1 2 3; do
    run_unsigned_and_sign \
        "Rotation register member ${i}" \
        --active-address "${rotation_addresses[$i]}" \
        genkey-and-register \
        -s "${rotation_dirs[$i]}" \
        -u "${rotation_urls[$i]}" \
        -n "${rotation_names[$i]}"
done

log "Rotation: check registration"
"${CLI[@]}" check-committee -s "$rot0"

log "Rotation: create continuing member messages"
"${CLI[@]}" --active-address "$ADDR1" create-message -s "$rot0" -o "$share1"
"${CLI[@]}" --active-address "$ADDR0" create-message -s "$rot1" -o "$share0"
"${CLI[@]}" --active-address "$ADDR2" create-message -s "$rot2" -o "$share2"

log "Rotation: initialize new member state"
"${CLI[@]}" --active-address "$ADDR3" init-state -s "$rot3"

rotation_messages="$STATE_ROOT/rotation-messages"
# The fresh committee threshold is 2, so rotation must process exactly two
# continuing-member messages even though all continuing members have local state.
copy_messages "$rotation_messages" "$rot0" "$rot1"

for i in 0 1 2 3; do
    run_unsigned_and_sign \
        "Rotation propose member ${i}" \
        --active-address "${rotation_addresses[$i]}" \
        process-all-and-propose \
        -s "${rotation_dirs[$i]}" \
        -m "$rotation_messages"
done

log "Rotation: wait for finalized key server"
rotation_check_output=$("${CLI[@]}" check-committee -s "$rot0")
printf '%s\n' "$rotation_check_output"
rotation_key_server_obj_id=$(printf '%s\n' "$rotation_check_output" | extract_key_server_obj_id)
if [[ -z "$rotation_key_server_obj_id" ]]; then
    rotation_key_server_obj_id=$(wait_for_key_server_obj_id "$rot0" | tail -n 1)
fi
printf 'Rotated KEY_SERVER_OBJ_ID=%s\n' "$rotation_key_server_obj_id"

rot_share1=$(require_yaml_scalar "$rot0/dkg.yaml" "MASTER_SHARE_V1")
rot_share0=$(require_yaml_scalar "$rot1/dkg.yaml" "MASTER_SHARE_V1")
rot_share2=$(require_yaml_scalar "$rot2/dkg.yaml" "MASTER_SHARE_V1")
rot_share3=$(require_yaml_scalar "$rot3/dkg.yaml" "MASTER_SHARE_V1")
printf 'Rotation MASTER_SHARE_V1 %s=%s\n' "$ADDR1" "$rot_share1"
printf 'Rotation MASTER_SHARE_V1 %s=%s\n' "$ADDR0" "$rot_share0"
printf 'Rotation MASTER_SHARE_V1 %s=%s\n' "$ADDR2" "$rot_share2"
printf 'Rotation MASTER_SHARE_V1 %s=%s\n' "$ADDR3" "$rot_share3"

upgrade_pkg="$STATE_ROOT/upgrade-move/committee"
prepare_upgrade_package "$upgrade_pkg"

log "Package upgrade: digest"
digest_output=$("${CLI[@]}" package-digest -p "$upgrade_pkg" -n "$NETWORK")
printf '%s\n' "$digest_output"
upgrade_digest=$(printf '%s\n' "$digest_output" | awk '/Digest for package/ { print $NF; exit }')
if [[ -z "$upgrade_digest" ]]; then
    printf 'Could not parse package digest from package-digest output.\n' >&2
    exit 1
fi
printf 'Upgrade package digest=%s\n' "$upgrade_digest"

run_unsigned_and_sign \
    "Package upgrade approve member 0" \
    --active-address "$ADDR1" \
    approve-upgrade \
    -p "$upgrade_pkg" \
    -k "$rotation_key_server_obj_id" \
    -n "$NETWORK"

run_unsigned_and_sign \
    "Package upgrade reject member 1" \
    --active-address "$ADDR0" \
    reject-upgrade \
    -k "$rotation_key_server_obj_id" \
    -n "$NETWORK"

run_unsigned_and_sign \
    "Package upgrade re-approve member 1" \
    --active-address "$ADDR0" \
    approve-upgrade \
    -p "$upgrade_pkg" \
    -k "$rotation_key_server_obj_id" \
    -n "$NETWORK"

run_unsigned_and_sign \
    "Package upgrade approve member 2" \
    --active-address "$ADDR2" \
    approve-upgrade \
    -p "$upgrade_pkg" \
    -k "$rotation_key_server_obj_id" \
    -n "$NETWORK"

log "Package upgrade: check proposal status"
"${CLI[@]}" check-key-server-status -k "$rotation_key_server_obj_id" -n "$NETWORK"

run_unsigned_and_sign \
    "Package upgrade authorize and execute" \
    --active-address "$ADDR0" \
    authorize-and-upgrade \
    -p "$upgrade_pkg" \
    -k "$rotation_key_server_obj_id" \
    -n "$NETWORK"

log "Package upgrade: final status"
"${CLI[@]}" check-key-server-status -k "$rotation_key_server_obj_id" -n "$NETWORK"

cat <<EOF

Sanity flow complete.

State root: ${STATE_ROOT}
Fresh committee object: ${fresh_committee_id}
Fresh key server object: ${fresh_key_server_obj_id}
Rotated committee object: ${rotation_committee_id}
Rotated key server object: ${rotation_key_server_obj_id}

Fresh shares:
  ${ADDR0} MASTER_SHARE_V0=${share0}
  ${ADDR1} MASTER_SHARE_V0=${share1}
  ${ADDR2} MASTER_SHARE_V0=${share2}

Rotation shares:
  ${ADDR1} MASTER_SHARE_V1=${rot_share1}
  ${ADDR0} MASTER_SHARE_V1=${rot_share0}
  ${ADDR2} MASTER_SHARE_V1=${rot_share2}
  ${ADDR3} MASTER_SHARE_V1=${rot_share3}

SUCCESS_PACKAGE_DIGEST=${upgrade_digest}
EOF

log "Cleanup local sanity state"
cleanup_state
trap - EXIT
