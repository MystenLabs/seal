#!/usr/bin/env python
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
DKG scripts for both coordinator and member operations.

Coordinator usage:
    python dkg-scripts.py publish-and-init -c dkg.yaml
    python dkg-scripts.py check-committee -c dkg.yaml
    python dkg-scripts.py process-all-and-propose -c dkg.yaml -m ./dkg-messages
    python dkg-scripts.py init-rotation -c dkg.yaml

Member usage:
    python dkg-scripts.py genkey-and-register -c dkg.yaml -k ./dkg-state/dkg.key -u <my-server-url> -n <my-server-name>
    python dkg-scripts.py init-state -c dkg.yaml -k ./dkg-state/dkg.key -s ./dkg-state
    python dkg-scripts.py create-message -c dkg.yaml -k ./dkg-state/dkg.key -s ./dkg-state [--old-share <hex>]
    python dkg-scripts.py process-all-and-propose -c dkg.yaml -m ./dkg-messages
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml


def normalize_sui_address(value: Any) -> str:
    """Normalize a Sui address / object ID from YAML into a 0x-prefixed hex string."""
    if value is None:
        return None

    # PyYAML may parse `0x...` as int; convert back to 0xNN..NN (64 nybbles)
    if isinstance(value, int):
        return "0x" + format(value, "064x")

    # Already string: just return as-is (caller may ensure correct format)
    return str(value)


def normalize_sui_address_list(values: list[Any]) -> list[str]:
    """Normalize a list of Sui addresses / object IDs."""
    return [normalize_sui_address(v) for v in values]


def run_sui_command(args: list[str]) -> dict:
    """Run a sui CLI command and return parsed JSON output."""
    cmd = ["sui", "client", "--json"] + args
    print(f"Running: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"\nCommand failed with exit code {result.returncode}", file=sys.stderr)
        if result.stderr:
            print(f"stderr:\n{result.stderr}", file=sys.stderr)
        if result.stdout:
            print(f"stdout:\n{result.stdout}", file=sys.stderr)
        sys.exit(1)

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON output: {e}", file=sys.stderr)
        print(f"Output: {result.stdout}", file=sys.stderr)
        sys.exit(1)


def extract_published_package_id(output: dict) -> str:
    """Extract published package ID from sui publish output."""
    effects = output.get("effects", {})
    created = effects.get("created", [])

    for obj in created:
        owner = obj.get("owner", {})
        if owner == "Immutable":
            return obj["reference"]["objectId"]

    raise ValueError("Could not find published package ID in output")


def extract_object_id_by_type(output: dict, type_suffix: str) -> str:
    """Extract object ID by type suffix from sui call output."""
    effects = output.get("effects", {})
    created = effects.get("created", [])

    # Get object changes for type info
    object_changes = output.get("objectChanges", [])
    type_map = {}
    for change in object_changes:
        if change.get("type") == "created":
            obj_id = change.get("objectId")
            obj_type = change.get("objectType", "")
            type_map[obj_id] = obj_type

    for obj in created:
        obj_id = obj["reference"]["objectId"]
        obj_type = type_map.get(obj_id, "")
        if type_suffix in obj_type:
            return obj_id

    raise ValueError(f"Could not find object with type '{type_suffix}' in output")


def load_config(config_path: str) -> dict:
    """Load YAML configuration file."""
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
        print(f"Please create a config file or check the path.", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error: Invalid YAML in config file: {e}", file=sys.stderr)
        sys.exit(1)


def validate_required_fields(config: dict, required_fields: list[str], command_name: str, suggestion: str = None):
    """Validate that required fields exist in config with helpful error messages."""
    missing = [f for f in required_fields if not config.get(f)]
    if missing:
        print(f"\n[ERROR] Missing required fields for '{command_name}':", file=sys.stderr)
        for field in missing:
            print(f"  - {field}", file=sys.stderr)

        if suggestion:
            print(f"\nSuggestion: {suggestion}", file=sys.stderr)

        sys.exit(1)


def update_config_fields(config_path: str, updates: dict):
    """Update specific fields in YAML config without rewriting the entire file."""
    with open(config_path, "r") as f:
        content = f.read()

    # Define markers for where to insert specific fields
    # Maps field name -> marker regex to find insertion point
    field_markers = {
        # publish-and-init fields
        "COORDINATOR_ADDRESS": r"# AUTO-GENERATED by 'publish-and-init' script \(coordinator\)\n# ============================================================================\n",
        "COMMITTEE_PKG": r"# AUTO-GENERATED by 'publish-and-init' script \(coordinator\)\n# ============================================================================\n",
        "COMMITTEE_ID": r"# AUTO-GENERATED by 'publish-and-init' script \(coordinator\)\n# ============================================================================\n",
        # init-rotation fields
        "CURRENT_COMMITTEE_ID": r"# AUTO-GENERATED by 'init-rotation' script \(coordinator\)\n# ============================================================================\n",
        # member fields
        "MY_ADDRESS": r"# MEMBER SECTION - Added from provided arguments\n# ============================================================================\n",
        "MY_SERVER_URL": r"# MEMBER SECTION - Added from provided arguments\n# ============================================================================\n",
        "MY_SERVER_NAME": r"# MEMBER SECTION - Added from provided arguments\n# ============================================================================\n",
        "DKG_ENC_PK": r"# AUTO-GENERATED by 'genkey-and-register' script \(member\)\n# ============================================================================\n",
        "DKG_SIGNING_PK": r"# AUTO-GENERATED by 'genkey-and-register' script \(member\)\n# ============================================================================\n",
        # process-all-and-propose fields
        "KEY_SERVER_PK": r"# AUTO-GENERATED by 'process-all-and-propose' script\n# ============================================================================\n",
        "PARTIAL_PKS": r"# AUTO-GENERATED by 'process-all-and-propose' script\n# ============================================================================\n",
        "MASTER_SHARE": r"# AUTO-GENERATED by 'process-all-and-propose' script\n# ============================================================================\n",
    }

    for key, value in updates.items():
        # Match the key and replace its value, preserving formatting
        # For list fields (PARTIAL_PKS_VX), we need to match the entire list block
        if key.startswith('PARTIAL_PKS_V'):
            # Pattern to match: KEY:\n- item1\n- item2\n...
            # Match from the key line until we hit a non-list line or end
            pattern = rf'^{re.escape(key)}:(?:\n- .+)*'
            replacement = f'{key}: {value}'

            if re.search(rf'^{re.escape(key)}:', content, flags=re.MULTILINE):
                # Field exists, replace the entire block
                content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
            else:
                # Field doesn't exist, insert it
                base_key = key.rsplit('_V', 1)[0]
                marker = field_markers.get(base_key)

                if marker and re.search(marker, content):
                    # Insert after the marker
                    marker_match = re.search(marker, content)
                    insert_pos = marker_match.end()
                    content = content[:insert_pos] + f'{replacement}\n' + content[insert_pos:]
                else:
                    # No marker found, append at end
                    if not content.endswith('\n'):
                        content += '\n'
                    content += f'{replacement}\n'
        else:
            # Single-line field
            pattern = rf'^{re.escape(key)}:.*$'
            replacement = f'{key}: {value}'

            if re.search(pattern, content, flags=re.MULTILINE):
                # Field exists, update it
                content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
            else:
                # Field doesn't exist, need to insert it
                # For versioned fields like MASTER_SHARE_V1, use the base field marker
                base_key = key
                if re.match(r'^MASTER_SHARE_V\d+$', key):
                    base_key = key.rsplit('_V', 1)[0]

                # If CURRENT_COMMITTEE_ID exists in updates or already in file, we're in init-rotation context
                if key in ["COORDINATOR_ADDRESS", "COMMITTEE_PKG", "COMMITTEE_ID"] and ("CURRENT_COMMITTEE_ID" in updates or re.search(r'^CURRENT_COMMITTEE_ID:', content, flags=re.MULTILINE)):
                    marker = r"# AUTO-GENERATED by 'init-rotation' script \(coordinator\)\n# ============================================================================\n"
                else:
                    marker = field_markers.get(base_key)

                if marker and re.search(marker, content):
                    # Insert after the marker
                    marker_match = re.search(marker, content)
                    insert_pos = marker_match.end()
                    content = content[:insert_pos] + f'{replacement}\n' + content[insert_pos:]
                else:
                    # No marker found, append at end
                    if not content.endswith('\n'):
                        content += '\n'
                    content += f'{replacement}\n'

    with open(config_path, "w") as f:
        f.write(content)


def get_network_env(network: str) -> str:
    """Convert network config to sui env name."""
    if isinstance(network, dict):
        # Handle tagged enum like !Testnet
        return list(network.keys())[0].lower()
    return str(network).lower()


def switch_sui_context(network_env: str, address: str | None = None):
    """Switch sui client to the specified network and optionally address."""
    print(f"Switching to network: {network_env}")
    subprocess.run(["sui", "client", "switch", "--env", str(network_env)], check=True)

    if address is not None:
        addr_str = str(address)
        print(f"Switching to address: {addr_str}")
        subprocess.run(
            ["sui", "client", "switch", "--address", addr_str],
            check=True,
        )


def publish_and_init(config_path: str):
    """Publish committee package and initialize committee."""
    config = load_config(config_path)

    # Check if already initialized
    if config.get("COMMITTEE_PKG") and config.get("COMMITTEE_ID"):
        print("Committee already initialized:")
        print(f"  COMMITTEE_PKG: {normalize_sui_address(config.get('COMMITTEE_PKG'))}")
        print(f"  COMMITTEE_ID: {normalize_sui_address(config.get('COMMITTEE_ID'))}")
        print("\nSkipping publish and init. Remove these fields from config to reinitialize.")
        return

    network = config.get("NETWORK", "testnet")
    network_env = get_network_env(network)

    # Get coordinator address from sui client active-address
    print("\n=== Getting coordinator address from sui client ===")
    result = subprocess.run(
        ["sui", "client", "active-address"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Error: Failed to get active address from sui client", file=sys.stderr)
        sys.exit(1)

    coordinator_address = result.stdout.strip()
    if not coordinator_address:
        print("Error: sui client active-address returned empty result", file=sys.stderr)
        sys.exit(1)

    print(f"Using coordinator address: {coordinator_address}")

    # Normalize addresses from YAML
    members = normalize_sui_address_list(config.get("MEMBERS", []))
    threshold = config.get("THRESHOLD", 2)

    if not members:
        print("Error: MEMBERS list is empty", file=sys.stderr)
        sys.exit(1)

    if threshold <= 1:
        print(f"Error: THRESHOLD must be greater than 1, got {threshold}", file=sys.stderr)
        sys.exit(1)

    # Switch to correct network
    switch_sui_context(network_env)

    # Publish the package
    print("\nPublishing seal_committee package...")
    committee_path = (
        Path(__file__).parent.parent.parent.parent / "move" / "committee"
    )

    publish_output = run_sui_command(
        ["publish", str(committee_path)]
    )

    package_id = extract_published_package_id(publish_output)
    print(f"Published package: {package_id}")

    # Initialize the committee
    print("\nInitializing committee...")
    members_json = json.dumps(members)

    init_output = run_sui_command(
        [
            "call",
            "--package",
            package_id,
            "--module",
            "seal_committee",
            "--function",
            "init_committee",
            "--args",
            str(threshold),
            members_json,
        ]
    )

    committee_id = extract_object_id_by_type(init_output, "Committee")
    print(f"Created committee: {committee_id}")

    # Update config
    update_config_fields(
        config_path,
        {
            "COORDINATOR_ADDRESS": coordinator_address,
            "COMMITTEE_ID": committee_id,
            "COMMITTEE_PKG": package_id,
        },
    )

    print(f"\nUpdated {config_path} with:")
    print(f"  COORDINATOR_ADDRESS: {coordinator_address}")
    print(f"  COMMITTEE_PKG: {package_id}")
    print(f"  COMMITTEE_ID: {committee_id}")
    print("\nShare this file with committee members.")


def init_rotation(config_path: str):
    """Initialize committee rotation."""
    config = load_config(config_path)

    # Check if already initialized
    if config.get("COMMITTEE_ID"):
        print("Committee rotation already initialized:")
        print(f"  COMMITTEE_ID: {normalize_sui_address(config.get('COMMITTEE_ID'))}")
        print("\nSkipping init-rotation. Remove COMMITTEE_ID from config to re-initialize.")
        return

    network = config.get("NETWORK", "testnet")
    network_env = get_network_env(network)

    # Get coordinator address from sui client active-address
    print("\n=== Getting coordinator address from sui client ===")
    result = subprocess.run(
        ["sui", "client", "active-address"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Error: Failed to get active address from sui client", file=sys.stderr)
        sys.exit(1)

    coordinator_address = result.stdout.strip()
    if not coordinator_address:
        print("Error: sui client active-address returned empty result", file=sys.stderr)
        sys.exit(1)

    print(f"Using coordinator address: {coordinator_address}")

    key_server_obj_id = normalize_sui_address(config.get("KEY_SERVER_OBJ_ID"))
    members = normalize_sui_address_list(config.get("MEMBERS", []))
    threshold = config.get("THRESHOLD", 2)

    if not key_server_obj_id:
        print("Error: KEY_SERVER_OBJ_ID not found in config", file=sys.stderr)
        sys.exit(1)

    if not members:
        print("Error: MEMBERS list is empty", file=sys.stderr)
        sys.exit(1)

    if threshold <= 1:
        print(f"Error: THRESHOLD must be greater than 1, got {threshold}", file=sys.stderr)
        sys.exit(1)

    # Switch to correct network
    switch_sui_context(network_env)

    # Fetch key server object and get current committee ID from its owner field
    print(f"\nFetching key server object: {key_server_obj_id}...")
    key_server_obj = run_sui_command(["object", key_server_obj_id])
    owner_field = key_server_obj.get("owner", {})

    if not (isinstance(owner_field, dict) and "ObjectOwner" in owner_field):
        print("Error: Key server owner is not an object (expected Field wrapper)", file=sys.stderr)
        print(f"Owner field: {owner_field}", file=sys.stderr)
        sys.exit(1)

    field_wrapper_id = owner_field["ObjectOwner"]
    field_obj = run_sui_command(["object", field_wrapper_id])
    content = field_obj.get("content", {})
    fields = content.get("fields", {})
    name_obj = fields.get("name", {})
    name_fields = name_obj.get("fields", {})
    current_committee_id = name_fields.get("name")

    if not current_committee_id:
        print("Error: Could not extract committee ID from field wrapper", file=sys.stderr)
        print(f"Field object: {field_obj}", file=sys.stderr)
        sys.exit(1)

    print(f"\nCurrent committee ID: {current_committee_id}")

    # Fetch committee object to extract package ID from its type
    committee_obj = run_sui_command(["object", current_committee_id])
    committee_type = committee_obj.get("type", "")

    if not committee_type:
        print("Error: Could not extract type from committee object", file=sys.stderr)
        sys.exit(1)

    # Extract package ID from committee type (format: "package_id::module::Type")
    package_id = committee_type.split("::")[0]
    print(f"Committee package ID: {package_id}")

    # For init-rotation, update COORDINATOR_ADDRESS, COMMITTEE_PKG and CURRENT_COMMITTEE_ID under 'init-rotation' marker
    update_config_fields(
        config_path,
        {
            "COORDINATOR_ADDRESS": coordinator_address,
            "COMMITTEE_PKG": package_id,
            "CURRENT_COMMITTEE_ID": current_committee_id,
        },
    )
    print(f"  COORDINATOR_ADDRESS: {coordinator_address}")
    print(f"  COMMITTEE_PKG: {package_id}")
    print(f"  CURRENT_COMMITTEE_ID: {current_committee_id}")

    # Call init_rotation
    print("\nInitializing rotation...")
    members_json = json.dumps(members)

    rotation_output = run_sui_command(
        [
            "call",
            "--package",
            package_id,
            "--module",
            "seal_committee",
            "--function",
            "init_rotation",
            "--args",
            current_committee_id,
            str(threshold),
            members_json,
        ]
    )

    new_committee_id = extract_object_id_by_type(rotation_output, "Committee")
    print(f"Created new committee for rotation: {new_committee_id}")

    # Update config with new committee ID
    update_config_fields(
        config_path,
        {
            "COMMITTEE_ID": new_committee_id,
        },
    )

    print(f"\nUpdated {config_path} with:")
    print(f"  COMMITTEE_ID: {new_committee_id}")
    print("\nShare this file with committee members.")


def genkey_and_register(config_path: str, server_url: str, server_name: str, keys_file: str = "./dkg-state/dkg.key"):
    """Generate DKG keys and register onchain (member operation)."""
    config = load_config(config_path)

    # Check if already generated keys
    if config.get("DKG_ENC_PK") and config.get("DKG_SIGNING_PK"):
        print("Keys already generated:")
        print(f"  DKG_ENC_PK: {config.get('DKG_ENC_PK')}")
        print(f"  DKG_SIGNING_PK: {config.get('DKG_SIGNING_PK')}")
        print("\nSkipping key generation and registration.")
        print("WARNING: If these keys were already registered onchain, this operation cannot be redone.")
        print("Remove these fields from config only if you need to regenerate for a different committee.")
        return

    # Validate server_url and server_name are provided
    if not server_url or not server_url.strip():
        print("Error: Server URL is required and cannot be empty", file=sys.stderr)
        sys.exit(1)

    if not server_name or not server_name.strip():
        print("Error: Server name is required and cannot be empty", file=sys.stderr)
        sys.exit(1)

    print("\n=== Getting active address from sui client ===")
    result = subprocess.run(
        ["sui", "client", "active-address"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Error: Failed to get active address from sui client", file=sys.stderr)
        sys.exit(1)

    my_address = result.stdout.strip()
    if not my_address:
        print("Error: sui client active-address returned empty result", file=sys.stderr)
        sys.exit(1)

    print(f"Active address: {my_address}")
    print(f"Server URL: {server_url}")
    print(f"Server Name: {server_name}")

    # Update config file
    update_config_fields(
        config_path,
        {
            "MY_ADDRESS": my_address,
            "MY_SERVER_URL": server_url,
            "MY_SERVER_NAME": server_name,
        },
    )
    print(f"\n✓ Updated {config_path} with MY_ADDRESS, MY_SERVER_URL, and MY_SERVER_NAME")

    # Reload config
    config = load_config(config_path)

    # Validate required fields
    validate_required_fields(
        config,
        ["MY_ADDRESS", "MY_SERVER_URL", "MY_SERVER_NAME", "COMMITTEE_PKG", "COMMITTEE_ID", "NETWORK"],
        "genkey-and-register",
        "Make sure you have received the config file from the coordinator with COMMITTEE_PKG and COMMITTEE_ID, and provide --server-url and --server-name arguments."
    )

    # Normalize addresses from YAML
    my_address = normalize_sui_address(config["MY_ADDRESS"])
    my_server_url = config["MY_SERVER_URL"]
    my_server_name = config["MY_SERVER_NAME"]
    committee_pkg = normalize_sui_address(config["COMMITTEE_PKG"])
    committee_id = normalize_sui_address(config["COMMITTEE_ID"])
    network = config["NETWORK"]
    network_env = get_network_env(network)

    # Step 1: Generate keys using cargo
    print("\n=== Generating DKG keys ===")
    print(f"Running: cargo run --bin dkg-cli generate-keys --keys-file {keys_file}")
    result = subprocess.run([
        "cargo", "run", "--bin", "dkg-cli", "generate-keys",
        "--keys-file", keys_file
    ])
    if result.returncode != 0:
        sys.exit(1)

    # Step 2: Read generated keys
    key_file = Path(keys_file)
    if not key_file.exists():
        print(f"Error: Key file not found at {key_file}", file=sys.stderr)
        sys.exit(1)

    with open(key_file, "r") as f:
        keys = json.load(f)

    enc_pk = keys.get("enc_pk")
    signing_pk = keys.get("signing_pk")

    if not enc_pk or not signing_pk:
        print("Error: Failed to read enc_pk or signing_pk from key file", file=sys.stderr)
        sys.exit(1)

    print(f"Generated keys:")
    print(f"  DKG_ENC_PK: {enc_pk}")
    print(f"  DKG_SIGNING_PK: {signing_pk}")

    # Step 3: Update config with public keys
    print(f"\n=== Updating {config_path} ===")
    update_config_fields(
        config_path,
        {
            "DKG_ENC_PK": enc_pk,
            "DKG_SIGNING_PK": signing_pk,
        },
    )
    print("Config updated with DKG_ENC_PK and DKG_SIGNING_PK")

    # Step 4: Switch network and address
    print(f"\n=== Switching to network: {network_env} and address: {my_address} ===")
    switch_sui_context(network_env, my_address)

    # Step 5: Register onchain
    print(f"\n=== Registering onchain ===")
    subprocess.run([
        "sui", "client", "call",
        "--package", committee_pkg,
        "--module", "seal_committee",
        "--function", "register",
        "--args", committee_id, enc_pk, signing_pk, my_server_url, my_server_name
    ], check=True)

    print("\n[SUCCESS] Keys generated and registered onchain!")
    print(f"  Your address: {my_address}")
    print(f"  Server URL: {my_server_url}")
    print(f"  Server Name: {my_server_name}")
    print(f"  Committee ID: {committee_id}")
    print(f"\nIMPORTANT: Your private keys are stored in: {keys_file}")


def check_committee(config_path: str):
    """Check committee status and member registration (coordinator operation)."""
    config = load_config(config_path)

    # Validate required fields
    validate_required_fields(
        config,
        ["COMMITTEE_ID", "NETWORK"],
        "check-committee",
        "Make sure your config has COMMITTEE_ID and NETWORK."
    )

    # Normalize addresses from YAML
    committee_id = normalize_sui_address(config["COMMITTEE_ID"])
    network = config["NETWORK"]
    network_env = get_network_env(network)

    # Call the Rust CLI
    print(f"Checking committee status for {committee_id}...\n")
    subprocess.run([
        "cargo", "run", "--bin", "dkg-cli", "check-committee",
        "--committee-id", committee_id,
        "--network", network_env
    ], check=True)


def create_message(config_path: str, keys_file: str = "./dkg-state/dkg.key", state_dir: str = "./dkg-state", old_share: str = None):
    """Create DKG message for phase 2 (member operation)."""
    config = load_config(config_path)

    # Validate required fields
    validate_required_fields(
        config,
        ["MY_ADDRESS", "COMMITTEE_ID", "NETWORK"],
        "create-message",
        "Make sure your config has MY_ADDRESS, COMMITTEE_ID (from coordinator), and NETWORK."
    )

    # Normalize addresses from YAML
    my_address = normalize_sui_address(config["MY_ADDRESS"])
    committee_id = normalize_sui_address(config["COMMITTEE_ID"])
    network = config["NETWORK"]
    network_env = get_network_env(network)

    # Call the Rust CLI
    print(f"\n=== Creating DKG message ===")
    print(f"  My address: {my_address}")
    print(f"  Committee ID: {committee_id}")
    print(f"  Network: {network_env}")
    print(f"  Keys file: {keys_file}")
    print(f"  State directory: {state_dir}")
    if old_share:
        print(f"  Old share: {old_share} (rotation mode)")
    print()

    cmd = [
        "cargo", "run", "--bin", "dkg-cli", "create-message",
        "--my-address", my_address,
        "--committee-id", committee_id,
        "--network", network_env,
        "--keys-file", keys_file,
        "--state-dir", state_dir
    ]

    # Add old-share argument if present (for rotation)
    if old_share:
        cmd.extend(["--old-share", old_share])

    result = subprocess.run(cmd)

    if result.returncode != 0:
        sys.exit(1)


def process_all_and_propose(config_path: str, messages_dir: str, keys_file: str = "./dkg-state/dkg.key", state_dir: str = "./dkg-state"):
    """Process all DKG messages and propose committee onchain (coordinator operation)."""
    config = load_config(config_path)

    # Validate required fields
    validate_required_fields(
        config,
        ["COMMITTEE_PKG", "COMMITTEE_ID", "NETWORK", "MY_ADDRESS"],
        "process-all-and-propose",
        "Make sure your config has COMMITTEE_PKG, COMMITTEE_ID, MY_ADDRESS, and NETWORK."
    )

    # Normalize addresses from YAML
    committee_pkg = normalize_sui_address(config["COMMITTEE_PKG"])
    committee_id = normalize_sui_address(config["COMMITTEE_ID"])
    my_address = normalize_sui_address(config["MY_ADDRESS"])
    network = config["NETWORK"]
    network_env = get_network_env(network)

    # Check if this is a rotation (CURRENT_COMMITTEE_ID present)
    current_committee_id = config.get("CURRENT_COMMITTEE_ID")
    is_rotation = current_committee_id is not None
    if is_rotation:
        current_committee_id = normalize_sui_address(current_committee_id)

    # Step 1: Run process-all command
    print(f"\n=== Processing DKG messages ===")
    print(f"  Messages directory: {messages_dir}")
    print(f"  State directory: {state_dir}")
    print(f"  Keys file: {keys_file}\n")

    result = subprocess.run([
        "cargo", "run", "--bin", "dkg-cli", "process-all",
        "--messages-dir", messages_dir,
        "--state-dir", state_dir,
        "--keys-file", keys_file,
        "--network", network_env
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error processing messages: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    # Step 2: Parse the output (suppress verbose cargo output)
    output = result.stdout

    # Extract values from output
    key_server_pk = None
    partial_pks = []
    master_share = None
    committee_version = None

    for line in output.split('\n'):
        if line.startswith('KEY_SERVER_PK='):
            key_server_pk = line.split('=', 1)[1]
        elif line.startswith('PARTY_') and '_PARTIAL_PK=' in line:
            partial_pk = line.split('=', 1)[1]
            partial_pks.append(partial_pk)
        elif line.startswith('MASTER_SHARE_V'):
            master_share = line.split('=', 1)[1]
        elif line.startswith('COMMITTEE_VERSION='):
            committee_version = line.split('=', 1)[1]

    if not key_server_pk or not partial_pks or not master_share or not committee_version:
        print("Error: Failed to parse all required values from process-all output", file=sys.stderr)
        sys.exit(1)

    # Check if MASTER_SHARE_V{version} and PARTIAL_PKS_V{version} already exist
    master_share_key = f"MASTER_SHARE_V{committee_version}"
    partial_pks_key = f"PARTIAL_PKS_V{committee_version}"

    if config.get(master_share_key) and config.get(partial_pks_key):
        print(f"\n[WARNING] {master_share_key} and {partial_pks_key} already exist in config!", file=sys.stderr)
        print(f"[WARNING] Skipping processing and onchain proposal.", file=sys.stderr)
        print(f"[WARNING] To reprocess messages and propose onchain, remove {master_share_key} and {partial_pks_key} from the config file.", file=sys.stderr)
        return

    # Step 3: Append parsed values to config file
    print(f"\n=== Updating {config_path} ===")

    # Read content to check if marker exists
    with open(config_path, 'r') as f:
        content = f.read()

    marker = "# AUTO-GENERATED by 'process-all-and-propose' script"

    # Only append if marker doesn't exist
    if marker not in content:
        with open(config_path, 'a') as f:
            f.write("\n# ============================================================================\n")
            f.write("# AUTO-GENERATED by 'process-all-and-propose' script\n")
            f.write("# ============================================================================\n")

    # Now append the versioned fields using update_config_fields
    partial_pks_yaml = "\n".join([f"- '{pk}'" for pk in partial_pks])

    # For fresh DKG (v0), also write KEY_SERVER_PK
    # For rotation (v1+), KEY_SERVER_PK must match existing value from v0
    fields_to_update = {
        f"PARTIAL_PKS_V{committee_version}": f"\n{partial_pks_yaml}",
        f"MASTER_SHARE_V{committee_version}": f"'{master_share}'",
    }

    if committee_version == 0:
        # Fresh DKG - write KEY_SERVER_PK
        fields_to_update["KEY_SERVER_PK"] = f"'{key_server_pk}'"
    else:
        # Rotation - verify KEY_SERVER_PK matches existing value
        existing_key_server_pk = config.get("KEY_SERVER_PK")
        if existing_key_server_pk:
            # Normalize for comparison (strip quotes)
            existing_pk = existing_key_server_pk.strip("'\"")
            if existing_pk != key_server_pk:
                print(f"ERROR: KEY_SERVER_PK mismatch!", file=sys.stderr)
                print(f"  Expected (from v0): {existing_pk}", file=sys.stderr)
                print(f"  Got (from rotation): {key_server_pk}", file=sys.stderr)
                sys.exit(1)
            print(f"✓ KEY_SERVER_PK verification passed (unchanged from v0)")
        else:
            print(f"Warning: KEY_SERVER_PK not found in config, cannot verify", file=sys.stderr)

    update_config_fields(config_path, fields_to_update)

    print(f"✓ Config updated with:")
    if committee_version == 0:
        print(f"  KEY_SERVER_PK: {key_server_pk}")
    print(f"  PARTIAL_PKS_V{committee_version}: {len(partial_pks)} entries")
    print(f"  MASTER_SHARE_V{committee_version}: {master_share}")

    # Step 4: Switch network and address for propose
    print(f"\n=== Switching to network: {network_env} and address: {my_address} ===")
    switch_sui_context(network_env, my_address)

    # Step 5: Call propose function onchain
    if is_rotation:
        print(f"\n=== Proposing committee rotation onchain ===")
        print(f"  New Committee ID: {committee_id}")
        print(f"  Current Committee ID: {current_committee_id}")
    else:
        print(f"\n=== Proposing committee onchain ===")

    # Format partial PKs as vector: [0x..., 0x..., 0x...]
    partial_pks_arg = "[" + ", ".join(partial_pks) + "]"

    if is_rotation:
        # Use propose_for_rotation for key rotation
        subprocess.run([
            "sui", "client", "call",
            "--package", committee_pkg,
            "--module", "seal_committee",
            "--function", "propose_for_rotation",
            "--args", committee_id, partial_pks_arg, current_committee_id
        ], check=True)
    else:
        # Use propose for fresh DKG
        subprocess.run([
            "sui", "client", "call",
            "--package", committee_pkg,
            "--module", "seal_committee",
            "--function", "propose",
            "--args", committee_id, partial_pks_arg, key_server_pk
        ], check=True)

    print("\n✓ Successfully processed messages and proposed committee onchain!")
    print(f"  MASTER_SHARE_V{committee_version} can be found in {config_path} that will be used later to start the key server. Back it up securely and do not share it with anyone.")
    print(f"  Committee ID: {committee_id}")
    print(f"  Key Server PK: {key_server_pk}")
    print(f"  Partial PKs: {len(partial_pks)} entries")

def main():
    parser = argparse.ArgumentParser(description="DKG scripts for coordinator and member operations")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # publish-and-init command (coordinator)
    publish_parser = subparsers.add_parser(
        "publish-and-init",
        help="[Coordinator] Publish committee package and initialize committee",
    )
    publish_parser.add_argument(
        "--config",
        "-c",
        default="dkg.yaml",
        help="Path to configuration file (default: dkg.yaml)",
    )

    # init-rotation command (coordinator)
    rotation_parser = subparsers.add_parser(
        "init-rotation",
        help="[Coordinator] Initialize committee rotation",
    )
    rotation_parser.add_argument(
        "--config",
        "-c",
        default="dkg.yaml",
        help="Path to configuration file (default: dkg.yaml)",
    )

    # check-committee command (coordinator)
    check_parser = subparsers.add_parser(
        "check-committee",
        help="[Coordinator] Check committee status and member registration",
    )
    check_parser.add_argument(
        "--config",
        "-c",
        default="dkg.yaml",
        help="Path to configuration file (default: dkg.yaml)",
    )

    # genkey-and-register command (member)
    genkey_parser = subparsers.add_parser(
        "genkey-and-register",
        help="[Member] Generate DKG keys locally and register onchain",
    )
    genkey_parser.add_argument(
        "--config",
        "-c",
        default="dkg.yaml",
        help="Path to configuration file (default: dkg.yaml)",
    )
    genkey_parser.add_argument(
        "--keys-file",
        "-k",
        default="./dkg-state/dkg.key",
        help="Path to write keys file (default: ./dkg-state/dkg.key)",
    )
    genkey_parser.add_argument(
        "--server-url",
        "-u",
        required=True,
        help="Server URL to register",
    )
    genkey_parser.add_argument(
        "--server-name",
        "-n",
        required=True,
        help="Server name to register",
    )

    # init-state command (member) - alias for create-message without old-share
    init_state_parser = subparsers.add_parser(
        "init-state",
        help="[Member] Initialize DKG state and create message (for fresh DKG or new members in rotation)",
    )
    init_state_parser.add_argument(
        "--config",
        "-c",
        default="dkg.yaml",
        help="Path to configuration file (default: dkg.yaml)",
    )
    init_state_parser.add_argument(
        "--keys-file",
        "-k",
        default="./dkg-state/dkg.key",
        help="Path to keys file (default: ./dkg-state/dkg.key)",
    )
    init_state_parser.add_argument(
        "--state-dir",
        "-s",
        default="./dkg-state",
        help="State directory (default: ./dkg-state)",
    )

    # create-message command (member) - for both fresh DKG and rotation
    create_msg_parser = subparsers.add_parser(
        "create-message",
        help="[Member] Create DKG message (fresh DKG or rotation with --old-share)",
    )
    create_msg_parser.add_argument(
        "--config",
        "-c",
        default="dkg.yaml",
        help="Path to configuration file (default: dkg.yaml)",
    )
    create_msg_parser.add_argument(
        "--keys-file",
        "-k",
        default="./dkg-state/dkg.key",
        help="Path to keys file (default: ./dkg-state/dkg.key)",
    )
    create_msg_parser.add_argument(
        "--state-dir",
        "-s",
        default="./dkg-state",
        help="State directory (default: ./dkg-state)",
    )
    create_msg_parser.add_argument(
        "--old-share",
        required=False,
        default=None,
        help="Old master share for rotation (continuing members only). Omit for fresh DKG.",
    )

    # process-all-and-propose command (coordinator)
    process_parser = subparsers.add_parser(
        "process-all-and-propose",
        help="[Coordinator] Process all messages and propose committee onchain",
    )
    process_parser.add_argument(
        "--config",
        "-c",
        default="dkg.yaml",
        help="Path to configuration file (default: dkg.yaml)",
    )
    process_parser.add_argument(
        "--messages-dir",
        "-m",
        default="./dkg-messages",
        help="Directory containing message_*.json files (default: ./dkg-messages)",
    )
    process_parser.add_argument(
        "--keys-file",
        "-k",
        default="./dkg-state/dkg.key",
        help="Path to keys file (default: ./dkg-state/dkg.key)",
    )
    process_parser.add_argument(
        "--state-dir",
        "-s",
        default="./dkg-state",
        help="State directory (default: ./dkg-state)",
    )

    args = parser.parse_args()

    if args.command == "publish-and-init":
        publish_and_init(args.config)
    elif args.command == "init-rotation":
        init_rotation(args.config)
    elif args.command == "check-committee":
        check_committee(args.config)
    elif args.command == "genkey-and-register":
        genkey_and_register(args.config, args.server_url, args.server_name, args.keys_file)
    elif args.command == "init-state":
        # init-state is just create-message with no old share
        create_message(args.config, args.keys_file, args.state_dir, old_share=None)
    elif args.command == "create-message":
        create_message(args.config, args.keys_file, args.state_dir, args.old_share)
    elif args.command == "process-all-and-propose":
        process_all_and_propose(args.config, args.messages_dir, args.keys_file, args.state_dir)


if __name__ == "__main__":
    main()