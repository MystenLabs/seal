#!/usr/bin/env python3
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
Upgrade CLI for Sui Move contract upgrades.

Usage:
    # Step 1: Compute package digest
    python upgrade-cli.py package-digest --package-path ./

    # Step 2: Vote for upgrade (each committee member)
    python upgrade-cli.py vote --package-path ./ --key-server-id <ID>

    # Step 3: Authorize upgrade (after quorum reached)
    python upgrade-cli.py authorize --package-path ./ --key-server-id <ID>

    # Step 4: Perform upgrade (using upgrade ticket)
    python upgrade-cli.py upgrade --upgrade-capability <ID> --upgrade-ticket <ID>

    # Step 5: Commit upgrade (finalize)
    python upgrade-cli.py commit --key-server-id <ID> --upgrade-receipt <ID>
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def fetch_ids_from_key_server(key_server_obj_id: str) -> dict:
    """Fetch committee_id, upgrade_manager_id, and package_id from key server object."""
    print(f"Fetching committee info from key server: {key_server_obj_id}...\n")

    # Fetch key server object
    result = subprocess.run(
        ["sui", "client", "--json", "object", key_server_obj_id],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"Error: Failed to fetch key server object", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)

    key_server_obj = json.loads(result.stdout)
    owner_field = key_server_obj.get("owner", {})

    # Extract committee ID from owner field
    if not (isinstance(owner_field, dict) and "ObjectOwner" in owner_field):
        print("Error: Key server owner is not an object (expected Field wrapper)", file=sys.stderr)
        sys.exit(1)

    field_wrapper_id = owner_field["ObjectOwner"]

    # Fetch field wrapper to get committee ID
    result = subprocess.run(
        ["sui", "client", "--json", "object", field_wrapper_id],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"Error: Failed to fetch field wrapper object", file=sys.stderr)
        sys.exit(1)

    field_obj = json.loads(result.stdout)
    content = field_obj.get("content", {})
    fields = content.get("fields", {})
    name_obj = fields.get("name", {})
    name_fields = name_obj.get("fields", {})
    committee_id = name_fields.get("name")

    if not committee_id:
        print("Error: Could not extract committee ID from field wrapper", file=sys.stderr)
        sys.exit(1)

    print(f"Found committee ID: {committee_id}")

    # Fetch committee object to get upgrade_manager_id and package_id
    result = subprocess.run(
        ["sui", "client", "--json", "object", committee_id],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"Error: Failed to fetch committee object", file=sys.stderr)
        sys.exit(1)

    committee_obj = json.loads(result.stdout)

    # Extract package ID from committee type
    committee_type = committee_obj.get("type", "")
    if not committee_type:
        print("Error: Could not extract type from committee object", file=sys.stderr)
        sys.exit(1)

    package_id = committee_type.split("::")[0]
    print(f"Found package ID: {package_id}")

    # Extract upgrade_manager_id from committee fields
    content = committee_obj.get("content", {})
    fields = content.get("fields", {})
    upgrade_manager_field = fields.get("upgrade_manager_id")

    if not upgrade_manager_field:
        print("Error: upgrade_manager_id not found in committee object", file=sys.stderr)
        print("Has the upgrade manager been created? Run publish-and-init to create it.", file=sys.stderr)
        sys.exit(1)

    # upgrade_manager_id is stored as Option<ID>, so it's a dict with "vec" key
    if isinstance(upgrade_manager_field, dict) and "vec" in upgrade_manager_field:
        upgrade_manager_vec = upgrade_manager_field["vec"]
        if len(upgrade_manager_vec) == 0:
            print("Error: upgrade_manager_id is None (not set)", file=sys.stderr)
            print("Has the upgrade manager been created? Run publish-and-init to create it.", file=sys.stderr)
            sys.exit(1)
        upgrade_manager_id = upgrade_manager_vec[0]
    else:
        print("Error: Unexpected format for upgrade_manager_id field", file=sys.stderr)
        sys.exit(1)

    print(f"Found upgrade manager ID: {upgrade_manager_id}\n")

    return {
        "committee_id": committee_id,
        "package_id": package_id,
        "upgrade_manager_id": upgrade_manager_id,
    }


def compute_package_digest(package_path: str):
    """Compute and display the package digest for a Sui Move package."""
    package_path = Path(package_path).resolve()

    if not package_path.exists():
        print(f"Error: Package path does not exist: {package_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Building package at: {package_path}")
    print()

    # Build the package with --dump-bytecode-as-base64 to get digest
    cmd = ["sui", "move", "build", "--dump-bytecode-as-base64"]
    result = subprocess.run(
        cmd,
        cwd=package_path,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"Error: Failed to build package", file=sys.stderr)
        if result.stderr:
            # Print build warnings/errors
            print(result.stderr, file=sys.stderr)
        sys.exit(1)

    # Find JSON start (skip build output like "INCLUDING DEPENDENCY...")
    stdout = result.stdout
    json_start = stdout.find('{')

    if json_start == -1:
        print(f"Error: Failed to find JSON in build output", file=sys.stderr)
        print(f"Output: {stdout}", file=sys.stderr)
        sys.exit(1)

    json_output = stdout[json_start:]

    try:
        data = json.loads(json_output)
        digest_bytes = bytes(data['digest'])

        # Verify it's 32 bytes (required by Sui)
        if len(digest_bytes) != 32:
            print(f"Error: Digest must be 32 bytes, got {len(digest_bytes)}", file=sys.stderr)
            sys.exit(1)

        print(f"Digest for package '{package_path.name}': 0x{digest_bytes.hex()}")

    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON output: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyError:
        print("Error: 'digest' field not found in build output", file=sys.stderr)
        sys.exit(1)


def get_package_digest_bytes(package_path: str) -> bytes:
    """Get package digest as bytes (for internal use)."""
    package_path = Path(package_path).resolve()

    cmd = ["sui", "move", "build", "--dump-bytecode-as-base64"]
    result = subprocess.run(
        cmd,
        cwd=package_path,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"Error: Failed to build package", file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        sys.exit(1)

    stdout = result.stdout
    json_start = stdout.find('{')

    if json_start == -1:
        print(f"Error: Failed to find JSON in build output", file=sys.stderr)
        sys.exit(1)

    try:
        data = json.loads(stdout[json_start:])
        digest_bytes = bytes(data['digest'])

        if len(digest_bytes) != 32:
            print(f"Error: Digest must be 32 bytes, got {len(digest_bytes)}", file=sys.stderr)
            sys.exit(1)

        return digest_bytes
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Error: Failed to parse digest from build output: {e}", file=sys.stderr)
        sys.exit(1)


def run_sui_call(package: str, module: str, function: str, args: list, gas_budget: int = 10000000):
    """Run a sui client call command."""
    cmd = [
        "sui", "client", "call",
        "--package", package,
        "--module", module,
        "--function", function,
        "--gas-budget", str(gas_budget)
    ]

    for arg in args:
        cmd.extend(["--args", str(arg)])

    print(f"Running: {' '.join(cmd)}\n")
    result = subprocess.run(cmd)

    if result.returncode != 0:
        print(f"\nCommand failed with exit code {result.returncode}", file=sys.stderr)
        sys.exit(1)


def vote_for_upgrade(package_path: str, key_server_obj_id: str):
    """Vote for an upgrade with the computed package digest."""
    # Fetch IDs from key server
    ids = fetch_ids_from_key_server(key_server_obj_id)

    print(f"Building package and computing digest...\n")
    digest_bytes = get_package_digest_bytes(package_path)
    digest_hex = "0x" + digest_bytes.hex()

    print(f"Package digest: {digest_hex}\n")
    print(f"Voting for upgrade...\n")

    run_sui_call(
        package=ids["package_id"],
        module="upgrade",
        function="vote_for_upgrade",
        args=[ids["upgrade_manager_id"], ids["committee_id"], digest_hex],
        gas_budget=10000000
    )

    print("\n✓ Vote recorded!")


def authorize_upgrade(package_path: str, key_server_obj_id: str):
    """Authorize an upgrade after quorum is reached."""
    # Fetch IDs from key server
    ids = fetch_ids_from_key_server(key_server_obj_id)

    print(f"Building package and computing digest...\n")
    digest_bytes = get_package_digest_bytes(package_path)
    digest_hex = "0x" + digest_bytes.hex()

    print(f"Package digest: {digest_hex}\n")
    print(f"Authorizing upgrade...\n")

    run_sui_call(
        package=ids["package_id"],
        module="upgrade",
        function="authorize_upgrade",
        args=[ids["upgrade_manager_id"], ids["committee_id"], digest_hex],
        gas_budget=10000000
    )

    print("\n✓ Upgrade authorized! Look for UpgradeTicket object ID in the output above.")


def perform_upgrade(upgrade_capability_id: str, upgrade_ticket_id: str, package_path: str):
    """Perform the package upgrade using the upgrade ticket."""
    print(f"Performing package upgrade...\n")

    cmd = [
        "sui", "client", "upgrade",
        "--upgrade-capability", upgrade_capability_id,
        "--upgrade-ticket", upgrade_ticket_id,
        "--gas-budget", "100000000",
        str(Path(package_path).resolve())
    ]

    print(f"Running: {' '.join(cmd)}\n")
    result = subprocess.run(cmd)

    if result.returncode != 0:
        print(f"\nCommand failed with exit code {result.returncode}", file=sys.stderr)
        sys.exit(1)

    print("\n✓ Upgrade performed! Look for UpgradeReceipt object ID in the output above.")


def commit_upgrade(key_server_obj_id: str, upgrade_receipt_id: str):
    """Commit the upgrade receipt to finalize the upgrade."""
    # Fetch IDs from key server
    ids = fetch_ids_from_key_server(key_server_obj_id)

    print(f"Committing upgrade...\n")

    run_sui_call(
        package=ids["package_id"],
        module="upgrade",
        function="commit_upgrade",
        args=[ids["upgrade_manager_id"], upgrade_receipt_id],
        gas_budget=10000000
    )

    print("\n✓ Upgrade committed! The upgrade process is complete.")


def main():
    parser = argparse.ArgumentParser(
        description="Upgrade CLI for Sui Move package operations"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # package-digest command
    digest_parser = subparsers.add_parser(
        "package-digest",
        help="Compute the package digest for upgrade voting"
    )
    digest_parser.add_argument(
        "--package-path",
        "-p",
        default=".",
        help="Path to the package directory (default: current directory)"
    )

    # vote command
    vote_parser = subparsers.add_parser(
        "vote",
        help="Vote for an upgrade (computes digest automatically)"
    )
    vote_parser.add_argument(
        "--package-path",
        "-p",
        default=".",
        help="Path to the package directory (default: current directory)"
    )
    vote_parser.add_argument(
        "--key-server-id",
        required=True,
        help="The key server object ID"
    )

    # authorize command
    authorize_parser = subparsers.add_parser(
        "authorize",
        help="Authorize an upgrade after quorum is reached"
    )
    authorize_parser.add_argument(
        "--package-path",
        "-p",
        default=".",
        help="Path to the package directory (default: current directory)"
    )
    authorize_parser.add_argument(
        "--key-server-id",
        required=True,
        help="The key server object ID"
    )

    # upgrade command
    upgrade_parser = subparsers.add_parser(
        "upgrade",
        help="Perform the package upgrade using the upgrade ticket"
    )
    upgrade_parser.add_argument(
        "--upgrade-capability",
        required=True,
        help="The upgrade capability object ID"
    )
    upgrade_parser.add_argument(
        "--upgrade-ticket",
        required=True,
        help="The upgrade ticket object ID (from authorize step)"
    )
    upgrade_parser.add_argument(
        "--package-path",
        "-p",
        default=".",
        help="Path to the package directory (default: current directory)"
    )

    # commit command
    commit_parser = subparsers.add_parser(
        "commit",
        help="Commit the upgrade receipt to finalize the upgrade"
    )
    commit_parser.add_argument(
        "--key-server-id",
        required=True,
        help="The key server object ID"
    )
    commit_parser.add_argument(
        "--upgrade-receipt",
        required=True,
        help="The upgrade receipt object ID (from upgrade step)"
    )

    args = parser.parse_args()

    if args.command == "package-digest":
        compute_package_digest(args.package_path)
    elif args.command == "vote":
        vote_for_upgrade(args.package_path, args.key_server_id)
    elif args.command == "authorize":
        authorize_upgrade(args.package_path, args.key_server_id)
    elif args.command == "upgrade":
        perform_upgrade(args.upgrade_capability, args.upgrade_ticket, args.package_path)
    elif args.command == "commit":
        commit_upgrade(args.key_server_id, args.upgrade_receipt)


if __name__ == "__main__":
    main()
