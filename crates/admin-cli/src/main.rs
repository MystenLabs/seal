// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Admin CLI for Sui Move contract upgrades.
//!
//!
//! Usage:
//!     # Compute package digest (optional, for verification)
//!     cargo run -p admin-cli -- package-digest \
//!       --package-path ./move/committee \
//!       --network <NETWORK>
//!
//!     # Vote for upgrade (each committee member)
//!     cargo run -p admin-cli -- vote \
//!       --package-path ./move/committee \
//!       --key-server-id <ID> \
//!       --network <NETWORK>
//!
//!     # Authorize and upgrade (after quorum reached)
//!     cargo run -p admin-cli -- authorize-and-upgrade \
//!       --package-path ./move/committee \
//!       --key-server-id <ID> \
//!       --network <NETWORK>
//!
//!     # Reset proposal (if threshold not reached)
//!     cargo run -p admin-cli -- reset-proposal \
//!       --key-server-id <ID> \
//!       --network <NETWORK>
//!
//!     # View committee information and proposal status
//!     cargo run -p admin-cli -- get-key-server \
//!       --key-server-id <ID> \
//!       --network <NETWORK>

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use move_package_alt_compilation::build_config::BuildConfig as MoveBuildConfig;
use seal_committee::{create_grpc_client, fetch_committee_by_key_server, Network};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use sui_move_build::BuildConfig;
use sui_package_alt::{mainnet_environment, testnet_environment};
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_sdk::{rpc_types::SuiTransactionBlockEffectsAPI, wallet_context::WalletContext};
use sui_sdk_types::Address;
use sui_types::{
    base_types::{ObjectID, SuiAddress},
    object::Owner,
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::TransactionData,
    Identifier,
};

#[derive(Parser)]
#[command(name = "admin-cli")]
#[command(about = "Admin CLI for Sui Move package operations", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to Sui wallet config (default: ~/.sui/sui_config/client.yaml)
    #[arg(long, global = true)]
    wallet: Option<PathBuf>,

    /// Override the active address from the wallet config
    #[arg(long, global = true)]
    active_address: Option<SuiAddress>,
}

#[derive(Subcommand)]
enum Commands {
    /// Compute the package digest for upgrade voting
    PackageDigest {
        /// Path to the package directory
        #[arg(short, long, default_value = ".")]
        package_path: PathBuf,
        /// Network (mainnet or testnet)
        #[arg(long, required = true)]
        network: Network,
    },
    /// Vote for an upgrade (computes digest automatically)
    Vote {
        /// Path to the package directory
        #[arg(short, long, default_value = ".")]
        package_path: PathBuf,
        /// The key server object ID
        #[arg(long, required = true)]
        key_server_id: Address,
        /// Network (mainnet or testnet)
        #[arg(long, required = true)]
        network: Network,
        /// Gas budget in MIST
        #[arg(long, default_value = "10000000")]
        gas_budget: u64,
    },
    /// Authorize and upgrade the package after quorum is reached (performs authorize + upgrade + commit)
    AuthorizeAndUpgrade {
        /// Path to the package directory
        #[arg(short, long, default_value = ".")]
        package_path: PathBuf,
        /// The key server object ID
        #[arg(long, required = true)]
        key_server_id: Address,
        /// Network (mainnet or testnet)
        #[arg(long, required = true)]
        network: Network,
        /// Gas budget in MIST
        #[arg(long, default_value = "50000000")]
        gas_budget: u64,
    },
    /// Reset the current upgrade proposal if it hasn't reached threshold
    ResetProposal {
        /// The key server object ID
        #[arg(long, required = true)]
        key_server_id: Address,
        /// Network (mainnet or testnet)
        #[arg(long, required = true)]
        network: Network,
        /// Gas budget in MIST
        #[arg(long, default_value = "10000000")]
        gas_budget: u64,
    },
    /// Get and display committee information and proposal status from key server
    GetKeyServer {
        /// The key server object ID
        #[arg(long, required = true)]
        key_server_id: Address,
        /// Network (mainnet or testnet)
        #[arg(long, required = true)]
        network: Network,
    },
}

struct UpgradeParams {
    committee_id: ObjectID,
    package_id: ObjectID,
    upgrade_manager_id: ObjectID,
}

/// Create a BuildConfig for package compilation.
fn create_build_config(network: &Network) -> BuildConfig {
    let move_build_config = MoveBuildConfig {
        root_as_zero: true,
        ..Default::default()
    };

    let environment = match network {
        Network::Testnet => testnet_environment(),
        Network::Mainnet => mainnet_environment(),
    };

    BuildConfig {
        config: move_build_config,
        run_bytecode_verifier: true,
        print_diags_to_stderr: true,
        environment,
    }
}

/// Load wallet context from path.
fn load_wallet(
    wallet_path: Option<PathBuf>,
    active_address: Option<SuiAddress>,
) -> Result<WalletContext> {
    let config_path = wallet_path
        .or_else(|| {
            let mut default = dirs::home_dir()?;
            default.extend([".sui", "sui_config", "client.yaml"]);
            Some(default)
        })
        .ok_or_else(|| anyhow!("Cannot find wallet config path"))?;

    let mut wallet = WalletContext::new(&config_path).context("Failed to load wallet context")?;

    // Override active address if specified.
    if let Some(addr) = active_address {
        wallet.config.active_address = Some(addr);
    }

    Ok(wallet)
}

/// Fetch committee_id, package_id, and upgrade_manager_id from key server object.
async fn fetch_ids_from_key_server(
    key_server_id: &Address,
    network: &Network,
) -> Result<UpgradeParams> {
    println!("Fetching committee info from key server: {}", key_server_id);

    let mut grpc_client = create_grpc_client(network)?;
    let (committee_id, committee) =
        fetch_committee_by_key_server(&mut grpc_client, key_server_id).await?;

    println!("Found committee ID: {}", committee_id);

    // Extract package ID from committee object type.
    let mut ledger_client = grpc_client.ledger_client();
    let mut request = GetObjectRequest::default();
    request.object_id = Some(committee_id.to_string());
    request.read_mask = Some(prost_types::FieldMask {
        paths: vec!["object_type".to_string()],
    });

    let response = ledger_client
        .get_object(request)
        .await
        .map(|r| r.into_inner())?;

    let obj_type_str = response
        .object
        .as_ref()
        .and_then(|obj| obj.object_type.as_ref())
        .ok_or_else(|| anyhow!("Could not get committee object type"))?;

    let package_id_str = obj_type_str
        .split("::")
        .next()
        .ok_or_else(|| anyhow!("Invalid committee type format"))?;

    let package_id =
        Address::from_str(package_id_str).map_err(|_| anyhow!("Invalid package ID format"))?;
    println!("Found package ID: {}", package_id);

    // Extract upgrade_manager_id from committee state.
    let upgrade_manager_id = committee
        .upgrade_manager_id
        .ok_or_else(|| anyhow!("upgrade_manager_id not found"))?;

    println!("Found upgrade manager ID: {}\n", upgrade_manager_id);

    Ok(UpgradeParams {
        committee_id: ObjectID::new(committee_id.into_inner()),
        package_id: ObjectID::new(package_id.into_inner()),
        upgrade_manager_id: ObjectID::new(upgrade_manager_id.into_inner()),
    })
}

/// Compute package digest as bytes
fn get_package_digest_bytes(package_path: &Path, network: &Network) -> Result<Vec<u8>> {
    let build_config = create_build_config(network);
    let compiled_package = build_config
        .build(&package_path.canonicalize()?)
        .context("Failed to build package")?;

    let digest = compiled_package.get_package_digest(/* with_unpublished_deps */ false);
    Ok(digest.to_vec())
}

/// Compute and display the package digest
fn compute_package_digest(package_path: &Path, network: &Network) -> Result<()> {
    println!("Building package at: {}", package_path.display());
    println!();

    let digest_bytes = get_package_digest_bytes(package_path, network)?;
    println!(
        "Digest for package '{}': 0x{}",
        package_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy(),
        hex::encode(digest_bytes)
    );

    Ok(())
}

/// Execute a programmable transaction
async fn execute_transaction(
    wallet: &mut WalletContext,
    pt_builder: ProgrammableTransactionBuilder,
    gas_budget: u64,
) -> Result<()> {
    let sender = wallet.active_address()?;
    let client = wallet.get_client().await?;

    let pt = pt_builder.finish();

    // Get gas price
    let gas_price = client.read_api().get_reference_gas_price().await?;

    // Get gas coin
    let gas_coin = wallet
        .gas_for_owner_budget(sender, gas_budget, Default::default())
        .await?
        .1;

    // Build transaction data
    let tx_data = TransactionData::new_programmable(
        sender,
        vec![gas_coin.object_ref()],
        pt,
        gas_budget,
        gas_price,
    );

    // Sign transaction
    let transaction = wallet.sign_transaction(&tx_data).await;

    // Execute transaction
    println!("\nExecuting transaction...");
    let response = wallet.execute_transaction_may_fail(transaction).await?;

    // Check execution status
    if let Some(effects) = &response.effects {
        match &effects.status() {
            sui_sdk::rpc_types::SuiExecutionStatus::Success => {
                println!("\n✓ Transaction succeeded!");
                println!("Transaction digest: {}", response.digest);
            }
            sui_sdk::rpc_types::SuiExecutionStatus::Failure { error } => {
                return Err(anyhow!("Transaction failed: {}", error));
            }
        }
    }

    // Print created objects (for upgrade ticket/receipt)
    if let Some(effects) = &response.effects {
        let created = effects.created();
        if !created.is_empty() {
            println!("\nCreated objects:");
            for obj_ref in created {
                println!("  {}", obj_ref.reference.object_id);
            }
        }
    }

    Ok(())
}

/// Helper function to fetch upgrade manager and committee objects
async fn fetch_upgrade_objects(
    wallet: &mut WalletContext,
    ids: &UpgradeParams,
) -> Result<(
    sui_sdk::rpc_types::SuiObjectData,
    sui_sdk::rpc_types::SuiObjectData,
)> {
    let client = wallet.get_client().await?;
    let upgrade_manager_obj = client
        .read_api()
        .get_object_with_options(
            ids.upgrade_manager_id,
            sui_sdk::rpc_types::SuiObjectDataOptions::default().with_owner(),
        )
        .await?
        .data
        .ok_or_else(|| anyhow!("Upgrade manager object not found"))?;

    let committee_obj = client
        .read_api()
        .get_object_with_options(
            ids.committee_id,
            sui_sdk::rpc_types::SuiObjectDataOptions::default().with_owner(),
        )
        .await?
        .data
        .ok_or_else(|| anyhow!("Committee object not found"))?;

    Ok((upgrade_manager_obj, committee_obj))
}

/// Helper function to add upgrade manager object to programmable transaction
async fn add_upgrade_manager_arg(
    pt_builder: &mut ProgrammableTransactionBuilder,
    upgrade_manager_obj: &sui_sdk::rpc_types::SuiObjectData,
    upgrade_manager_id: ObjectID,
    wallet: &mut WalletContext,
) -> Result<sui_types::transaction::Argument> {
    match &upgrade_manager_obj.owner {
        Some(Owner::Shared {
            initial_shared_version,
        }) => pt_builder.obj(sui_types::transaction::ObjectArg::SharedObject {
            id: upgrade_manager_id,
            initial_shared_version: *initial_shared_version,
            mutability: sui_types::transaction::SharedObjectMutability::Mutable,
        }),
        _ => {
            let obj_ref = wallet.get_object_ref(upgrade_manager_id).await?;
            pt_builder.obj(sui_types::transaction::ObjectArg::ImmOrOwnedObject(obj_ref))
        }
    }
}

/// Helper function to add committee object to programmable transaction
async fn add_committee_arg(
    pt_builder: &mut ProgrammableTransactionBuilder,
    committee_obj: &sui_sdk::rpc_types::SuiObjectData,
    committee_id: ObjectID,
    wallet: &mut WalletContext,
) -> Result<sui_types::transaction::Argument> {
    match &committee_obj.owner {
        Some(Owner::Shared {
            initial_shared_version,
        }) => pt_builder.obj(sui_types::transaction::ObjectArg::SharedObject {
            id: committee_id,
            initial_shared_version: *initial_shared_version,
            mutability: sui_types::transaction::SharedObjectMutability::Immutable,
        }),
        _ => {
            let committee_ref = wallet.get_object_ref(committee_id).await?;
            pt_builder.obj(sui_types::transaction::ObjectArg::ImmOrOwnedObject(
                committee_ref,
            ))
        }
    }
}

/// Vote for an upgrade with the computed package digest
async fn vote_for_upgrade(
    package_path: &Path,
    key_server_addr: &Address,
    network: &Network,
    wallet: &mut WalletContext,
    gas_budget: u64,
) -> Result<()> {
    let ids = fetch_ids_from_key_server(key_server_addr, network).await?;

    println!("Building package and computing digest...\n");
    let digest_bytes = get_package_digest_bytes(package_path, network)?;
    let digest_hex = format!("0x{}", hex::encode(&digest_bytes));

    println!("Package digest: {}\n", digest_hex);
    println!("Voting for upgrade...\n");

    let sender = wallet.active_address()?;
    println!(
        "Calling {}::upgrade::vote_for_upgrade with sender {}",
        ids.package_id, sender
    );

    // Fetch full objects to check ownership
    let (upgrade_manager_obj, committee_obj) = fetch_upgrade_objects(wallet, &ids).await?;

    // Build programmable transaction
    let mut pt_builder = ProgrammableTransactionBuilder::new();

    // Add objects to transaction
    let upgrade_manager_arg = add_upgrade_manager_arg(
        &mut pt_builder,
        &upgrade_manager_obj,
        ids.upgrade_manager_id,
        wallet,
    )
    .await?;
    let committee_arg =
        add_committee_arg(&mut pt_builder, &committee_obj, ids.committee_id, wallet).await?;
    let digest_arg = pt_builder.pure(digest_bytes)?;

    pt_builder.programmable_move_call(
        ids.package_id,
        Identifier::from_str("upgrade")?,
        Identifier::from_str("vote_for_upgrade")?,
        vec![],
        vec![upgrade_manager_arg, committee_arg, digest_arg],
    );

    execute_transaction(wallet, pt_builder, gas_budget).await?;

    println!("\n✓ Vote recorded!");
    Ok(())
}

/// Authorize and upgrade the package after quorum is reached
async fn authorize_and_upgrade(
    package_path: &Path,
    key_server_addr: &Address,
    network: &Network,
    wallet: &mut WalletContext,
    gas_budget: u64,
) -> Result<()> {
    let ids = fetch_ids_from_key_server(key_server_addr, network).await?;
    let upgrade_manager_id = ids.upgrade_manager_id;
    let package_id = ids.package_id;

    println!("Building package and computing digest...\n");
    let digest_bytes = get_package_digest_bytes(package_path, network)?;
    let digest_hex = format!("0x{}", hex::encode(&digest_bytes));

    println!("Package digest: {}\n", digest_hex);
    println!("Authorizing upgrade...\n");

    let sender = wallet.active_address()?;
    println!(
        "Calling {}::upgrade::authorize_upgrade with sender {}",
        package_id, sender
    );

    // Fetch full objects to check ownership
    let (upgrade_manager_obj, committee_obj) = fetch_upgrade_objects(wallet, &ids).await?;
    // Build programmable transaction
    let mut pt_builder = ProgrammableTransactionBuilder::new();

    // Add objects to transaction
    let upgrade_manager_arg = add_upgrade_manager_arg(
        &mut pt_builder,
        &upgrade_manager_obj,
        upgrade_manager_id,
        wallet,
    )
    .await?;
    let committee_arg =
        add_committee_arg(&mut pt_builder, &committee_obj, ids.committee_id, wallet).await?;
    let digest_arg = pt_builder.pure(digest_bytes)?;

    // Call authorize_upgrade which returns an UpgradeTicket
    let upgrade_ticket = pt_builder.programmable_move_call(
        package_id,
        Identifier::from_str("upgrade")?,
        Identifier::from_str("authorize_upgrade")?,
        vec![],
        vec![upgrade_manager_arg, committee_arg, digest_arg],
    );

    // Build the package to get compiled modules
    println!("Building package for upgrade...\n");

    // Use build config that preserves published dependency addresses
    let build_config = create_build_config(network);
    let compiled_package = build_config
        .build(&package_path.canonicalize()?)
        .context("Failed to build package")?;

    // Get compiled modules
    let modules = compiled_package.get_package_bytes(false);

    // Get dependency IDs
    let dependencies: Vec<ObjectID> = compiled_package
        .dependency_ids
        .published
        .into_values()
        .collect();

    // Perform the upgrade with the ticket
    let upgrade_receipt = pt_builder.upgrade(ids.package_id, upgrade_ticket, dependencies, modules);

    // Commit the upgrade with the receipt
    let upgrade_manager_arg_2 = add_upgrade_manager_arg(
        &mut pt_builder,
        &upgrade_manager_obj,
        ids.upgrade_manager_id,
        wallet,
    )
    .await?;

    pt_builder.programmable_move_call(
        ids.package_id,
        Identifier::from_str("upgrade")?,
        Identifier::from_str("commit_upgrade")?,
        vec![],
        vec![upgrade_manager_arg_2, upgrade_receipt],
    );

    println!("Executing authorize + upgrade + commit in one ptb...\n");
    execute_transaction(wallet, pt_builder, gas_budget).await?;

    println!("\n✓ Upgrade complete! Package has been authorized, upgraded, and committed.");
    Ok(())
}

/// Reset the current upgrade proposal
async fn reset_proposal(
    key_server_addr: &Address,
    network: &Network,
    wallet: &mut WalletContext,
    gas_budget: u64,
) -> Result<()> {
    let ids = fetch_ids_from_key_server(key_server_addr, network).await?;

    println!("Resetting upgrade proposal...\n");

    let sender = wallet.active_address()?;
    println!(
        "Calling {}::upgrade::reset_proposal with sender {}",
        ids.package_id, sender
    );

    // Fetch full objects to check ownership
    let (upgrade_manager_obj, committee_obj) = fetch_upgrade_objects(wallet, &ids).await?;

    // Build programmable transaction
    let mut pt_builder = ProgrammableTransactionBuilder::new();

    // Add objects to transaction
    let upgrade_manager_arg = add_upgrade_manager_arg(
        &mut pt_builder,
        &upgrade_manager_obj,
        ids.upgrade_manager_id,
        wallet,
    )
    .await?;
    let committee_arg =
        add_committee_arg(&mut pt_builder, &committee_obj, ids.committee_id, wallet).await?;

    pt_builder.programmable_move_call(
        ids.package_id,
        Identifier::from_str("upgrade")?,
        Identifier::from_str("reset_proposal")?,
        vec![],
        vec![upgrade_manager_arg, committee_arg],
    );

    execute_transaction(wallet, pt_builder, gas_budget).await?;

    println!("\n✓ Proposal reset! You can now vote again.");
    Ok(())
}

/// Get and display committee information from key server
async fn get_key_server_info(key_server_addr: &Address, network: &Network) -> Result<()> {
    let ids = fetch_ids_from_key_server(key_server_addr, network).await?;

    // Fetch committee data
    let mut grpc_client = create_grpc_client(network)?;
    let (committee_addr, committee) =
        fetch_committee_by_key_server(&mut grpc_client, key_server_addr).await?;

    println!("\n=== Committee Information ===");
    println!("Committee ID:       {}", committee_addr);
    println!("Package ID:         {}", ids.package_id);
    println!("Upgrade Manager ID: {}", ids.upgrade_manager_id);
    println!("Total members:      {}", committee.members.len());
    println!("Threshold:          {}", committee.threshold);
    println!("State:              {:?}", committee.state);

    println!("\n=== Committee Members ===");
    for (idx, member) in committee.members.iter().enumerate() {
        println!("  {}. {}", idx + 1, member);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut wallet = load_wallet(cli.wallet, cli.active_address)?;

    match cli.command {
        Commands::PackageDigest {
            package_path,
            network,
        } => compute_package_digest(&package_path, &network),
        Commands::Vote {
            package_path,
            key_server_id,
            network,
            gas_budget,
        } => {
            vote_for_upgrade(
                &package_path,
                &key_server_id,
                &network,
                &mut wallet,
                gas_budget,
            )
            .await
        }
        Commands::AuthorizeAndUpgrade {
            package_path,
            key_server_id,
            network,
            gas_budget,
        } => {
            authorize_and_upgrade(
                &package_path,
                &key_server_id,
                &network,
                &mut wallet,
                gas_budget,
            )
            .await
        }
        Commands::ResetProposal {
            key_server_id,
            network,
            gas_budget,
        } => reset_proposal(&key_server_id, &network, &mut wallet, gas_budget).await,
        Commands::GetKeyServer {
            key_server_id,
            network,
        } => get_key_server_info(&key_server_id, &network).await,
    }
}
