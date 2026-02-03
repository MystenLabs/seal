// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

mod types;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use fastcrypto::bls12381::min_sig::BLS12381KeyPair;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::groups::bls12381::{G2Element, Scalar as G2Scalar};
use fastcrypto::groups::GroupElement;
use fastcrypto::traits::KeyPair as _;
use fastcrypto_tbls::dkg_v1::Party;
use fastcrypto_tbls::ecies_v1::{PrivateKey, PublicKey};
use fastcrypto_tbls::nodes::{Node, Nodes};
use fastcrypto_tbls::random_oracle::RandomOracle;
use move_package_alt_compilation::build_config::BuildConfig as MoveBuildConfig;
use rand::thread_rng;
use seal_committee::grpc_helper::to_partial_key_servers;
use seal_committee::{
    build_new_to_old_map, create_grpc_client, fetch_committee_data, fetch_key_server_by_committee,
    CommitteeState, Network, ServerType,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use sui_move_build::BuildConfig;
use sui_package_alt::{mainnet_environment, testnet_environment};
use sui_sdk::rpc_types::{SuiTransactionBlockEffectsAPI, SuiTransactionBlockResponse};
use sui_sdk::wallet_context::WalletContext;
use sui_sdk_types::Address;
use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use sui_types::transaction::SharedObjectMutability;
use sui_types::transaction::{ObjectArg, TransactionData};
use sui_types::{
    base_types::{ObjectID, SuiAddress},
    object::Owner,
};
use types::{DkgState, InitializedConfig, KeysFile};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::types::{sign_message, verify_signature, SignedMessage};

#[derive(Parser)]
#[command(name = "dkg-cli")]
#[command(about = "DKG and key rotation CLI tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to Sui wallet config (default: ~/.sui/sui_config/client.yaml)
    #[arg(long, global = true)]
    wallet: Option<PathBuf>,

    /// Override the active address from the wallet config
    #[arg(long, global = true)]
    active_address: Option<SuiAddress>,

    /// Gas budget for transactions (default: 100000000 = 0.1 SUI)
    #[arg(long, global = true, default_value = "100000000")]
    gas_budget: u64,
}

#[derive(Subcommand)]
enum Commands {
    /// Publish committee package and initialize committee (coordinator operation).
    PublishAndInit {
        /// Path to configuration file.
        #[arg(short, long, default_value = "dkg-state/dkg.yaml")]
        config: PathBuf,
    },

    /// Initialize committee rotation (coordinator operation).
    InitRotation {
        /// Path to configuration file.
        #[arg(short, long, default_value = "dkg-state/dkg.yaml")]
        config: PathBuf,
    },

    /// Generate DKG keys and register onchain (member operation).
    GenkeyAndRegister {
        /// State directory (contains dkg.yaml and dkg.key).
        #[arg(short = 's', long, default_value = "dkg-state")]
        state_dir: PathBuf,

        /// Path to configuration file (overrides default <state_dir>/dkg.yaml).
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Path to write keys file (overrides default <state_dir>/dkg.key).
        #[arg(short = 'k', long)]
        keys_file: Option<PathBuf>,

        /// Server URL to register.
        #[arg(short = 'u', long)]
        server_url: String,

        /// Server name to register.
        #[arg(short = 'n', long)]
        server_name: String,
    },

    /// Initialize state for DKG party for new member joining in a rotation (member operation).
    InitState {
        /// State directory (contains dkg.yaml, dkg.key, and state).
        #[arg(short = 's', long, default_value = "dkg-state")]
        state_dir: PathBuf,

        /// Path to configuration file (overrides default <state_dir>/dkg.yaml).
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Path to the keys file (overrides default <state_dir>/dkg.key).
        #[arg(short = 'k', long)]
        keys_file: Option<PathBuf>,
    },

    /// Initialize DKG party state and create DKG message (member operation).
    /// For fresh DKG: all members create messages (no old share needed).
    /// For rotation: continuing members must provide --old-share.
    CreateMessage {
        /// State directory (contains dkg.yaml, dkg.key, and state).
        #[arg(short = 's', long, default_value = "dkg-state")]
        state_dir: PathBuf,

        /// Path to configuration file (overrides default <state_dir>/dkg.yaml).
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Path to the keys file (overrides default <state_dir>/dkg.key).
        #[arg(short = 'k', long)]
        keys_file: Option<PathBuf>,

        /// Old share for key rotation (hex-encoded BCS, required for continuing members in rotation).
        #[arg(short = 'o', long)]
        old_share: Option<String>,
    },

    /// Process all messages and propose committee onchain (member operation).
    ProcessAllAndPropose {
        /// State directory (contains dkg.yaml, dkg.key, and state).
        #[arg(short = 's', long, default_value = "dkg-state")]
        state_dir: PathBuf,

        /// Directory containing message_*.json files from all parties.
        #[arg(short = 'm', long, default_value = "dkg-messages")]
        messages_dir: PathBuf,

        /// Path to configuration file (overrides default <state_dir>/dkg.yaml).
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Path to keys file (overrides default <state_dir>/dkg.key).
        #[arg(short = 'k', long)]
        keys_file: Option<PathBuf>,
    },

    /// Check committee status and member registration.
    CheckCommittee {
        /// Path to configuration file.
        #[arg(short, long, default_value = "dkg-state/dkg.yaml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::PublishAndInit { config } => {
            let config_content = load_config(&config)?;

            // Check if already initialized
            if config_content.get("COMMITTEE_PKG").is_some()
                && config_content.get("COMMITTEE_ID").is_some()
            {
                let committee_pkg = config_content["COMMITTEE_PKG"].as_str().unwrap();
                let committee_id = config_content["COMMITTEE_ID"].as_str().unwrap();
                println!("Committee already initialized:");
                println!("  COMMITTEE_PKG: {}", committee_pkg);
                println!("  COMMITTEE_ID: {}", committee_id);
                println!(
                    "\nSkipping publish and init. Remove these fields from config to reinitialize."
                );
                return Ok(());
            }

            let network = get_network(&config_content)?;
            let members = get_members(&config_content)?;
            let threshold = get_threshold(&config_content)?;

            // Load wallet
            let mut wallet = load_wallet(cli.wallet.as_deref(), cli.active_address)?;
            let coordinator_address = wallet.active_address()?;

            println!("Using coordinator address: {}", coordinator_address);
            println!("Network: {:?}", network);
            println!("Members: {} addresses", members.len());
            println!("Threshold: {}", threshold);

            // Get committee package path
            let committee_path = std::env::current_dir()?.join("move/committee");
            if !committee_path.exists() {
                bail!(
                    "Committee package not found at: {}",
                    committee_path.display()
                );
            }

            // Remove Published.toml to ensure fresh publish
            let published_toml = committee_path.join("Published.toml");
            if published_toml.exists() {
                println!(
                    "Removing {} to enable fresh publish...",
                    published_toml.display()
                );
                fs::remove_file(published_toml)?;
            }

            // Publish the package
            println!("\nPublishing seal_committee package...");
            let sender = coordinator_address;

            // Build and publish package
            let compiled_package = create_build_config(&network).build(&committee_path)?;

            let compiled_modules_bytes =
                compiled_package.get_package_bytes(/* with_unpublished_deps */ false);

            let mut grpc_client = create_grpc_client(&network)?;
            let gas_price = grpc_client.get_reference_gas_price().await?;
            let gas_budget = cli.gas_budget;

            let gas_coin = wallet
                .gas_for_owner_budget(sender, gas_budget, Default::default())
                .await?
                .1;

            let dependencies: Vec<ObjectID> = compiled_package
                .dependency_ids
                .published
                .into_values()
                .collect();

            let mut builder = ProgrammableTransactionBuilder::new();
            let upgrade_cap = builder.publish_upgradeable(compiled_modules_bytes, dependencies);
            builder.transfer_arg(sender, upgrade_cap);

            let tx_data = TransactionData::new_programmable(
                sender,
                vec![gas_coin.object_ref()],
                builder.finish(),
                gas_budget,
                gas_price,
            );

            println!("\nExecuting publish transaction...");
            let response = execute_tx_and_log_status(&wallet, tx_data).await?;

            // Extract published package ID
            let package_id = response
                .effects
                .as_ref()
                .and_then(|effects| {
                    effects.created().iter().find_map(|obj_ref| {
                        if matches!(obj_ref.owner, Owner::Immutable) {
                            Some(obj_ref.reference.object_id)
                        } else {
                            None
                        }
                    })
                })
                .ok_or_else(|| anyhow!("Could not find published package ID"))?;

            println!("Published package: {}", package_id);

            // Initialize the committee
            println!("\nInitializing committee...");
            let mut init_builder = ProgrammableTransactionBuilder::new();

            // Call init_committee function
            let threshold_arg = init_builder.pure(threshold)?;
            let members_arg = init_builder.pure(members)?;

            init_builder.programmable_move_call(
                package_id,
                "seal_committee".parse()?,
                "init_committee".parse()?,
                vec![],
                vec![threshold_arg, members_arg],
            );

            let init_gas_coin = wallet
                .gas_for_owner_budget(sender, gas_budget, Default::default())
                .await?
                .1;

            let init_tx_data = TransactionData::new_programmable(
                sender,
                vec![init_gas_coin.object_ref()],
                init_builder.finish(),
                gas_budget,
                gas_price,
            );

            println!("\nExecuting init_committee transaction...");
            let init_response = execute_tx_and_log_status(&wallet, init_tx_data).await?;

            // Extract committee ID
            let committee_id = extract_created_committee_id(&init_response)?;

            println!("Created committee: {}", committee_id);

            // Update config
            update_config_bytes_val(
                &config,
                "publish-and-init",
                vec![
                    ("COMMITTEE_PKG", package_id.as_ref()),
                    ("COMMITTEE_ID", committee_id.as_ref()),
                    ("COORDINATOR_ADDRESS", coordinator_address.as_ref()),
                ],
            )?;

            println!(
                "\nUpdated file {}. Share this file with committee members.",
                config.display()
            );
        }

        Commands::InitRotation { config } => {
            let config_content = load_config(&config)?;

            let committee_id = get_config_field(
                &config_content,
                &["init-rotation", "publish-and-init"],
                "COMMITTEE_ID",
            )
            .and_then(|v| v.as_str());

            if committee_id.is_some() {
                println!("Committee rotation already initialized:");
                println!("  COMMITTEE_ID: {}", committee_id.unwrap());
                println!(
                    "\nSkipping init-rotation. Remove COMMITTEE_ID from config to re-initialize."
                );
                return Ok(());
            }

            let key_server_obj_id = get_config_field(
                &config_content,
                &["init-rotation-params"],
                "KEY_SERVER_OBJ_ID",
            )
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("KEY_SERVER_OBJ_ID not found in config"))?;
            let key_server_obj_id = Address::from_str(key_server_obj_id)?;
            let network = get_network(&config_content)?;
            let members = get_members(&config_content)?;
            let threshold = get_threshold(&config_content)?;

            // Load wallet
            let mut wallet = load_wallet(cli.wallet.as_deref(), cli.active_address)?;
            let coordinator_address = wallet.active_address()?;

            println!("Using coordinator address: {}", coordinator_address);

            // Fetch key server and extract current committee ID
            println!("\nFetching key server: {}...", key_server_obj_id);
            let mut grpc_client = create_grpc_client(&network)?;

            // Fetch key server object owner (field wrapper ID)
            let mut ledger_client = grpc_client.ledger_client();
            let mut ks_request = sui_rpc::proto::sui::rpc::v2::GetObjectRequest::default();
            ks_request.object_id = Some(key_server_obj_id.to_string());
            ks_request.read_mask = Some(prost_types::FieldMask {
                paths: vec!["owner".to_string()],
            });

            let ks_response = ledger_client
                .get_object(ks_request)
                .await
                .map(|r| r.into_inner())?;
            let ks_object = ks_response
                .object
                .ok_or_else(|| anyhow!("Key server object not found"))?;

            let owner_data = ks_object
                .owner
                .ok_or_else(|| anyhow!("Key server object has no owner"))?;

            // Owner has fields: kind, address, version
            // For object owner, address contains the owner object ID
            let owner_address = owner_data
                .address
                .ok_or_else(|| anyhow!("Owner has no address"))?;
            let field_wrapper_id = Address::from_str(&owner_address)?;

            // Fetch field wrapper to extract committee ID from its name
            let mut fw_request = sui_rpc::proto::sui::rpc::v2::GetObjectRequest::default();
            fw_request.object_id = Some(field_wrapper_id.to_string());
            fw_request.read_mask = Some(prost_types::FieldMask {
                paths: vec!["bcs".to_string()],
            });

            let fw_response = ledger_client
                .get_object(fw_request)
                .await
                .map(|r| r.into_inner())?;
            let fw_bcs = fw_response
                .object
                .and_then(|obj| obj.bcs)
                .and_then(|bcs| bcs.value)
                .ok_or_else(|| anyhow!("Field wrapper BCS data not found"))?;

            let fw_object: sui_sdk_types::Object = bcs::from_bytes(&fw_bcs)?;
            let fw_struct = fw_object
                .as_struct()
                .ok_or_else(|| anyhow!("Field wrapper is not a Move struct"))?;

            // Deserialize as Field<Wrapper<ID>, ID> to extract committee ID
            #[derive(serde::Deserialize)]
            #[allow(dead_code)]
            struct UidWrapper {
                id: Address,
            }
            #[derive(serde::Deserialize)]
            struct Wrapper {
                name: Address,
            }
            #[derive(serde::Deserialize)]
            #[allow(dead_code)]
            struct FieldWrapper {
                id: UidWrapper,
                name: Wrapper,
                value: Address,
            }
            let field: FieldWrapper = bcs::from_bytes(fw_struct.contents())?;
            let current_committee_id = field.name.name;

            println!("\nCurrent committee ID: {}", current_committee_id);

            // Get package ID from current committee using gRPC
            // Fetch the committee object to get type information
            let mut committee_request = sui_rpc::proto::sui::rpc::v2::GetObjectRequest::default();
            committee_request.object_id = Some(current_committee_id.to_string());
            committee_request.read_mask = Some(prost_types::FieldMask {
                paths: vec!["object_type".to_string()],
            });

            let committee_response = ledger_client
                .get_object(committee_request)
                .await
                .map(|r| r.into_inner())?;

            let object_type = committee_response
                .object
                .and_then(|obj| obj.object_type)
                .ok_or_else(|| anyhow!("Committee object has no type"))?;

            // Parse the object type string (format: "package_id::module::Type")
            // Extract package ID from the first part
            let package_id_str = object_type
                .split("::")
                .next()
                .ok_or_else(|| anyhow!("Could not extract package ID from object type"))?;
            let package_id = ObjectID::from_hex_literal(package_id_str)?;

            println!("Committee package ID: {}", package_id);

            // Update config with current committee info
            update_config_bytes_val(
                &config,
                "init-rotation",
                vec![
                    ("COMMITTEE_PKG", package_id.as_ref()),
                    ("CURRENT_COMMITTEE_ID", current_committee_id.inner()),
                    ("COORDINATOR_ADDRESS", coordinator_address.as_ref()),
                ],
            )?;

            println!("\n✓ Updated {} init-rotation section with COMMITTEE_PKG, CURRENT_COMMITTEE_ID, COORDINATOR_ADDRESS", config.display());

            // Call init_rotation
            println!("\nInitializing rotation...");
            let mut rotation_builder = ProgrammableTransactionBuilder::new();

            let current_committee_obj_id = ObjectID::new(current_committee_id.into_inner());
            let current_committee_arg = rotation_builder.obj(
                get_shared_committee_arg(&mut grpc_client, current_committee_obj_id, false).await?,
            )?;
            let threshold_arg = rotation_builder.pure(threshold)?;
            let members_arg = rotation_builder.pure(members)?;

            rotation_builder.programmable_move_call(
                package_id,
                "seal_committee".parse()?,
                "init_rotation".parse()?,
                vec![],
                vec![current_committee_arg, threshold_arg, members_arg],
            );

            let gas_budget = cli.gas_budget;
            let gas_price = grpc_client.get_reference_gas_price().await?;
            let gas_coin = wallet
                .gas_for_owner_budget(coordinator_address, gas_budget, Default::default())
                .await?
                .1;

            let rotation_tx_data = TransactionData::new_programmable(
                coordinator_address,
                vec![gas_coin.object_ref()],
                rotation_builder.finish(),
                gas_budget,
                gas_price,
            );

            println!("\nExecuting init_rotation transaction...");
            let rotation_response = execute_tx_and_log_status(&wallet, rotation_tx_data).await?;

            // Extract new committee ID
            let new_committee_id = extract_created_committee_id(&rotation_response)?;

            println!("Created new committee for rotation: {}", new_committee_id);

            // Update config with new committee ID
            update_config_bytes_val(
                &config,
                "init-rotation",
                vec![("COMMITTEE_ID", new_committee_id.as_ref())],
            )?;

            println!(
                "\n✓ Updated {} init-rotation section with COMMITTEE_ID",
                config.display()
            );
            println!("\nShare this file with committee members.");
        }

        Commands::GenkeyAndRegister {
            state_dir,
            config,
            keys_file,
            server_url,
            server_name,
        } => {
            // Derive config and keys_file paths from state_dir if not provided
            let config = config.unwrap_or_else(|| state_dir.join("dkg.yaml"));
            let keys_file = keys_file.unwrap_or_else(|| state_dir.join("dkg.key"));

            let config_content = load_config(&config)?;

            // Check if already generated keys
            if get_config_field(&config_content, &["genkey-and-register"], "DKG_ENC_PK").is_some()
                && get_config_field(&config_content, &["genkey-and-register"], "DKG_SIGNING_PK")
                    .is_some()
            {
                println!("Keys already generated. Skipping key generation and registration. Remove the genkey-and-register section from the config file to re-run this operation.");
                println!(
                    "WARNING: If these keys were already registered onchain, this operation cannot be redone."
                );
                return Ok(());
            }

            // Validate inputs
            if server_url.trim().is_empty() {
                bail!("Server URL is required and cannot be empty");
            }
            if server_name.trim().is_empty() {
                bail!("Server name is required and cannot be empty");
            }

            // Load wallet
            let mut wallet = load_wallet(cli.wallet.as_deref(), cli.active_address)?;
            let my_address = wallet.active_address()?;

            println!("\n=== Getting active address from wallet ===");
            println!("Active address: {}", my_address);
            println!("Server URL: {}", server_url);
            println!("Server Name: {}", server_name);

            // Update config with member info
            update_config_bytes_val(
                &config,
                "genkey-and-register",
                vec![("MY_ADDRESS", my_address.as_ref())],
            )?;
            // Add plain string values
            update_config_string_val(
                &config,
                "genkey-and-register",
                vec![
                    ("MY_SERVER_URL", server_url.as_str()),
                    ("MY_SERVER_NAME", server_name.as_str()),
                ],
            )?;
            println!(
                "\n✓ Updated {} with genkey-and-register section (MY_ADDRESS, MY_SERVER_URL, MY_SERVER_NAME)",
                config.display()
            );

            // Reload config
            let config_content = load_config(&config)?;

            // Validate required fields from coordinator's config
            validate_required_fields(
                &config_content,
                &[
                    ("COMMITTEE_PKG", &["publish-and-init", "init-rotation"] as &[&str]),
                    ("COMMITTEE_ID", &["publish-and-init", "init-rotation"] as &[&str]),
                    ("NETWORK", &["init-params"] as &[&str]),
                ],
                "genkey-and-register",
                "Make sure you have received the config file from the coordinator with COMMITTEE_PKG, COMMITTEE_ID, and NETWORK"
            )?;

            let committee_pkg_str = get_config_field(
                &config_content,
                &["publish-and-init", "init-rotation"],
                "COMMITTEE_PKG",
            )
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("COMMITTEE_PKG not found in config"))?;
            let committee_id_str = get_config_field(
                &config_content,
                &["publish-and-init", "init-rotation"],
                "COMMITTEE_ID",
            )
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("COMMITTEE_ID not found in config"))?;

            let committee_pkg = ObjectID::from_hex_literal(committee_pkg_str)?;
            let committee_id = ObjectID::from_hex_literal(committee_id_str)?;

            // Generate keys
            println!("\n=== Generating DKG keys ===");
            let enc_sk = PrivateKey::<G2Element>::new(&mut thread_rng());
            let enc_pk = PublicKey::<G2Element>::from_private_key(&enc_sk);

            let signing_kp = BLS12381KeyPair::generate(&mut thread_rng());
            let signing_pk = signing_kp.public().clone();
            let signing_sk = signing_kp.private();

            // Serialize keys to BCS bytes (used for both config and onchain registration)
            let enc_pk_bytes = bcs::to_bytes(&enc_pk)?;
            let signing_pk_bytes = bcs::to_bytes(&signing_pk)?;

            let created_keys_file = KeysFile {
                enc_sk,
                enc_pk,
                signing_sk,
                signing_pk,
            };

            // Write keys to file
            let json_content = serde_json::to_string_pretty(&created_keys_file)?;
            if let Some(parent) = keys_file.parent() {
                fs::create_dir_all(parent)?;
            }
            write_secret_file(&keys_file, &json_content)?;

            // Update config with public keys (hex-encoded)
            update_config_bytes_val(
                &config,
                "genkey-and-register",
                vec![
                    ("DKG_ENC_PK", &enc_pk_bytes),
                    ("DKG_SIGNING_PK", &signing_pk_bytes),
                ],
            )?;
            println!(
                "\n✓ Updated {} genkey-and-register section with DKG_ENC_PK, DKG_SIGNING_PK",
                config.display()
            );

            // Register onchain
            println!("\n=== Registering onchain ===");
            let network = get_network(&config_content)?;

            let gas_budget = cli.gas_budget;
            let mut grpc_client = create_grpc_client(&network)?;
            let gas_price = grpc_client.get_reference_gas_price().await?;

            let mut register_builder = ProgrammableTransactionBuilder::new();

            let committee_arg = register_builder
                .obj(get_shared_committee_arg(&mut grpc_client, committee_id, true).await?)?;

            let enc_pk_arg = register_builder.pure(enc_pk_bytes)?;
            let signing_pk_arg = register_builder.pure(signing_pk_bytes)?;
            let url_arg = register_builder.pure(server_url.as_str())?;
            let name_arg = register_builder.pure(server_name.as_str())?;

            register_builder.programmable_move_call(
                committee_pkg,
                "seal_committee".parse()?,
                "register".parse()?,
                vec![],
                vec![committee_arg, enc_pk_arg, signing_pk_arg, url_arg, name_arg],
            );
            let gas_coin = wallet
                .gas_for_owner_budget(my_address, gas_budget, Default::default())
                .await?
                .1;

            let register_tx_data = TransactionData::new_programmable(
                my_address,
                vec![gas_coin.object_ref()],
                register_builder.finish(),
                gas_budget,
                gas_price,
            );

            println!("\nExecuting register transaction...");
            let _register_response = execute_tx_and_log_status(&wallet, register_tx_data).await?;

            println!("\n[SUCCESS] Keys generated and registered onchain!");
            println!("  Your address: {}", my_address);
            println!("  Server URL: {}", server_url);
            println!("  Server Name: {}", server_name);
            println!("  Committee ID: {}", committee_id);
            println!(
                "\nIMPORTANT: Your private keys are stored in: {}",
                keys_file.display()
            );
        }

        Commands::InitState {
            state_dir,
            config,
            keys_file,
        } => {
            // Derive config and keys_file paths from state_dir if not provided
            let config = config.unwrap_or_else(|| state_dir.join("dkg.yaml"));
            let keys_file = keys_file.unwrap_or_else(|| state_dir.join("dkg.key"));

            // Call shared function with no old share
            create_dkg_state_and_message(&state_dir, &config, &keys_file, None).await?;
        }

        Commands::CreateMessage {
            state_dir,
            config,
            keys_file,
            old_share,
        } => {
            // Derive config and keys_file paths from state_dir if not provided
            let config = config.unwrap_or_else(|| state_dir.join("dkg.yaml"));
            let keys_file = keys_file.unwrap_or_else(|| state_dir.join("dkg.key"));

            // Call shared function - it will validate old_share based on onchain committee state
            create_dkg_state_and_message(&state_dir, &config, &keys_file, old_share).await?;
        }
        Commands::ProcessAllAndPropose {
            state_dir,
            messages_dir,
            config,
            keys_file,
        } => {
            // Derive config and keys_file paths from state_dir if not provided
            let config = config.unwrap_or_else(|| state_dir.join("dkg.yaml"));
            let keys_file = keys_file.unwrap_or_else(|| state_dir.join("dkg.key"));

            let config_content = load_config(&config)?;

            // Validate required fields
            validate_required_fields(
                &config_content,
                &[
                    (
                        "COMMITTEE_PKG",
                        &["publish-and-init", "init-rotation"] as &[&str],
                    ),
                    (
                        "COMMITTEE_ID",
                        &["publish-and-init", "init-rotation"] as &[&str],
                    ),
                    ("NETWORK", &["init-params"] as &[&str]),
                    ("MY_ADDRESS", &["genkey-and-register"] as &[&str]),
                ],
                "process-all-and-propose",
                "Make sure your config has COMMITTEE_PKG, COMMITTEE_ID, MY_ADDRESS, and NETWORK.",
            )?;

            let committee_pkg_str = get_config_field(
                &config_content,
                &["publish-and-init", "init-rotation"],
                "COMMITTEE_PKG",
            )
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("COMMITTEE_PKG not found in config"))?;
            let committee_id_str = get_config_field(
                &config_content,
                &["publish-and-init", "init-rotation"],
                "COMMITTEE_ID",
            )
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("COMMITTEE_ID not found in config"))?;
            let my_address_str =
                get_config_field(&config_content, &["genkey-and-register"], "MY_ADDRESS")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("MY_ADDRESS not found in config"))?;

            let committee_pkg = ObjectID::from_hex_literal(committee_pkg_str)?;
            let committee_id = ObjectID::from_hex_literal(committee_id_str)?;
            let my_address = SuiAddress::from_str(my_address_str)?;
            let network = get_network(&config_content)?;

            // Check if this is a rotation
            let current_committee_id =
                get_config_field(&config_content, &["init-rotation"], "CURRENT_COMMITTEE_ID")
                    .and_then(|v| v.as_str())
                    .map(ObjectID::from_hex_literal)
                    .transpose()?;
            let is_rotation = current_committee_id.is_some();

            // Process DKG messages
            println!("\n=== Processing DKG messages ===");
            println!("  Messages directory: {:?}", messages_dir);
            println!("  State directory: {:?}", state_dir);
            println!("  Keys file: {:?}\n", keys_file);

            let mut state = DkgState::load(&state_dir)?;
            let local_keys = KeysFile::load(&keys_file)?;

            // Load and process all messages
            let messages = load_messages_from_dir(&messages_dir)?;
            let output = process_dkg_messages(&mut state, messages, &local_keys)?;

            // Determine version
            let version = determine_committee_version(&network, &state.config.committee_id).await?;

            // Extract key server PK and master share as raw bytes (will be hex-encoded)
            let key_server_pk_bytes = bcs::to_bytes(&output.vss_pk.c0())?;
            let master_share_bytes = if let Some(shares) = &output.shares {
                shares
                    .first()
                    .map(|share| bcs::to_bytes(&share.value))
                    .transpose()?
                    .unwrap_or_default()
            } else {
                vec![]
            };

            // Partial PKs need to be hex strings for YAML list serialization
            let mut partial_pks = Vec::new();
            for party_id in 0..state.config.nodes.num_nodes() {
                let share_index = NonZeroU16::new(party_id as u16 + 1).expect("must be valid");
                let partial_pk = output.vss_pk.eval(share_index);
                partial_pks.push(to_hex(&partial_pk.value)?);
            }

            // Check if already written to config
            let master_share_key = format!("MASTER_SHARE_V{}", version);
            let partial_pks_key = format!("PARTIAL_PKS_V{}", version);

            if get_config_field(
                &config_content,
                &["process-all-and-propose"],
                &master_share_key,
            )
            .is_some()
                && get_config_field(
                    &config_content,
                    &["process-all-and-propose"],
                    &partial_pks_key,
                )
                .is_some()
            {
                println!(
                    "\n[WARNING] {} and {} already exist in config!",
                    master_share_key, partial_pks_key
                );
                println!("[WARNING] Skipping processing and onchain proposal.");
                println!("[WARNING] To reprocess messages and propose onchain, remove the process-all-and-propose section from the config file.");
                return Ok(());
            }

            // Update config file
            println!("\n=== Updating {} ===", config.display());

            // Serialize partial_pks as YAML list (for config storage)
            let partial_pks_yaml = serde_yaml::to_string(&partial_pks)?;

            if version == 0 {
                // For v0, add KEY_SERVER_PK, PARTIAL_PKS_V0, MASTER_SHARE_V0
                update_config_bytes_val(
                    &config,
                    "process-all-and-propose",
                    vec![("KEY_SERVER_PK", &key_server_pk_bytes)],
                )?;
                update_config_string_val(
                    &config,
                    "process-all-and-propose",
                    vec![(partial_pks_key.as_str(), partial_pks_yaml.trim())],
                )?;
                update_config_bytes_val(
                    &config,
                    "process-all-and-propose",
                    vec![(master_share_key.as_str(), &master_share_bytes)],
                )?;
            } else {
                // For rotation, verify KEY_SERVER_PK matches, then add PARTIAL_PKS_VX and MASTER_SHARE_VX
                if let Some(existing_key_server_pk) = get_config_field(
                    &config_content,
                    &["process-all-and-propose"],
                    "KEY_SERVER_PK",
                ) {
                    let existing_pk = existing_key_server_pk
                        .as_str()
                        .unwrap_or("")
                        .trim_matches('\'')
                        .trim_matches('"');
                    let key_server_pk_hex = Hex::encode_with_format(&key_server_pk_bytes);
                    if existing_pk != key_server_pk_hex {
                        bail!(
                            "KEY_SERVER_PK mismatch!\n  Expected (from v0): {}\n  Got (from rotation): {}",
                            existing_pk,
                            key_server_pk_hex
                        );
                    }
                    println!("✓ KEY_SERVER_PK verification passed (unchanged from v0)");
                }
                update_config_string_val(
                    &config,
                    "process-all-and-propose",
                    vec![(partial_pks_key.as_str(), partial_pks_yaml.trim())],
                )?;
                update_config_bytes_val(
                    &config,
                    "process-all-and-propose",
                    vec![(master_share_key.as_str(), &master_share_bytes)],
                )?;
            }

            if version == 0 {
                println!("\n✓ Updated {} process-all-and-propose section with KEY_SERVER_PK, PARTIAL_PKS_V{}, MASTER_SHARE_V{}", config.display(), version, version);
            } else {
                println!("\n✓ Updated {} process-all-and-propose section with PARTIAL_PKS_V{}, MASTER_SHARE_V{}", config.display(), version, version);
            }

            // Load wallet and propose onchain
            let wallet = load_wallet(cli.wallet.as_deref(), cli.active_address)?;

            if is_rotation {
                println!("\n=== Proposing committee rotation onchain ===");
                println!("  New Committee ID: {}", committee_id);
                println!("  Current Committee ID: {}", current_committee_id.unwrap());
            } else {
                println!("\n=== Proposing committee onchain ===");
            }

            let gas_budget = cli.gas_budget;
            let mut grpc_client = create_grpc_client(&network)?;
            let gas_price = grpc_client.get_reference_gas_price().await?;

            let mut propose_builder = ProgrammableTransactionBuilder::new();

            let committee_arg = propose_builder
                .obj(get_shared_committee_arg(&mut grpc_client, committee_id, true).await?)?;

            // Decode hex strings to raw BLS point bytes for Move function
            let partial_pks_bytes: Vec<Vec<u8>> = partial_pks
                .iter()
                .map(|hex_str| Hex::decode(hex_str))
                .collect::<Result<Vec<_>, _>>()?;
            let partial_pks_arg = propose_builder.pure(partial_pks_bytes)?;

            if is_rotation {
                let current_committee_obj_id = current_committee_id.unwrap();
                let current_committee_arg = propose_builder.obj(
                    get_shared_committee_arg(&mut grpc_client, current_committee_obj_id, true)
                        .await?,
                )?;

                propose_builder.programmable_move_call(
                    committee_pkg,
                    "seal_committee".parse()?,
                    "propose_for_rotation".parse()?,
                    vec![],
                    vec![committee_arg, partial_pks_arg, current_committee_arg],
                );
            } else {
                // Use key server PK bytes directly
                let key_server_pk_arg = propose_builder.pure(key_server_pk_bytes)?;

                propose_builder.programmable_move_call(
                    committee_pkg,
                    "seal_committee".parse()?,
                    "propose".parse()?,
                    vec![],
                    vec![committee_arg, partial_pks_arg, key_server_pk_arg],
                );
            }
            let gas_coin = wallet
                .gas_for_owner_budget(my_address, gas_budget, Default::default())
                .await?
                .1;

            let propose_tx_data = TransactionData::new_programmable(
                my_address,
                vec![gas_coin.object_ref()],
                propose_builder.finish(),
                gas_budget,
                gas_price,
            );

            println!("\nExecuting propose transaction...");
            let _propose_response = execute_tx_and_log_status(&wallet, propose_tx_data).await?;

            println!("\n✓ Successfully processed messages and proposed committee onchain!");
            println!(
                "  MASTER_SHARE_V{} can be found in {} that will be used later to start the key server. Back it up securely and do not share it with anyone.",
                version,
                config.display()
            );
            println!("  Committee ID: {}", committee_id);
            println!("  Partial PKs: {} entries", partial_pks.len());
        }

        Commands::CheckCommittee { config } => {
            let config_content = load_config(&config)?;

            // Validate required fields
            validate_required_fields(
                &config_content,
                &[
                    (
                        "COMMITTEE_ID",
                        &["publish-and-init", "init-rotation"] as &[&str],
                    ),
                    ("NETWORK", &["init-params"] as &[&str]),
                ],
                "check-committee",
                "Make sure your config has COMMITTEE_ID and NETWORK.",
            )?;

            let committee_id_str = get_config_field(
                &config_content,
                &["publish-and-init", "init-rotation"],
                "COMMITTEE_ID",
            )
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("COMMITTEE_ID not found in config"))?;
            let committee_id = Address::from_str(committee_id_str)?;
            let network = get_network(&config_content)?;

            // Fetch committee from onchain
            let mut grpc_client = create_grpc_client(&network)?;
            let committee = fetch_committee_data(&mut grpc_client, &committee_id).await?;

            println!("Committee ID: {committee_id}");
            println!("Total members: {}", committee.members.len());
            println!("Threshold: {}", committee.threshold);
            println!("State: {:?}", committee.state);

            // Check which members are registered and approved based on state
            match &committee.state {
                CommitteeState::Init { members_info } => {
                    let registered_addrs: HashSet<_> = members_info
                        .0
                        .contents
                        .iter()
                        .map(|entry| entry.key)
                        .collect();

                    let mut registered = Vec::new();
                    let mut not_registered = Vec::new();

                    for member_addr in &committee.members {
                        if registered_addrs.contains(member_addr) {
                            registered.push(*member_addr);
                        } else {
                            not_registered.push(*member_addr);
                        }
                    }

                    println!(
                        "\nRegistered members ({}/{}):",
                        registered.len(),
                        committee.members.len()
                    );
                    for addr in &registered {
                        println!("  ✓ {addr}");
                    }

                    if !not_registered.is_empty() {
                        println!();
                        println!("⚠ Missing members ({}):", not_registered.len());
                        for addr in &not_registered {
                            println!("  ✗ {addr}");
                        }
                        println!(
                            "\nWaiting for {} member(s) to register before proceeding to phase 2.",
                            not_registered.len()
                        );
                    } else {
                        println!();
                        println!("✓ All members registered! Good to proceed to phase 2.");
                    }
                }
                CommitteeState::PostDKG { approvals, .. } => {
                    let approved_addrs: HashSet<_> = approvals.contents.iter().cloned().collect();

                    // Show approval status
                    let mut approved = Vec::new();
                    let mut not_approved = Vec::new();

                    for member_addr in &committee.members {
                        if approved_addrs.contains(member_addr) {
                            approved.push(*member_addr);
                        } else {
                            not_approved.push(*member_addr);
                        }
                    }

                    println!(
                        "\nApproved members ({}/{}):",
                        approved.len(),
                        committee.members.len()
                    );
                    for addr in &approved {
                        println!("  ✓ {addr}");
                    }

                    if !not_approved.is_empty() {
                        println!();
                        println!("⚠ Members who haven't approved ({}):", not_approved.len());
                        for addr in &not_approved {
                            println!("  ✗ {addr}");
                        }
                        println!(
                            "\nWaiting for {} member(s) to approve before finalizing.",
                            not_approved.len()
                        );
                    } else {
                        println!();
                        println!("✓ All members approved! Committee can be finalized.");
                    }
                }
                CommitteeState::Finalized => {
                    println!("\n✓ Committee is finalized!");

                    // Fetch key server object ID and version
                    println!("\nFetching key server object ID...");
                    match fetch_key_server_by_committee(&mut grpc_client, &committee_id).await {
                        Ok((ks_obj_id, key_server)) => {
                            println!("KEY_SERVER_OBJ_ID: {ks_obj_id}");

                            // Extract and print committee version
                            match key_server.server_type {
                                ServerType::Committee { version, .. } => {
                                    println!("COMMITTEE_VERSION: {version}");
                                }
                                _ => {
                                    println!("Warning: KeyServer is not of type Committee");
                                }
                            }

                            // Display partial key server information
                            println!("\nPartial Key Servers:");
                            match to_partial_key_servers(&key_server).await {
                                Ok(partial_key_servers) => {
                                    for (addr, info) in partial_key_servers {
                                        println!("  Address: {}", addr);
                                        println!("    Name: {}", info.name);
                                        println!("    URL: {}", info.url);
                                        println!("    Party ID: {}", info.party_id);
                                        println!();
                                    }
                                }
                                Err(e) => {
                                    println!(
                                        "Warning: Could not fetch partial key server info: {e}"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            println!("Warning: Could not fetch key server object: {e}");
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Execute transaction and log status.
async fn execute_tx_and_log_status(
    wallet: &WalletContext,
    tx_data: TransactionData,
) -> Result<SuiTransactionBlockResponse> {
    let transaction = wallet.sign_transaction(&tx_data).await;
    let response = wallet.execute_transaction_may_fail(transaction).await?;

    // Check transaction status
    let digest = response.digest;
    let effects = response.effects.as_ref();
    let status = effects
        .map(|e| e.status())
        .ok_or_else(|| anyhow!("No effects in transaction response"))?;

    if !status.is_ok() {
        bail!("Transaction failed with status: {:?}", status);
    }

    println!("Transaction success! Digest: {}", digest);
    Ok(response)
}

/// Extract the committee object ID from a transaction response.
fn extract_created_committee_id(response: &SuiTransactionBlockResponse) -> Result<ObjectID> {
    response
        .effects
        .as_ref()
        .and_then(|_effects| {
            response.object_changes.as_ref().and_then(|changes| {
                changes.iter().find_map(|change| {
                    if let sui_sdk::rpc_types::ObjectChange::Created {
                        object_id,
                        object_type,
                        ..
                    } = change
                    {
                        if object_type.to_string().contains("Committee") {
                            Some(*object_id)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
            })
        })
        .ok_or_else(|| anyhow!("Could not find created Committee object"))
}

/// Get shared object argument for a committee object using gRPC.
async fn get_shared_committee_arg(
    grpc_client: &mut sui_rpc::client::Client,
    committee_id: ObjectID,
    mutable: bool,
) -> Result<ObjectArg> {
    let mut ledger_client = grpc_client.ledger_client();

    let mut request = sui_rpc::proto::sui::rpc::v2::GetObjectRequest::default();
    request.object_id = Some(committee_id.to_string());
    request.read_mask = Some(prost_types::FieldMask {
        paths: vec!["owner".to_string()],
    });

    let response = ledger_client
        .get_object(request)
        .await
        .map(|r| r.into_inner())?;

    let object = response
        .object
        .ok_or_else(|| anyhow!("Committee object not found"))?;

    let owner = object
        .owner
        .ok_or_else(|| anyhow!("Committee object has no owner"))?;

    // For shared objects, version field contains the initial_shared_version
    let initial_shared_version = owner
        .version
        .ok_or_else(|| anyhow!("Shared object has no version"))?;

    Ok(ObjectArg::SharedObject {
        id: committee_id,
        initial_shared_version: initial_shared_version.into(),
        mutability: if mutable {
            SharedObjectMutability::Mutable
        } else {
            SharedObjectMutability::Immutable
        },
    })
}

/// Shared logic for creating DKG state and message.
async fn create_dkg_state_and_message(
    state_dir: &Path,
    config: &Path,
    keys_file: &Path,
    old_share: Option<String>,
) -> Result<()> {
    // Load config to get parameters
    let config_content = load_config(config)?;

    // Get my_address from config
    let addr_str = get_config_field(&config_content, &["genkey-and-register"], "MY_ADDRESS")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("MY_ADDRESS not found in config"))?;
    let my_address = Address::from_str(addr_str)?;

    // Get committee_id from config
    let id_str = get_config_field(
        &config_content,
        &["publish-and-init", "init-rotation"],
        "COMMITTEE_ID",
    )
    .and_then(|v| v.as_str())
    .ok_or_else(|| anyhow!("COMMITTEE_ID not found in config"))?;
    let committee_id = Address::from_str(id_str)?;

    // Get network from config
    let network = get_network(&config_content)?;

    let local_keys = KeysFile::load(keys_file)?;

    // Parse old share from command argument if provided. Provided for continuing members
    // in key rotation.
    let (my_old_share, my_old_pk) = if let Some(share_hex) = old_share {
        let key_share: G2Scalar = bcs::from_bytes(&Hex::decode(&share_hex)?)?;
        let key_pk = G2Element::generator() * key_share;
        println!("Continuing member for key rotation, old share parsed.");
        (Some(key_share), Some(key_pk))
    } else {
        (None, None)
    };

    // Fetch current committee from onchain.
    let mut grpc_client = create_grpc_client(&network)?;
    let committee = fetch_committee_data(&mut grpc_client, &committee_id).await?;

    // Validate committee state contains my address.
    if !committee.contains(&my_address) {
        return Err(anyhow!(
            "Address {} is not a member of committee {}",
            my_address,
            committee_id
        ));
    }

    println!(
        "Fetched committee with {} members, threshold: {}",
        committee.members.len(),
        committee.threshold
    );

    // Fetch members info.
    let members_info = committee.get_members_info()?;

    let my_member_info = members_info
        .get(&my_address)
        .ok_or_else(|| anyhow!("Address {} not found in committee members", my_address))?;
    let my_party_id = my_member_info.party_id;
    let registered_enc_pk = &my_member_info.enc_pk;
    let registered_signing_pk = &my_member_info.signing_pk;

    // Validate PK locally vs registration onchain.
    if &local_keys.enc_pk != registered_enc_pk || &local_keys.signing_pk != registered_signing_pk {
        return Err(anyhow!(
            "Mismatched PK for address {}!\n\
            ECIES PK Derived from secret: {}\n\
            Registered onchain: {}\n\
            Signing PK Derived from secret: {}\n\
            Registered onchain: {}",
            my_address,
            to_hex(&local_keys.enc_pk)?,
            to_hex(&my_member_info.enc_pk)?,
            to_hex(&local_keys.signing_pk)?,
            to_hex(&my_member_info.signing_pk)?
        ));
    }
    println!("Registered public keys onchain validated. My party ID: {my_party_id}");

    // Get old committee params for key rotation.
    let (old_threshold, new_to_old_mapping, expected_old_pks) = match committee.old_committee_id {
        None => {
            if my_old_share.is_some() {
                return Err(anyhow!("--old-share should not be provided for fresh DKG."));
            }
            println!("No old committee ID, performing fresh DKG.");
            (None, None, None)
        }
        Some(old_committee_id) => {
            println!("Old committee ID: {old_committee_id}, performing key rotation.");

            let old_committee = fetch_committee_data(&mut grpc_client, &old_committee_id).await?;
            let old_threshold = Some(old_committee.threshold);
            let new_to_old_mapping = build_new_to_old_map(&committee, &old_committee);

            // Fetch partial key server info from the old committee's key server object.
            let (_, ks) =
                fetch_key_server_by_committee(&mut grpc_client, &old_committee_id).await?;
            let old_partial_key_infos = to_partial_key_servers(&ks).await?;

            // Build mapping from old party ID to partial public key.
            let expected_old_pks: HashMap<u16, G2Element> = old_partial_key_infos
                .into_values()
                .map(|info| (info.party_id, info.partial_pk))
                .collect();

            // Validate my_old_share and membership in old committee.
            match my_old_share {
                Some(_) => {
                    if !old_committee.contains(&my_address) {
                        return Err(anyhow!(
                            "Invalid state: My address {} not found in old committee {} so I am a new member. Do not provide `--old-share` for key rotation.",
                            my_address,
                            old_committee_id
                        ));
                    }
                    println!("Continuing member for key rotation.");
                }
                None => {
                    if old_committee.contains(&my_address) {
                        return Err(anyhow!(
                            "Invalid state: My address {} found in old committee {} so I am a continuing member. Must provide `--old-share` for key rotation.",
                            my_address,
                            old_committee_id
                        ));
                    }
                    println!("New member for key rotation.");
                }
            }
            (
                old_threshold,
                Some(new_to_old_mapping),
                Some(expected_old_pks),
            )
        }
    };

    // Create nodes for all parties with their enc_pks and collect signing pks.
    let mut nodes = Vec::new();
    let mut signing_pks = HashMap::new();
    for (_, m) in members_info {
        nodes.push(Node {
            id: m.party_id,
            pk: m.enc_pk,
            weight: 1,
        });
        signing_pks.insert(m.party_id, m.signing_pk);
    }

    // Create message if:
    // - Fresh DKG: everyone creates a message (old_threshold is None).
    // - Rotation: only continuing members create a message (my_old_share is Some).
    let my_message = if old_threshold.is_none() || my_old_share.is_some() {
        println!("Creating DKG message for party {my_party_id}...");
        let random_oracle = RandomOracle::new(&committee_id.to_string());
        let party = Party::<G2Element, G2Element>::new_advanced(
            local_keys.enc_sk.clone(),
            Nodes::new(nodes.clone())?.clone(),
            committee.threshold,
            random_oracle,
            my_old_share,
            old_threshold,
            &mut thread_rng(),
        )?;

        let message = party.create_message(&mut thread_rng())?;
        let nizk_proof = party.nizk_pop_of_secret(&mut thread_rng());
        let signed_message = sign_message(message.clone(), &local_keys.signing_sk, nizk_proof);

        // Write message to file.
        let message_base64 = Base64::encode(bcs::to_bytes(&signed_message)?);
        let message_file = state_dir.join(format!("message_{my_party_id}.json"));

        let message_json = serde_json::json!({
            "message": message_base64
        });
        fs::write(&message_file, serde_json::to_string_pretty(&message_json)?)?;

        println!(
            "DKG message written to: {}. Share this file with the coordinator.",
            message_file.display()
        );
        Some(message)
    } else {
        println!("New member in rotation, skipping message creation.");
        None
    };

    let state = DkgState {
        config: InitializedConfig {
            my_party_id,
            nodes: Nodes::new(nodes)?,
            committee_id,
            threshold: committee.threshold,
            signing_pks,
            old_threshold,
            new_to_old_mapping,
            expected_old_pks,
            my_old_share,
            my_old_pk,
        },
        my_message,
        received_messages: HashMap::new(),
        processed_messages: vec![],
        confirmation: None,
        output: None,
    };

    state.save(state_dir)?;
    println!("State saved to {state_dir:?}. Wait for coordinator to announce phase 3.");
    Ok(())
}

/// Load wallet context from path.
fn load_wallet(
    wallet_path: Option<&Path>,
    active_address: Option<SuiAddress>,
) -> Result<WalletContext> {
    let config_path = if let Some(path) = wallet_path {
        path.to_path_buf()
    } else {
        let mut default = dirs::home_dir().ok_or_else(|| anyhow!("Cannot find home directory"))?;
        default.extend([".sui", "sui_config", "client.yaml"]);
        default
    };

    let mut wallet = WalletContext::new(&config_path).context("Failed to load wallet context")?;

    // Override active address if specified.
    if let Some(addr) = active_address {
        wallet.config.active_address = Some(addr);
    }

    Ok(wallet)
}

/// Helper function to write a file with restricted permissions (owner only) in Unix systems.
fn write_secret_file(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content)?;
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Helper function to BCS-serialize and format any serializable value as hex string with 0x prefix.
fn to_hex<T: Serialize>(value: &T) -> Result<String> {
    Ok(Hex::encode_with_format(&bcs::to_bytes(value)?))
}

/// Load YAML configuration file.
fn load_config(path: &Path) -> Result<serde_yaml::Value> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse YAML config: {}", path.display()))
}

/// Get a field from config, checking nested sections first, then flat structure.
fn get_config_field<'a>(
    config: &'a serde_yaml::Value,
    sections: &[&str],
    field: &str,
) -> Option<&'a serde_yaml::Value> {
    for section in sections {
        if let Some(section_val) = config.get(section)
            && let Some(field_val) = section_val.get(field)
        {
            return Some(field_val);
        }
    }
    None
}

/// Get network from config.
fn get_network(config: &serde_yaml::Value) -> Result<Network> {
    let network_val = get_config_field(config, &["init-params"], "NETWORK")
        .ok_or_else(|| anyhow!("NETWORK not found in config"))?;

    let network_str = if let Some(s) = network_val.as_str() {
        s
    } else if let Some(mapping) = network_val.as_mapping() {
        // Handle tagged enum like !Testnet
        mapping
            .keys()
            .next()
            .and_then(|k| k.as_str())
            .ok_or_else(|| anyhow!("Invalid NETWORK format"))?
    } else {
        bail!("Invalid NETWORK format");
    };

    Network::from_str(&network_str.to_lowercase()).map_err(|e| anyhow!(e))
}

/// Get members list from config.
fn get_members(config: &serde_yaml::Value) -> Result<Vec<SuiAddress>> {
    let members = get_config_field(config, &["init-params"], "MEMBERS")
        .and_then(|v| v.as_sequence())
        .ok_or_else(|| anyhow!("MEMBERS list not found or invalid in config"))?;

    if members.is_empty() {
        bail!("MEMBERS list is empty");
    }

    members
        .iter()
        .map(|member| {
            let addr_str = member
                .as_str()
                .ok_or_else(|| anyhow!("Member address must be a string"))?;
            SuiAddress::from_str(addr_str).context("Invalid member address")
        })
        .collect()
}

/// Get threshold from config.
fn get_threshold(config: &serde_yaml::Value) -> Result<u16> {
    let threshold = get_config_field(config, &["init-params"], "THRESHOLD")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("THRESHOLD not found or invalid in config"))?;

    if threshold <= 1 {
        bail!("THRESHOLD must be greater than 1, got {}", threshold);
    }

    Ok(threshold as u16)
}

/// Validate required fields exist in config (checking nested sections).
fn validate_required_fields(
    config: &serde_yaml::Value,
    required_fields: &[(&str, &[&str])], // (field_name, sections_to_check)
    command_name: &str,
    suggestion: &str,
) -> Result<()> {
    let missing: Vec<_> = required_fields
        .iter()
        .filter(|(field, sections)| get_config_field(config, sections, field).is_none())
        .map(|(field, _)| field)
        .collect();

    if !missing.is_empty() {
        let mut error_msg = format!(
            "\n[ERROR] Missing required fields for '{}':\n",
            command_name
        );
        for field in missing {
            error_msg.push_str(&format!("  - {}\n", field));
        }
        error_msg.push_str(&format!("\nSuggestion: {}\n", suggestion));
        bail!(error_msg);
    }

    Ok(())
}

/// Update fields within a specific section of the YAML config with hex-encoded byte values.
fn update_config_bytes_val(path: &Path, section: &str, updates: Vec<(&str, &[u8])>) -> Result<()> {
    let string_updates: Vec<(&str, String)> = updates
        .into_iter()
        .map(|(key, bytes)| (key, Hex::encode_with_format(bytes)))
        .collect();
    let string_refs: Vec<(&str, &str)> = string_updates
        .iter()
        .map(|(k, v)| (*k, v.as_str()))
        .collect();
    update_config_string_val(path, section, string_refs)
}

/// Update fields within a specific section of the YAML config with string values.
fn update_config_string_val(path: &Path, section: &str, updates: Vec<(&str, &str)>) -> Result<()> {
    let content = fs::read_to_string(path)?;
    let mut config: serde_yaml::Value = serde_yaml::from_str(&content)?;

    // Ensure the section exists
    if config.get(section).is_none() {
        config[section] = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }

    // Update fields in the section
    for (key, value) in updates {
        let yaml_value: serde_yaml::Value = serde_yaml::from_str(value)
            .unwrap_or_else(|_| serde_yaml::Value::String(value.to_string()));
        config[section][key] = yaml_value;
    }

    let updated = serde_yaml::to_string(&config)?;
    fs::write(path, updated)?;
    Ok(())
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

/// Load DKG messages from a directory
fn load_messages_from_dir(messages_dir: &Path) -> Result<Vec<SignedMessage>> {
    let mut messages = Vec::new();
    let entries = fs::read_dir(messages_dir).map_err(|e| {
        anyhow!(
            "Failed to read messages directory {:?}: {}",
            messages_dir,
            e
        )
    })?;

    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let content = fs::read_to_string(&path)
            .map_err(|e| anyhow!("Failed to read {}: {}", path.display(), e))?;

        let json: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse {}: {}", path.display(), e))?;

        let message_base64 = json["message"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing 'message' field in {}", path.display()))?;

        let signed_message: SignedMessage = bcs::from_bytes(&Base64::decode(message_base64)?)
            .map_err(|e| {
                anyhow!(
                    "Failed to deserialize message from {}: {}",
                    path.display(),
                    e
                )
            })?;

        messages.push(signed_message);
    }

    if messages.is_empty() {
        bail!("No message files found in directory: {:?}", messages_dir);
    }

    Ok(messages)
}

/// Process DKG messages and complete the protocol
fn process_dkg_messages(
    state: &mut DkgState,
    messages: Vec<SignedMessage>,
    local_keys: &KeysFile,
) -> Result<fastcrypto_tbls::dkg_v1::Output<G2Element, G2Element>> {
    println!("Processing {} message(s)...", messages.len());

    // Validate message count
    if let Some(old_threshold) = state.config.old_threshold {
        if messages.len() != old_threshold as usize {
            bail!(
                "Key rotation requires exactly {} messages from continuing members, got {}",
                old_threshold,
                messages.len()
            );
        }
    } else {
        let num_parties = state.config.nodes.num_nodes();
        if messages.len() != num_parties {
            bail!(
                "Fresh DKG requires {} messages (one from each party), got {}",
                num_parties,
                messages.len()
            );
        }
    }

    // Create party
    let party = Party::<G2Element, G2Element>::new_advanced(
        local_keys.enc_sk.clone(),
        state.config.nodes.clone(),
        state.config.threshold,
        RandomOracle::new(&state.config.committee_id.to_string()),
        state.config.my_old_share,
        state.config.old_threshold,
        &mut thread_rng(),
    )?;

    // Process each message
    for signed_msg in messages {
        let sender_party_id = signed_msg.message.sender;
        println!("Processing message from party {sender_party_id}...");

        let sender_signing_pk = state
            .config
            .signing_pks
            .get(&sender_party_id)
            .ok_or_else(|| anyhow!("Signing public key not found for party {}", sender_party_id))?;
        verify_signature(&signed_msg, sender_signing_pk)?;

        let processed = if state.config.old_threshold.is_some() {
            let new_to_old_mapping = state
                .config
                .new_to_old_mapping
                .as_ref()
                .ok_or_else(|| anyhow!("Missing new-to-old mapping for key rotation"))?;
            let old_party_id = new_to_old_mapping.get(&sender_party_id).ok_or_else(|| {
                anyhow!(
                    "Party {} not found in old committee mapping",
                    sender_party_id
                )
            })?;
            let expected_old_pks = state
                .config
                .expected_old_pks
                .as_ref()
                .ok_or_else(|| anyhow!("Missing expected old partial PKs for key rotation"))?;
            let expected_pk = expected_old_pks
                .get(old_party_id)
                .ok_or_else(|| anyhow!("Partial PK not found for old party {}", old_party_id))?;

            party
                .process_message_with_checks(
                    signed_msg.message.clone(),
                    &Some(*expected_pk),
                    &Some(signed_msg.nizk_proof.clone()),
                    &mut thread_rng(),
                )
                .map_err(|e| {
                    anyhow!("Key rotation verification failed for party {sender_party_id}: {e}")
                })?
        } else {
            party.process_message_with_checks(
                signed_msg.message.clone(),
                &None,
                &Some(signed_msg.nizk_proof.clone()),
                &mut thread_rng(),
            )?
        };

        if let Some(complaint) = &processed.complaint {
            bail!(
                "Do NOT propose onchain. Complaint found {:?} for party {}",
                complaint,
                processed.message.sender
            );
        }
        println!("Successfully processed message from party {sender_party_id}");
        state.processed_messages.push(processed);
    }

    // Merge and complete
    let (confirmation, used_msgs) = party.merge(&state.processed_messages)?;

    if !confirmation.complaints.is_empty() {
        bail!(
            "Do NOT propose onchain. Complaint(s) found: {:?}",
            confirmation.complaints
        );
    }

    state.confirmation = Some((confirmation, used_msgs.clone()));

    let output = if state.config.old_threshold.is_some() {
        let new_to_old_mapping = state
            .config
            .new_to_old_mapping
            .as_ref()
            .ok_or_else(|| anyhow!("Missing new-to-old mapping for key rotation"))?;
        let sender_to_old_map: HashMap<u16, u16> = new_to_old_mapping
            .iter()
            .map(|(new_id, old_id)| (*new_id, *old_id))
            .collect();

        println!("Completing key rotation with mapping: {sender_to_old_map:?}");
        party.complete_optimistic_key_rotation(&used_msgs, &sender_to_old_map)?
    } else {
        party.complete_optimistic(&used_msgs)?
    };

    state.output = Some(output.clone());
    Ok(output)
}

/// Determine the committee version from the network
async fn determine_committee_version(network: &Network, committee_id: &Address) -> Result<u32> {
    let mut grpc_client = create_grpc_client(network)?;
    let committee = fetch_committee_data(&mut grpc_client, committee_id).await?;

    if let Some(old_committee_id) = committee.old_committee_id {
        // Rotation: fetch the old committee's KeyServer version then increment by 1
        match fetch_key_server_by_committee(&mut grpc_client, &old_committee_id).await {
            Ok((_, key_server_v2)) => match key_server_v2.server_type {
                ServerType::Committee { version, .. } => {
                    println!(
                        "Old committee version: {}, new version will be: {}",
                        version,
                        version + 1
                    );
                    Ok(version + 1)
                }
                _ => bail!("Old KeyServer is not of type Committee"),
            },
            Err(e) => {
                bail!(
                    "Failed to fetch old committee's KeyServer for rotation: {}",
                    e
                );
            }
        }
    } else {
        // Fresh DKG: version is 0
        println!("Fresh DKG, version will be: 0");
        Ok(0)
    }
}
