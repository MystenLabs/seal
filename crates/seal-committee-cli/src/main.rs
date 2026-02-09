// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

mod types;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use fastcrypto::bls12381::min_sig::BLS12381KeyPair;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::groups::bls12381::{G1Element, G2Element, Scalar as G2Scalar};
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
    build_new_to_old_map, create_grpc_client, fetch_committee_data,
    fetch_committee_from_key_server, fetch_key_server_by_committee, fetch_upgrade_manager,
    fetch_upgrade_proposal, CommitteeState, KeyServerV2, Network, ServerType, UpgradeVote,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use sui_move_build::BuildConfig;
use sui_package_alt::{mainnet_environment, testnet_environment};
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_sdk::rpc_types::{SuiTransactionBlockEffectsAPI, SuiTransactionBlockResponse};
use sui_sdk::wallet_context::WalletContext;
use sui_sdk_types::{Address, StructTag};
use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use sui_types::transaction::{ObjectArg, SharedObjectMutability, TransactionData};
use sui_types::{
    base_types::{ObjectID, SuiAddress},
    object::Owner,
};
use types::{DkgState, InitializedConfig, KeysFile};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::types::{sign_message, verify_signature, SignedMessage};

#[derive(Parser)]
#[command(name = "seal-committee-cli")]
#[command(about = "Seal committee CLI tool for DKG ceremony and contract upgrades.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to Sui wallet config (default: ~/.sui/sui_config/client.yaml).
    #[arg(long, global = true)]
    wallet: Option<PathBuf>,

    /// Override the active address from the wallet config.
    #[arg(long, global = true)]
    active_address: Option<SuiAddress>,

    /// Gas budget for transactions (default: 100000000 = 0.1 SUI).
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

        /// Directory containing message_*.json files (overrides default <state_dir>/dkg-messages).
        #[arg(short = 'm', long)]
        messages_dir: Option<PathBuf>,

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

    /// Compute package digest for upgrade verification.
    PackageDigest {
        /// Path to the Move package to build and compute digest for.
        #[arg(short, long, default_value = "move/committee")]
        package_path: PathBuf,

        /// Network to build for (Testnet or Mainnet).
        #[arg(short, long)]
        network: String,
    },

    /// Approve package upgrade (as committee member).
    ApproveUpgrade {
        /// Path to the Move package to upgrade to.
        #[arg(short, long, default_value = "move/committee")]
        package_path: PathBuf,

        /// Key server object ID.
        #[arg(short, long)]
        key_server_id: String,

        /// Network to use.
        #[arg(short, long)]
        network: String,
    },

    /// Reject package upgrade (as committee member).
    RejectUpgrade {
        /// Path to the Move package to upgrade to.
        #[arg(short, long, default_value = "move/committee")]
        package_path: PathBuf,

        /// Key server object ID.
        #[arg(short, long)]
        key_server_id: String,

        /// Network to use.
        #[arg(short, long)]
        network: String,
    },

    /// Authorize and execute package upgrade (after threshold of approvals is reached).
    AuthorizeAndUpgrade {
        /// Path to the Move package to upgrade to.
        #[arg(short, long, default_value = "move/committee")]
        package_path: PathBuf,

        /// Key server object ID.
        #[arg(short, long)]
        key_server_id: String,

        /// Network to use.
        #[arg(short, long)]
        network: String,
    },

    /// Reset upgrade proposal (if threshold of rejections is reached).
    ResetProposal {
        /// Key server object ID.
        #[arg(short, long)]
        key_server_id: String,

        /// Network to use.
        #[arg(short, long)]
        network: String,
    },

    /// Check key server status, including the committee that owns it, and the UpgradeManager with proposal status held by this committee.
    CheckKeyServerStatus {
        /// Key server object ID.
        #[arg(short, long)]
        key_server_id: String,

        /// Network to use.
        #[arg(short, long)]
        network: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::PublishAndInit { config } => {
            let config_content = load_config(&config)?;

            // Check if already initialized.
            if config_content.get("COMMITTEE_PKG").is_some()
                || config_content.get("COMMITTEE_ID").is_some()
            {
                println!("Committee already initialized. Skipping publish and init. Remove these fields from config to reinitialize.");
                return Ok(());
            }

            let network = get_network(&config_content)?;
            let members = get_members(&config_content)?;
            let threshold = get_threshold(&config_content)?;

            // Load wallet.
            let mut wallet = load_wallet(cli.wallet.as_deref(), cli.active_address)?;
            let coordinator_address = wallet.active_address()?;

            println!("Using coordinator address: {}", coordinator_address);
            println!("Network: {:?}", network);
            println!("Members: {} addresses", members.len());
            println!("Threshold: {}", threshold);

            // Get committee package path.
            let committee_path = std::env::current_dir()?.join("move/committee");
            if !committee_path.exists() {
                bail!(
                    "Committee package not found at: {}",
                    committee_path.display()
                );
            }

            // Remove Published.toml to ensure fresh publish for committee package.
            let published_toml = committee_path.join("Published.toml");
            if published_toml.exists() {
                println!(
                    "Removing {} to enable fresh publish...",
                    published_toml.display()
                );
                fs::remove_file(published_toml)?;
            }

            // Build and publish package.
            let compiled_package = create_build_config(&network).build(&committee_path)?;
            let compiled_modules_bytes = compiled_package.get_package_bytes(false);

            let mut grpc_client = create_grpc_client(&network)?;
            let (gas_price, gas_budget, gas_coin_ref) = get_gas_params(
                &mut grpc_client,
                &wallet,
                coordinator_address,
                cli.gas_budget,
            )
            .await?;

            let dependencies: Vec<ObjectID> = compiled_package
                .dependency_ids
                .published
                .into_values()
                .collect();

            let mut builder = ProgrammableTransactionBuilder::new();
            let upgrade_cap = builder.publish_upgradeable(compiled_modules_bytes, dependencies);
            builder.transfer_arg(coordinator_address, upgrade_cap);

            let tx_data = TransactionData::new_programmable(
                coordinator_address,
                vec![gas_coin_ref],
                builder.finish(),
                gas_budget,
                gas_price,
            );

            println!("\nExecuting publish transaction...");
            let response = execute_tx_and_log_status(&wallet, tx_data).await?;

            // Extract published package ID, UpgradeCap, and InitCap.
            let effects = response
                .effects
                .as_ref()
                .ok_or_else(|| anyhow!("No effects in transaction response"))?;

            let package_id = effects
                .created()
                .iter()
                .find_map(|obj_ref| {
                    if matches!(obj_ref.owner, Owner::Immutable) {
                        Some(obj_ref.reference.object_id)
                    } else {
                        None
                    }
                })
                .ok_or_else(|| anyhow!("Could not find published package ID"))?;

            println!("Published package: {}", package_id);

            // Find UpgradeCap and InitCap.
            let upgrade_cap_id = extract_created_object_by_type(&response, "UpgradeCap")?;
            let init_cap_id = extract_created_object_by_type(&response, "InitCap")?;

            println!("UpgradeCap ID: {}", upgrade_cap_id);
            println!("InitCap ID: {}", init_cap_id);

            // Initialize the committee with InitCap and UpgradeCap.
            let mut init_builder = ProgrammableTransactionBuilder::new();

            // Get object args for InitCap and UpgradeCap.
            let init_cap_ref = wallet.get_object_ref(init_cap_id).await?;
            let init_cap_arg = init_builder.obj(ObjectArg::ImmOrOwnedObject(init_cap_ref))?;

            let upgrade_cap_ref = wallet.get_object_ref(upgrade_cap_id).await?;
            let upgrade_cap_arg = init_builder.obj(ObjectArg::ImmOrOwnedObject(upgrade_cap_ref))?;

            let threshold_arg = init_builder.pure(threshold)?;
            let members_arg = init_builder.pure(members)?;

            init_builder.programmable_move_call(
                package_id,
                "seal_committee".parse()?,
                "init_committee".parse()?,
                vec![],
                vec![init_cap_arg, upgrade_cap_arg, threshold_arg, members_arg],
            );

            let init_gas_coin_ref = wallet
                .gas_for_owner_budget(coordinator_address, gas_budget, Default::default())
                .await?
                .1
                .object_ref();

            let init_tx_data = TransactionData::new_programmable(
                coordinator_address,
                vec![init_gas_coin_ref],
                init_builder.finish(),
                gas_budget,
                gas_price,
            );

            println!("\nExecuting init_committee transaction...");
            let init_response = execute_tx_and_log_status(&wallet, init_tx_data).await?;

            // Extract committee ID.
            let committee_id = extract_created_committee_id(&init_response)?;
            println!("Created committee: {}", committee_id);

            // Update config.
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
                "\nUpdated file {} publish-and-init section with COMMITTEE_PKG, COMMITTEE_ID, and COORDINATOR_ADDRESS. Share this file with committee members.",
                config.display()
            );
        }

        Commands::InitRotation { config } => {
            let config_content = load_config(&config)?;

            if get_config_field(&config_content, &["init-rotation"], "COMMITTEE_ID").is_some() {
                println!("Committee rotation already initialized. Skipping init-rotation. Remove COMMITTEE_ID from config to re-initialize.");
                return Ok(());
            }

            let key_server_obj_id = get_key_server_obj_id(&config_content)?;
            let network = get_network(&config_content)?;
            let members = get_members(&config_content)?;
            let threshold = get_threshold(&config_content)?;

            // Load wallet.
            let mut wallet = load_wallet(cli.wallet.as_deref(), cli.active_address)?;
            let coordinator_address = wallet.active_address()?;
            println!("Using coordinator address: {}", coordinator_address);

            // Fetch key server and extract current committee ID from owner field.
            println!("\nFetching key server: {}...", key_server_obj_id);

            let mut grpc_client = create_grpc_client(&network)?;
            let mut ledger_client = grpc_client.ledger_client();
            let mut ks_request = GetObjectRequest::default();
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

            // Parse owner as Address.
            let owner_address = owner_data
                .address
                .ok_or_else(|| anyhow!("Owner has no address"))?;
            let field_wrapper_id = Address::from_str(&owner_address)?;

            // Fetch field wrapper and extract committee ID.
            let mut fw_request = GetObjectRequest::default();
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

            let field: seal_committee::FieldWrapper<Address, Address> =
                bcs::from_bytes(fw_struct.contents())?;
            let current_committee_id = field.name.name;
            println!("\nCurrent committee ID: {}", current_committee_id);

            // Get package ID from type info.
            let mut committee_request = GetObjectRequest::default();
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

            // Parse from package_id::module::Type.
            let struct_tag = StructTag::from_str(&object_type)?;
            let package_id = ObjectID::new(struct_tag.address().into_inner());
            println!("Committee package ID: {}", package_id);

            // Update config.
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

            // Call init_rotation.
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

            let (gas_price, gas_budget, gas_coin_ref) = get_gas_params(
                &mut grpc_client,
                &wallet,
                coordinator_address,
                cli.gas_budget,
            )
            .await?;

            let rotation_tx_data = TransactionData::new_programmable(
                coordinator_address,
                vec![gas_coin_ref],
                rotation_builder.finish(),
                gas_budget,
                gas_price,
            );

            println!("\nExecuting init_rotation transaction...");
            let rotation_response = execute_tx_and_log_status(&wallet, rotation_tx_data).await?;

            // Extract new committee ID.
            let new_committee_id = extract_created_committee_id(&rotation_response)?;
            println!("Created new committee for rotation: {}", new_committee_id);

            // Update config with new committee ID.
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
            let (config, keys_file) = derive_paths(&state_dir, config, keys_file);
            let config_content = load_config(&config)?;

            // Check if already generated keys.
            if get_config_field(&config_content, &["genkey-and-register"], "DKG_ENC_PK").is_some()
                || get_config_field(&config_content, &["genkey-and-register"], "DKG_SIGNING_PK")
                    .is_some()
            {
                println!("Keys already generated. Skipping key generation and registration. Remove the genkey-and-register section from the config file to re-run this operation.");
                println!(
                    "WARNING: If these keys were already registered onchain, need to restart from publish-and-init step."
                );
                return Ok(());
            }

            // Validate inputs.
            if server_url.trim().is_empty() || server_name.trim().is_empty() {
                bail!("Server URL and name are required.");
            }

            // Load wallet.
            let mut wallet = load_wallet(cli.wallet.as_deref(), cli.active_address)?;
            let my_address = wallet.active_address()?;

            println!("\n=== Getting active address from wallet ===");
            println!("Active address: {}", my_address);
            println!("Server URL: {}", server_url);
            println!("Server Name: {}", server_name);

            // Update config with my address, server URL, and server name.
            update_config_bytes_val(
                &config,
                "genkey-and-register",
                vec![("MY_ADDRESS", my_address.as_ref())],
            )?;
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

            // Reload config.
            let config_content = load_config(&config)?;

            let committee_pkg = get_committee_pkg(&config_content)?;
            let committee_id = get_committee_id(&config_content)?;

            // Generate keys.
            println!("\n=== Generating DKG keys ===");
            let enc_sk = PrivateKey::<G1Element>::new(&mut thread_rng());
            let enc_pk = PublicKey::<G1Element>::from_private_key(&enc_sk);

            let signing_kp = BLS12381KeyPair::generate(&mut thread_rng());
            let signing_pk = signing_kp.public().clone();
            let signing_sk = signing_kp.private();

            // Serialize keys to BCS bytes.
            let enc_pk_bytes = bcs::to_bytes(&enc_pk)?;
            let signing_pk_bytes = bcs::to_bytes(&signing_pk)?;

            let created_keys_file = KeysFile {
                enc_sk,
                enc_pk,
                signing_sk,
                signing_pk,
            };

            // Write keys to file.
            let json_content = serde_json::to_string_pretty(&created_keys_file)?;
            if let Some(parent) = keys_file.parent() {
                fs::create_dir_all(parent)?;
            }
            write_secret_file(&keys_file, &json_content)?;

            // Update config with public keys.
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

            println!("\n=== Registering onchain ===");
            let network = get_network(&config_content)?;
            let mut grpc_client = create_grpc_client(&network)?;

            // Register onchain.
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

            let (gas_price, gas_budget, gas_coin_ref) =
                get_gas_params(&mut grpc_client, &wallet, my_address, cli.gas_budget).await?;

            let register_tx_data = TransactionData::new_programmable(
                my_address,
                vec![gas_coin_ref],
                register_builder.finish(),
                gas_budget,
                gas_price,
            );

            println!("\nExecuting register transaction...");
            let _register_response = execute_tx_and_log_status(&wallet, register_tx_data).await?;

            println!("\n Keys generated and registered onchain!");
            println!(
                "\nYour DKG private keys are stored in: {}",
                keys_file.display()
            );
        }

        Commands::InitState {
            state_dir,
            config,
            keys_file,
        } => {
            let (config, keys_file) = derive_paths(&state_dir, config, keys_file);

            // Call shared function with no old share.
            create_dkg_state_and_message(&state_dir, &config, &keys_file, None).await?;
        }

        Commands::CreateMessage {
            state_dir,
            config,
            keys_file,
            old_share,
        } => {
            let (config, keys_file) = derive_paths(&state_dir, config, keys_file);
            create_dkg_state_and_message(&state_dir, &config, &keys_file, old_share).await?;
        }
        Commands::ProcessAllAndPropose {
            state_dir,
            messages_dir,
            config,
            keys_file,
        } => {
            let (config, keys_file) = derive_paths(&state_dir, config, keys_file);
            let full_messages_dir = messages_dir.unwrap_or_else(|| state_dir.join("dkg-messages"));
            let config_content = load_config(&config)?;

            let committee_pkg = get_committee_pkg(&config_content)?;
            let committee_id = get_committee_id(&config_content)?;
            let my_address = SuiAddress::from_bytes(get_my_address(&config_content)?.inner())?;
            let network = get_network(&config_content)?;

            // Check if this is a rotation.
            let current_committee_id =
                get_config_field(&config_content, &["init-rotation"], "CURRENT_COMMITTEE_ID")
                    .and_then(|v| v.as_str())
                    .map(ObjectID::from_hex_literal)
                    .transpose()?;
            let is_rotation = current_committee_id.is_some();

            // Process DKG messages.
            println!("\n=== Processing DKG messages ===");
            println!("  Messages directory: {:?}", full_messages_dir);
            println!("  State directory: {:?}", state_dir);
            println!("  Keys file: {:?}\n", keys_file);

            let mut state = DkgState::load(&state_dir)?;
            let local_keys = KeysFile::load(&keys_file)?;

            // Load and process all messages.
            let messages = load_messages_from_dir(&full_messages_dir)?;
            let output = process_dkg_messages(&mut state, messages, &local_keys)?;

            // Determine version.
            let mut grpc_client = create_grpc_client(&network)?;
            let version =
                determine_committee_version(&mut grpc_client, &state.config.committee_id).await?;

            // Extract key server PK and master share.
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

            // Check if already written to config.
            let master_share_key = format!("MASTER_SHARE_V{}", version);
            let partial_pks_key = format!("PARTIAL_PKS_V{}", version);

            if get_config_field(
                &config_content,
                &["process-all-and-propose"],
                &master_share_key,
            )
            .is_some()
                || get_config_field(
                    &config_content,
                    &["process-all-and-propose"],
                    &partial_pks_key,
                )
                .is_some()
            {
                println!("[WARNING] Skipping processing and onchain proposal. To reprocess messages and propose onchain, remove the process-all-and-propose section from the config file.");
                return Ok(());
            }

            // Serialize partial_pks to yaml list.
            let mut partial_pks = Vec::new();
            for party_id in 0..state.config.nodes.num_nodes() {
                let share_index = NonZeroU16::new(party_id as u16 + 1).expect("must be valid");
                let partial_pk = output.vss_pk.eval(share_index);
                partial_pks.push(to_hex(&partial_pk.value)?);
            }
            let partial_pks_yaml = serde_yaml::to_string(&partial_pks)?;

            if version == 0 {
                // For v0, add KEY_SERVER_PK, PARTIAL_PKS_V0, MASTER_SHARE_V0.
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
                // For rotation, verify KEY_SERVER_PK matches, then add PARTIAL_PKS_VX and MASTER_SHARE_VX.
                if let Some(existing_key_server_pk) = get_config_field(
                    &config_content,
                    &["process-all-and-propose"],
                    "KEY_SERVER_PK",
                ) {
                    let existing_pk = existing_key_server_pk.as_str().unwrap_or("");
                    let key_server_pk_hex = Hex::encode_with_format(&key_server_pk_bytes);
                    if existing_pk != key_server_pk_hex {
                        bail!(
                            "KEY_SERVER_PK mismatch!\n  Expected (from v0): {}\n  Got (from rotation): {}",
                            existing_pk,
                            key_server_pk_hex
                        );
                    }
                    println!("✓ KEY_SERVER_PK unchanged.");
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

            // Load wallet.
            let wallet = load_wallet(cli.wallet.as_deref(), cli.active_address)?;

            if is_rotation {
                println!("\n=== Proposing committee rotation onchain ===");
                println!("  New Committee ID: {}", committee_id);
                println!("  Current Committee ID: {}", current_committee_id.unwrap());
            } else {
                println!("\n=== Proposing committee onchain ===");
            }

            // Propose committee onchain.
            let mut propose_builder = ProgrammableTransactionBuilder::new();

            let committee_arg = propose_builder
                .obj(get_shared_committee_arg(&mut grpc_client, committee_id, true).await?)?;
            let partial_pks_bytes: Vec<Vec<u8>> = partial_pks
                .iter()
                .map(|s| Hex::decode(s))
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
                // Use key server PK bytes directly.
                let key_server_pk_arg = propose_builder.pure(key_server_pk_bytes)?;

                propose_builder.programmable_move_call(
                    committee_pkg,
                    "seal_committee".parse()?,
                    "propose".parse()?,
                    vec![],
                    vec![committee_arg, partial_pks_arg, key_server_pk_arg],
                );
            }

            let (gas_price, gas_budget, gas_coin_ref) =
                get_gas_params(&mut grpc_client, &wallet, my_address, cli.gas_budget).await?;

            let propose_tx_data = TransactionData::new_programmable(
                my_address,
                vec![gas_coin_ref],
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
            println!("  Partial PKs: {} entries", partial_pks.len());
        }

        Commands::CheckCommittee { config } => {
            let config_content = load_config(&config)?;

            let committee_id = Address::from(get_committee_id(&config_content)?.into_bytes());
            let network = get_network(&config_content)?;

            // Fetch committee from onchain.
            let mut grpc_client = create_grpc_client(&network)?;
            let committee = fetch_committee_data(&mut grpc_client, &committee_id).await?;

            println!("Committee ID: {committee_id}");
            println!("Total members: {}", committee.members.len());
            println!("Threshold: {}", committee.threshold);
            println!("State: {:?}", committee.state);

            // Check which members are registered and approved based on state.
            match &committee.state {
                CommitteeState::Init { members_info } => {
                    let registered_addrs: HashSet<_> = members_info
                        .0
                        .contents
                        .iter()
                        .map(|entry| entry.key)
                        .collect();

                    let (registered, not_registered): (Vec<_>, Vec<_>) = committee
                        .members
                        .iter()
                        .copied()
                        .partition(|member_addr| registered_addrs.contains(member_addr));

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

                    // Show approval status.
                    let (approved, not_approved): (Vec<_>, Vec<_>) = committee
                        .members
                        .iter()
                        .copied()
                        .partition(|member_addr| approved_addrs.contains(member_addr));

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

                    match fetch_key_server_by_committee(&mut grpc_client, &committee_id).await {
                        Ok((ks_obj_id, key_server)) => {
                            println!("KEY_SERVER_OBJ_ID: {ks_obj_id}");

                            // Extract and print committee version.
                            match key_server.server_type {
                                ServerType::Committee { version, .. } => {
                                    println!("COMMITTEE_VERSION: {version}");
                                }
                                _ => {
                                    println!("Warning: KeyServer is not of type Committee");
                                }
                            }

                            // Display partial key servers.
                            display_partial_key_servers(&key_server).await?;
                        }
                        Err(e) => {
                            println!("Warning: Could not fetch key server object: {e}");
                        }
                    }
                }
            }
        }

        Commands::PackageDigest {
            package_path,
            network,
        } => {
            let network = Network::from_str(&network.to_lowercase())
                .map_err(|e| anyhow!("Invalid network: {}", e))?;

            compute_package_digest(&package_path, &network)?;
        }

        Commands::ApproveUpgrade {
            package_path,
            key_server_id,
            network,
        } => {
            let network = Network::from_str(&network.to_lowercase())
                .map_err(|e| anyhow!("Invalid network: {}", e))?;
            let mut wallet = load_wallet(cli.wallet.as_deref(), cli.active_address)?;
            vote_for_upgrade(
                &package_path,
                &key_server_id,
                &network,
                &mut wallet,
                cli.gas_budget,
                true, // approve
            )
            .await?;
        }

        Commands::RejectUpgrade {
            package_path,
            key_server_id,
            network,
        } => {
            let network = Network::from_str(&network.to_lowercase())
                .map_err(|e| anyhow!("Invalid network: {}", e))?;
            let mut wallet = load_wallet(cli.wallet.as_deref(), cli.active_address)?;
            vote_for_upgrade(
                &package_path,
                &key_server_id,
                &network,
                &mut wallet,
                cli.gas_budget,
                false, // reject
            )
            .await?;
        }

        Commands::AuthorizeAndUpgrade {
            package_path,
            key_server_id,
            network,
        } => {
            let network = Network::from_str(&network.to_lowercase())
                .map_err(|e| anyhow!("Invalid network: {}", e))?;

            // Load wallet.
            let mut wallet = load_wallet(cli.wallet.as_deref(), cli.active_address)?;
            let executor_address = wallet.active_address()?;

            println!("Executor address: {}", executor_address);
            println!("Network: {:?}", network);

            // Build package and compute digest.
            let digest = get_package_digest(&package_path, &network)?;
            println!("\nPackage digest: {}", digest);

            // Build the package to get compiled modules and dependencies.
            let compiled_package = create_build_config(&network).build(&package_path)?;
            let compiled_modules_bytes = compiled_package.get_package_bytes(false);

            // Fetch key server to get committee ID.
            let mut grpc_client = create_grpc_client(&network)?;
            let key_server_addr = Address::from_hex(&key_server_id)?;
            let (committee_id, _) =
                fetch_committee_from_key_server(&mut grpc_client, &key_server_addr).await?;

            // Fetch current package ID from UpgradeCap (not from Committee object type).
            let upgrade_manager = fetch_upgrade_manager(&mut grpc_client, &committee_id)
                .await?
                .ok_or_else(|| anyhow!("No UpgradeManager found for committee"))?;
            let committee_pkg = ObjectID::new(upgrade_manager.cap.package.into_inner());

            println!("Committee ID: {}", committee_id);
            println!("Current package: {}", committee_pkg);
            println!("Package version: {}", upgrade_manager.cap.version);

            let committee_obj_id = ObjectID::new(committee_id.into_inner());

            // Get dependencies for upgrade.
            let dependencies: Vec<ObjectID> = compiled_package
                .dependency_ids
                .published
                .into_values()
                .collect();

            // Build upgrade transaction: authorize + upgrade + commit.
            let mut upgrade_builder = ProgrammableTransactionBuilder::new();

            // Call authorize_upgrade.
            let committee_arg_auth = upgrade_builder
                .obj(get_shared_committee_arg(&mut grpc_client, committee_obj_id, true).await?)?;

            let upgrade_ticket = upgrade_builder.programmable_move_call(
                committee_pkg,
                "seal_committee".parse()?,
                "authorize_upgrade".parse()?,
                vec![],
                vec![committee_arg_auth],
            );

            // Perform upgrade.
            let upgrade_receipt = upgrade_builder.upgrade(
                committee_pkg,
                upgrade_ticket,
                dependencies,
                compiled_modules_bytes,
            );

            // Commit upgrade.
            let committee_arg_commit = upgrade_builder
                .obj(get_shared_committee_arg(&mut grpc_client, committee_obj_id, true).await?)?;

            upgrade_builder.programmable_move_call(
                committee_pkg,
                "seal_committee".parse()?,
                "commit_upgrade".parse()?,
                vec![],
                vec![committee_arg_commit, upgrade_receipt],
            );

            let (gas_price, gas_budget, gas_coin_ref) =
                get_gas_params(&mut grpc_client, &wallet, executor_address, cli.gas_budget).await?;

            let upgrade_tx_data = TransactionData::new_programmable(
                executor_address,
                vec![gas_coin_ref],
                upgrade_builder.finish(),
                gas_budget,
                gas_price,
            );

            println!("\nExecuting authorize, upgrade, and commit in one ptb...");
            let upgrade_response = execute_tx_and_log_status(&wallet, upgrade_tx_data).await?;

            // Extract new package ID.
            let new_package_id = upgrade_response
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
                .ok_or_else(|| anyhow!("Could not find upgraded package ID"))?;

            println!("\n✓ Successfully upgraded package!");
            println!("New package ID: {}", new_package_id);
        }

        Commands::ResetProposal {
            key_server_id,
            network,
        } => {
            let network = Network::from_str(&network.to_lowercase())
                .map_err(|e| anyhow!("Invalid network: {}", e))?;

            // Load wallet.
            let mut wallet = load_wallet(cli.wallet.as_deref(), cli.active_address)?;
            let member_address = wallet.active_address()?;

            println!("Member address: {}", member_address);
            println!("Network: {:?}", network);

            // Fetch key server to get committee ID.
            let mut grpc_client = create_grpc_client(&network)?;
            let key_server_addr = Address::from_hex(&key_server_id)?;
            let (committee_id, _) =
                fetch_committee_from_key_server(&mut grpc_client, &key_server_addr).await?;

            // Fetch current package ID from UpgradeCap.
            let upgrade_manager = fetch_upgrade_manager(&mut grpc_client, &committee_id)
                .await?
                .ok_or_else(|| anyhow!("No UpgradeManager found for committee"))?;
            let committee_pkg = ObjectID::new(upgrade_manager.cap.package.into_inner());

            println!("Committee ID: {}", committee_id);
            println!("Current package: {}", committee_pkg);

            // Build reset transaction.
            let mut reset_builder = ProgrammableTransactionBuilder::new();
            let committee_obj_id = ObjectID::new(committee_id.into_inner());
            let committee_arg = reset_builder
                .obj(get_shared_committee_arg(&mut grpc_client, committee_obj_id, true).await?)?;

            reset_builder.programmable_move_call(
                committee_pkg,
                "seal_committee".parse()?,
                "reset_proposal".parse()?,
                vec![],
                vec![committee_arg],
            );

            let (gas_price, gas_budget, gas_coin_ref) =
                get_gas_params(&mut grpc_client, &wallet, member_address, cli.gas_budget).await?;

            let reset_tx_data = TransactionData::new_programmable(
                member_address,
                vec![gas_coin_ref],
                reset_builder.finish(),
                gas_budget,
                gas_price,
            );

            println!("\nExecuting reset-proposal transaction...");
            let _reset_response = execute_tx_and_log_status(&wallet, reset_tx_data).await?;

            println!("\n✓ Successfully reset upgrade proposal!");
        }

        Commands::CheckKeyServerStatus {
            key_server_id,
            network,
        } => {
            let network = Network::from_str(&network.to_lowercase())
                .map_err(|e| anyhow!("Invalid network: {}", e))?;

            println!("Network: {:?}", network);
            println!("Key Server ID: {}", key_server_id);

            let mut grpc_client = create_grpc_client(&network)?;
            let key_server_addr = Address::from_hex(&key_server_id)?;

            // Fetch committee information.
            let (committee_id, _committee_pkg) =
                fetch_committee_from_key_server(&mut grpc_client, &key_server_addr).await?;

            println!("\n=== Committee Information ===");
            let committee = fetch_committee_data(&mut grpc_client, &committee_id).await?;
            println!("Committee ID: {}", committee_id);
            println!("Total members: {}", committee.members.len());
            println!("Threshold: {}", committee.threshold);
            println!("State: {:?}", committee.state);

            // Fetch key server.
            match fetch_key_server_by_committee(&mut grpc_client, &committee_id).await {
                Ok((ks_obj_id, key_server)) => {
                    println!("\n=== Key Server ===");
                    println!("Key Server Object ID: {}", ks_obj_id);

                    match key_server.server_type {
                        ServerType::Committee { version, .. } => {
                            println!("Committee Version: {}", version);
                        }
                        _ => {
                            println!("Warning: KeyServer is not of type Committee");
                        }
                    }

                    // Display partial key servers.
                    display_partial_key_servers(&key_server).await?;
                }
                Err(e) => {
                    println!("Warning: Could not fetch key server object: {}", e);
                }
            }

            // Fetch and display package upgrade information.
            println!("\n=== Package Information ===");
            match fetch_upgrade_manager(&mut grpc_client, &committee_id).await {
                Ok(Some(upgrade_manager)) => {
                    println!("Current Package: {}", upgrade_manager.cap.package);
                    println!("Package Version: {}", upgrade_manager.cap.version);
                }
                Ok(None) => {
                    println!("No UpgradeManager found (package cannot be upgraded)");
                }
                Err(e) => {
                    println!("Could not fetch package information: {}", e);
                }
            }

            // Fetch upgrade proposal status.
            println!("\n=== Upgrade Proposal Status ===");
            match fetch_upgrade_proposal(&mut grpc_client, &committee_id).await {
                Ok(Some(proposal)) => {
                    println!("Active Proposal:");
                    println!("  Digest: {}", Hex::encode_with_format(&proposal.digest.0));
                    println!("  Version: {}", proposal.version);
                    println!("  Threshold: {}", committee.threshold);

                    for entry in &proposal.votes.0.contents {
                        let vote_str = match entry.value {
                            UpgradeVote::Approve => "Approve",
                            UpgradeVote::Reject => "Reject",
                        };
                        println!("    {}: {}", entry.key, vote_str);
                    }
                }
                Ok(None) => {
                    println!("No active upgrade proposal.");
                }
                Err(e) => {
                    println!("Could not fetch upgrade proposal: {}", e);
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

    let digest = response.digest;
    let effects = response.effects.as_ref();
    let status = effects
        .map(|e| e.status())
        .ok_or_else(|| anyhow!("No effects in transaction response"))?;

    if !status.is_ok() {
        bail!("Transaction FAILED with status: {:?}", status);
    }

    println!("Transaction SUCCESS!");
    println!("Digest: {}", digest);
    Ok(response)
}

/// Extract a created object ID by type name from a transaction response.
fn extract_created_object_by_type(
    response: &SuiTransactionBlockResponse,
    type_name: &str,
) -> Result<ObjectID> {
    response
        .object_changes
        .as_ref()
        .ok_or_else(|| anyhow!("No object changes in response"))?
        .iter()
        .find_map(|change| {
            if let sui_sdk::rpc_types::ObjectChange::Created {
                object_id,
                object_type,
                ..
            } = change
                && object_type.to_string().contains(type_name)
            {
                return Some(*object_id);
            }
            None
        })
        .ok_or_else(|| anyhow!("Could not find created {} object", type_name))
}

/// Extract the committee object ID from a transaction response.
fn extract_created_committee_id(response: &SuiTransactionBlockResponse) -> Result<ObjectID> {
    extract_created_object_by_type(response, "Committee")
}

/// Get shared object argument for a committee object using gRPC.
async fn get_shared_committee_arg(
    grpc_client: &mut sui_rpc::client::Client,
    committee_id: ObjectID,
    mutable: bool,
) -> Result<ObjectArg> {
    let mut ledger_client = grpc_client.ledger_client();

    let mut request = GetObjectRequest::default();
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

    // Get initial_shared_version for shared object committee.
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
    // Load config to get parameters.
    let config_content = load_config(config)?;
    let my_address = get_my_address(&config_content)?;
    let committee_id = Address::from(get_committee_id(&config_content)?.into_bytes());
    let network = get_network(&config_content)?;

    // Load local keys.
    let local_keys = KeysFile::load(keys_file)?;

    // Parse old share from command argument if provided. Provided for continuing members in key rotation.
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
        let party = Party::<G2Element, G1Element>::new_advanced(
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

/// Get gas price, budget, and coin for a transaction.
async fn get_gas_params(
    grpc_client: &mut sui_rpc::client::Client,
    wallet: &WalletContext,
    address: SuiAddress,
    gas_budget: u64,
) -> Result<(u64, u64, sui_types::base_types::ObjectRef)> {
    let gas_price = grpc_client.get_reference_gas_price().await?;
    let gas_coin = wallet
        .gas_for_owner_budget(address, gas_budget, Default::default())
        .await?
        .1;
    Ok((gas_price, gas_budget, gas_coin.object_ref()))
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

/// Derive config and keys_file paths from state_dir if not provided.
fn derive_paths(
    state_dir: &Path,
    config: Option<PathBuf>,
    keys_file: Option<PathBuf>,
) -> (PathBuf, PathBuf) {
    let config = config.unwrap_or_else(|| state_dir.join("dkg.yaml"));
    let keys_file = keys_file.unwrap_or_else(|| state_dir.join("dkg.key"));
    (config, keys_file)
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

    let network_str = network_val
        .as_str()
        .ok_or_else(|| anyhow!("NETWORK must be a string (Testnet or Mainnet)"))?;

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

/// Get key server object ID from config.
fn get_key_server_obj_id(config: &serde_yaml::Value) -> Result<String> {
    get_config_field(config, &["init-rotation-params"], "KEY_SERVER_OBJ_ID")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("KEY_SERVER_OBJ_ID not found in config"))
}

/// Get COMMITTEE_PKG from config.
fn get_committee_pkg(config: &serde_yaml::Value) -> Result<ObjectID> {
    let pkg_str = get_config_field(
        config,
        &["publish-and-init", "init-rotation"],
        "COMMITTEE_PKG",
    )
    .and_then(|v| v.as_str())
    .ok_or_else(|| anyhow!("COMMITTEE_PKG not found in config"))?;
    Ok(ObjectID::from_hex_literal(pkg_str)?)
}

/// Get COMMITTEE_ID from config.
fn get_committee_id(config: &serde_yaml::Value) -> Result<ObjectID> {
    let id_str = get_config_field(
        config,
        &["publish-and-init", "init-rotation"],
        "COMMITTEE_ID",
    )
    .and_then(|v| v.as_str())
    .ok_or_else(|| anyhow!("COMMITTEE_ID not found in config"))?;
    Ok(ObjectID::from_hex_literal(id_str)?)
}

/// Get MY_ADDRESS from config.
fn get_my_address(config: &serde_yaml::Value) -> Result<Address> {
    let addr_str = get_config_field(config, &["genkey-and-register"], "MY_ADDRESS")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("MY_ADDRESS not found in config"))?;
    Ok(Address::from_str(addr_str)?)
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

    // Ensure the section exists.
    if config.get(section).is_none() {
        config[section] = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }

    // Update fields in the section.
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

/// Load DKG messages from a directory.
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

/// Process DKG messages and complete the protocol.
fn process_dkg_messages(
    state: &mut DkgState,
    messages: Vec<SignedMessage>,
    local_keys: &KeysFile,
) -> Result<fastcrypto_tbls::dkg_v1::Output<G2Element, G1Element>> {
    println!("Processing {} message(s)...", messages.len());

    // Validate message count.
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

    // Create party.
    let party = Party::<G2Element, G1Element>::new_advanced(
        local_keys.enc_sk.clone(),
        state.config.nodes.clone(),
        state.config.threshold,
        RandomOracle::new(&state.config.committee_id.to_string()),
        state.config.my_old_share,
        state.config.old_threshold,
        &mut thread_rng(),
    )?;

    // Process each message.
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

    // Merge and complete.
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

/// Determine the committee version from the network.
async fn determine_committee_version(
    grpc_client: &mut sui_rpc::client::Client,
    committee_id: &Address,
) -> Result<u32> {
    let committee = fetch_committee_data(grpc_client, committee_id).await?;

    if let Some(old_committee_id) = committee.old_committee_id {
        // Rotation: fetch the old committee's KeyServer version then increment by 1.
        match fetch_key_server_by_committee(grpc_client, &old_committee_id).await {
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
        // Fresh DKG: version is 0.
        println!("Fresh DKG, version will be: 0");
        Ok(0)
    }
}

/// Compute and display the package digest.
fn compute_package_digest(package_path: &Path, network: &Network) -> Result<()> {
    println!("Building package at: {}", package_path.display());
    println!();

    let digest = get_package_digest(package_path, network)?;
    println!(
        "Digest for package '{}': {}",
        package_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy(),
        digest
    );

    Ok(())
}

/// Compute package digest as hex string.
fn get_package_digest(package_path: &Path, network: &Network) -> Result<String> {
    let build_config = create_build_config(network);
    let compiled_package = build_config
        .build(&package_path.canonicalize()?)
        .context("Failed to build package")?;

    let digest = compiled_package.get_package_digest(/* with_unpublished_deps */ false);
    Ok(Hex::encode_with_format(digest))
}

/// Display partial key server information.
async fn display_partial_key_servers(key_server: &KeyServerV2) -> Result<()> {
    println!("\n=== Partial Key Servers ===");
    match to_partial_key_servers(key_server).await {
        Ok(partial_key_servers) => {
            for (addr, info) in partial_key_servers {
                println!("Address: {}", addr);
                println!("  Name: {}", info.name);
                println!("  URL: {}", info.url);
                println!("  Party ID: {}", info.party_id);
                println!();
            }
        }
        Err(e) => {
            println!("Warning: Could not fetch partial key server info: {}", e);
        }
    }
    Ok(())
}

/// Helper function to vote (approve or reject) for package upgrade.
async fn vote_for_upgrade(
    package_path: &Path,
    key_server_id: &str,
    network: &Network,
    wallet: &mut WalletContext,
    gas_budget: u64,
    approve: bool,
) -> Result<()> {
    let voter_address = wallet.active_address()?;

    println!("Voter address: {}", voter_address);
    println!("Network: {:?}", network);

    // Build package and compute digest.
    let digest = get_package_digest(package_path, network)?;
    println!("\nPackage digest: {}", digest);

    // Fetch key server to get committee ID.
    let mut grpc_client = create_grpc_client(network)?;
    let key_server_addr = Address::from_hex(key_server_id)?;
    let (committee_id, _) =
        fetch_committee_from_key_server(&mut grpc_client, &key_server_addr).await?;

    // Fetch current package ID from UpgradeCap.
    let upgrade_manager = fetch_upgrade_manager(&mut grpc_client, &committee_id)
        .await?
        .ok_or_else(|| anyhow!("No UpgradeManager found for committee"))?;
    let committee_pkg = ObjectID::new(upgrade_manager.cap.package.into_inner());

    println!("Committee ID: {}", committee_id);
    println!("Current package: {}", committee_pkg);

    // Build vote transaction.
    let mut vote_builder = ProgrammableTransactionBuilder::new();
    let committee_obj_id = ObjectID::new(committee_id.into_inner());
    let committee_arg = vote_builder
        .obj(get_shared_committee_arg(&mut grpc_client, committee_obj_id, true).await?)?;

    let digest_bytes = Hex::decode(&digest)?;
    let digest_arg = vote_builder.pure(digest_bytes)?;

    let function_name = if approve {
        "approve_digest_for_upgrade"
    } else {
        "reject_digest_for_upgrade"
    };

    vote_builder.programmable_move_call(
        committee_pkg,
        "seal_committee".parse()?,
        function_name.parse()?,
        vec![],
        vec![committee_arg, digest_arg],
    );

    let (gas_price, gas_budget, gas_coin_ref) =
        get_gas_params(&mut grpc_client, wallet, voter_address, gas_budget).await?;

    let vote_tx_data = TransactionData::new_programmable(
        voter_address,
        vec![gas_coin_ref],
        vote_builder.finish(),
        gas_budget,
        gas_price,
    );

    println!("\nExecuting {} vote transaction...", function_name);
    let _vote_response = execute_tx_and_log_status(wallet, vote_tx_data).await?;

    println!("\n✓ Successfully voted to {}!", function_name);
    Ok(())
}
