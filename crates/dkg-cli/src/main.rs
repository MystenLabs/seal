// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::groups::bls12381::{G2Element, Scalar as G2Scalar};
use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto_tbls::dkg_v1::{Message, Output, ProcessedMessage, UsedProcessedMessages};
use fastcrypto_tbls::ecies_v1::{PrivateKey, PublicKey};
use fastcrypto_tbls::nodes::{Node, Nodes};
use rand::thread_rng;
use seal_committee::{
    build_new_to_old_map, create_grpc_client, fetch_committee_data, format_pk_hex, KeysFile,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use sui_sdk_types::Address;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Initialized party configuration.
#[derive(Serialize, Deserialize)]
struct InitializedConfig {
    /// My party ID for this committee.
    my_party_id: u16,
    /// ECIES private key.
    enc_sk: PrivateKey<G2Element>,
    /// Signing key.
    signing_sk: G2Scalar,
    /// All nodes in the protocol.
    nodes: Nodes<G2Element>,
    /// This committee ID, used for random oracle.
    committee_id: Address,
    /// Threshold for this committee.
    threshold: u16,
    /// Threshold for old committee, for key rotation.
    old_threshold: Option<u16>,
    /// Mapping from new party ID to old party ID, for key rotation.
    new_to_old_mapping: Option<HashMap<u16, u16>>,
    /// Expected partial public keys from old committee, for key rotation.
    expected_old_pks: Option<HashMap<u16, G2Element>>,
    /// Old partial key share for key rotation, for continuing members for key rotation.
    my_old_share: Option<G2Scalar>,
    /// Old partial public key for key rotation, for continuing members for key rotation.
    my_old_pk: Option<G2Element>,
}

/// Local state for DKG protocol, used for storing messages and output.
#[derive(Serialize, Deserialize)]
struct DkgState {
    /// Configuration
    config: InitializedConfig,
    /// Messages created by this party.
    my_message: Option<Message<G2Element, G2Element>>,
    /// Messages received from other parties.
    received_messages: HashMap<u16, Message<G2Element, G2Element>>,
    /// Processed messages.
    processed_messages: Vec<ProcessedMessage<G2Element, G2Element>>,
    /// Confirmation and used messages.
    confirmation: Option<(
        fastcrypto_tbls::dkg_v1::Confirmation<G2Element>,
        UsedProcessedMessages<G2Element, G2Element>,
    )>,
    /// Final output (if completed).
    output: Option<Output<G2Element, G2Element>>,
}

#[derive(Parser)]
#[command(name = "dkg-cli")]
#[command(about = "DKG and key rotation CLI tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate ECIES and signing key pairs.
    GenerateKeys {
        /// Path to write the secret keys file (default: ./.dkg.key).
        #[arg(long, default_value = ".dkg.key")]
        secret_keys_file: PathBuf,
    },

    /// Initialize DKG party, for fresh DKG or key rotation. Reads keys from file.
    Init {
        /// My address, used to find my party ID in the committee.
        #[arg(long)]
        my_address: Address,

        /// Current committee object ID.
        #[arg(long)]
        committee_id: Address,

        /// Network (mainnet or testnet).
        #[arg(long, default_value = "testnet")]
        network: String,

        /// State directory (default: ./dkg-state).
        #[arg(long, default_value = "./dkg-state")]
        state_dir: PathBuf,

        /// Path to the keys file (default: ./.dkg.key).
        #[arg(long, default_value = ".dkg.key")]
        keys_file: PathBuf,

        /// Old share for key rotation (hex-encoded BCS, for continuing members only).
        #[arg(long)]
        old_share: Option<String>,
    },
}

impl DkgState {
    /// Save state to the given directory.
    fn save(&self, state_dir: &Path) -> Result<()> {
        fs::create_dir_all(state_dir)?;
        let path = state_dir.join("state.json");
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeys { secret_keys_file } => {
            let enc_sk = PrivateKey::<G2Element>::new(&mut thread_rng());
            let enc_pk = PublicKey::<G2Element>::from_private_key(&enc_sk);
            let signing_sk = G2Scalar::rand(&mut thread_rng());
            let signing_pk = G2Element::generator() * signing_sk;

            let keys_file = KeysFile {
                enc_sk,
                enc_pk,
                signing_sk,
                signing_pk,
            };

            // Serialize to JSON
            let json_content = serde_json::to_string_pretty(&keys_file)?;

            if let Some(parent) = secret_keys_file.parent() {
                fs::create_dir_all(parent)?;
            }

            write_secret_file(&secret_keys_file, &json_content)?;

            println!("Secret keys written to: {}", secret_keys_file.display());
            #[cfg(not(unix))]
            println!("WARNING: On non-Unix systems, manually restrict file permissions");
        }

        Commands::Init {
            my_address,
            committee_id,
            network,
            state_dir,
            keys_file,
            old_share,
        } => {
            // Read secrets from keys file (JSON format).
            let keys_content = fs::read_to_string(&keys_file)
                .map_err(|e| anyhow!("Failed to read keys file {}: {}", keys_file.display(), e))?;

            let local_keys: KeysFile = serde_json::from_str(&keys_content)
                .map_err(|e| anyhow!("Failed to parse keys file as JSON: {}", e))?;

            // Parse old share from command argument if provided (for key rotation).
            let (my_old_share, my_old_pk) = if let Some(share_hex) = old_share {
                let key_share: G2Scalar = bcs::from_bytes(&Hex::decode(&share_hex)?)?;
                let key_pk = G2Element::generator() * key_share;
                (Some(key_share), Some(key_pk))
            } else {
                (None, None)
            };

            // Fetch current committee from onchain.
            let mut grpc_client = create_grpc_client(&network)?;
            let committee = fetch_committee_data(&committee_id, &mut grpc_client).await?;

            // Validate committee state is in Init state and contains my address.
            committee.is_init()?;
            assert!(committee.contains(&my_address));

            println!(
                "Fetched committee with {} members, threshold: {}",
                committee.members.len(),
                committee.threshold
            );

            // Fetch members info.
            let members_info = committee.get_members_info()?;

            let my_member_info = members_info
                .iter()
                .find(|m| m.address == my_address)
                .ok_or_else(|| anyhow!("Address {} not found in committee members", my_address))?;
            let my_party_id = my_member_info.party_id;
            let registered_enc_pk = &my_member_info.enc_pk;
            let registered_signing_pk = &my_member_info.signing_pk;
            println!("My party ID: {}", my_party_id);

            // Validate PK locally vs registration onchain.
            if &local_keys.enc_pk != registered_enc_pk
                || &local_keys.signing_pk != registered_signing_pk
            {
                return Err(anyhow!(
                    "Mismatched PK for address {}!\n\
                    ECIES PK Derived from secret: {}\n\
                    Registered onchain: {}\n\
                    Signing PK Derived from secret: {}\n\
                    Registered onchain: {}",
                    my_address,
                    format_pk_hex(&local_keys.enc_pk)?,
                    format_pk_hex(registered_enc_pk)?,
                    format_pk_hex(&local_keys.signing_pk)?,
                    format_pk_hex(registered_signing_pk)?
                ));
            }
            println!("Successfully validated registered public keys onchain.");

            // Get old committee params for key rotation.
            let (old_threshold, new_to_old_mapping, expected_old_pks) = match committee
                .old_committee_id
            {
                None => {
                    if my_old_share.is_some() {
                        return Err(anyhow!("DKG_KEY_SHARE should not be set for fresh DKG!"));
                    }
                    println!("No old committee ID, performing fresh DKG.");
                    (None, None, None)
                }
                Some(old_committee_id) => {
                    println!(
                        "Old committee ID: {}, performing key rotation.",
                        old_committee_id
                    );

                    let old_committee =
                        fetch_committee_data(&old_committee_id, &mut grpc_client).await?;
                    let old_threshold = Some(old_committee.threshold);
                    let new_to_old_mapping = build_new_to_old_map(&committee, &old_committee);

                    // TODO: Fetch this from the key server object owned by the old committee.
                    let expected_old_pks = HashMap::new();

                    // Validate my_old_share and membership in old committee.
                    match my_old_share {
                        Some(_) => {
                            if !old_committee.contains(&my_address) {
                                return Err(anyhow!(
                                    "Invalid state: My address {} not found in old committee {} so 
                                    I am a new member. Do not provide `--old-share` for key rotation.",
                                    my_address,
                                    old_committee_id
                                ));
                            }
                            println!("Continuing member for key rotation.");
                        }
                        None => {
                            if old_committee.contains(&my_address) {
                                return Err(anyhow!(
                                    "Invalid state: My address {} found in old committee {} so I am 
                                    a continuing member. Must provide `--old-share` for key rotation.",
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

            // Create nodes for all parties with their enc_pks.
            let mut nodes = Vec::new();
            for m in members_info {
                nodes.push(Node {
                    id: m.party_id,
                    pk: m.enc_pk,
                    weight: 1,
                });
            }

            let state = DkgState {
                config: InitializedConfig {
                    my_party_id,
                    enc_sk: local_keys.enc_sk,
                    signing_sk: local_keys.signing_sk,
                    nodes: Nodes::new(nodes)?,
                    committee_id,
                    threshold: committee.threshold,
                    old_threshold,
                    new_to_old_mapping,
                    expected_old_pks,
                    my_old_share,
                    my_old_pk,
                },
                my_message: None,
                received_messages: HashMap::new(),
                processed_messages: vec![],
                confirmation: None,
                output: None,
            };

            state.save(&state_dir)?;
            println!(
                "State saved to {:?}. Ready for DKG protocol. Run 'create-message' to start.",
                state_dir
            );
        }
    }
    Ok(())
}

/// Helper function to write a file with restricted permissions (Unix only).
fn write_secret_file(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content)?;
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600); // Read/write for owner only
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}
