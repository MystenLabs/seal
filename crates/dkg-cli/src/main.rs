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
use seal_committee::{build_new_to_old_map, create_grpc_client, fetch_committee_data};
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
    new_to_old_mapping: HashMap<u16, u16>,
    /// Expected partial public keys from old committee, for key rotation.
    expected_old_pks: HashMap<u16, G2Element>,
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
    my_messages: Vec<Message<G2Element, G2Element>>,
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
        /// Path to write the secret keys file (default: ./.dkg-keys).
        #[arg(long, default_value = ".dkg-keys")]
        secret_keys_file: PathBuf,
    },

    /// Initialize DKG party, for fresh DKG or key rotation. Requires DKG_ENC_SK and DKG_SIGNING_SK
    /// environment variables. For key rotation with continuing members, also requires
    /// DKG_OLD_SHARE.
    Init {
        /// My address, used to find my party ID in the committee.
        #[arg(long)]
        my_address: Address,

        /// Current committee object ID.
        #[arg(long)]
        committee_id: Address,

        /// Key server object ID (For key rotation to fetch old partial public keys).
        #[arg(long)]
        key_server_id: Option<Address>,

        /// Network (mainnet or testnet).
        #[arg(long, default_value = "testnet")]
        network: String,

        /// State directory.
        #[arg(long)]
        state_dir: PathBuf,
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

            let enc_pk_hex = Hex::encode_with_format(bcs::to_bytes(&enc_pk)?);
            let signing_pk_hex = Hex::encode_with_format(bcs::to_bytes(&signing_pk)?);
            let enc_sk_hex = Hex::encode_with_format(bcs::to_bytes(&enc_sk)?);
            let signing_sk_hex = Hex::encode_with_format(bcs::to_bytes(&signing_sk)?);

            // Write secret keys to file
            let secret_keys_content =
                format!("enc_sk: {}\nsigning_sk: {}\n", enc_sk_hex, signing_sk_hex);

            if let Some(parent) = secret_keys_file.parent() {
                fs::create_dir_all(parent)?;
            }

            write_secret_file(&secret_keys_file, &secret_keys_content)?;

            println!("Secret keys written to: {}", secret_keys_file.display());
            #[cfg(not(unix))]
            println!("WARNING: On non-Unix systems, manually restrict file permissions");
            println!();
            println!("==============STEP 1: REGISTER ONCHAIN===============");
            println!("export MY_ADDRESS=<your address to use> # check with: sui client addresses");
            println!("export DKG_ENC_PK={}", enc_pk_hex);
            println!("export DKG_SIGNING_PK={}", signing_pk_hex);
            println!();
            println!("sui client switch --address $MY_ADDRESS");
            println!("sui client call --package $COMMITTEE_PKG --module seal_committee \\");
            println!("  --function register \\");
            println!("  --args $COMMITTEE_ID x\"$DKG_ENC_PK\" x\"$DKG_SIGNING_PK\" \"https://your-url.com\"");
            println!();
            println!(
                "==============STEP 2: AFTER ALL MEMBERS REGISTERS, RUN DKG INIT ==============="
            );
            println!(
                "export DKG_ENC_SK=$(grep enc_sk {} | cut -d: -f2 | xargs)",
                secret_keys_file.display()
            );
            println!(
                "export DKG_SIGNING_SK=$(grep signing_sk {} | cut -d: -f2 | xargs)",
                secret_keys_file.display()
            );
            println!();
            println!("cargo run dkg-cli init --my-address $MY_ADDRESS --committee-id $COMMITTEE_ID --state-dir ./state");
        }

        Commands::Init {
            my_address,
            committee_id,
            key_server_id,
            network,
            state_dir,
        } => {
            // Read secrets from environment variables.
            let enc_sk_hex = std::env::var("DKG_ENC_SK")
                .map_err(|_| anyhow!("DKG_ENC_SK environment variable not set"))?;
            let signing_sk_hex = std::env::var("DKG_SIGNING_SK")
                .map_err(|_| anyhow!("DKG_SIGNING_SK environment variable not set"))?;

            // Read old share from environment variable if provided (for key rotation).
            let old_share_hex = std::env::var("DKG_OLD_SHARE").ok();

            // Check if this is fresh DKG or rotation.
            let (is_rotation, is_continuing) = if key_server_id.is_some() {
                if old_share_hex.is_some() {
                    (true, true)
                } else {
                    (true, false)
                }
            } else {
                if old_share_hex.is_some() {
                    return Err(anyhow!(
                        "DKG_OLD_SHARE env var is set but key_server_id is missing. \
                        For key rotation, both are required."
                    ));
                }
                (false, false)
            };
            println!(
                "Initializing DKG party, committee {}, my address {}, is_rotation: {}, is_continuing: {}",
                committee_id, my_address, is_rotation, is_continuing
            );

            // Fetch current committee from onchain.
            let mut grpc_client = create_grpc_client(&network)?;
            let committee = fetch_committee_data(&committee_id, &mut grpc_client).await?;
            println!(
                "Fetched committee with {} members, threshold: {}",
                committee.members.len(),
                committee.threshold
            );

            // Validate committee state is in Init.
            committee.is_init()?;

            // Parse keys.
            let enc_sk: PrivateKey<G2Element> = bcs::from_bytes(&Hex::decode(&enc_sk_hex)?)?;
            let enc_pk = PublicKey::<G2Element>::from_private_key(&enc_sk);
            let signing_sk: G2Scalar = bcs::from_bytes(&Hex::decode(&signing_sk_hex)?)?;
            let signing_pk = G2Element::generator() * signing_sk;

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
            if &enc_pk != registered_enc_pk || &signing_pk != registered_signing_pk {
                return Err(anyhow!(
                    "Mismatched PK for {}!\n\
                    ECIES PK Derived from secret: {}\n\
                    Registered onchain: {}\n\
                    Signing PK Derived from secret: {}\n\
                    Registered onchain: {}",
                    my_address,
                    Hex::encode(&bcs::to_bytes(&enc_pk)?),
                    Hex::encode(&bcs::to_bytes(registered_enc_pk)?),
                    Hex::encode(&bcs::to_bytes(&signing_pk)?),
                    Hex::encode(&bcs::to_bytes(registered_signing_pk)?)
                ));
            }
            println!("Successfully validated registered public keys onchain.");

            // For key rotation, fetch old committee data, build new_to_old mapping, and fetch expected old pks.
            let (old_threshold, new_to_old_mapping, expected_old_pks, my_old_share, my_old_pk) =
                if is_rotation {
                    let old_committee_id = committee.old_committee_id.ok_or_else(|| {
                        anyhow!(
                            "Committee {} does not have old_committee_id for rotation",
                            committee_id
                        )
                    })?;

                    let old_committee =
                        fetch_committee_data(&old_committee_id, &mut grpc_client).await?;

                    // Validate old committee is finalized.
                    old_committee
                        .is_finalized()
                        .map_err(|e| anyhow!("{}. Cannot perform key rotation.", e))?;

                    // Build new to old party ID mapping.
                    let new_to_old_map = build_new_to_old_map(&committee, &old_committee);

                    // TODO: fetch this from onchain using key_server_id.
                    let expected_old_pks = HashMap::new();

                    // Validate continuing member if applicable.
                    if is_continuing
                        && (!committee.members.contains(&my_address)
                            || !old_committee.members.contains(&my_address))
                    {
                        return Err(anyhow!("Not a continuing member."));
                    }

                    let (my_old_share, my_old_pk) = match old_share_hex {
                        Some(ref share_hex) => {
                            let key_share: G2Scalar = bcs::from_bytes(&Hex::decode(share_hex)?)?;
                            let partial_pk = G2Element::generator() * key_share;
                            // TODO: verify the old partial pk matches with the partial key server
                            // for this address in key server object.
                            (Some(key_share), Some(partial_pk))
                        }
                        None => (None, None),
                    };

                    (
                        Some(old_committee.threshold),
                        new_to_old_map,
                        expected_old_pks,
                        my_old_share,
                        my_old_pk,
                    )
                } else {
                    (None, HashMap::new(), HashMap::new(), None, None)
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
                    enc_sk,
                    signing_sk,
                    nodes: Nodes::new(nodes)?,
                    committee_id,
                    threshold: committee.threshold,
                    old_threshold,
                    new_to_old_mapping,
                    expected_old_pks,
                    my_old_share,
                    my_old_pk,
                },
                my_messages: vec![],
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
