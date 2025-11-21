// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

mod types;

use anyhow::{anyhow, Result};
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
use rand::thread_rng;
use seal_committee::grpc_helper::to_partial_key_servers;
use seal_committee::{
    build_new_to_old_map, create_grpc_client, fetch_committee_data, fetch_key_server_by_committee,
    Network,
};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use sui_sdk_types::Address;
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
}

#[derive(Subcommand)]
enum Commands {
    /// Generate ECIES and signing key pairs.
    GenerateKeys {
        /// Path to write the keys file (default: ./dkg-state/dkg.key).
        #[arg(long, default_value = "./dkg-state/dkg.key")]
        keys_file: PathBuf,
    },

    /// Initialize DKG party state and create DKG message.
    /// For key rotation, provide `--old-share` for continuing members.
    CreateMessage {
        /// My address, used to find my party ID in the committee.
        #[arg(long)]
        my_address: Address,

        /// Current committee object ID.
        #[arg(long)]
        committee_id: Address,

        /// Network (mainnet or testnet).
        #[arg(long, value_parser = parse_network)]
        network: Network,

        /// State directory (default: ./dkg-state).
        #[arg(long, default_value = "./dkg-state")]
        state_dir: PathBuf,

        /// Path to the keys file (default: ./dkg-state/dkg.key).
        #[arg(long, default_value = "./dkg-state/dkg.key")]
        keys_file: PathBuf,

        /// Old share for key rotation (hex-encoded BCS, for continuing members only).
        #[arg(long)]
        old_share: Option<String>,
    },

    /// Process all messages and attempt to finalize if no complaints.
    ProcessAll {
        /// Directory containing message_*.json files from all parties.
        #[arg(short, long)]
        messages_dir: PathBuf,
        /// State directory
        #[arg(short = 's', long, default_value = "./dkg-state")]
        state_dir: PathBuf,
        /// Path to keys file
        #[arg(short = 'k', long, default_value = "./dkg-state/dkg.key")]
        keys_file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeys { keys_file } => {
            let enc_sk = PrivateKey::<G2Element>::new(&mut thread_rng());
            let enc_pk = PublicKey::<G2Element>::from_private_key(&enc_sk);

            let signing_kp = BLS12381KeyPair::generate(&mut thread_rng());
            let signing_pk = signing_kp.public().clone();
            let signing_sk = signing_kp.private();

            let created_keys_file = KeysFile {
                enc_sk,
                enc_pk,
                signing_sk,
                signing_pk,
            };

            // Serialize to JSON
            let json_content = serde_json::to_string_pretty(&created_keys_file)?;

            if let Some(parent) = keys_file.parent() {
                fs::create_dir_all(parent)?;
            }

            write_secret_file(&keys_file, &json_content)?;

            println!("Keys written to: {}", keys_file.display());
            #[cfg(not(unix))]
            println!("WARNING: On non-Unix systems, manually restrict file permissions");
        }

        Commands::CreateMessage {
            my_address,
            committee_id,
            network,
            state_dir,
            keys_file,
            old_share,
        } => {
            let local_keys = KeysFile::load(&keys_file)?;

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

            // Validate committee state is in Init state and contains my address.
            committee.is_init()?;
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
                    format_pk_hex(&my_member_info.enc_pk)?,
                    format_pk_hex(&local_keys.signing_pk)?,
                    format_pk_hex(&my_member_info.signing_pk)?
                ));
            }
            println!("Registered public keys onchain validated. My party ID: {my_party_id}");

            // Get old committee params for key rotation.
            let (old_threshold, new_to_old_mapping, expected_old_pks) = match committee
                .old_committee_id
            {
                None => {
                    if my_old_share.is_some() {
                        return Err(anyhow!("--old-share should not be provided for fresh DKG."));
                    }
                    println!("No old committee ID, performing fresh DKG.");
                    (None, None, None)
                }
                Some(old_committee_id) => {
                    println!("Old committee ID: {old_committee_id}, performing key rotation.");

                    let old_committee =
                        fetch_committee_data(&mut grpc_client, &old_committee_id).await?;
                    let old_threshold = Some(old_committee.threshold);
                    let new_to_old_mapping = build_new_to_old_map(&committee, &old_committee);

                    // Fetch partial key server info from the old committee's key server object.
                    let (_, ks) =
                        fetch_key_server_by_committee(&mut grpc_client, &committee_id).await?;
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
                let signed_message = sign_message(message.clone(), &local_keys.signing_sk);

                // Write message to file.
                let message_base64 = Base64::encode(bcs::to_bytes(&signed_message)?);
                let message_file = PathBuf::from(format!("message_{my_party_id}.json"));

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

            state.save(&state_dir)?;
            println!("State saved to {state_dir:?}. Wait for coordinator to announce phase 3.");
        }
        Commands::ProcessAll {
            messages_dir,
            state_dir,
            keys_file,
        } => {
            let mut state = DkgState::load(&state_dir)?;
            let local_keys = KeysFile::load(&keys_file)?;

            // Read all files from the messages directory.
            let mut messages = Vec::new();
            let entries = fs::read_dir(&messages_dir).map_err(|e| {
                anyhow!(
                    "Failed to read messages directory {:?}: {}",
                    messages_dir,
                    e
                )
            })?;

            for entry in entries {
                let path = entry?.path();

                let content = fs::read_to_string(&path)
                    .map_err(|e| anyhow!("Failed to read {}: {}", path.display(), e))?;

                let json: serde_json::Value = serde_json::from_str(&content)
                    .map_err(|e| anyhow!("Failed to parse {}: {}", path.display(), e))?;

                let message_base64 = json["message"]
                    .as_str()
                    .ok_or_else(|| anyhow!("Missing 'message' field in {}", path.display()))?;

                let signed_message: SignedMessage =
                    bcs::from_bytes(&Base64::decode(message_base64)?).map_err(|e| {
                        anyhow!(
                            "Failed to deserialize message from {}: {}",
                            path.display(),
                            e
                        )
                    })?;

                messages.push(signed_message);
            }

            if messages.is_empty() {
                return Err(anyhow!("No files found in directory: {:?}", messages_dir));
            }

            println!("Processing {} message(s)...", messages.len());

            if let Some(old_threshold) = state.config.old_threshold {
                // Key rotation: need messages from old threshold members.
                if messages.len() < old_threshold as usize {
                    return Err(anyhow!(
                        "Key rotation requires at least {} messages from old committee members, got {}.",
                        old_threshold, messages.len()
                    ));
                }
            } else {
                // Fresh DKG: need messages from all parties.
                let num_parties = state.config.nodes.num_nodes();
                if messages.len() != state.config.nodes.num_nodes() {
                    return Err(anyhow!(
                        "Fresh DKG requires {} messages (one from each party), got {}.",
                        num_parties,
                        messages.len()
                    ));
                }
            }

            // Create party.
            let party = Party::<G2Element, G2Element>::new_advanced(
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

                // Verify signed message using onchain signing pk for each party.
                let sender_signing_pk =
                    state
                        .config
                        .signing_pks
                        .get(&sender_party_id)
                        .ok_or_else(|| {
                            anyhow!("Signing public key not found for party {}", sender_party_id)
                        })?;
                verify_signature(&signed_msg, sender_signing_pk)?;

                // For rotation, find the expected old partial PK for this sender.
                let processed = if state.config.old_threshold.is_some() {
                    let new_to_old_mapping =
                        state.config.new_to_old_mapping.as_ref().ok_or_else(|| {
                            anyhow!("Missing new-to-old mapping for key rotation")
                        })?;
                    let old_party_id =
                        new_to_old_mapping.get(&sender_party_id).ok_or_else(|| {
                            anyhow!(
                                "Party {} not found in old committee mapping",
                                sender_party_id
                            )
                        })?;
                    let expected_old_pks =
                        state.config.expected_old_pks.as_ref().ok_or_else(|| {
                            anyhow!("Missing expected old partial PKs for key rotation")
                        })?;
                    let expected_pk = expected_old_pks.get(old_party_id).ok_or_else(|| {
                        anyhow!("Partial PK not found for old party {}", old_party_id)
                    })?;

                    match party.process_message_and_check_pk(
                        signed_msg.message.clone(),
                        expected_pk,
                        &mut thread_rng(),
                    ) {
                        Ok(proc) => proc,
                        Err(e) => {
                            return Err(anyhow!(
                                "Key rotation verification failed for party {sender_party_id}: {e}",
                            ));
                        }
                    }
                } else {
                    // Fresh DKG.
                    party.process_message(signed_msg.message.clone(), &mut thread_rng())?
                };

                if let Some(complaint) = &processed.complaint {
                    return Err(anyhow!(
                        "Do NOT propose onchain. Complaint found {:?} for party {}.",
                        complaint,
                        processed.message.sender
                    ));
                }
                println!("Successfully message processed from party {sender_party_id}...");
                state.processed_messages.push(processed);
            }

            // Merge processed messages.
            let (confirmation, used_msgs) = party.merge(&state.processed_messages)?;

            // Check complaints.
            if !confirmation.complaints.is_empty() {
                let complaints = confirmation.complaints.clone();
                state.confirmation = Some((confirmation, used_msgs));
                state.save(&state_dir)?;
                return Err(anyhow!(
                    "Do NOT propose onchain. Complaint(s) found {:?}.",
                    complaints,
                ));
            }

            state.confirmation = Some((confirmation.clone(), used_msgs.clone()));

            // Complete the protocol.
            let output = if state.config.old_threshold.is_some() {
                // Key rotation: use complete_optimistic_key_rotation.
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
                // Fresh DKG.
                party.complete_optimistic(&used_msgs)?
            };

            state.output = Some(output.clone());

            println!("============KEY SERVER PK AND PARTIAL PKS=====================");
            println!("KEY_SERVER_PK={}", format_pk_hex(&output.vss_pk.c0())?);

            // Get partial public keys for all parties in the new committee.
            for party_id in 0..state.config.nodes.num_nodes() {
                // party id is 0 index and share index is party id + 1
                let share_index = NonZeroU16::new(party_id as u16 + 1).expect("must be valid");
                let partial_pk = output.vss_pk.eval(share_index);
                println!(
                    "PARTY_{}_PARTIAL_PK={}",
                    party_id,
                    format_pk_hex(&partial_pk.value)?
                );
            }

            println!("============YOUR PARTIAL KEY SHARE, KEEP SECRET=====================");
            if let Some(shares) = &output.shares {
                for share in shares {
                    println!("MASTER_SHARE={}", format_pk_hex(&share.value)?);
                }
            }

            println!("============FULL VSS POLYNOMIAL COEFFICIENTS=====================");
            for i in 0..=output.vss_pk.degree() {
                let coeff = output.vss_pk.coefficient(i);
                println!("Coefficient {}: {}", i, format_pk_hex(coeff)?);
            }
        }
    }
    Ok(())
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

/// Helper function to format a BCS-serializable value as hex string with 0x prefix.
fn format_pk_hex<T: Serialize>(pk: &T) -> Result<String> {
    Ok(Hex::encode_with_format(&bcs::to_bytes(pk)?))
}

/// Helper function to parse network string into Network enum.
fn parse_network(s: &str) -> Result<Network> {
    Network::from_str(s).map_err(|e| anyhow::anyhow!(e))
}
