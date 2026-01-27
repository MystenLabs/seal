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
    CommitteeState, Network, ServerType,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
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
        /// Network (mainnet or testnet).
        #[arg(short = 'n', long, value_parser = parse_network)]
        network: Network,
    },

    /// Check committee status and member registration.
    CheckCommittee {
        /// Committee object ID to check.
        #[arg(long)]
        committee_id: Address,

        /// Network (mainnet or testnet).
        #[arg(long, value_parser = parse_network)]
        network: Network,
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
                let signed_message =
                    sign_message(message.clone(), &local_keys.signing_sk, nizk_proof);

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

            state.save(&state_dir)?;
            println!("State saved to {state_dir:?}. Wait for coordinator to announce phase 3.");
        }
        Commands::ProcessAll {
            messages_dir,
            state_dir,
            keys_file,
            network,
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
                // Key rotation: need messages from exactly old threshold members (continuing members).
                if messages.len() != old_threshold as usize {
                    return Err(anyhow!(
                        "Key rotation requires exactly {} messages from continuing members (old committee threshold), got {}.",
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

                    match party.process_message_with_checks(
                        signed_msg.message.clone(),
                        &Some(*expected_pk),
                        &Some(signed_msg.nizk_proof.clone()),
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
                    // Fresh DKG
                    party.process_message_with_checks(
                        signed_msg.message.clone(),
                        &None,
                        &Some(signed_msg.nizk_proof.clone()),
                        &mut thread_rng(),
                    )?
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

            // Determine the committee version.
            let version = {
                let mut grpc_client = create_grpc_client(&network)?;
                let committee =
                    fetch_committee_data(&mut grpc_client, &state.config.committee_id).await?;

                if let Some(old_committee_id) = committee.old_committee_id {
                    // Rotation: fetch the old committee's KeyServer version then increment by 1.
                    match fetch_key_server_by_committee(&mut grpc_client, &old_committee_id).await {
                        Ok((_, key_server_v2)) => match key_server_v2.server_type {
                            ServerType::Committee { version, .. } => {
                                println!(
                                    "Old committee version: {}, new version will be: {}",
                                    version,
                                    version + 1
                                );
                                version + 1
                            }
                            _ => return Err(anyhow!("Old KeyServer is not of type Committee")),
                        },
                        Err(e) => {
                            return Err(anyhow!(
                                "Failed to fetch old committee's KeyServer for rotation: {}",
                                e
                            ));
                        }
                    }
                } else {
                    // Fresh DKG: version is 0.
                    println!("Fresh DKG, version will be: 0");
                    0
                }
            };

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
                    println!("MASTER_SHARE_V{}={}", version, format_pk_hex(&share.value)?);
                }
            }

            println!("============COMMITTEE VERSION=====================");
            println!("COMMITTEE_VERSION={version}");

            println!("============FULL VSS POLYNOMIAL COEFFICIENTS=====================");
            for i in 0..=output.vss_pk.degree() {
                let coeff = output.vss_pk.coefficient(i);
                println!("Coefficient {}: {}", i, format_pk_hex(coeff)?);
            }
        }

        Commands::CheckCommittee {
            committee_id,
            network,
        } => {
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
