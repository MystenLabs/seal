// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

mod grpc_helpers;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::groups::bls12381::{G2Element, Scalar as G2Scalar};
use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto_tbls::dkg_v1::{Message, Output, Party, ProcessedMessage, UsedProcessedMessages};
use fastcrypto_tbls::ecies_v1::{PrivateKey, PublicKey};
use fastcrypto_tbls::nodes::{Node, Nodes};
use fastcrypto_tbls::random_oracle::RandomOracle;
use grpc_helpers::{
    create_grpc_client, fetch_committee_data, fetch_old_partial_pks_from_keyserver,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use sui_types::base_types::{ObjectID, SuiAddress};

/// Configuration for a DKG party
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PartyConfig {
    /// Unique party ID
    party_id: u16,
    /// ECIES private key for encryption
    enc_sk: PrivateKey<G2Element>,
    /// ECIES public key for encryption
    enc_pk: PublicKey<G2Element>,
    /// Signing key (for message authentication, not part of DKG)
    signing_sk: G2Scalar,
    /// Signing public key
    signing_pk: G2Element,
    /// The committee object ID (used for random oracle)
    committee_id: ObjectID,
    /// Threshold (t)
    threshold: u16,
    /// Old threshold for key rotation (None for fresh DKG)
    old_threshold: Option<u16>,
    /// Old share for key rotation (None for fresh DKG)
    old_share: Option<G2Scalar>,
    /// Old partial public key for key rotation verification
    old_enc_pk: Option<PublicKey<G2Element>>,
    /// Old party ID (for continuing members in rotation)
    old_party_id: Option<u16>,
}

/// State of the DKG protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DkgState {
    /// Configuration
    config: PartyConfig,
    /// All nodes in the protocol
    nodes: Nodes<G2Element>,
    /// Messages created by this party
    my_messages: Vec<Message<G2Element, G2Element>>,
    /// Messages received from other parties
    received_messages: HashMap<u16, Message<G2Element, G2Element>>,
    /// Processed messages
    processed_messages: Vec<ProcessedMessage<G2Element, G2Element>>,
    /// Confirmation and used messages
    confirmation: Option<(
        fastcrypto_tbls::dkg_v1::Confirmation<G2Element>,
        UsedProcessedMessages<G2Element, G2Element>,
    )>,
    /// Final output (if completed)
    output: Option<Output<G2Element, G2Element>>,
    /// Mapping from new party ID to old party ID (for rotation)
    new_to_old_mapping: HashMap<u16, u16>,
    /// Expected partial public keys from old committee (for rotation verification)
    expected_old_partial_pks: HashMap<u16, G2Element>,
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
    /// Generate ECIES keypair for registration
    GenerateKeys,

    /// Initialize DKG party (fresh DKG or key rotation)
    Init {
        /// My address (used to determine party id based on position in committee.members)
        #[arg(long)]
        my_address: SuiAddress,

        /// Committee object ID
        #[arg(short = 'c', long)]
        committee_id: ObjectID,

        /// ECIES private key (hex encoded)
        #[arg(long)]
        ecies_sk: String,

        /// Signing private key (hex encoded)
        #[arg(long)]
        signing_sk: String,

        /// KeyServer object ID (required for key rotation to fetch old partial public keys)
        #[arg(long)]
        key_server_id: Option<ObjectID>,

        /// Old key share (for continuing members in key rotation)
        #[arg(long)]
        old_share: Option<String>,

        /// Network (mainnet or testnet)
        #[arg(long, default_value = "testnet")]
        network: String,

        /// State directory
        #[arg(short = 's', long)]
        state_dir: PathBuf,
    },

    /// Create and output DKG message
    CreateMessage {
        /// State directory
        #[arg(short = 's', long)]
        state_dir: PathBuf,
    },

    /// Process all messages and attempt to finalize if no complaints
    ProcessAllMessages {
        /// Base64 encoded messages (comma-separated for multiple messages)
        #[arg(short, long, value_delimiter = ',')]
        messages: Vec<String>,
        /// State directory
        #[arg(short = 's', long)]
        state_dir: PathBuf,
    },
}

impl DkgState {
    fn save(&self, state_dir: &Path) -> Result<()> {
        fs::create_dir_all(state_dir)?;
        let path = state_dir.join("state.json");
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    fn load(state_dir: &Path) -> Result<Self> {
        let path = state_dir.join("state.json");
        let json = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeys => {
            let enc_sk = PrivateKey::<G2Element>::new(&mut thread_rng());
            let enc_pk = PublicKey::<G2Element>::from_private_key(&enc_sk);
            let signing_sk = G2Scalar::rand(&mut thread_rng());
            let signing_pk = G2Element::generator() * signing_sk;

            println!("==============FOR REGISTRATION ONCHAIN===============");
            println!(
                "ECIES_PK={}",
                Hex::encode_with_format(bcs::to_bytes(&enc_pk)?)
            );
            println!(
                "SIGNING_PK={}",
                Hex::encode_with_format(bcs::to_bytes(&signing_pk)?)
            );

            println!("\n==============KEEP SECRET, FOR DKG INITIALIZATION===============");
            println!(
                "ECIES_SK={}",
                Hex::encode_with_format(bcs::to_bytes(&enc_sk)?)
            );
            println!(
                "SIGNING_SK={}",
                Hex::encode_with_format(bcs::to_bytes(&signing_sk)?)
            );
        }

        Commands::Init {
            my_address,
            committee_id,
            ecies_sk,
            signing_sk,
            key_server_id,
            old_share,
            network,
            state_dir,
        } => {
            // Create gRPC client.
            let mut grpc_client = create_grpc_client(&network)?;

            // Fetch committee data from onchain.
            let committee_data = fetch_committee_data(&committee_id, &mut grpc_client).await?;
            println!(
                "Fetched committee with {} members, threshold: {}, network: {}",
                committee_data.members.len(),
                committee_data.threshold,
                network
            );

            // Check init for fresh DKG or rotation.
            let is_rotation = if committee_data.old_committee_id.is_some()
                && key_server_id.is_some()
                && old_share.is_some()
            {
                println!(
                    "Initializing key rotation for address {} and committee: {}",
                    my_address, committee_id
                );
                true
            } else if committee_data.old_committee_id.is_none()
                && key_server_id.is_none()
                && old_share.is_none()
            {
                println!(
                    "Initializing fresh DKG for address {} and committee {}",
                    my_address, committee_id
                );
                false
            } else {
                return Err(anyhow!("Invalid initialization parameters"));
            };

            // Parse keys
            let enc_sk: PrivateKey<G2Element> = bcs::from_bytes(&Hex::decode(&ecies_sk)?)?;
            let enc_pk = PublicKey::<G2Element>::from_private_key(&enc_sk);
            let signing_sk: G2Scalar = bcs::from_bytes(&Hex::decode(&signing_sk)?)?;
            let signing_pk = G2Element::generator() * signing_sk;

            // Find my party ID in the committee by address
            let my_party_id = committee_data.find_party_id(&my_address).ok_or_else(|| {
                anyhow!("My address {} not found in committee members", my_address)
            })?;
            println!("My party ID: {}", my_party_id);

            let old_share = old_share
                .as_ref()
                .map(|s| -> Result<G2Scalar> { Ok(bcs::from_bytes(&Hex::decode(s)?)?) })
                .transpose()?;

            let (my_old_party_id, old_enc_pk, old_threshold, new_to_old_map, expected_pks) =
                if is_rotation {
                    let old_committee_data = fetch_committee_data(
                        &committee_data.old_committee_id.unwrap(),
                        &mut grpc_client,
                    )
                    .await?;
                    let my_old_party_id = old_committee_data
                        .find_party_id(&my_address)
                        .ok_or_else(|| {
                            anyhow!(
                                "My address {} not found in old committee members",
                                my_address
                            )
                        })?;
                    let old_enc_pk = old_committee_data
                        .members
                        .iter()
                        .find(|(_, address, _)| *address == my_address)
                        .map(|(_, _, pk)| pk.clone())
                        .ok_or_else(|| {
                            anyhow!(
                                "My old ECIES PK not found in old committee members {}",
                                my_address
                            )
                        })?;
                    let old_threshold = old_committee_data.threshold;

                    let mut new_to_old_map = HashMap::new();
                    committee_data
                        .members
                        .iter()
                        .for_each(|(party_id, address, _)| {
                            let old_party_id = old_committee_data
                                .members
                                .iter()
                                .find(|(_, addr, _)| addr == address)
                                .map(|(old_party_id, _, _)| *old_party_id);
                            if let Some(old_party_id) = old_party_id {
                                new_to_old_map.insert(*party_id, old_party_id);
                            }
                        });

                    let expected_pks = fetch_old_partial_pks_from_keyserver(
                        &key_server_id.unwrap(),
                        &mut grpc_client,
                    )
                    .await?;
                    (
                        Some(my_old_party_id),
                        Some(old_enc_pk),
                        Some(old_threshold),
                        new_to_old_map,
                        expected_pks,
                    )
                } else {
                    (None, None, None, HashMap::new(), HashMap::new())
                };

            // Create nodes for all parties using their enc_pks
            let mut nodes = Vec::new();
            for (party_id, _, pk) in committee_data.members {
                nodes.push(Node {
                    id: party_id,
                    pk,
                    weight: 1,
                });
            }

            let config = PartyConfig {
                party_id: my_party_id,
                enc_sk,
                enc_pk,
                signing_sk,
                signing_pk,
                committee_id,
                threshold: committee_data.threshold,
                old_threshold,
                old_share,
                old_enc_pk,
                old_party_id: my_old_party_id,
            };

            let state = DkgState {
                config,
                nodes: Nodes::new(nodes)?,
                my_messages: vec![],
                received_messages: HashMap::new(),
                processed_messages: vec![],
                confirmation: None,
                output: None,
                new_to_old_mapping: new_to_old_map,
                expected_old_partial_pks: expected_pks,
            };

            state.save(&state_dir)?;
            println!(
                "State saved to {:?}. Ready for DKG protocol. Run 'create-message' to start.",
                state_dir
            );
        }

        Commands::CreateMessage { state_dir } => {
            let mut state = DkgState::load(&state_dir)?;

            // For rotation, only continuing members create messages
            if state.config.old_share.is_none() {
                println!(
                    "New party {} - skipping message creation for rotation",
                    state.config.party_id
                );
                return Ok(());
            }

            println!("Creating DKG message for party {}", state.config.party_id);

            let random_oracle = RandomOracle::new(&state.config.committee_id.to_string());

            // Create party instance
            let party = if let Some(old_share) = state.config.old_share {
                // Key rotation case - continuing member
                Party::<G2Element, G2Element>::new_advanced(
                    state.config.enc_sk.clone(),
                    state.nodes.clone(),
                    state.config.threshold,
                    random_oracle,
                    Some(old_share),
                    state.config.old_threshold,
                    &mut thread_rng(),
                )?
            } else {
                // Fresh DKG case
                Party::<G2Element, G2Element>::new_advanced(
                    state.config.enc_sk.clone(),
                    state.nodes.clone(),
                    state.config.threshold,
                    random_oracle,
                    None,
                    None,
                    &mut thread_rng(),
                )?
            };

            // Create message
            let message = party.create_message(&mut thread_rng())?;

            // Sign the message
            let message_bytes = bcs::to_bytes(&message)?;
            let signature = sign_message(&message_bytes, &state.config.signing_sk);

            // Store message
            state.my_messages.push(message.clone());
            state.save(&state_dir)?;

            // Output signed message
            let signed_message = SignedMessage {
                message: message_bytes,
                signature,
                signer_pk: state.config.signing_pk,
            };

            let encoded = Base64::encode(bcs::to_bytes(&signed_message)?);
            println!("DKG message created (base64):");
            println!("MESSAGE_{}={}", state.config.party_id, encoded);
            println!("\nShare this message with other parties");
        }

        Commands::ProcessAllMessages {
            messages,
            state_dir,
        } => {
            let mut state = DkgState::load(&state_dir)?;

            // For rotation, verify we have exactly t' messages
            if let Some(old_threshold) = state.config.old_threshold {
                if messages.len() != old_threshold as usize {
                    return Err(anyhow!(
                        "Key rotation requires exactly {} messages from old committee members, got {}",
                        old_threshold, messages.len()
                    ));
                }
                println!(
                    "Processing {} messages for key rotation (t' = {})",
                    messages.len(),
                    old_threshold
                );
            } else {
                println!("Processing {} message(s) for fresh DKG", messages.len());
            }

            // Create party once for all messages
            let party = Party::<G2Element, G2Element>::new_advanced(
                state.config.enc_sk.clone(),
                state.nodes.clone(),
                state.config.threshold,
                RandomOracle::new(&state.config.committee_id.to_string()),
                state.config.old_share,
                state.config.old_threshold,
                &mut thread_rng(),
            )?;

            let mut processed_count = 0;

            // Process each message
            for message in messages {
                // Decode base64 message
                let bytes = Base64::decode(&message)?;
                let signed_msg: SignedMessage = bcs::from_bytes(&bytes)?;

                let msg: Message<G2Element, G2Element> = bcs::from_bytes(&signed_msg.message)?;
                println!("  Processing message from party {}...", msg.sender);

                // TODO: verify signed message using onchain signing pk for each party

                // Store message
                state.received_messages.insert(msg.sender, msg.clone());

                // For rotation, find the expected old partial PK for this sender
                let processed = if state.config.old_threshold.is_some() {
                    // Find old party ID for this sender
                    let old_party_id = state.new_to_old_mapping.get(&msg.sender).or(
                        // If not in mapping, sender might be using old party ID directly
                        // This is a simplification - in production, need proper mapping
                        Some(&msg.sender),
                    );

                    if let Some(old_id) = old_party_id {
                        if let Some(expected_pk) = state.expected_old_partial_pks.get(old_id) {
                            println!("    Verifying against old partial PK for party {}", old_id);
                            match party.process_message_and_check_pk(
                                msg.clone(),
                                expected_pk,
                                &mut thread_rng(),
                            ) {
                                Ok(proc) => proc,
                                Err(e) => {
                                    println!(
                                        "ERROR: Verification failed for party {} (old party {})",
                                        msg.sender, old_id
                                    );
                                    println!("Error: {:?}", e);
                                    println!("Aborting protocol - all parties should abort");
                                    return Err(anyhow!(
                                        "Key rotation verification failed for party {}",
                                        msg.sender
                                    ));
                                }
                            }
                        } else {
                            return Err(anyhow!("No expected partial PK for old party {}", old_id));
                        }
                    } else {
                        return Err(anyhow!("No mapping found for party {}", msg.sender));
                    }
                } else {
                    // Fresh DKG
                    party.process_message(msg, &mut thread_rng())?
                };

                if let Some(complaint) = &processed.complaint {
                    println!(
                        "ERROR: Complaint found from party {}",
                        processed.message.sender
                    );
                    println!("Complaint details: {:?}", complaint);
                    println!("Protocol aborted - do not approve onchain");
                    return Err(anyhow!(
                        "DKG protocol failed due to complaint from party {}",
                        processed.message.sender
                    ));
                }

                state.processed_messages.push(processed);
                processed_count += 1;
            }

            println!("\n Successfully processed {} message(s)", processed_count);

            // Merge processed messages
            let (confirmation, used_msgs) = party.merge(&state.processed_messages)?;

            // Check for complaints
            if !confirmation.complaints.is_empty() {
                println!("ERROR: Complaints found after merge");
                println!("Complaints: {:?}", confirmation.complaints);
                println!("Do NOT approve onchain - protocol failed");
                state.confirmation = Some((confirmation, used_msgs));
                state.save(&state_dir)?;
                return Err(anyhow!("DKG protocol failed due to complaints"));
            }

            state.confirmation = Some((confirmation.clone(), used_msgs.clone()));

            // Complete the protocol
            let output = if state.config.old_threshold.is_some() {
                // Key rotation: use complete_optimistic_key_rotation
                let sender_to_old_map: HashMap<u16, u16> = state
                    .new_to_old_mapping
                    .iter()
                    .map(|(new_id, old_id)| (*new_id, *old_id))
                    .collect();

                println!(
                    "Completing key rotation with mapping: {:?}",
                    sender_to_old_map
                );
                party.complete_optimistic_key_rotation(&used_msgs, &sender_to_old_map)?
            } else {
                // Fresh DKG
                party.complete_optimistic(&used_msgs)?
            };

            state.output = Some(output.clone());

            println!("============MASTER PK AND PARTIAL PKS=====================");
            println!(
                "KEY_SERVER_PK={}",
                Hex::encode_with_format(bcs::to_bytes(output.vss_pk.c0())?)
            );
            // Generate partial public keys for ALL parties in the new committee
            for party_id in 0..state.nodes.num_nodes() {
                // party id is 0 index and share index is party id + 1
                let share_index = NonZeroU16::new(party_id as u16 + 1).unwrap();
                let partial_pk = output.vss_pk.eval(share_index);
                println!(
                    "PARTY_{}_PARTIAL_PK={}",
                    party_id,
                    Hex::encode_with_format(bcs::to_bytes(&partial_pk.value)?)
                );
            }

            println!("============YOUR PARTIAL KEY SHARE, KEEP SECRET=====================");
            if let Some(shares) = &output.shares {
                for share in shares {
                    println!(
                        "MASTER_KEY={}",
                        Hex::encode_with_format(bcs::to_bytes(&share.value)?)
                    );
                }
            }

            println!("============FULL VSS POLYNOMIAL COEFFICIENTS=====================");
            for i in 0..=output.vss_pk.degree() {
                let coeff = output.vss_pk.coefficient(i);
                println!(
                    "Coefficient {}: {}",
                    i,
                    Hex::encode_with_format(bcs::to_bytes(coeff)?)
                );
            }
        }
    }

    Ok(())
}

/// Signed message wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedMessage {
    message: Vec<u8>,
    signature: Vec<u8>,
    signer_pk: G2Element,
}

/// BLS signature for message authentication
fn sign_message(message: &[u8], sk: &G2Scalar) -> Vec<u8> {
    use fastcrypto::groups::HashToGroupElement;

    // Hash message to G2 point
    let msg_point = G2Element::hash_to_group_element(message);

    // Sign by multiplying with secret key: signature = sk * H(m)
    let signature = msg_point * sk;

    bcs::to_bytes(&signature).expect("Serialization failed")
}
