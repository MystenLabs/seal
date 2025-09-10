// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::groups::bls12381::{G2Element, Scalar as G2Scalar};
use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto_tbls::dkg_v1::{Message, Output, Party, ProcessedMessage, UsedProcessedMessages};
use fastcrypto_tbls::ecies_v1::{PrivateKey, PublicKey};
use fastcrypto_tbls::nodes::{Node, Nodes};
use fastcrypto_tbls::random_oracle::RandomOracle;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use tracing::warn;

/// Default directory for storing DKG state
const DKG_STATE_DIR: &str = ".dkg-state";

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
    committee_id: String,
    /// Threshold (t)
    threshold: u16,
    /// Old threshold for key rotation (None for fresh DKG)
    old_threshold: Option<u16>,
    /// Old share for key rotation (None for fresh DKG)
    old_share: Option<G2Scalar>,
    /// Old partial public key for key rotation verification
    old_pk: Option<G2Element>,
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

    /// Initialize DKG party by fetching InitCommittee from chain
    Init {
        /// My address (to determine my party ID from sorted committee)
        #[arg(long)]
        my_address: String,

        /// InitCommittee object ID
        #[arg(short = 'c', long)]
        committee_id: String,

        /// ECIES private key (hex encoded)
        #[arg(long)]
        ecies_sk: String,

        /// Signing private key (hex encoded)
        #[arg(long)]
        signing_sk: String,

        /// Threshold (number of parties needed to sign)
        #[arg(short, long)]
        threshold: u16,

        /// State directory (default: .dkg-state)
        #[arg(short = 's', long, default_value = DKG_STATE_DIR)]
        state_dir: PathBuf,
    },

    /// Initialize for key rotation
    InitRotation {
        /// Party ID (unique identifier)
        #[arg(short, long)]
        party_id: u16,
        /// Committee ID (e.g., new Sui object ID)
        #[arg(short = 'c', long)]
        committee_id: String,
        /// Candidate object IDs for new committee (comma-separated)
        #[arg(long, value_delimiter = ',')]
        candidates: Vec<String>,
        /// New threshold
        #[arg(short, long)]
        threshold: u16,
        /// Old threshold (t' from previous committee)
        #[arg(long)]
        old_threshold: u16,
        /// Old share (hex encoded, for parties in both committees)
        #[arg(long)]
        old_share: Option<String>,
        /// Old partial public key (hex encoded, for verification)
        #[arg(long)]
        old_pk: Option<String>,
        /// State directory (default: .dkg-state)
        #[arg(short = 's', long, default_value = DKG_STATE_DIR)]
        state_dir: PathBuf,
    },

    /// Create and output DKG message
    CreateMessage {
        /// State directory
        #[arg(short = 's', long, default_value = DKG_STATE_DIR)]
        state_dir: PathBuf,
    },

    /// Process all messages and attempt to finalize if no complaints
    ProcessAllMessages {
        /// Base64 encoded messages (comma-separated for multiple messages)
        #[arg(short, long, value_delimiter = ',')]
        messages: Vec<String>,
        /// Expected partial public key (hex, for key rotation only)
        #[arg(long)]
        expected_pk: Option<String>,
        /// State directory
        #[arg(short = 's', long, default_value = DKG_STATE_DIR)]
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

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeys => {
            let mut rng = StdRng::from_entropy();
            let enc_sk = PrivateKey::<G2Element>::new(&mut rng);
            let enc_pk = PublicKey::<G2Element>::from_private_key(&enc_sk);

            // Also generate signing keypair
            let signing_sk = G2Scalar::rand(&mut rng);
            let signing_pk = G2Element::generator() * signing_sk;

            println!("\nECIES Public Key (for registration):");
            println!("  0x{}", Hex::encode(bcs::to_bytes(&enc_pk)?));

            println!("\nSigning Public Key:");
            println!("  0x{}", Hex::encode(bcs::to_bytes(&signing_pk)?));

            println!("\nECIES Private Key (keep secret):");
            println!("  0x{}", Hex::encode(bcs::to_bytes(&enc_sk)?));

            println!("\nSigning Private Key (keep secret):");
            println!("  0x{}", Hex::encode(bcs::to_bytes(&signing_sk)?));

            println!("\nIMPORTANT: Save the private keys securely.");
        }

        Commands::Init {
            my_address,
            committee_id,
            ecies_sk,
            signing_sk,
            threshold,
            state_dir,
        } => {
            println!("Initializing DKG party for address {}", my_address);
            println!("Fetching InitCommittee from chain: {}", committee_id);

            // TODO: read from members array from the InitCommittee obj
            let candidate_addresses = [
                "0x0636157e9d013585ff473b3b378499ac2f1d207ed07d70e2cd815711725bca9d".to_string(), // Party 0
                "0xe6a37ff5cd968b6a666fb033d85eabc674449f44f9fc2b600e55e27354211ed6".to_string(), // Party 1
            ];

            // TODO: read from init committee obj
            let candidate_public_keys = [
                "0x886d98eddd9f4e66e69f620dff66b6ed3c21f3cf5bde3b42d1e18159ad2e7b59ed5eb994b2bdcc491d29a1c5d4d492fc0c549c8d20838c6adaa82945a60908f3a481c78273eadbc51d94906238d6fe2f16494559556b074e7bb6f36807f8462c",
                "0xab5603f3cfaef06c0994f289bf8f1519222edd6ed48b49d9ebb975312dfbcd513dca31c83f6d1d1f45188f373aff95ae06f81dfd2cfafd69f679ce22d311ad4d34725277b369ece21f98e8f3ac257a589c0075d7533487862170760c69aedf4e",
            ];

            // Find my party ID based on address position in sorted list
            let my_party_id = candidate_addresses
                .iter()
                .position(|addr| addr == &my_address)
                .ok_or_else(|| {
                    anyhow!(
                        "My address {} not found in committee candidates",
                        my_address
                    )
                })? as u16;

            let my_enc_sk: PrivateKey<G2Element> = bcs::from_bytes(&Hex::decode(&ecies_sk)?)?;
            let my_enc_pk = PublicKey::<G2Element>::from_private_key(&my_enc_sk);
            let my_signing_sk: G2Scalar = bcs::from_bytes(&Hex::decode(&signing_sk)?)?;
            let my_signing_pk = G2Element::generator() * my_signing_sk;

            // Create nodes for all parties using real public keys
            let mut nodes = Vec::new();
            for (i, _addr) in candidate_addresses.iter().enumerate() {
                let public_key_bytes = Hex::decode(candidate_public_keys[i])?;
                let node_pk: PublicKey<G2Element> = bcs::from_bytes(&public_key_bytes)?;
                nodes.push(Node {
                    id: i as u16,
                    pk: node_pk,
                    weight: 1,
                });
            }

            let config = PartyConfig {
                party_id: my_party_id,
                enc_sk: my_enc_sk,
                enc_pk: my_enc_pk,
                signing_sk: my_signing_sk,
                signing_pk: my_signing_pk,
                committee_id,
                threshold,
                old_threshold: None,
                old_share: None,
                old_pk: None,
            };

            let state = DkgState {
                config,
                nodes: Nodes::new(nodes)?,
                my_messages: vec![],
                received_messages: HashMap::new(),
                processed_messages: vec![],
                confirmation: None,
                output: None,
            };

            state.save(&state_dir)?;
            println!("DKG party initialized and saved to {:?}", state_dir);
            println!("Ready for DKG protocol. Run 'create-message' to start.");
        }

        Commands::InitRotation {
            party_id: _,
            committee_id: _,
            candidates: _,
            threshold: _,
            old_threshold: _,
            old_share: _,
            old_pk: _,
            state_dir: _,
        } => {
            // TODO
        }

        Commands::CreateMessage { state_dir } => {
            let mut state = DkgState::load(&state_dir)?;

            println!("Creating DKG message for party {}", state.config.party_id);

            let random_oracle = RandomOracle::new(&state.config.committee_id);
            let mut rng = StdRng::from_entropy();

            // Create party instance
            let party = if let Some(old_share) = state.config.old_share {
                // Key rotation case
                Party::<G2Element, G2Element>::new_advanced(
                    state.config.enc_sk.clone(),
                    state.nodes.clone(),
                    state.config.threshold,
                    random_oracle,
                    Some(old_share),
                    state.config.old_threshold,
                    &mut rng,
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
                    &mut rng,
                )?
            };

            // Create message
            let message = party.create_message(&mut rng)?;

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
            println!("{}", encoded);
            println!("\nShare this message with other parties");
        }

        Commands::ProcessAllMessages {
            messages,
            expected_pk: _,
            state_dir,
        } => {
            let mut state = DkgState::load(&state_dir)?;

            println!("Processing {} message(s)...", messages.len());

            let random_oracle = RandomOracle::new(&state.config.committee_id);
            let mut rng = StdRng::from_entropy();

            // Create party once for all messages
            let party = Party::<G2Element, G2Element>::new_advanced(
                state.config.enc_sk.clone(),
                state.nodes.clone(),
                state.config.threshold,
                random_oracle,
                state.config.old_share,
                state.config.old_threshold,
                &mut rng,
            )?;

            let mut processed_count = 0;
            let mut complaints_count = 0;

            // Process each message
            for message in messages {
                // Decode base64 message
                let bytes = Base64::decode(&message)?;
                let signed_msg: SignedMessage = bcs::from_bytes(&bytes)?;

                let msg: Message<G2Element, G2Element> = bcs::from_bytes(&signed_msg.message)?;
                println!("  Processing message from party {}...", msg.sender);

                // todo: verify signed message using onchain signing pk for each party

                // Store message
                state.received_messages.insert(msg.sender, msg.clone());

                // Process message
                let processed = if let (Some(old_pk), Some(_old_threshold)) =
                    (state.config.old_pk, state.config.old_threshold)
                {
                    // Key rotation: verify with old pk
                    party.process_message_and_check_pk(msg, &old_pk, &mut rng)?
                } else {
                    // Fresh DKG
                    party.process_message(msg, &mut rng)?
                };

                if let Some(_complaint) = &processed.complaint {
                    warn!(
                        "Found complaint in processed message from party {}",
                        processed.message.sender
                    );
                    complaints_count += 1;
                }

                state.processed_messages.push(processed);
                processed_count += 1;
            }

            println!("\n Successfully processed {} message(s)", processed_count);

            if complaints_count != 0 {
                return Err(anyhow!("Cannot complete with complaints present"));
            }

            // merge
            let (confirmation, used_msgs) = party.merge(&state.processed_messages)?;
            state.confirmation = Some((confirmation, used_msgs.clone()));

            // complete
            let output = party.complete_optimistic(&used_msgs)?;
            state.output = Some(output.clone());

            println!("========================================");
            println!("ALL PARTIES' PARTIAL PUBLIC KEYS:");
            // vss_pk.c0 is the aggregated ks pk
            for (party_id, _) in state.received_messages {
                // party id is 0 index and share index is party id + 1
                let share_index = NonZeroU16::new(party_id + 1).unwrap();
                let partial_pk = output.vss_pk.eval(share_index);
                println!(
                    "   Party {} partial public key: 0x{}",
                    party_id,
                    Hex::encode(bcs::to_bytes(&partial_pk.value)?)
                );
            }

            if let Some(shares) = &output.shares {
                println!("========================================");
                println!(
                    "YOUR SECRET SHARE (THIS IS YOUR MASTER KEY FOR THE KEY SERVER- KEEP PRIVATE):"
                );
                for share in shares {
                    println!("   0x{}", Hex::encode(bcs::to_bytes(&share.value)?));
                }

                println!("========================================");
                println!("YOUR PARTY ID AND PARTIAL PUBLIC KEY:");
                for share in shares {
                    let my_partial_pk = output.vss_pk.eval(share.index);
                    println!(
                        "  Party ID {} 0x{}",
                        state.config.party_id,
                        Hex::encode(bcs::to_bytes(&my_partial_pk.value)?)
                    );
                }
            }

            println!("========================================");
            println!("FULL VSS POLYNOMIAL COEFFICIENTS:");
            for i in 0..=output.vss_pk.degree() {
                let coeff = output.vss_pk.coefficient(i);
                println!(
                    "   Coefficient {}: 0x{}",
                    i,
                    Hex::encode(bcs::to_bytes(coeff)?)
                );
            }
            println!("========================================");
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
