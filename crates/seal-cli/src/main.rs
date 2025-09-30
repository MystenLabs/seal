// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use crypto::dem::{Aes256Gcm, Hmac256Ctr};
use crypto::ibe::{generate_seed, SEED_LENGTH};
use crypto::prefixed_hex::PrefixedHex;
use crypto::EncryptionInput::Plain;
use crypto::{
    create_full_id, ibe, seal_decrypt, seal_encrypt, Ciphertext, EncryptedObject, EncryptionInput,
    IBEEncryptions, IBEPublicKeys, IBEUserSecretKeys, ObjectID,
};
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::bls12381::{G1Element, G2Element, Scalar};
use fastcrypto::serde_helpers::ToFromByteArray;
use rand::thread_rng;
use reqwest::Body;
use seal_sdk::types::{FetchKeyRequest, FetchKeyResponse};
use seal_sdk::IBEPublicKey;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use sui_sdk::rpc_types::SuiParsedData;
use sui_sdk::SuiClientBuilder;
use sui_sdk_types::ObjectId as NewObjectID;
use sui_types::dynamic_field::DynamicFieldName;
use sui_types::TypeTag;

const KEY_LENGTH: usize = 32;

/// Key server object layout containing object id, name, url, and public key.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyServerInfo {
    pub object_id: ObjectID,
    pub name: String,
    pub url: String,
    pub public_key: String,
}

/// Fetch and parse key server object from fullnode.
/// TODO: rewrite with sui-rust-sdk
pub async fn fetch_key_server_urls(
    key_server_ids: &[ObjectID],
    network: &str,
) -> Result<Vec<KeyServerInfo>, FastCryptoError> {
    let sui_rpc = match network {
        "mainnet" => "https://fullnode.mainnet.sui.io:443",
        "testnet" => "https://fullnode.testnet.sui.io:443",
        _ => {
            return Err(FastCryptoError::GeneralError(format!(
                "Invalid network: {}. Use 'mainnet' or 'testnet'",
                network
            )))
        }
    };
    let sui_client = SuiClientBuilder::default()
        .build(sui_rpc)
        .await
        .map_err(|e| FastCryptoError::GeneralError(format!("Failed to build Sui client: {}", e)))?;
    let mut key_servers = Vec::new();
    for object_id in key_server_ids {
        // Get the dynamic field object for version 1
        let dynamic_field_name = DynamicFieldName {
            type_: TypeTag::U64,
            value: serde_json::Value::String("1".to_string()),
        };

        match sui_client
            .read_api()
            .get_dynamic_field_object(
                sui_types::base_types::ObjectID::new(object_id.into_inner()),
                dynamic_field_name,
            )
            .await
        {
            Ok(response) => {
                if let Some(object_data) = response.data {
                    if let Some(content) = object_data.content {
                        if let SuiParsedData::MoveObject(parsed_data) = content {
                            let fields = &parsed_data.fields;

                            // Convert fields to JSON value for access
                            let fields_json = serde_json::to_value(fields).map_err(|e| {
                                FastCryptoError::GeneralError(format!(
                                    "Failed to serialize fields: {}",
                                    e
                                ))
                            })?;

                            // Extract URL and name from the nested 'value' field
                            let value_struct = fields_json.get("value").ok_or_else(|| {
                                FastCryptoError::GeneralError(format!(
                                    "Missing 'value' field for object {}",
                                    object_id
                                ))
                            })?;

                            let value_fields = value_struct.get("fields").ok_or_else(|| {
                                FastCryptoError::GeneralError(format!(
                                    "Missing 'fields' in value struct for object {}",
                                    object_id
                                ))
                            })?;

                            let url = value_fields.get("url")
                                .and_then(|v| match v {
                                    serde_json::Value::String(s) => Some(s.clone()),
                                    _ => None,
                                })
                                .ok_or_else(|| FastCryptoError::GeneralError(format!("Missing or invalid 'url' field in value fields for object {}", object_id)))?;

                            let name = value_fields
                                .get("name")
                                .map(|v| match v {
                                    serde_json::Value::String(s) => s.clone(),
                                    _ => "Unknown".to_string(),
                                })
                                .unwrap_or_else(|| "Unknown".to_string());

                            let public_key = value_fields.get("pk")
                                .and_then(|v| match v {
                                    serde_json::Value::Array(arr) => {
                                        // Convert array of numbers to bytes then to hex string
                                        let bytes: Result<Vec<u8>, _> = arr.iter()
                                            .map(|n| n.as_u64().and_then(|n| u8::try_from(n).ok()))
                                            .collect::<Option<Vec<_>>>()
                                            .ok_or("Invalid byte values in pk array");
                                        bytes.ok().map(|b| Hex::encode(&b))
                                    },
                                    serde_json::Value::String(s) => Some(s.clone()),
                                    _ => None,
                                })
                                .ok_or_else(|| FastCryptoError::GeneralError(format!("Missing or invalid 'pk' field in value fields for object {}", object_id)))?;

                            key_servers.push(KeyServerInfo {
                                object_id: *object_id,
                                name,
                                url,
                                public_key,
                            });
                        } else {
                            return Err(FastCryptoError::GeneralError(format!(
                                "Unexpected content type for object {}",
                                object_id
                            )));
                        }
                    } else {
                        return Err(FastCryptoError::GeneralError(format!(
                            "No content found for object {}",
                            object_id
                        )));
                    }
                } else {
                    return Err(FastCryptoError::GeneralError(format!(
                        "Object {} not found",
                        object_id
                    )));
                }
            }
            Err(e) => {
                return Err(FastCryptoError::GeneralError(format!(
                    "Failed to fetch dynamic field for object {}: {}",
                    object_id, e
                )));
            }
        }
    }

    Ok(key_servers)
}

/// Default encoding for serializing and deserializing values.
type DefaultEncoding = PrefixedHex;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Generate a new master key and public key.
    Genkey,
    /// Generate a fresh seed for deriving keys. See [`Command::DeriveKey`].
    GenSeed,
    /// Derive a key pair from a seed and an index for use with permissioned servers.
    DeriveKey {
        /// Seed for the key pair. Must be 32 bytes.
        #[arg(long)]
        seed: EncodedByteArray<SEED_LENGTH>,
        /// Index for the key pair. This is used to derive a different key pair from the same seed.
        #[arg(long)]
        index: u64,
    },
    /// Extract a user secret key from an id and a master key.
    Extract {
        /// The Sui address of the Move package that handles the KMS for this key
        #[arg(long)]
        package_id: ObjectID,
        /// The ID of the key that should be derived.
        #[arg(long)]
        id: EncodedBytes,
        /// Master key. Hex encoding of a BLS12-381 scalar.
        #[arg(long, value_parser = parse_serializable::<Scalar, DefaultEncoding>)]
        master_key: Scalar,
    },
    /// Verify a user secret key against a public key.
    Verify {
        /// The Sui address of the Move package that handles the KMS for this key
        #[arg(long)]
        package_id: ObjectID,
        /// The ID of the key that should be derived.
        #[arg(long)]
        id: EncodedBytes,
        /// User secret key. Hex encoding of a compressed BLS12-381 G1Element.
        #[arg(long, value_parser = parse_serializable::<G1Element, DefaultEncoding>)]
        user_secret_key: G1Element,
        /// Public key. Hex encoding of a compressed BLS12-381 G2Element.
        #[arg(long, value_parser = parse_serializable::<G2Element, DefaultEncoding>)]
        public_key: G2Element,
    },
    /// Derive a key using Seal.
    /// The key is derived from the ID using an IBKEM, Boneh-Franklin over BLS12381.
    /// This outputs both the encrypted object as a hex-encoded BCS serialization, which can be shared publicly, and the derived symmetric key which should be kept privately.
    Plain {
        /// The Sui address of the Move package that handles the KMS for this key
        #[arg(long)]
        package_id: ObjectID,
        /// The ID of the key that should be derived.
        #[arg(long)]
        id: EncodedBytes,
        /// The number of key servers that need to be present for decryption
        #[arg(long)]
        threshold: u8,
        /// The hex-encoded public keys for the key servers
        #[arg(value_parser = parse_serializable::<G2Element, DefaultEncoding>, num_args = 1..)]
        public_keys: Vec<G2Element>,
        /// The address for the Move objects representing the key servers
        #[arg(num_args = 1.., last = true)]
        object_ids: Vec<ObjectID>,
    },
    /// Encrypt a message using Seal.
    /// The key is derived from the ID using an IBKEM, Boneh-Franklin over BLS12381, and the message is encrypted using AES-256-GCM.
    /// This outputs both the encrypted object as a hex-encoded BCS serialization, which can be shared publicly, and the derived symmetric key which should be kept privately.
    EncryptAes {
        /// The message to encrypt as hex-encoded bytes
        #[arg(long)]
        message: EncodedBytes,
        /// Optional additional authenticated data as hex-encoded bytes
        #[arg(long)]
        aad: Option<EncodedBytes>,
        /// The Sui address of the Move package that handles the KMS for this encryption
        #[arg(long)]
        package_id: ObjectID,
        /// The ID of the key that should be used for this encryption
        #[arg(long)]
        id: EncodedBytes,
        /// The number of key servers that need to be present for decryption
        #[arg(long)]
        threshold: u8,
        /// The hex-encoded public keys for the key servers
        #[arg(value_parser = parse_serializable::<G2Element, DefaultEncoding>, num_args = 1..)]
        public_keys: Vec<G2Element>,
        /// The address for the Move objects representing the key servers
        #[arg(num_args = 1.., last = true)]
        object_ids: Vec<ObjectID>,
    },
    /// Encrypt a message using Seal.
    /// The key is derived from the ID using an IBKEM, Boneh-Franklin over BLS12381, and the message is encrypted using counter-mode with hmac-sha3-256 as a PRF.
    /// This outputs both the encrypted object as a hex-encoded BCS serialization, which can be shared publicly, and the derived symmetric key which should be kept privately.
    EncryptHmac {
        /// The message to encrypt as hex-encoded bytes
        #[arg(long)]
        message: EncodedBytes,
        /// Optional additional authenticated data as hex-encoded bytes
        #[arg(long)]
        aad: Option<EncodedBytes>,
        /// The Sui address of the Move package that handles the KMS for this encryption
        #[arg(long)]
        package_id: ObjectID,
        /// The ID of the key that should be used for this encryption
        #[arg(long)]
        id: EncodedBytes,
        /// The number of key servers that need to be present for decryption
        #[arg(long)]
        threshold: u8,
        /// The hex-encoded public keys for the key servers
        #[arg(value_parser = parse_serializable::<G2Element, DefaultEncoding>, num_args = 1..)]
        public_keys: Vec<G2Element>,
        /// The address for the Move objects representing the key servers
        #[arg(num_args = 1.., last = true)]
        object_ids: Vec<ObjectID>,
    },
    /// Decrypt a Seal encrypted object.
    /// In case the encrypted object holds a message, this is returned.
    /// If Plain was used, the derived encryption key is returned.
    Decrypt {
        /// An encrypted object as hex-encoded bytes
        #[arg(value_parser = parse_serializable::<EncryptedObject, DefaultEncoding>)]
        encrypted_object: EncryptedObject,
        /// The secret keys for the key servers. The order of the keys must match the order of the key servers in the object_ids field.
        #[arg(value_parser = parse_serializable::<G1Element, DefaultEncoding>, num_args = 1..)]
        secret_keys: Vec<G1Element>,
        /// The address for the Move objects representing the key servers used for this decryption.
        #[arg(num_args = 1.., last = true)]
        object_ids: Vec<ObjectID>,
    },
    /// Parse a Seal encrypted object.
    /// This outputs the parts of the parsed encrypted object as a hex-encoded BCS serialization.
    Parse {
        /// The encrypted object as hex-encoded bytes
        #[arg(value_parser = parse_serializable::<EncryptedObject, DefaultEncoding>)]
        encrypted_object: EncryptedObject,
    },
    SymmetricDecrypt {
        /// An encrypted object as hex-encoded bytes.
        #[arg(value_parser = parse_serializable::<EncryptedObject, DefaultEncoding>)]
        encrypted_object: EncryptedObject,
        /// The derived symmetric key from the encryption.
        #[arg(long)]
        key: EncodedByteArray<KEY_LENGTH>,
    },
    /// Encrypt a secret's Hex encoded bytes using Seal. This uses the public fullnode for
    /// retrieval of key servers' public keys for the given network.
    Encrypt {
        /// The secrets to encrypt.
        #[arg(long, value_delimiter = ',')]
        secrets: Vec<EncodedBytes>,

        /// Unique per package identifier for all secrets.
        #[arg(long, value_delimiter = ',')]
        ids: Vec<EncodedBytes>,

        /// Package ID that defines seal policy.
        #[arg(short = 'p', long)]
        package_id: ObjectID,

        /// Comma-separated key server object IDs (e.g., 0x123,0x456)
        #[arg(short = 'k', long, value_delimiter = ',')]
        key_server_ids: Vec<ObjectID>,

        /// Threshold
        #[arg(short = 't', long)]
        threshold: u8,

        /// Network (mainnet or testnet)
        #[arg(short = 'n', long, default_value = "testnet")]
        network: String,
    },
    /// Fetch keys from Seal servers using encoded fetch keys request.
    FetchKeys {
        /// Hex encoded fetch keys request.
        #[arg(long)]
        request: EncodedBytes,

        /// Comma-separated key server object IDs (e.g., 0x123,0x456)
        #[arg(short = 'k', long, value_delimiter = ',')]
        key_server_ids: Vec<ObjectID>,

        /// Threshold
        #[arg(short = 't', long)]
        threshold: u8,

        /// Network (mainnet or testnet)
        #[arg(short = 'n', long, default_value = "testnet")]
        network: String,
    },
}

struct GenkeyOutput((Scalar, G2Element));
struct GenSeedOutput([u8; SEED_LENGTH]);
struct ExtractOutput(G1Element);
struct VerifyOutput(FastCryptoResult<()>);
struct EncryptionOutput((EncryptedObject, [u8; KEY_LENGTH]));
struct DecryptionOutput(Vec<u8>);
struct ParseOutput(EncryptedObject);
struct SymmetricDecryptOutput(Vec<u8>);

#[tokio::main]
async fn main() -> FastCryptoResult<()> {
    let args = Arguments::parse();

    let output = match args.command {
        Command::Genkey => GenkeyOutput(ibe::generate_key_pair(&mut thread_rng())).to_string(),
        Command::GenSeed => GenSeedOutput(generate_seed(&mut thread_rng())).to_string(),
        Command::DeriveKey {
            seed,
            index: derivation_index,
        } => {
            if seed.0.len() != SEED_LENGTH {
                return Err(FastCryptoError::InputLengthWrong(SEED_LENGTH));
            }
            GenkeyOutput(ibe::into_key_pair(ibe::derive_master_key(
                &seed.0,
                derivation_index,
            )))
            .to_string()
        }
        Command::Extract {
            package_id,
            id,
            master_key,
        } => ExtractOutput(ibe::extract(
            &master_key,
            &create_full_id(package_id.inner(), &id.0),
        ))
        .to_string(),
        Command::Verify {
            package_id,
            id,
            user_secret_key,
            public_key,
        } => VerifyOutput(ibe::verify_user_secret_key(
            &user_secret_key,
            &create_full_id(package_id.inner(), &id.0),
            &public_key,
        ))
        .to_string(),
        Command::Plain {
            package_id,
            id,
            threshold,
            public_keys,
            object_ids,
        } => EncryptionOutput(seal_encrypt(
            package_id,
            id.0,
            object_ids,
            &IBEPublicKeys::BonehFranklinBLS12381(public_keys),
            threshold,
            Plain,
        )?)
        .to_string(),
        Command::EncryptAes {
            message,
            aad,
            package_id,
            id,
            threshold,
            public_keys,
            object_ids,
        } => EncryptionOutput(seal_encrypt(
            package_id,
            id.0,
            object_ids,
            &IBEPublicKeys::BonehFranklinBLS12381(public_keys),
            threshold,
            EncryptionInput::Aes256Gcm {
                data: message.0,
                aad: aad.map(|a| a.0),
            },
        )?)
        .to_string(),
        Command::EncryptHmac {
            message,
            aad,
            package_id,
            id,
            threshold,
            public_keys,
            object_ids,
        } => EncryptionOutput(seal_encrypt(
            package_id,
            id.0,
            object_ids,
            &IBEPublicKeys::BonehFranklinBLS12381(public_keys),
            threshold,
            EncryptionInput::Hmac256Ctr {
                data: message.0,
                aad: aad.map(|a| a.0),
            },
        )?)
        .to_string(),
        Command::Decrypt {
            encrypted_object,
            secret_keys,
            object_ids,
        } => DecryptionOutput(seal_decrypt(
            &encrypted_object, // TODO
            &IBEUserSecretKeys::BonehFranklinBLS12381(
                object_ids.into_iter().zip(secret_keys).collect(),
            ),
            None,
        )?)
        .to_string(),
        Command::Parse { encrypted_object } => ParseOutput(encrypted_object).to_string(),
        Command::SymmetricDecrypt {
            encrypted_object,
            key,
        } => match encrypted_object.ciphertext {
            Ciphertext::Aes256Gcm { blob, aad } => {
                Aes256Gcm::decrypt(&blob, &aad.unwrap_or(vec![]), &key.0)
            }
            Ciphertext::Hmac256Ctr { blob, aad, mac } => {
                Hmac256Ctr::decrypt(&blob, &mac, &aad.unwrap_or(vec![]), &key.0)
            }
            _ => Err(FastCryptoError::InvalidInput),
        }
        .map(SymmetricDecryptOutput)?
        .to_string(),
        Command::Encrypt {
            secrets,
            ids,
            package_id,
            key_server_ids,
            threshold,
            network,
        } => {
            if secrets.len() != ids.len() || secrets.is_empty() {
                return Err(FastCryptoError::GeneralError(
                    "Number of secrets and ids must be the same and must be greater than 0"
                        .to_string(),
                ));
            }
            // Fetch key server info including public keys from blockchain
            let key_server_infos = fetch_key_server_urls(&key_server_ids, &network)
                .await
                .map_err(|e| {
                    FastCryptoError::GeneralError(format!("Failed to fetch key server info: {}", e))
                })?;

            // Parse public keys from fetched data
            let pks: Vec<IBEPublicKey> = key_server_infos
                .iter()
                .map(|info| -> Result<IBEPublicKey, FastCryptoError> {
                    let bytes = Hex::decode(&info.public_key).map_err(|e| {
                        FastCryptoError::GeneralError(format!("Invalid public key hex: {}", e))
                    })?;
                    let pk = IBEPublicKey::from_byte_array(&bytes.try_into().map_err(|_| {
                        FastCryptoError::GeneralError("Invalid public key length".to_string())
                    })?)?;
                    Ok(pk)
                })
                .collect::<Result<Vec<_>, _>>()?;

            // Encrypt the secret
            let package_id = NewObjectID::new(package_id.as_bytes().try_into().map_err(|e| {
                FastCryptoError::GeneralError(format!("Invalid package ID: {}", e))
            })?);
            let mut encrypted_objects = Vec::new();
            for (id, secret) in ids.into_iter().zip(secrets.into_iter()) {
                let (encrypted_object, _) = seal_encrypt(
                    package_id,
                    id.0,
                    key_server_ids.clone(),
                    &IBEPublicKeys::BonehFranklinBLS12381(pks.clone()),
                    threshold,
                    EncryptionInput::Aes256Gcm {
                        data: secret.0,
                        aad: None,
                    },
                )
                .map_err(|e| FastCryptoError::GeneralError(format!("Encryption failed: {}", e)))?;
                encrypted_objects.push(encrypted_object);
            }
            format!(
                "Encoded encrypted object:\n{}",
                Hex::encode(bcs::to_bytes(&encrypted_objects).expect("serialization failed"))
            )
        }
        Command::FetchKeys {
            request,
            key_server_ids,
            threshold,
            network,
        } => {
            // Parse fetch keys request.
            let request: FetchKeyRequest = bcs::from_bytes(&request.0).map_err(|e| {
                FastCryptoError::GeneralError(format!(
                    "Failed to parse FetchKeyRequest from BCS: {}",
                    e
                ))
            })?;

            // Fetch keys from key server urls and collect service id and its seal responses.
            let mut seal_responses = Vec::new();
            let client = reqwest::Client::new();
            for server in &fetch_key_server_urls(&key_server_ids, &network)
                .await
                .map_err(|e| {
                    FastCryptoError::GeneralError(format!("Failed to fetch key server URLs: {}", e))
                })?
            {
                println!(
                    "Fetching from {} ({}/v1/fetch_key)",
                    server.name, server.url
                );
                match client
                    .post(format!("{}/v1/fetch_key", server.url))
                    .header("Client-Sdk-Type", "rust")
                    .header("Client-Sdk-Version", "1.0.0")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        request.to_json_string().expect("should not fail"),
                    ))
                    .send()
                    .await
                {
                    Ok(response) => {
                        if response.status().is_success() {
                            let response_bytes = response.bytes().await.expect("should not fail");
                            let response: FetchKeyResponse =
                                serde_json::from_slice(&response_bytes)
                                    .expect("Failed to deserialize response");
                            seal_responses.push((server.object_id, response));
                            println!("\n Success {}", server.name);
                        } else {
                            let error_text = response
                                .text()
                                .await
                                .unwrap_or_else(|_| "Unknown error".to_string());
                            eprintln!("Server returned error: {}", error_text);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed: {}", e);
                    }
                }

                if seal_responses.len() >= threshold as usize {
                    println!("Reached threshold of {} responses", threshold);
                    break;
                }
            }

            if seal_responses.len() < threshold as usize {
                return Err(FastCryptoError::GeneralError(format!(
                    "Failed to get enough responses: {} < {}",
                    seal_responses.len(),
                    threshold
                )));
            }

            format!(
                "\n {:?} Encoded seal responses: {:?}",
                seal_responses.len(),
                Hex::encode(bcs::to_bytes(&seal_responses).expect("should not fail"))
            )
        }
    };
    println!("{}", output);
    Ok(())
}

/// Type used for binary inputs to the CLI.
#[derive(Debug, Clone)]
struct EncodedBytes(Vec<u8>);

impl FromStr for EncodedBytes {
    type Err = FastCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DefaultEncoding::decode(s).map(EncodedBytes)
    }
}

#[derive(Debug, Clone)]
struct EncodedByteArray<const N: usize>([u8; N]);

impl<const N: usize> FromStr for EncodedByteArray<N> {
    type Err = FastCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DefaultEncoding::decode(s)
            .map_err(|_| FastCryptoError::InvalidInput)
            .and_then(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| FastCryptoError::InputLengthWrong(N))
            })
            .map(EncodedByteArray)
    }
}

//
// Output formatting
//
fn serializable_to_string<T: Serialize>(t: &T) -> String {
    DefaultEncoding::encode(bcs::to_bytes(t).expect("serialization failed"))
}

pub fn parse_serializable<T: for<'a> Deserialize<'a>, E: Encoding>(s: &str) -> Result<T, String> {
    let bytes = E::decode(s).map_err(|e| format!("{}", e))?;
    bcs::from_bytes(&bytes).map_err(|e| format!("{}", e))
}

impl Display for GenkeyOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Master key: {}\nPublic key: {}",
            serializable_to_string(&self.0 .0),
            serializable_to_string(&self.0 .1),
        )
    }
}

impl Display for GenSeedOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Seed: {}", DefaultEncoding::encode(self.0))
    }
}

impl Display for ExtractOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "User secret key: {}", serializable_to_string(&self.0))
    }
}

impl Display for VerifyOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            if self.0.is_ok() {
                "Verification successful"
            } else {
                "Verification failed"
            }
        )
    }
}

impl Display for EncryptionOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Encrypted object (bcs): {}\nSymmetric key: {}",
            DefaultEncoding::encode(bcs::to_bytes(&self.0 .0).unwrap()),
            DefaultEncoding::encode(self.0 .1)
        )
    }
}

impl Display for DecryptionOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Decrypted message: {}", DefaultEncoding::encode(&self.0))
    }
}

impl Display for ParseOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Version: {}", self.0.version)?;
        writeln!(f, "Package ID: {}", self.0.package_id)?;
        writeln!(f, "ID: {}", DefaultEncoding::encode(&self.0.id))?;
        writeln!(f, "Services: share index:")?;
        for (id, index) in &self.0.services {
            writeln!(f, "  {}: {}", id, index)?;
        }
        writeln!(f, "Threshold: {}", self.0.threshold)?;
        writeln!(f, "Ciphertext:")?;
        match &self.0.ciphertext {
            Ciphertext::Aes256Gcm { blob, aad } => {
                writeln!(f, "  Type: AES-256-GCM")?;
                writeln!(f, "  Blob: {}", DefaultEncoding::encode(blob))?;
                writeln!(
                    f,
                    "  AAD: {}\n",
                    aad.as_ref()
                        .map_or("None".to_string(), DefaultEncoding::encode)
                )?;
            }
            Ciphertext::Hmac256Ctr { blob, aad, mac } => {
                writeln!(f, "  Type: HMAC-256-CTR")?;
                writeln!(f, "  Blob: {}", DefaultEncoding::encode(blob))?;
                writeln!(
                    f,
                    "  AAD: {}",
                    aad.as_ref()
                        .map_or("None".to_string(), DefaultEncoding::encode)
                )?;
                writeln!(f, "  MAC: {}", DefaultEncoding::encode(mac))?;
            }
            Ciphertext::Plain => {
                writeln!(f, "  Type: Plain")?;
            }
        }
        writeln!(f, "Encrypted shares:")?;
        match &self.0.encrypted_shares {
            IBEEncryptions::BonehFranklinBLS12381 {
                encrypted_shares: shares,
                nonce: encapsulation,
                .. // TODO
            } => {
                writeln!(f, "  Type: Boneh-Franklin BLS12-381")?;
                writeln!(f, "  Shares:")?;
                for share in shares.iter() {
                    writeln!(f, "    {}", DefaultEncoding::encode(share))?;
                }
                write!(
                    f,
                    "  Encapsulation: {}",
                    serializable_to_string(&encapsulation)
                )?;
            }
        };
        Ok(())
    }
}

impl Display for SymmetricDecryptOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Decrypted message: {}", DefaultEncoding::encode(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_key_server_urls() {
        let key_server_ids = vec![ObjectID::from_str(
            "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75",
        )
        .unwrap()];
        let key_servers = fetch_key_server_urls(&key_server_ids, "testnet")
            .await
            .unwrap();
        assert_eq!(key_servers.len(), 1);
        assert_eq!(
            key_servers[0].url,
            "https://seal-key-server-testnet-1.mystenlabs.com"
        );
        // Verify public key exists
        assert!(!key_servers[0].public_key.is_empty());
    }
}
