// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use crypto::dem::{Aes256Gcm, Hmac256Ctr};
use crypto::EncryptionInput::Plain;
use crypto::{
    create_full_id, ibe, seal_decrypt, seal_encrypt, Ciphertext, EncryptedObject, EncryptionInput,
    IBEEncryptions, IBEPublicKeys, IBEUserSecretKeys, ObjectID,
};
use fastcrypto::encoding::Encoding;
use fastcrypto::encoding::Hex;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::bls12381::{G1Element, G2Element, Scalar};
use rand::thread_rng;
use serde::Deserialize;
use serde::Serialize;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

const KEY_LENGTH: usize = 32;

/// Default encoding for serializing and deserializing values.
type DefaultEncoding = Hex;

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
    /// Extract a user secret key from an id and a master key.
    Extract {
        /// The Sui address of the Move package that handles the KMS for this key
        #[arg(long)]
        package_id: ObjectID,
        /// The ID of the key that should be derived.
        #[arg(long)]
        id: EncodedBytes,
        /// Master key. Base64 encoding of a BLS12-381 scalar.
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
        /// User secret key. Base64 encoding of a compressed BLS12-381 G1Element.
        #[arg(long, value_parser = parse_serializable::<G1Element, DefaultEncoding>)]
        user_secret_key: G1Element,
        /// Public key. Base64 encoding of a compressed BLS12-381 G2Element.
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
        key: EncodedBytes,
    },
}

struct GenkeyOutput((Scalar, G2Element));
struct ExtractOutput(G1Element);
struct VerifyOutput(FastCryptoResult<()>);
struct EncryptionOutput((EncryptedObject, [u8; KEY_LENGTH]));
struct DecryptionOutput(Vec<u8>);
struct ParseOutput(EncryptedObject);
struct SymmetricDecryptOutput(Vec<u8>);

fn main() -> FastCryptoResult<()> {
    let args = Arguments::parse();

    let output = match args.command {
        Command::Genkey => GenkeyOutput(ibe::generate_key_pair(&mut thread_rng())).to_string(),
        Command::Extract {
            package_id,
            id,
            master_key,
        } => ExtractOutput(ibe::extract(
            &master_key,
            &create_full_id(&package_id, &id.0),
        ))
        .to_string(),
        Command::Verify {
            package_id,
            id,
            user_secret_key,
            public_key,
        } => VerifyOutput(ibe::verify_user_secret_key(
            &user_secret_key,
            &create_full_id(&package_id, &id.0),
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
        } => {
            let dem_key = key
                .0
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?;
            let EncryptedObject { ciphertext, .. } = encrypted_object;

            match ciphertext {
                Ciphertext::Aes256Gcm { blob, aad } => {
                    Aes256Gcm::decrypt(&blob, &aad.unwrap_or(vec![]), &dem_key)
                }
                Ciphertext::Hmac256Ctr { blob, aad, mac } => {
                    Hmac256Ctr::decrypt(&blob, &mac, &aad.unwrap_or(vec![]), &dem_key)
                }
                _ => Err(FastCryptoError::InvalidInput),
            }
            .map(SymmetricDecryptOutput)?
            .to_string()
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
            Hex::encode(self.0 .1)
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
