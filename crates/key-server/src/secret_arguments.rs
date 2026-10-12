// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Secret arguments for `seal_approve*` functions.
//!
//! A function `seal_approve<suffix>` with secret arguments has a matching public function
//! `seal_secret_arguments<suffix>` taking the same arguments as the requester's call. It returns
//! an [EncryptedObject] with id [SECRET_CUSTODY_ID] and threshold 1, encrypted to all key servers,
//! and whether access should be granted if that ciphertext is invalid. The plaintext is
//! `bcs(vector<vector<u8>>)`: the BCS encodings of the secret values.
//!
//! The requester omits the secret arguments. The key server decrypts them and inserts them right
//! after the id before evaluating the PTB. Functions without a matching
//! `seal_secret_arguments<suffix>` have no secret arguments.
//!
//! Share consistency is checked, so all key servers decrypt the same values or all find the
//! ciphertext invalid. If the policy opts in, an invalid ciphertext grants access to that call's
//! id, so the encryptor cannot block decryption by corrupting the secret. Such a policy must only
//! return ciphertexts set by whoever controls the id.

use crate::cache::default_lru_cache;
use crate::errors::InternalError;
use crate::types::{IbeMasterKey, IbePublicKey};
use crypto::ibe;
use crypto::{
    create_full_id, seal_decrypt, Ciphertext, EncryptedObject, IBEPublicKeys, IBEUserSecretKeys,
};
use fastcrypto::serde_helpers::ToFromByteArray;
use key_server::sui_rpc_client::SuiRpcClient;
use key_server::valid_ptb::SECRET_CUSTODY_ID;
use moka::sync::Cache;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::str::FromStr;
use sui_rpc::proto::sui::rpc::v2::execution_error::ExecutionErrorKind;
use sui_sdk_types::{
    Address, Argument, Command, GasPayment, Identifier, Input, MoveCall, ProgrammableTransaction,
    Transaction, TransactionExpiration, TransactionKind,
};
use tonic::Code;

const SEAL_APPROVE_PREFIX: &str = "seal_approve";
const SECRET_ARGUMENTS_PREFIX: &str = "seal_secret_arguments";

/// Functions known not to have a matching `seal_secret_arguments*` function.
static NO_SECRET_ARGUMENTS: Lazy<Cache<(Address, Identifier, Identifier), ()>> =
    Lazy::new(default_lru_cache);

/// The function holding the secret arguments of `seal_approve<suffix>` is
/// `seal_secret_arguments<suffix>`.
fn secret_arguments_function(seal_approve: &Identifier) -> Identifier {
    let suffix = seal_approve
        .as_str()
        .strip_prefix(SEAL_APPROVE_PREFIX)
        .expect("checked by ValidPtb");
    Identifier::from_str(&format!("{SECRET_ARGUMENTS_PREFIX}{suffix}")).expect("valid identifier")
}

pub struct Resolved {
    /// The PTB with secret arguments inserted. Calls whose invalid custody grants access are
    /// removed, so their ids are not evaluated. If no calls remain, access is granted.
    pub ptb: ProgrammableTransaction,
    /// Whether any call uses secret arguments.
    pub uses_secret_arguments: bool,
}

/// Why a custody ciphertext could not be used.
#[derive(Debug, PartialEq)]
enum InvalidCustody {
    /// The ciphertext is invalid for all key servers.
    Invalid,
    /// This key server is not one of the recipients.
    NotListed,
}

/// Insert the secret arguments of the `seal_approve*` calls in `ptb`. `master_key` is `None` if
/// this key server cannot decrypt custody ciphertexts (committee mode).
pub async fn resolve(
    sui_rpc_client: &SuiRpcClient,
    master_key: Option<&IbeMasterKey>,
    first_pkg_id: Address,
    ptb: &ProgrammableTransaction,
    sender: Address,
    gas_price: u64,
) -> Result<Resolved, InternalError> {
    let mut resolved = ProgrammableTransaction {
        inputs: ptb.inputs.clone(),
        commands: vec![],
    };
    let mut uses_secret_arguments = false;
    for cmd in &ptb.commands {
        let Command::MoveCall(call) = cmd else {
            resolved.commands.push(cmd.clone());
            continue;
        };
        let Some((custody, open_if_invalid)) =
            fetch_custody(sui_rpc_client, ptb, call, sender, gas_price).await?
        else {
            resolved.commands.push(cmd.clone());
            continue;
        };
        uses_secret_arguments = true;
        let Some(master_key) = master_key else {
            return Err(InternalError::InvalidPTB(
                "Secret arguments are not supported by committee key servers".to_string(),
            ));
        };
        match decrypt_custody(sui_rpc_client, &custody, master_key, &first_pkg_id).await? {
            Ok(values) => {
                resolved
                    .commands
                    .push(insert_secret_arguments(&mut resolved.inputs, call, values)?)
            }
            // Grant access to this call's id by not evaluating it
            Err(InvalidCustody::Invalid) if open_if_invalid => {}
            Err(_) => return Err(InternalError::NoAccess("Access denied".to_string())),
        }
    }
    Ok(Resolved {
        ptb: resolved,
        uses_secret_arguments,
    })
}

/// Call `seal_secret_arguments<suffix>` with the arguments of `call`. Returns `None` if it is not
/// defined, and otherwise the custody ciphertext and whether an invalid one grants access.
async fn fetch_custody(
    sui_rpc_client: &SuiRpcClient,
    ptb: &ProgrammableTransaction,
    call: &MoveCall,
    sender: Address,
    gas_price: u64,
) -> Result<Option<(Vec<u8>, bool)>, InternalError> {
    let function = secret_arguments_function(&call.function);
    let key = (call.package, call.module.clone(), call.function.clone());
    if NO_SECRET_ARGUMENTS.contains_key(&key) {
        return Ok(None);
    }

    let transaction = Transaction {
        kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
            inputs: ptb.inputs.clone(),
            commands: vec![Command::MoveCall(MoveCall {
                function: function.clone(),
                ..call.clone()
            })],
        }),
        sender,
        gas_payment: GasPayment {
            objects: vec![],
            owner: sender,
            price: gas_price,
            budget: crate::MAX_COMPUTATION_UNITS * gas_price,
        },
        expiration: TransactionExpiration::None,
    };
    let response = sui_rpc_client
        .simulate_transaction(transaction)
        .await
        .map_err(|e| InternalError::Failure(format!("Failed to fetch secret arguments: {e}")))?;

    if let Some(error) = &response.transaction().effects().status().error {
        if error.kind() == ExecutionErrorKind::FunctionNotFound {
            NO_SECRET_ARGUMENTS.insert(key, ());
            return Ok(None);
        }
        return Err(InternalError::NoAccess("Access denied".to_string()));
    }
    let invalid =
        || InternalError::InvalidPTB(format!("{function} must return (vector<u8>, bool)"));
    let return_value = |i: usize| {
        response
            .command_outputs
            .first()
            .and_then(|output| output.return_values.get(i))
            .and_then(|value| value.value.as_ref())
            .and_then(|bcs| bcs.value.as_ref())
            .ok_or_else(invalid)
    };
    let custody = bcs::from_bytes(return_value(0)?).map_err(|_| invalid())?;
    let open_if_invalid = bcs::from_bytes(return_value(1)?).map_err(|_| invalid())?;
    Ok(Some((custody, open_if_invalid)))
}

/// Decrypt a custody ciphertext, checking that the shares of all key servers are consistent.
async fn decrypt_custody(
    sui_rpc_client: &SuiRpcClient,
    custody: &[u8],
    master_key: &IbeMasterKey,
    first_pkg_id: &Address,
) -> Result<Result<Vec<Vec<u8>>, InvalidCustody>, InternalError> {
    let Ok(custody) = bcs::from_bytes::<EncryptedObject>(custody) else {
        return Ok(Err(InvalidCustody::Invalid));
    };
    let Some(public_keys) = fetch_public_keys(sui_rpc_client, &custody).await? else {
        return Ok(Err(InvalidCustody::Invalid));
    };
    Ok(decrypt_with_public_keys(
        &custody,
        &public_keys,
        master_key,
        first_pkg_id,
    ))
}

/// Fetch the public keys of the key servers in the custody ciphertext. Returns `None` if one of
/// them is not a valid key server.
async fn fetch_public_keys(
    sui_rpc_client: &SuiRpcClient,
    custody: &EncryptedObject,
) -> Result<Option<Vec<IbePublicKey>>, InternalError> {
    let mut public_keys = Vec::with_capacity(custody.services.len());
    for (key_server, _) in &custody.services {
        let pk = match sui_rpc_client.fetch_key_server_by_id(key_server).await {
            Ok(key_server) => key_server.pk,
            Err(e) if matches!(e.code, Some(Code::NotFound | Code::InvalidArgument)) => {
                return Ok(None)
            }
            Err(e) => {
                return Err(InternalError::Failure(format!(
                    "Failed to fetch key server: {e}"
                )))
            }
        };
        let Some(pk) = pk
            .try_into()
            .ok()
            .and_then(|pk| IbePublicKey::from_byte_array(&pk).ok())
        else {
            return Ok(None);
        };
        public_keys.push(pk);
    }
    Ok(Some(public_keys))
}

/// Decrypt the custody ciphertext with this key server's key and check that the shares of all
/// key servers are consistent.
fn decrypt_with_public_keys(
    custody: &EncryptedObject,
    public_keys: &[IbePublicKey],
    master_key: &IbeMasterKey,
    first_pkg_id: &Address,
) -> Result<Vec<Vec<u8>>, InvalidCustody> {
    if custody.package_id != *first_pkg_id
        || custody.id != SECRET_CUSTODY_ID
        || custody.threshold != 1
        || matches!(custody.ciphertext, Ciphertext::Plain)
    {
        return Err(InvalidCustody::Invalid);
    }

    // This key server may appear more than once in the services if it is weighted.
    let own_pk = ibe::public_key_from_master_key(master_key);
    let usk = ibe::extract(
        master_key,
        &create_full_id(&first_pkg_id.into_inner(), SECRET_CUSTODY_ID),
    );
    let user_secret_keys: HashMap<_, _> = custody
        .services
        .iter()
        .zip(public_keys)
        .filter(|(_, pk)| **pk == own_pk)
        .map(|((key_server, _), _)| (*key_server, usk))
        .collect();
    if user_secret_keys.is_empty() {
        return Err(InvalidCustody::NotListed);
    }

    seal_decrypt(
        custody,
        &IBEUserSecretKeys::BonehFranklinBLS12381(user_secret_keys),
        Some(&IBEPublicKeys::BonehFranklinBLS12381(public_keys.to_vec())),
    )
    .ok()
    .and_then(|plaintext| bcs::from_bytes(&plaintext).ok())
    .ok_or(InvalidCustody::Invalid)
}

/// Add the secret values as new inputs and insert them right after the id of `call`. New inputs
/// are used so the values cannot flow into other arguments.
fn insert_secret_arguments(
    inputs: &mut Vec<Input>,
    call: &MoveCall,
    values: Vec<Vec<u8>>,
) -> Result<Command, InternalError> {
    let mut arguments = vec![call.arguments[0]];
    for value in values {
        inputs.push(Input::Pure(value));
        let index = u16::try_from(inputs.len() - 1)
            .map_err(|_| InternalError::InvalidPTB("Too many inputs".to_string()))?;
        arguments.push(Argument::Input(index));
    }
    arguments.extend_from_slice(&call.arguments[1..]);
    Ok(Command::MoveCall(MoveCall {
        arguments,
        ..call.clone()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{seal_encrypt, EncryptionInput, IBEEncryptions};
    use rand::thread_rng;

    fn encrypt_custody(
        package_id: Address,
        id: &[u8],
        master_keys: &[IbeMasterKey],
        values: &[Vec<u8>],
    ) -> (EncryptedObject, Vec<IbePublicKey>) {
        let public_keys = master_keys
            .iter()
            .map(ibe::public_key_from_master_key)
            .collect::<Vec<_>>();
        let services = (1..=master_keys.len() as u8)
            .map(|i| Address::new([i; 32]))
            .collect();
        let (custody, _) = seal_encrypt(
            package_id,
            id.to_vec(),
            services,
            &IBEPublicKeys::BonehFranklinBLS12381(public_keys.clone()),
            1,
            EncryptionInput::Aes256Gcm {
                data: bcs::to_bytes(values).unwrap(),
                aad: None,
            },
        )
        .unwrap();
        (custody, public_keys)
    }

    #[test]
    fn test_decrypt_custody() {
        let package_id = Address::new([7; 32]);
        let master_keys = (0..3)
            .map(|_| ibe::generate_key_pair(&mut thread_rng()).0)
            .collect::<Vec<_>>();
        let values = vec![bcs::to_bytes(&42u64).unwrap()];

        // Every key server decrypts the same values.
        let (custody, pks) = encrypt_custody(package_id, SECRET_CUSTODY_ID, &master_keys, &values);
        for master_key in &master_keys {
            assert_eq!(
                decrypt_with_public_keys(&custody, &pks, master_key, &package_id),
                Ok(values.clone())
            );
        }

        // Wrong package or wrong id is invalid.
        let invalid = Err(InvalidCustody::Invalid);
        assert_eq!(
            decrypt_with_public_keys(&custody, &pks, &master_keys[0], &Address::ZERO),
            invalid
        );
        let (wrong_id, pks) = encrypt_custody(package_id, b"other", &master_keys, &values);
        assert_eq!(
            decrypt_with_public_keys(&wrong_id, &pks, &master_keys[0], &package_id),
            invalid
        );

        // A key server that is not a recipient cannot decrypt.
        let other_key = ibe::generate_key_pair(&mut thread_rng()).0;
        assert_eq!(
            decrypt_with_public_keys(&custody, &pks, &other_key, &package_id),
            Err(InvalidCustody::NotListed)
        );

        // Inconsistent shares are invalid for every key server.
        let mut inconsistent = custody.clone();
        let IBEEncryptions::BonehFranklinBLS12381 {
            encrypted_shares, ..
        } = &mut inconsistent.encrypted_shares;
        encrypted_shares[2][0] ^= 1;
        for master_key in &master_keys {
            assert_eq!(
                decrypt_with_public_keys(&inconsistent, &pks, master_key, &package_id),
                invalid
            );
        }
    }

    #[test]
    fn test_secret_arguments_function() {
        let name = |s: &str| Identifier::from_str(s).unwrap();
        assert_eq!(
            secret_arguments_function(&name("seal_approve")),
            name("seal_secret_arguments")
        );
        assert_eq!(
            secret_arguments_function(&name("seal_approve_owner")),
            name("seal_secret_arguments_owner")
        );
    }

    #[test]
    fn test_insert_secret_arguments() {
        let call = MoveCall {
            package: Address::ZERO,
            module: Identifier::from_str("m").unwrap(),
            function: Identifier::from_str("seal_approve").unwrap(),
            type_arguments: vec![],
            arguments: vec![Argument::Input(0), Argument::Input(1)],
        };
        let mut inputs = vec![Input::Pure(vec![1]), Input::Pure(vec![0])];

        let Command::MoveCall(inserted) =
            insert_secret_arguments(&mut inputs, &call, vec![vec![8], vec![9]]).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            inserted.arguments,
            vec![
                Argument::Input(0),
                Argument::Input(2),
                Argument::Input(3),
                Argument::Input(1)
            ]
        );
        assert_eq!(inputs[2..], [Input::Pure(vec![8]), Input::Pure(vec![9])]);
    }
}
