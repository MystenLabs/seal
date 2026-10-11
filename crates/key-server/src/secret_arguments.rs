// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Secret arguments for `seal_approve*` functions.
//!
//! A module with secret arguments defines a public function
//! `seal_secret_arguments(id: vector<u8>, <objects>): (u64, vector<u8>)`, taking the id and the
//! object arguments of the `seal_approve*` call. It returns the number k of secret arguments and an
//! [EncryptedObject] with id [SECRET_CUSTODY_ID] and threshold 1, encrypted to all key servers.
//! The plaintext is `bcs(vector<vector<u8>>)`: the BCS encodings of the k secret values.
//!
//! The key server decrypts the secret values and uses them as arguments 1..=k (right after the
//! id) of the `seal_approve*` call before evaluating the PTB. Modules without
//! `seal_secret_arguments` have no secret arguments.
//!
//! If the custody ciphertext is invalid, every key server comes to the same conclusion (share
//! consistency is checked) and grants access. This way, the encryptor cannot block decryption by
//! withholding or corrupting the secret. `seal_secret_arguments` must therefore only return
//! ciphertexts set by whoever controls the id.

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

const SECRET_ARGUMENTS_FUNCTION: &str = "seal_secret_arguments";

/// Modules known not to define `seal_secret_arguments`.
static NO_SECRET_ARGUMENTS: Lazy<Cache<(Address, Identifier), ()>> = Lazy::new(default_lru_cache);

pub enum SecretArguments {
    /// No call in the PTB has secret arguments.
    NotUsed,
    /// A custody ciphertext is invalid, so access is granted without evaluating the PTB.
    InvalidCustody,
    /// The PTB with the secret values filled in.
    Resolved(ProgrammableTransaction),
}

/// Fill in the secret arguments of the `seal_approve*` calls in `ptb`. `master_key` is `None` if
/// this key server cannot decrypt custody ciphertexts (committee mode).
pub async fn resolve(
    sui_rpc_client: &SuiRpcClient,
    master_key: Option<&IbeMasterKey>,
    first_pkg_id: Address,
    ptb: &ProgrammableTransaction,
    sender: Address,
    gas_price: u64,
) -> Result<SecretArguments, InternalError> {
    let mut resolved: Option<ProgrammableTransaction> = None;
    for (index, cmd) in ptb.commands.iter().enumerate() {
        let Command::MoveCall(cmd) = cmd else {
            continue;
        };
        let Some((k, custody)) = fetch_custody(sui_rpc_client, ptb, cmd, sender, gas_price).await?
        else {
            continue;
        };
        let Some(master_key) = master_key else {
            return Err(InternalError::InvalidPTB(
                "Secret arguments are not supported by committee key servers".to_string(),
            ));
        };
        let Ok(custody) = bcs::from_bytes::<EncryptedObject>(&custody) else {
            return Ok(SecretArguments::InvalidCustody);
        };
        let Some(public_keys) = fetch_public_keys(sui_rpc_client, &custody).await? else {
            return Ok(SecretArguments::InvalidCustody);
        };
        let values = match decrypt_custody(&custody, &public_keys, master_key, &first_pkg_id) {
            Some(values) if values.len() as u64 == k => values,
            _ => return Ok(SecretArguments::InvalidCustody),
        };
        resolved = Some(fill_in_secret_arguments(
            resolved.as_ref().unwrap_or(ptb),
            index,
            values,
        )?);
    }
    Ok(resolved.map_or(SecretArguments::NotUsed, SecretArguments::Resolved))
}

/// Call `seal_secret_arguments` with the id and object arguments of `cmd`. Returns `None` if the
/// module does not define it or if there are no secret arguments.
async fn fetch_custody(
    sui_rpc_client: &SuiRpcClient,
    ptb: &ProgrammableTransaction,
    cmd: &MoveCall,
    sender: Address,
    gas_price: u64,
) -> Result<Option<(u64, Vec<u8>)>, InternalError> {
    let key = (cmd.package, cmd.module.clone());
    if NO_SECRET_ARGUMENTS.contains_key(&key) {
        return Ok(None);
    }

    // The id and all object arguments
    let arguments = cmd
        .arguments
        .iter()
        .enumerate()
        .filter(|(i, arg)| {
            *i == 0 || !matches!(arg, Argument::Input(j) if matches!(ptb.inputs.get(*j as usize), Some(Input::Pure(_))))
        })
        .map(|(_, arg)| *arg)
        .collect();
    let transaction = Transaction {
        kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
            inputs: ptb.inputs.clone(),
            commands: vec![Command::MoveCall(MoveCall {
                package: cmd.package,
                module: cmd.module.clone(),
                function: Identifier::from_str(SECRET_ARGUMENTS_FUNCTION).expect("valid"),
                type_arguments: cmd.type_arguments.clone(),
                arguments,
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
    let invalid = || {
        InternalError::InvalidPTB(format!(
            "{SECRET_ARGUMENTS_FUNCTION} must return (u64, vector<u8>)"
        ))
    };
    let return_value = |i: usize| {
        response
            .command_outputs
            .first()
            .and_then(|output| output.return_values.get(i))
            .and_then(|value| value.value.as_ref())
            .and_then(|bcs| bcs.value.as_ref())
            .ok_or_else(invalid)
    };
    let k: u64 = bcs::from_bytes(return_value(0)?).map_err(|_| invalid())?;
    let custody = bcs::from_bytes(return_value(1)?).map_err(|_| invalid())?;
    Ok(Some((k, custody)).filter(|_| k > 0))
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
            Err(e) if matches!(e.code, Some(Code::NotFound | Code::InvalidArgument) | None) => {
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
/// key servers are consistent. Returns `None` if the ciphertext is invalid.
fn decrypt_custody(
    custody: &EncryptedObject,
    public_keys: &[IbePublicKey],
    master_key: &IbeMasterKey,
    first_pkg_id: &Address,
) -> Option<Vec<Vec<u8>>> {
    if custody.package_id != *first_pkg_id
        || custody.id != SECRET_CUSTODY_ID
        || custody.threshold != 1
        || matches!(custody.ciphertext, Ciphertext::Plain)
    {
        return None;
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
        return None;
    }

    let plaintext = seal_decrypt(
        custody,
        &IBEUserSecretKeys::BonehFranklinBLS12381(user_secret_keys),
        Some(&IBEPublicKeys::BonehFranklinBLS12381(public_keys.to_vec())),
    )
    .ok()?;
    bcs::from_bytes(&plaintext).ok()
}

/// Add the secret values as new inputs and use them as arguments 1..=k of the command at
/// `index`. New inputs are used so the values cannot flow into other arguments.
fn fill_in_secret_arguments(
    ptb: &ProgrammableTransaction,
    index: usize,
    values: Vec<Vec<u8>>,
) -> Result<ProgrammableTransaction, InternalError> {
    let mut ptb = ptb.clone();
    let k = values.len();
    let first_input = ptb.inputs.len();
    ptb.inputs.extend(values.into_iter().map(Input::Pure));
    let Some(Command::MoveCall(cmd)) = ptb.commands.get_mut(index) else {
        return Err(InternalError::InvalidPTB("Invalid command".to_string()));
    };
    if cmd.arguments.len() <= k {
        return Err(InternalError::InvalidPTB(
            "Too few arguments for secret arguments".to_string(),
        ));
    }
    for i in 0..k {
        let input = u16::try_from(first_input + i)
            .map_err(|_| InternalError::InvalidPTB("Too many inputs".to_string()))?;
        cmd.arguments[i + 1] = Argument::Input(input);
    }
    Ok(ptb)
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
                decrypt_custody(&custody, &pks, master_key, &package_id),
                Some(values.clone())
            );
        }

        // Wrong package, wrong id or an unknown key server is invalid.
        assert!(decrypt_custody(&custody, &pks, &master_keys[0], &Address::ZERO).is_none());
        let (wrong_id, pks) = encrypt_custody(package_id, b"other", &master_keys, &values);
        assert!(decrypt_custody(&wrong_id, &pks, &master_keys[0], &package_id).is_none());
        let other_key = ibe::generate_key_pair(&mut thread_rng()).0;
        assert!(decrypt_custody(&custody, &pks, &other_key, &package_id).is_none());

        // Inconsistent shares are invalid for every key server.
        let mut inconsistent = custody.clone();
        let IBEEncryptions::BonehFranklinBLS12381 {
            encrypted_shares, ..
        } = &mut inconsistent.encrypted_shares;
        encrypted_shares[2][0] ^= 1;
        for master_key in &master_keys {
            assert!(decrypt_custody(&inconsistent, &pks, master_key, &package_id).is_none());
        }
    }

    #[test]
    fn test_fill_in_secret_arguments() {
        let call = || {
            Command::MoveCall(MoveCall {
                package: Address::ZERO,
                module: Identifier::from_str("m").unwrap(),
                function: Identifier::from_str("seal_approve").unwrap(),
                type_arguments: vec![],
                arguments: vec![Argument::Input(0), Argument::Input(1), Argument::Input(1)],
            })
        };
        let ptb = ProgrammableTransaction {
            inputs: vec![Input::Pure(vec![1]), Input::Pure(vec![0])],
            commands: vec![call(), call()],
        };

        let filled = fill_in_secret_arguments(&ptb, 0, vec![vec![9]]).unwrap();
        assert_eq!(filled.inputs.len(), 3);
        let Command::MoveCall(secret) = &filled.commands[0] else {
            panic!()
        };
        assert_eq!(
            secret.arguments,
            vec![Argument::Input(0), Argument::Input(2), Argument::Input(1)]
        );
        // Other calls are untouched.
        assert_eq!(filled.commands[1], ptb.commands[1]);

        assert!(fill_in_secret_arguments(&ptb, 0, vec![vec![1], vec![2], vec![3]]).is_err());
    }
}
