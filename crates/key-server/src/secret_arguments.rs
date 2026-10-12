// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Secret arguments for `seal_approve*` functions.
//!
//! A `seal_approve<suffix>` function takes secret arguments as parameters of type
//! `seal::secret::Secret<T>`, where `T` is a primitive type. It has a matching public function
//! `seal_secret_arguments<suffix>`, taking all non-secret arguments of `seal_approve<suffix>`. It
//! returns an [EncryptedObject] with id [SECRET_CUSTODY_ID] and threshold 1, encrypted to all key
//! servers, and whether access should be granted if that ciphertext is invalid. The plaintext is
//! `bcs(vector<vector<u8>>)`: the BCS encodings of the secret values, in order.
//!
//! The requester omits the secret arguments. The key server decrypts them and passes them as
//! `seal::secret::new<T>(value)` results when evaluating the PTB.
//!
//! Share consistency is checked, so all key servers decrypt the same values or all find the
//! ciphertext invalid. If the policy opts in, an invalid ciphertext grants access to that call's
//! id, so the encryptor cannot block decryption by corrupting the secret. Such a policy must only
//! return ciphertexts set by whoever controls the id.

use crate::cache::default_lru_cache;
use crate::common::fetch_first_pkg_id;
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
use std::sync::Arc;
use sui_rpc::proto::sui::rpc::v2::open_signature_body::Type;
use sui_rpc::proto::sui::rpc::v2::{FunctionDescriptor, OpenSignatureBody};
use sui_sdk_types::{
    Address, Argument, Command, GasPayment, Identifier, Input, MoveCall, ProgrammableTransaction,
    Transaction, TransactionExpiration, TransactionKind, TypeTag,
};
use tonic::Code;

const SEAL_APPROVE_PREFIX: &str = "seal_approve";
const SECRET_ARGUMENTS_PREFIX: &str = "seal_secret_arguments";
const SECRET_MODULE: &str = "secret";
const SECRET_STRUCT: &str = "Secret";
const SECRET_CONSTRUCTOR: &str = "new";

/// A parameter of a `seal_approve*` function.
#[derive(Clone, Debug, PartialEq)]
enum Param {
    /// `Secret<T>`, filled in by the key server.
    Secret(TypeTag),
    /// `&TxContext`, not passed as an argument.
    TxContext,
    /// Any other parameter, passed by the requester.
    Other,
}

/// A function, identified by package, module and name.
type FunctionKey = (Address, Identifier, Identifier);

/// Parameters of `seal_approve*` functions. They are fixed for a package version.
static SIGNATURES: Lazy<Cache<FunctionKey, Arc<Vec<Param>>>> = Lazy::new(default_lru_cache);

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
    /// The PTB with secret arguments filled in. Calls whose invalid custody grants access are
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

/// Fill in the secret arguments of the `seal_approve*` calls in `ptb`. `master_key` is `None` if
/// this key server cannot decrypt custody ciphertexts (committee mode). `seal_package` is the Seal
/// package defining `secret::Secret`.
pub async fn resolve(
    sui_rpc_client: &SuiRpcClient,
    master_key: Option<&IbeMasterKey>,
    first_pkg_id: Address,
    seal_package: Address,
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
        let params = fetch_params(sui_rpc_client, call, seal_package).await?;
        let secret_types = params
            .iter()
            .filter_map(|p| match p {
                Param::Secret(t) => Some(t),
                _ => None,
            })
            .collect::<Vec<_>>();
        if secret_types.is_empty() {
            resolved.commands.push(cmd.clone());
            continue;
        }
        uses_secret_arguments = true;
        let Some(master_key) = master_key else {
            return Err(InternalError::InvalidPTB(
                "Secret arguments are not supported by committee key servers".to_string(),
            ));
        };

        let (custody, open_if_invalid) =
            fetch_custody(sui_rpc_client, ptb, call, sender, gas_price).await?;
        let values = decrypt_custody(sui_rpc_client, &custody, master_key, &first_pkg_id)
            .await?
            .and_then(|values| {
                let valid = values.len() == secret_types.len()
                    && secret_types
                        .iter()
                        .zip(&values)
                        .all(|(t, v)| is_valid_value(t, v));
                if valid {
                    Ok(values)
                } else {
                    Err(InvalidCustody::Invalid)
                }
            });
        match values {
            Ok(values) => build_call(&mut resolved, call, &params, values, seal_package)?,
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

/// Fetch the parameters of the function called by `call`.
async fn fetch_params(
    sui_rpc_client: &SuiRpcClient,
    call: &MoveCall,
    seal_package: Address,
) -> Result<Arc<Vec<Param>>, InternalError> {
    let key = (call.package, call.module.clone(), call.function.clone());
    if let Some(params) = SIGNATURES.get(&key) {
        return Ok(params);
    }
    let function = sui_rpc_client
        .get_function(
            call.package,
            call.module.to_string(),
            call.function.to_string(),
        )
        .await
        .map_err(|e| match e.code {
            Some(Code::NotFound) => {
                InternalError::InvalidPTB(format!("Function {} not found", call.function))
            }
            _ => InternalError::Failure(format!("Failed to fetch function: {e}")),
        })?;
    let params = Arc::new(parse_params(sui_rpc_client, &function, seal_package).await?);
    SIGNATURES.insert(key, params.clone());
    Ok(params)
}

async fn parse_params(
    sui_rpc_client: &SuiRpcClient,
    function: &FunctionDescriptor,
    seal_package: Address,
) -> Result<Vec<Param>, InternalError> {
    let mut params = Vec::with_capacity(function.parameters.len());
    for param in &function.parameters {
        let body = param.body.clone().unwrap_or_default();
        let datatype = (body.r#type() == Type::Datatype)
            .then(|| body.type_name.as_deref().and_then(parse_datatype))
            .flatten();
        let param = match datatype {
            Some((address, module, name))
                if address == Address::TWO && module == "tx_context" && name == "TxContext" =>
            {
                Param::TxContext
            }
            Some((address, module, name))
                if module == SECRET_MODULE
                    && name == SECRET_STRUCT
                    && fetch_first_pkg_id(sui_rpc_client, &address).await?
                        == fetch_first_pkg_id(sui_rpc_client, &seal_package).await? =>
            {
                let invalid = || {
                    InternalError::InvalidPTB(
                        "Secret arguments must be passed by value as Secret<T> with a primitive T"
                            .to_string(),
                    )
                };
                if param.reference.is_some_and(|r| r != 0) {
                    return Err(invalid());
                }
                let t = body
                    .type_parameter_instantiation
                    .first()
                    .and_then(primitive_type)
                    .ok_or_else(invalid)?;
                Param::Secret(t)
            }
            _ => Param::Other,
        };
        params.push(param);
    }
    Ok(params)
}

/// Parse a type name like `0x2::tx_context::TxContext`.
fn parse_datatype(type_name: &str) -> Option<(Address, &str, &str)> {
    let mut parts = type_name.split("::");
    let address = Address::from_str(parts.next()?).ok()?;
    Some((address, parts.next()?, parts.next()?))
}

/// The type tag of a primitive type, or vectors of primitive types.
fn primitive_type(body: &OpenSignatureBody) -> Option<TypeTag> {
    Some(match body.r#type() {
        Type::Address => TypeTag::Address,
        Type::Bool => TypeTag::Bool,
        Type::U8 => TypeTag::U8,
        Type::U16 => TypeTag::U16,
        Type::U32 => TypeTag::U32,
        Type::U64 => TypeTag::U64,
        Type::U128 => TypeTag::U128,
        Type::U256 => TypeTag::U256,
        Type::Vector => TypeTag::Vector(Box::new(primitive_type(
            body.type_parameter_instantiation.first()?,
        )?)),
        _ => return None,
    })
}

/// Check that `value` is the BCS encoding of a value of the primitive type `t`.
fn is_valid_value(t: &TypeTag, mut value: &[u8]) -> bool {
    fn consume(t: &TypeTag, bytes: &mut &[u8]) -> Option<()> {
        let size = match t {
            TypeTag::Bool => {
                let (first, rest) = bytes.split_first()?;
                *bytes = rest;
                return (*first <= 1).then_some(());
            }
            TypeTag::U8 => 1,
            TypeTag::U16 => 2,
            TypeTag::U32 => 4,
            TypeTag::U64 => 8,
            TypeTag::U128 => 16,
            TypeTag::U256 | TypeTag::Address => 32,
            TypeTag::Vector(inner) => {
                let mut len: u64 = 0;
                for shift in (0..64).step_by(7) {
                    let (byte, rest) = bytes.split_first()?;
                    *bytes = rest;
                    len |= u64::from(byte & 0x7f) << shift;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                for _ in 0..len {
                    consume(inner, bytes)?;
                }
                return Some(());
            }
            _ => return None,
        };
        *bytes = bytes.get(size..)?;
        Some(())
    }
    consume(t, &mut value).is_some() && value.is_empty()
}

/// Call `seal_secret_arguments<suffix>` with the requester's arguments to `call`, i.e., all
/// non-secret arguments. Returns the custody ciphertext and whether an invalid one grants access.
async fn fetch_custody(
    sui_rpc_client: &SuiRpcClient,
    ptb: &ProgrammableTransaction,
    call: &MoveCall,
    sender: Address,
    gas_price: u64,
) -> Result<(Vec<u8>, bool), InternalError> {
    let function = secret_arguments_function(&call.function);
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

    if response.transaction().effects().status().error.is_some() {
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
    Ok((custody, open_if_invalid))
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

/// Append `call` to `ptb` with the secret values passed as `seal::secret::new<T>(value)` results
/// and the requester's arguments in the other positions.
fn build_call(
    ptb: &mut ProgrammableTransaction,
    call: &MoveCall,
    params: &[Param],
    values: Vec<Vec<u8>>,
    seal_package: Address,
) -> Result<(), InternalError> {
    let wrong_arguments =
        || InternalError::InvalidPTB("Wrong number of arguments for seal_approve".to_string());
    let index = |i: usize| {
        u16::try_from(i).map_err(|_| InternalError::InvalidPTB("Too large PTB".to_string()))
    };
    let mut public = call.arguments.iter();
    let mut values = values.into_iter();
    let mut arguments = vec![];
    for param in params {
        match param {
            Param::Secret(t) => {
                ptb.inputs
                    .push(Input::Pure(values.next().ok_or_else(wrong_arguments)?));
                ptb.commands.push(Command::MoveCall(MoveCall {
                    package: seal_package,
                    module: Identifier::from_str(SECRET_MODULE).expect("valid"),
                    function: Identifier::from_str(SECRET_CONSTRUCTOR).expect("valid"),
                    type_arguments: vec![t.clone()],
                    arguments: vec![Argument::Input(index(ptb.inputs.len() - 1)?)],
                }));
                arguments.push(Argument::Result(index(ptb.commands.len() - 1)?));
            }
            Param::TxContext => {}
            Param::Other => arguments.push(*public.next().ok_or_else(wrong_arguments)?),
        }
    }
    if public.next().is_some() {
        return Err(wrong_arguments());
    }
    ptb.commands.push(Command::MoveCall(MoveCall {
        arguments,
        ..call.clone()
    }));
    Ok(())
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
    fn test_secret_arguments_function_name() {
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
    fn test_is_valid_value() {
        let u64_vec = TypeTag::Vector(Box::new(TypeTag::U64));
        assert!(is_valid_value(
            &TypeTag::U64,
            &bcs::to_bytes(&7u64).unwrap()
        ));
        assert!(!is_valid_value(&TypeTag::U64, &[1, 2, 3]));
        assert!(!is_valid_value(&TypeTag::Bool, &[2]));
        assert!(is_valid_value(
            &u64_vec,
            &bcs::to_bytes(&vec![1u64, 2]).unwrap()
        ));
        assert!(!is_valid_value(&u64_vec, &[2, 0, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn test_build_call() {
        let call = MoveCall {
            package: Address::ZERO,
            module: Identifier::from_str("m").unwrap(),
            function: Identifier::from_str("seal_approve").unwrap(),
            type_arguments: vec![],
            arguments: vec![Argument::Input(0), Argument::Input(1)],
        };
        // seal_approve(id, Secret<u64>, &Object, &TxContext)
        let params = vec![
            Param::Other,
            Param::Secret(TypeTag::U64),
            Param::Other,
            Param::TxContext,
        ];
        let mut ptb = ProgrammableTransaction {
            inputs: vec![Input::Pure(vec![1]), Input::Pure(vec![0])],
            commands: vec![],
        };
        let value = bcs::to_bytes(&100u64).unwrap();

        build_call(&mut ptb, &call, &params, vec![value.clone()], Address::TWO).unwrap();
        assert_eq!(ptb.inputs[2], Input::Pure(value));
        let Command::MoveCall(new) = &ptb.commands[0] else {
            panic!()
        };
        assert_eq!(new.arguments, vec![Argument::Input(2)]);
        let Command::MoveCall(approve) = &ptb.commands[1] else {
            panic!()
        };
        assert_eq!(
            approve.arguments,
            vec![Argument::Input(0), Argument::Result(0), Argument::Input(1)]
        );

        // Wrong number of public arguments
        let short = MoveCall {
            arguments: vec![Argument::Input(0)],
            ..call
        };
        assert!(build_call(&mut ptb, &short, &params, vec![vec![0; 8]], Address::TWO).is_err());
    }
}
