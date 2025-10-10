use anyhow::bail;
use async_trait::async_trait;
use crypto::{elgamal, seal_encrypt, EncryptionInput, IBEPublicKeys};
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PrivateKey};
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::groups::bls12381::G2Element;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::{KeyPair, Signer, ToFromBytes};
use key_server::errors::InternalError;
use key_server::key_server_options::KeyServerOptions;
use key_server::master_keys::MasterKeys;
use key_server::signed_message::signed_request;
use key_server::sui_rpc_client::RpcClient;
use key_server::types::Network;
use key_server::valid_ptb::ValidPtb;
use key_server::{fetch_key, get_server, Certificate, FetchKeyRequest};
use rand::prelude::StdRng;
use rand::{thread_rng, SeedableRng};
use seal_sdk::{seal_decrypt_all_objects, signed_message};
use shared_crypto::intent::{Intent, IntentMessage};
use std::str::FromStr;
use sui_sdk::error::SuiRpcResult;
use sui_sdk::rpc_types::{
    Checkpoint, CheckpointId, DryRunTransactionBlockResponse, OwnedObjectRef, SuiExecutionStatus,
    SuiGasData, SuiObjectData, SuiObjectDataOptions, SuiObjectRef, SuiObjectResponse,
    SuiProgrammableTransactionBlock, SuiRawData, SuiRawMovePackage, SuiTransactionBlockData,
    SuiTransactionBlockDataV1, SuiTransactionBlockEffects, SuiTransactionBlockEffectsV1,
    SuiTransactionBlockKind, ZkLoginIntentScope, ZkLoginVerifyResult,
};
use sui_sdk::SuiClient;
use sui_types::base_types::{ObjectID, ObjectType, SuiAddress};
use sui_types::crypto::Signature;
use sui_types::digests::ObjectDigest;
use sui_types::dynamic_field::DynamicFieldName;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use sui_types::object::{Owner, OBJECT_START_VERSION};
use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use sui_types::signature::GenericSignature;
use sui_types::transaction::TransactionData;
use sui_types::SUI_CLOCK_OBJECT_ID;

const KEY_SERVER_OBJECT_ID: &str = "0x1";
const MASTER_KEY: &str = "0x403a839967eb6b81beac300dc7feab8eab18c4cfcd5f68126d4954c9370855b2";
const PUBLIC_KEY: &str = "0x8557fc1c2507a1b3898ab1f65654b7b79990bdcfa8caa6ef787418a1ac7657741b36a1aa7830364cd5af4856b0eb45a5118986a08046263048d6b4b4420af54700309c884d01b9d01f41779f9e0f5507f4cca1763a0765d136876e23940d1ec5";

const FIRST_PACKAGE_ID: &str = "0x123456";
const SECOND_PACKAGE_ID: &str = "0xabcdef";

#[derive(Clone)]
struct MockSuiClient;

#[async_trait]
impl RpcClient for MockSuiClient {
    async fn new_from_builder<Fut>(_build: Fut) -> SuiRpcResult<Self>
    where
        Fut: Future<Output = SuiRpcResult<SuiClient>> + Send,
    {
        SuiRpcResult::Ok(MockSuiClient)
    }

    async fn dry_run_transaction_block(
        &self,
        _tx: TransactionData,
    ) -> SuiRpcResult<DryRunTransactionBlockResponse> {
        SuiRpcResult::Ok(DryRunTransactionBlockResponse {
            effects: SuiTransactionBlockEffects::V1(SuiTransactionBlockEffectsV1 {
                status: SuiExecutionStatus::Success,
                executed_epoch: 0,
                gas_used: Default::default(),
                modified_at_versions: vec![],
                shared_objects: vec![],
                transaction_digest: Default::default(),
                created: vec![],
                mutated: vec![],
                unwrapped: vec![],
                deleted: vec![],
                unwrapped_then_deleted: vec![],
                wrapped: vec![],
                accumulator_events: vec![],
                gas_object: OwnedObjectRef {
                    owner: Owner::Immutable,
                    reference: SuiObjectRef {
                        object_id: SUI_CLOCK_OBJECT_ID,
                        version: Default::default(),
                        digest: ObjectDigest::new(Default::default()),
                    },
                },
                events_digest: None,
                dependencies: vec![],
                abort_error: None,
            }),
            events: Default::default(),
            object_changes: vec![],
            balance_changes: vec![],
            input: SuiTransactionBlockData::V1(SuiTransactionBlockDataV1 {
                transaction: SuiTransactionBlockKind::ProgrammableTransaction(
                    SuiProgrammableTransactionBlock {
                        inputs: vec![],
                        commands: vec![],
                    },
                ),
                sender: Default::default(),
                gas_data: SuiGasData {
                    payment: vec![],
                    owner: Default::default(),
                    price: 0,
                    budget: 0,
                },
            }),
            execution_error_source: None,
            suggested_gas_price: None,
        })
    }

    async fn get_object_with_options(
        &self,
        object_id: ObjectID,
        _options: SuiObjectDataOptions,
    ) -> SuiRpcResult<SuiObjectResponse> {
        let response = if object_id == ObjectID::from_hex_literal(FIRST_PACKAGE_ID).unwrap()
            || object_id == ObjectID::from_hex_literal(SECOND_PACKAGE_ID).unwrap()
        {
            SuiObjectResponse::new(
                Some(SuiObjectData {
                    object_id,
                    version: OBJECT_START_VERSION,
                    digest: ObjectDigest::new(Default::default()),
                    type_: Some(ObjectType::Package),
                    owner: None,
                    previous_transaction: None,
                    storage_rebate: None,
                    display: None,
                    content: None,
                    bcs: Some(SuiRawData::Package(SuiRawMovePackage {
                        id: object_id,
                        version: OBJECT_START_VERSION,
                        module_map: Default::default(),
                        type_origin_table: vec![],
                        linkage_table: Default::default(),
                    })),
                }),
                None,
            )
        } else {
            todo!()
        };

        SuiRpcResult::Ok(response)
    }

    async fn get_latest_checkpoint_sequence_number(
        &self,
    ) -> SuiRpcResult<CheckpointSequenceNumber> {
        todo!()
    }

    async fn get_checkpoint(&self, _id: CheckpointId) -> SuiRpcResult<Checkpoint> {
        todo!()
    }

    async fn get_dynamic_field_object(
        &self,
        _parent_object_id: ObjectID,
        _name: DynamicFieldName,
    ) -> SuiRpcResult<SuiObjectResponse> {
        todo!()
    }

    async fn get_reference_gas_price(&self) -> SuiRpcResult<u64> {
        todo!()
    }

    async fn verify_zklogin_signature(
        &self,
        _bytes: String,
        _signature: String,
        _intent_scope: ZkLoginIntentScope,
        _address: SuiAddress,
    ) -> SuiRpcResult<ZkLoginVerifyResult> {
        todo!()
    }
}

#[tokio::test]
async fn encrypt_and_decrypt_with_mock_server() -> Result<(), anyhow::Error> {
    let key_server_object_id = ObjectID::from_str(KEY_SERVER_OBJECT_ID).unwrap();

    let options = KeyServerOptions::new_open_server_with_default_values(
        Network::Devnet,
        key_server_object_id,
    );
    let master_keys = MasterKeys::load(&options.server_mode, MASTER_KEY)?;

    let (server, _, _) = get_server::<MockSuiClient>(options, master_keys)
        .await
        .unwrap();

    let server_public_key_bytes = hex::decode(PUBLIC_KEY.strip_prefix("0x").unwrap()).unwrap();
    let server_public_key_g2 =
        G2Element::from_byte_array(&server_public_key_bytes.try_into().unwrap()).unwrap();

    let server_public_keys = IBEPublicKeys::BonehFranklinBLS12381(vec![server_public_key_g2]);
    let package_id = ObjectID::from_hex_literal(FIRST_PACKAGE_ID).unwrap();
    let id = vec![1, 2, 3];
    let data: Vec<u8> = vec![0, 0, 0, 1]; // 1u16

    let (encrypted_object, _) = seal_encrypt(
        sui_sdk_types::ObjectId::from(package_id.into_bytes()),
        id.clone(),
        vec![sui_sdk_types::ObjectId::from(
            key_server_object_id.into_bytes(),
        )],
        &server_public_keys,
        1,
        EncryptionInput::Aes256Gcm {
            data: data.clone(),
            aad: None,
        },
    )
    .unwrap();

    let user_secret_key = Ed25519PrivateKey::from_bytes(&[
        16, 38, 58, 130, 194, 133, 180, 117, 252, 32, 106, 49, 97, 22, 170, 130, 33, 59, 81, 63,
        132, 11, 246, 227, 58, 130, 18, 208, 130, 124, 49, 12,
    ])
    .unwrap();
    let keypair = Ed25519KeyPair::from(user_secret_key);
    let user =
        SuiAddress::from_str("0xb743cafeb5da4914cef0cf0a32400c9adfedc5cdb64209f9e740e56d23065100")
            .unwrap();

    // Generate session key and encryption key
    let (enc_secret, enc_key, enc_verification_key) = elgamal::genkey(&mut thread_rng());
    let session = Ed25519KeyPair::generate(&mut StdRng::from_seed([1; 32]));

    // Create certificate
    let creation_time = chrono::Utc::now().timestamp_millis() as u64;
    let ttl_min = 10;
    let message = signed_message(
        package_id.to_hex_uncompressed(),
        session.public(),
        creation_time,
        ttl_min,
    );
    let msg_with_intent = IntentMessage::new(Intent::personal_message(), message.clone());
    let signature = Signature::new_secure(&msg_with_intent, &keypair);

    let certificate = Certificate {
        user,
        session_vk: session.public().clone(),
        creation_time,
        ttl_min,
        signature: GenericSignature::Signature(signature),
        mvr_name: None,
    };

    let mut ptb_builder = ProgrammableTransactionBuilder::new();
    let id_arg = ptb_builder.pure(id).unwrap();

    ptb_builder.programmable_move_call(
        package_id,
        "my_module".parse().unwrap(),
        "seal_approve".parse().unwrap(),
        vec![],
        vec![id_arg],
    );

    let ptb = ptb_builder.finish();

    let request_message = signed_request(&ptb, &enc_key, &enc_verification_key);
    let request_signature = session.sign(&request_message);

    // Create the FetchKeyRequest
    let request = FetchKeyRequest {
        ptb: Base64::encode(bcs::to_bytes(&ptb).unwrap()),
        enc_key,
        enc_verification_key,
        request_signature,
        certificate,
    };

    let fetch_keys_response = fetch_key(
        server,
        &request,
        ValidPtb::try_from(ptb).unwrap(),
        None,
        "1",
        1,
        None,
    )
    .await
    .unwrap();

    let sui_types_sdk_key_server_object_id =
        sui_sdk_types::ObjectId::from(key_server_object_id.into_bytes());

    let decrypted = seal_decrypt_all_objects(
        &enc_secret,
        &[(sui_types_sdk_key_server_object_id, fetch_keys_response)],
        &[encrypted_object],
        &[(sui_types_sdk_key_server_object_id, server_public_key_g2)]
            .into_iter()
            .collect(),
    )
    .unwrap()
    .into_iter()
    .next()
    .unwrap();

    assert_eq!(decrypted, data);

    Ok(())
}

#[tokio::test]
async fn encrypt_and_decrypt_wrong_id_with_mock_server() -> Result<(), anyhow::Error> {
    let key_server_object_id = ObjectID::from_str(KEY_SERVER_OBJECT_ID).unwrap();

    let options = KeyServerOptions::new_open_server_with_default_values(
        Network::Devnet,
        key_server_object_id,
    );
    let master_keys = MasterKeys::load(&options.server_mode, MASTER_KEY)?;

    let (server, _, _) = get_server::<MockSuiClient>(options, master_keys)
        .await
        .unwrap();

    let server_public_key_bytes = hex::decode(PUBLIC_KEY.strip_prefix("0x").unwrap()).unwrap();
    let server_public_key_g2 =
        G2Element::from_byte_array(&server_public_key_bytes.try_into().unwrap()).unwrap();

    let server_public_keys = IBEPublicKeys::BonehFranklinBLS12381(vec![server_public_key_g2]);
    let package_id = ObjectID::from_hex_literal(FIRST_PACKAGE_ID).unwrap();
    let id = vec![1, 2, 3];
    let data: Vec<u8> = vec![0, 0, 0, 1]; // 1u16

    let (encrypted_object, _) = seal_encrypt(
        sui_sdk_types::ObjectId::from(package_id.into_bytes()),
        id.clone(),
        vec![sui_sdk_types::ObjectId::from(
            key_server_object_id.into_bytes(),
        )],
        &server_public_keys,
        1,
        EncryptionInput::Aes256Gcm {
            data: data.clone(),
            aad: None,
        },
    )
    .unwrap();

    let user_secret_key = Ed25519PrivateKey::from_bytes(&[
        16, 38, 58, 130, 194, 133, 180, 117, 252, 32, 106, 49, 97, 22, 170, 130, 33, 59, 81, 63,
        132, 11, 246, 227, 58, 130, 18, 208, 130, 124, 49, 12,
    ])
    .unwrap();
    let keypair = Ed25519KeyPair::from(user_secret_key);
    let user =
        SuiAddress::from_str("0xb743cafeb5da4914cef0cf0a32400c9adfedc5cdb64209f9e740e56d23065100")
            .unwrap();

    // Generate session key and encryption key
    let (enc_secret, enc_key, enc_verification_key) = elgamal::genkey(&mut thread_rng());
    let session = Ed25519KeyPair::generate(&mut StdRng::from_seed([1; 32]));

    // Create certificate
    let creation_time = chrono::Utc::now().timestamp_millis() as u64;
    let ttl_min = 10;
    let message = signed_message(
        package_id.to_hex_uncompressed(),
        session.public(),
        creation_time,
        ttl_min,
    );
    let msg_with_intent = IntentMessage::new(Intent::personal_message(), message.clone());
    let signature = Signature::new_secure(&msg_with_intent, &keypair);

    let certificate = Certificate {
        user,
        session_vk: session.public().clone(),
        creation_time,
        ttl_min,
        signature: GenericSignature::Signature(signature),
        mvr_name: None,
    };

    let mut ptb_builder = ProgrammableTransactionBuilder::new();
    let id_arg = ptb_builder.pure(vec![0u8]).unwrap(); // This should make the later decrypt process to fail

    ptb_builder.programmable_move_call(
        package_id,
        "my_module".parse().unwrap(),
        "seal_approve".parse().unwrap(),
        vec![],
        vec![id_arg],
    );

    let ptb = ptb_builder.finish();

    let request_message = signed_request(&ptb, &enc_key, &enc_verification_key);
    let request_signature = session.sign(&request_message);

    // Create the FetchKeyRequest
    let request = FetchKeyRequest {
        ptb: Base64::encode(bcs::to_bytes(&ptb).unwrap()),
        enc_key,
        enc_verification_key,
        request_signature,
        certificate,
    };

    let fetch_keys_response = fetch_key(
        server,
        &request,
        ValidPtb::try_from(ptb).unwrap(),
        None,
        "1",
        1,
        None,
    )
    .await
    .unwrap();

    let sui_types_sdk_key_server_object_id =
        sui_sdk_types::ObjectId::from(key_server_object_id.into_bytes());

    let decrypted = seal_decrypt_all_objects(
        &enc_secret,
        &[(sui_types_sdk_key_server_object_id, fetch_keys_response)],
        &[encrypted_object],
        &[(sui_types_sdk_key_server_object_id, server_public_key_g2)]
            .into_iter()
            .collect(),
    );

    if decrypted.is_ok() {
        bail!("Should not succeed")
    }

    Ok(())
}

#[tokio::test]
async fn encrypt_and_decrypt_wrong_package_id_with_mock_server() -> Result<(), anyhow::Error> {
    let key_server_object_id = ObjectID::from_str(KEY_SERVER_OBJECT_ID).unwrap();

    let options = KeyServerOptions::new_open_server_with_default_values(
        Network::Devnet,
        key_server_object_id,
    );
    let master_keys = MasterKeys::load(&options.server_mode, MASTER_KEY)?;

    let (server, _, _) = get_server::<MockSuiClient>(options, master_keys)
        .await
        .unwrap();

    let server_public_key_bytes = hex::decode(PUBLIC_KEY.strip_prefix("0x").unwrap()).unwrap();
    let server_public_key_g2 =
        G2Element::from_byte_array(&server_public_key_bytes.try_into().unwrap()).unwrap();

    let server_public_keys = IBEPublicKeys::BonehFranklinBLS12381(vec![server_public_key_g2]);
    let package_id = ObjectID::from_hex_literal(FIRST_PACKAGE_ID).unwrap();
    let id = vec![1, 2, 3];
    let data: Vec<u8> = vec![0, 0, 0, 1]; // 1u16

    let (encrypted_object, _) = seal_encrypt(
        sui_sdk_types::ObjectId::from(package_id.into_bytes()),
        id.clone(),
        vec![sui_sdk_types::ObjectId::from(
            key_server_object_id.into_bytes(),
        )],
        &server_public_keys,
        1,
        EncryptionInput::Aes256Gcm {
            data: data.clone(),
            aad: None,
        },
    )
    .unwrap();

    let user_secret_key = Ed25519PrivateKey::from_bytes(&[
        16, 38, 58, 130, 194, 133, 180, 117, 252, 32, 106, 49, 97, 22, 170, 130, 33, 59, 81, 63,
        132, 11, 246, 227, 58, 130, 18, 208, 130, 124, 49, 12,
    ])
    .unwrap();
    let keypair = Ed25519KeyPair::from(user_secret_key);
    let user =
        SuiAddress::from_str("0xb743cafeb5da4914cef0cf0a32400c9adfedc5cdb64209f9e740e56d23065100")
            .unwrap();

    // Generate session key and encryption key
    let (enc_secret, enc_key, enc_verification_key) = elgamal::genkey(&mut thread_rng());
    let session = Ed25519KeyPair::generate(&mut StdRng::from_seed([1; 32]));

    // Create certificate
    let creation_time = chrono::Utc::now().timestamp_millis() as u64;
    let ttl_min = 10;

    let wrong_package_id = ObjectID::from_hex_literal(SECOND_PACKAGE_ID).unwrap();

    let message = signed_message(
        wrong_package_id.to_hex_uncompressed(),
        session.public(),
        creation_time,
        ttl_min,
    );
    let msg_with_intent = IntentMessage::new(Intent::personal_message(), message.clone());
    let signature = Signature::new_secure(&msg_with_intent, &keypair);

    let certificate = Certificate {
        user,
        session_vk: session.public().clone(),
        creation_time,
        ttl_min,
        signature: GenericSignature::Signature(signature),
        mvr_name: None,
    };

    let mut ptb_builder = ProgrammableTransactionBuilder::new();
    let id_arg = ptb_builder.pure(id).unwrap();

    ptb_builder.programmable_move_call(
        wrong_package_id, // This should make the later decrypt process to fail
        "my_module".parse().unwrap(),
        "seal_approve".parse().unwrap(),
        vec![],
        vec![id_arg],
    );

    let ptb = ptb_builder.finish();

    let request_message = signed_request(&ptb, &enc_key, &enc_verification_key);
    let request_signature = session.sign(&request_message);

    // Create the FetchKeyRequest
    let request = FetchKeyRequest {
        ptb: Base64::encode(bcs::to_bytes(&ptb).unwrap()),
        enc_key,
        enc_verification_key,
        request_signature,
        certificate,
    };

    let fetch_keys_response = fetch_key(
        server,
        &request,
        ValidPtb::try_from(ptb).unwrap(),
        None,
        "1",
        1,
        None,
    )
    .await
    .unwrap();

    let sui_types_sdk_key_server_object_id =
        sui_sdk_types::ObjectId::from(key_server_object_id.into_bytes());

    let decrypted = seal_decrypt_all_objects(
        &enc_secret,
        &[(sui_types_sdk_key_server_object_id, fetch_keys_response)],
        &[encrypted_object],
        &[(sui_types_sdk_key_server_object_id, server_public_key_g2)]
            .into_iter()
            .collect(),
    );

    if decrypted.is_ok() {
        bail!("Should not succeed")
    }

    Ok(())
}

#[tokio::test]
async fn encrypt_and_decrypt_invalid_signature_with_mock_server() -> Result<(), anyhow::Error> {
    let key_server_object_id = ObjectID::from_str(KEY_SERVER_OBJECT_ID).unwrap();

    let options = KeyServerOptions::new_open_server_with_default_values(
        Network::Devnet,
        key_server_object_id,
    );
    let master_keys = MasterKeys::load(&options.server_mode, MASTER_KEY)?;

    let (server, _, _) = get_server::<MockSuiClient>(options, master_keys)
        .await
        .unwrap();

    let package_id = ObjectID::from_hex_literal(FIRST_PACKAGE_ID).unwrap();
    let id: Vec<u8> = vec![1, 2, 3];

    let user_secret_key = Ed25519PrivateKey::from_bytes(&[
        16, 38, 58, 130, 194, 133, 180, 117, 252, 32, 106, 49, 97, 22, 170, 130, 33, 59, 81, 63,
        132, 11, 246, 227, 58, 130, 18, 208, 130, 124, 49, 12,
    ])
    .unwrap();
    let keypair = Ed25519KeyPair::from(user_secret_key);
    let user =
        SuiAddress::from_str("0xb743cafeb5da4914cef0cf0a32400c9adfedc5cdb64209f9e740e56d23065100")
            .unwrap();

    let (_, enc_key, enc_verification_key) = elgamal::genkey(&mut thread_rng());
    let session = Ed25519KeyPair::generate(&mut StdRng::from_seed([1; 32]));

    // Create certificate
    let creation_time = chrono::Utc::now().timestamp_millis() as u64;
    let ttl_min = 10;
    let message = "This is an invalid message, causing an invalid signature!";
    let msg_with_intent = IntentMessage::new(Intent::personal_message(), message);
    let signature = Signature::new_secure(&msg_with_intent, &keypair);

    let certificate = Certificate {
        user,
        session_vk: session.public().clone(),
        creation_time,
        ttl_min,
        signature: GenericSignature::Signature(signature),
        mvr_name: None,
    };

    let mut ptb_builder = ProgrammableTransactionBuilder::new();
    let id_arg = ptb_builder.pure(id).unwrap();

    ptb_builder.programmable_move_call(
        package_id,
        "my_module".parse().unwrap(),
        "seal_approve".parse().unwrap(),
        vec![],
        vec![id_arg],
    );

    let ptb = ptb_builder.finish();

    let request_message = signed_request(&ptb, &enc_key, &enc_verification_key);
    let request_signature = session.sign(&request_message);

    let request = FetchKeyRequest {
        ptb: Base64::encode(bcs::to_bytes(&ptb).unwrap()),
        enc_key,
        enc_verification_key,
        request_signature,
        certificate,
    };

    let fetch_keys_response_result = fetch_key(
        server,
        &request,
        ValidPtb::try_from(ptb).unwrap(),
        None,
        "1",
        1,
        None,
    )
    .await;

    match fetch_keys_response_result {
        Ok(_) => bail!("Should not succeed"),
        Err(InternalError::InvalidSignature) => {}
        Err(error) => bail!("Invalid error: {:?}", error),
    }

    Ok(())
}
