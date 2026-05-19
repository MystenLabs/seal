// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use fastcrypto::bls12381::min_sig::BLS12381PublicKey;
use serde::de::DeserializeOwned;

const MEMBER_0: &str = "0x00ba1ae103cf43b2017796914b20cfbed32fc78b43d506583cd2383af18ef739";
const MEMBER_1: &str = "0x393bddd124a05a95859579d635d46ef20e5be802362d5bbd86999e2c845bf153";
const MEMBER_2: &str = "0xb39cb0c9c979921bf1d63c3c6df20765b9c7c21b1ae9445ab42931f6e1b45c66";
const COMMITTEE_PKG: &str = "0xd0aa3b6dd0cc41b99f7d18f58cb9fe5f353aca8f5198e930f8cab3082dc40e82";
const COMMITTEE_ID: &str = "0x454c9cf3cb14caec4ccc6b90170f7af4c508af87c4d047085353d4b4d79fee85";

/// Write a file in a unique temp directory and return its path.
fn write_temp_file(test_name: &str, file_name: &str, content: &str) -> PathBuf {
    let suffix = format!("{:032x}", rand::random::<u128>());
    let dir = std::env::temp_dir().join(format!("seal-committee-cli-{test_name}-{suffix}"));
    fs::create_dir_all(&dir).expect("failed to create temp dir");
    let path = dir.join(file_name);
    fs::write(&path, content).expect("failed to write temp file");
    path
}

/// Write a dkg.yaml fixture in a unique temp directory.
fn write_temp_config(test_name: &str, content: &str) -> PathBuf {
    write_temp_file(test_name, "dkg.yaml", content)
}

/// Build the initial fresh-DKG config fixture.
fn initial_init_params_yaml() -> String {
    format!(
        "\
init-params:
  NETWORK: Testnet
  THRESHOLD: 2
  MEMBERS:
  - {MEMBER_0}
  - {MEMBER_1}
  - {MEMBER_2}
"
    )
}

/// Read one field from process-all-and-propose.
fn process_field<'a>(config: &'a serde_yaml::Value, key: &str) -> &'a serde_yaml::Value {
    config
        .get("process-all-and-propose")
        .and_then(|section| section.get(key))
        .unwrap_or_else(|| panic!("missing process-all-and-propose.{key}"))
}

/// Read one string field from any ordered list of config sections.
fn config_str_field<'a>(config: &'a serde_yaml::Value, sections: &[&str], key: &str) -> &'a str {
    get_config_field(config, sections, key)
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

/// Decode a config hex field and parse it into the expected BCS type.
fn config_bcs_hex_field<T: DeserializeOwned>(
    config: &serde_yaml::Value,
    sections: &[&str],
    key: &str,
) -> T {
    let bytes = Hex::decode(config_str_field(config, sections, key))
        .unwrap_or_else(|_| panic!("{key} should be hex"));
    bcs::from_bytes(&bytes).unwrap_or_else(|_| panic!("{key} should be valid BCS"))
}

/// Return valid process output fixtures in the order expected by persist_process_outputs.
fn valid_process_output_material() -> (Vec<u8>, Vec<u8>, String) {
    let key_server_pk = bcs::to_bytes(&(G2Element::generator() * G2Scalar::from(10u128))).unwrap();
    let master_share = bcs::to_bytes(&G2Scalar::from(20u128)).unwrap();
    let partial_pks: Vec<String> = [
        G2Element::generator() * G2Scalar::from(30u128),
        G2Element::generator() * G2Scalar::from(40u128),
    ]
    .iter()
    .map(|pk| Hex::encode_with_format(bcs::to_bytes(pk).unwrap()))
    .collect();
    (
        key_server_pk,
        master_share,
        serde_yaml::to_string(&partial_pks).expect("partial pk YAML should serialize"),
    )
}

/// Persist process outputs into a temp config and return the resulting error text.
fn persist_process_outputs_error(
    test_name: &str,
    config_content: &str,
    next_version: u32,
    key_server_pk: &[u8],
    old_key_server_pk: Option<&[u8]>,
    partial_pks_yaml: &str,
    master_share: &[u8],
) -> String {
    let config_path = write_temp_config(test_name, config_content);
    persist_process_outputs(
        &config_path,
        next_version,
        key_server_pk,
        old_key_server_pk,
        partial_pks_yaml.trim(),
        master_share,
    )
    .unwrap_err()
    .to_string()
}

#[test]
fn test_committee_ids_follow_fresh_and_rotation_config_shapes() {
    let initial_fresh_config: serde_yaml::Value =
        serde_yaml::from_str(&initial_init_params_yaml()).unwrap();
    assert!(get_committee_id(&initial_fresh_config).is_err());
    assert!(get_committee_pkg(&initial_fresh_config).is_err());

    let fresh_config: serde_yaml::Value = serde_yaml::from_str(&format!(
        "\
{}publish-and-init:
  COMMITTEE_PKG: {COMMITTEE_PKG}
  COMMITTEE_ID: {COMMITTEE_ID}
  COORDINATOR_ADDRESS: {MEMBER_0}
",
        initial_init_params_yaml()
    ))
    .unwrap();
    assert_eq!(
        get_committee_id(&fresh_config).unwrap(),
        Address::from_str(COMMITTEE_ID).unwrap()
    );
    assert_eq!(
        get_committee_pkg(&fresh_config).unwrap(),
        Address::from_str(COMMITTEE_PKG).unwrap()
    );

    let rotation_committee = "0x4444444444444444444444444444444444444444444444444444444444444444";
    let rotation_pkg = "0x6666666666666666666666666666666666666666666666666666666666666666";
    let key_server_obj_id = "0x7777777777777777777777777777777777777777777777777777777777777777";
    let rotation_config: serde_yaml::Value = serde_yaml::from_str(&format!(
        "\
{}init-rotation-params:
  KEY_SERVER_OBJ_ID: {key_server_obj_id}
init-rotation:
  COMMITTEE_ID: {rotation_committee}
  COMMITTEE_PKG: {rotation_pkg}
",
        initial_init_params_yaml()
    ))
    .unwrap();

    assert_eq!(
        get_key_server_obj_id(&rotation_config).unwrap(),
        Address::from_str(key_server_obj_id).unwrap()
    );
    assert_eq!(
        get_committee_id(&rotation_config).unwrap(),
        Address::from_str(rotation_committee).unwrap()
    );
    assert_eq!(
        get_committee_pkg(&rotation_config).unwrap(),
        Address::from_str(rotation_pkg).unwrap()
    );
}

#[test]
fn test_config_step_updates_add_fields_without_overwriting_existing_sections() {
    let config_path = write_temp_config("step-field-updates", &initial_init_params_yaml());
    update_config_bytes_val(
        &config_path,
        "publish-and-init",
        vec![
            (
                "COMMITTEE_PKG",
                Address::from_str(COMMITTEE_PKG).unwrap().inner(),
            ),
            (
                "COMMITTEE_ID",
                Address::from_str(COMMITTEE_ID).unwrap().inner(),
            ),
            (
                "COORDINATOR_ADDRESS",
                Address::from_str(MEMBER_0).unwrap().inner(),
            ),
        ],
    )
    .unwrap();

    let enc_sk = PrivateKey::<G1Element>::new(&mut thread_rng());
    let enc_pk = PublicKey::from_private_key(&enc_sk);
    let signing_kp = BLS12381KeyPair::generate(&mut thread_rng());
    let signing_pk = signing_kp.public().clone();
    let enc_pk_bytes = bcs::to_bytes(&enc_pk).unwrap();
    let signing_pk_bytes = bcs::to_bytes(&signing_pk).unwrap();

    update_config_bytes_val(
        &config_path,
        "genkey-and-register",
        vec![
            ("MY_ADDRESS", Address::from_str(MEMBER_0).unwrap().inner()),
            ("DKG_ENC_PK", &enc_pk_bytes),
            ("DKG_SIGNING_PK", &signing_pk_bytes),
        ],
    )
    .unwrap();
    update_config_string_val(
        &config_path,
        "genkey-and-register",
        vec![
            ("MY_SERVER_URL", "http://localhost:4000"),
            ("MY_SERVER_NAME", "server-mainnet-0"),
        ],
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();
    assert_eq!(get_network(&config).unwrap(), Network::Testnet);
    assert_eq!(get_threshold(&config).unwrap(), 2);
    assert_eq!(
        get_members(&config).unwrap(),
        vec![
            Address::from_str(MEMBER_0).unwrap(),
            Address::from_str(MEMBER_1).unwrap(),
            Address::from_str(MEMBER_2).unwrap(),
        ]
    );
    assert_eq!(
        config_str_field(&config, &["publish-and-init"], "COMMITTEE_ID"),
        COMMITTEE_ID
    );
    assert_eq!(
        config_str_field(&config, &["publish-and-init"], "COMMITTEE_PKG"),
        COMMITTEE_PKG
    );
    assert_eq!(get_my_address(&config).unwrap().to_string(), MEMBER_0);
    assert_eq!(
        config_str_field(&config, &["genkey-and-register"], "MY_SERVER_URL"),
        "http://localhost:4000"
    );
    assert_eq!(
        config_str_field(&config, &["genkey-and-register"], "MY_SERVER_NAME"),
        "server-mainnet-0"
    );

    let registered_enc_pk: PublicKey<G1Element> =
        config_bcs_hex_field(&config, &["genkey-and-register"], "DKG_ENC_PK");
    let registered_signing_pk: BLS12381PublicKey =
        config_bcs_hex_field(&config, &["genkey-and-register"], "DKG_SIGNING_PK");
    assert_eq!(bcs::to_bytes(&registered_enc_pk).unwrap(), enc_pk_bytes);
    assert_eq!(
        bcs::to_bytes(&registered_signing_pk).unwrap(),
        signing_pk_bytes
    );
}

#[test]
fn test_dkg_key_file_matches_registered_public_keys() {
    let mut rng = thread_rng();
    let enc_sk = PrivateKey::<G1Element>::new(&mut rng);
    let enc_pk = PublicKey::from_private_key(&enc_sk);
    let signing_kp = BLS12381KeyPair::generate(&mut rng);
    let signing_pk = signing_kp.public().clone();
    let signing_sk = signing_kp.private();
    let keys = KeysFile {
        enc_sk,
        enc_pk,
        signing_sk,
        signing_pk,
    };
    let dkg_enc_pk = Hex::encode_with_format(bcs::to_bytes(&keys.enc_pk).unwrap());
    let dkg_signing_pk = Hex::encode_with_format(bcs::to_bytes(&keys.signing_pk).unwrap());

    let config: serde_yaml::Value = serde_yaml::from_str(&format!(
        "\
genkey-and-register:
  DKG_ENC_PK: {dkg_enc_pk}
  DKG_SIGNING_PK: {dkg_signing_pk}
"
    ))
    .unwrap();

    let keys_path = write_temp_file(
        "dkg-key",
        "dkg.key",
        &serde_json::to_string_pretty(&keys).expect("keys should serialize"),
    );
    let keys = KeysFile::load(&keys_path).expect("dkg.key should load");
    let registered_enc_pk: PublicKey<G1Element> =
        config_bcs_hex_field(&config, &["genkey-and-register"], "DKG_ENC_PK");
    let registered_signing_pk: BLS12381PublicKey =
        config_bcs_hex_field(&config, &["genkey-and-register"], "DKG_SIGNING_PK");
    assert_eq!(
        bcs::to_bytes(&keys.enc_pk).unwrap(),
        bcs::to_bytes(&registered_enc_pk).unwrap()
    );
    assert_eq!(
        bcs::to_bytes(&keys.signing_pk).unwrap(),
        bcs::to_bytes(&registered_signing_pk).unwrap()
    );
}

#[test]
fn test_persist_process_outputs_for_fresh_dkg_writes_v0_fields() {
    let config_path = write_temp_config("fresh-process-outputs", "init-params: {}\n");
    let (key_server_pk, master_share, partial_pks_yaml) = valid_process_output_material();

    persist_process_outputs(
        &config_path,
        0,
        &key_server_pk,
        None,
        partial_pks_yaml.trim(),
        &master_share,
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();
    assert_eq!(
        config_str_field(&config, &["process-all-and-propose"], "KEY_SERVER_PK"),
        Hex::encode_with_format(&key_server_pk)
    );
    assert_eq!(
        config_str_field(&config, &["process-all-and-propose"], "MASTER_SHARE_V0"),
        Hex::encode_with_format(&master_share)
    );
    let _: G2Element = config_bcs_hex_field(&config, &["process-all-and-propose"], "KEY_SERVER_PK");
    let _: G2Scalar =
        config_bcs_hex_field(&config, &["process-all-and-propose"], "MASTER_SHARE_V0");

    let partial_pks = process_field(&config, "PARTIAL_PKS_V0")
        .as_sequence()
        .expect("PARTIAL_PKS_V0 should be a YAML list");
    assert_eq!(partial_pks.len(), 2);
    for partial_pk in partial_pks {
        let bytes = Hex::decode(partial_pk.as_str().expect("partial pk should be a string"))
            .expect("partial pk should be hex");
        let _: G2Element = bcs::from_bytes(&bytes).expect("partial pk should parse");
    }
}

#[test]
fn test_persist_process_outputs_for_rotation_preserves_key_server_pk() {
    let (key_server_pk, master_share, partial_pks_yaml) = valid_process_output_material();
    let existing_key_server_pk = Hex::encode_with_format(&key_server_pk);
    let config_path = write_temp_config(
        "rotation-process-outputs",
        &format!(
            "\
process-all-and-propose:
  KEY_SERVER_PK: '{existing_key_server_pk}'
  MASTER_SHARE_V0: '0x8888'
"
        ),
    );

    persist_process_outputs(
        &config_path,
        1,
        &key_server_pk,
        Some(&key_server_pk),
        partial_pks_yaml.trim(),
        &master_share,
    )
    .unwrap();

    let config = load_config(&config_path).unwrap();
    assert_eq!(
        config_str_field(&config, &["process-all-and-propose"], "KEY_SERVER_PK"),
        existing_key_server_pk
    );
    assert_eq!(
        config_str_field(&config, &["process-all-and-propose"], "MASTER_SHARE_V0"),
        "0x8888"
    );
    assert_eq!(
        config_str_field(&config, &["process-all-and-propose"], "MASTER_SHARE_V1"),
        Hex::encode_with_format(&master_share)
    );
    let _: G2Scalar =
        config_bcs_hex_field(&config, &["process-all-and-propose"], "MASTER_SHARE_V1");

    let partial_pks = process_field(&config, "PARTIAL_PKS_V1")
        .as_sequence()
        .expect("PARTIAL_PKS_V1 should be a YAML list");
    assert_eq!(partial_pks.len(), 2);
    for partial_pk in partial_pks {
        let bytes = Hex::decode(partial_pk.as_str().expect("partial pk should be a string"))
            .expect("partial pk should be hex");
        let _: G2Element = bcs::from_bytes(&bytes).expect("partial pk should parse");
    }
}

#[test]
fn test_validate_rotation_quorum_rejects_too_few_continuing_members() {
    let old_committee_id = Address::from_str(COMMITTEE_ID).unwrap();

    validate_rotation_quorum(&old_committee_id, 2, 2).unwrap();

    let err = validate_rotation_quorum(&old_committee_id, 3, 2)
        .unwrap_err()
        .to_string();
    assert!(err.contains("requires 3 continuing member message"));
    assert!(err.contains("only 2 new committee member"));
}

#[test]
fn test_validate_rotation_message_senders_rejects_new_members() {
    let mut new_to_old_mapping = HashMap::new();
    new_to_old_mapping.insert(0, 1);
    new_to_old_mapping.insert(1, 0);

    let valid_senders = HashSet::from([0, 1]);
    validate_rotation_message_senders(2, &new_to_old_mapping, &valid_senders).unwrap();

    let new_member_sender = HashSet::from([0, 2]);
    let err = validate_rotation_message_senders(2, &new_to_old_mapping, &new_member_sender)
        .unwrap_err()
        .to_string();
    assert!(err.contains("Invalid new party ID"));
    assert!(err.contains("[2]"));

    let missing_sender = HashSet::from([0]);
    let err = validate_rotation_message_senders(2, &new_to_old_mapping, &missing_sender)
        .unwrap_err()
        .to_string();
    assert!(err.contains("requires exactly 2 messages"));
}

#[test]
fn test_validate_continuing_member_old_share_matches_onchain_pk() {
    let my_address = Address::from_str(MEMBER_0).unwrap();
    let old_committee_id = Address::from_str(COMMITTEE_ID).unwrap();
    let old_share = G2Scalar::from(50u128);
    let expected_old_pk = G2Element::generator() * old_share;

    let mut new_to_old_mapping = HashMap::new();
    new_to_old_mapping.insert(1, 0);
    let mut expected_old_pks = HashMap::new();
    expected_old_pks.insert(0, expected_old_pk);

    validate_continuing_member_old_share(
        &my_address,
        &old_committee_id,
        1,
        &new_to_old_mapping,
        &expected_old_pks,
        &expected_old_pk,
    )
    .unwrap();

    let wrong_old_pk = G2Element::generator() * G2Scalar::from(51u128);
    let err = validate_continuing_member_old_share(
        &my_address,
        &old_committee_id,
        1,
        &new_to_old_mapping,
        &expected_old_pks,
        &wrong_old_pk,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("Invalid --old-share"));
    assert!(err.contains("party 0"));
}

#[test]
fn test_persist_process_outputs_rejects_version_mismatch() {
    let (key_server_pk, master_share, partial_pks_yaml) = valid_process_output_material();
    let err = persist_process_outputs_error(
        "existing-version-output",
        "\
process-all-and-propose:
  MASTER_SHARE_V1: '0x1234'
",
        1,
        &key_server_pk,
        Some(&key_server_pk),
        &partial_pks_yaml,
        &master_share,
    );
    assert!(err.contains("already contains output field"));

    let err = persist_process_outputs_error(
        "missing-old-key-server-pk",
        "init-params: {}\n",
        1,
        &key_server_pk,
        None,
        &partial_pks_yaml,
        &master_share,
    );
    assert!(err.contains("requires the old onchain KEY_SERVER_PK"));

    let mismatched_key_server_pk =
        bcs::to_bytes(&(G2Element::generator() * G2Scalar::from(99u128))).unwrap();
    let mismatched_key_server_pk_hex = Hex::encode_with_format(&mismatched_key_server_pk);
    let err = persist_process_outputs_error(
        "mismatched-key-server-pk",
        &format!(
            "\
process-all-and-propose:
  KEY_SERVER_PK: '{mismatched_key_server_pk_hex}'
"
        ),
        1,
        &key_server_pk,
        Some(&key_server_pk),
        &partial_pks_yaml,
        &master_share,
    );
    assert!(err.contains("process-all-and-propose.KEY_SERVER_PK mismatch"));
}

#[test]
fn test_persist_process_outputs_rejects_invalid_key_material() {
    let (key_server_pk, master_share, partial_pks_yaml) = valid_process_output_material();
    let err = persist_process_outputs_error(
        "invalid-key-server-pk",
        "init-params: {}\n",
        0,
        &[0, 0],
        None,
        &partial_pks_yaml,
        &master_share,
    );
    assert!(err.contains("KEY_SERVER_PK must be a valid BCS G2Element"));

    let err = persist_process_outputs_error(
        "invalid-master-share",
        "init-params: {}\n",
        1,
        &key_server_pk,
        Some(&key_server_pk),
        &partial_pks_yaml,
        &[0],
    );
    assert!(err.contains("MASTER_SHARE_V1 must be a valid BCS scalar"));

    let err = persist_process_outputs_error(
        "invalid-partial-pk",
        "init-params: {}\n",
        1,
        &key_server_pk,
        Some(&key_server_pk),
        "- 0xaa\n",
        &master_share,
    );
    assert!(err.contains("PARTIAL_PKS_V1[0] must be a valid BCS G2Element"));
}
