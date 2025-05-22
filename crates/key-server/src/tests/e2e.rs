// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::tests::externals::get_key;
use crate::tests::whitelist::{add_user_to_whitelist, create_whitelist, whitelist_create_ptb};
use crate::tests::SealTestCluster;
use crypto::{seal_decrypt, seal_encrypt, EncryptionInput, IBEPublicKeys, IBEUserSecretKeys};
use tracing_test::traced_test;

#[traced_test]
#[tokio::test]
async fn test_e2e() {
    let mut tc = SealTestCluster::new(3, 1).await;
    let (examples_package_id, _) = tc.publish("patterns").await;

    let (whitelist, cap) = create_whitelist(tc.get_mut(), examples_package_id).await;

    // Create test users
    let user_address = tc.users[0].address;
    add_user_to_whitelist(
        tc.get_mut(),
        examples_package_id,
        whitelist,
        cap,
        user_address,
    )
    .await;

    // We know the version at this point
    let initial_shared_version = 3;

    // Get keys from two key servers
    let ptb = whitelist_create_ptb(examples_package_id, whitelist, initial_shared_version);

    // Send requests to the key servers and decrypt the responses
    let usk0 = get_key(
        &tc.servers[0].server,
        &examples_package_id,
        ptb.clone(),
        &tc.users[0].keypair,
    )
    .await
    .unwrap();
    let usk1 = get_key(
        &tc.servers[1].server,
        &examples_package_id,
        ptb,
        &tc.users[0].keypair,
    )
    .await
    .unwrap();

    // Register the three services on-chain
    let (package_id, _) = tc.publish("seal").await;

    let mut services = vec![];
    for i in 0..3 {
        services.push(
            tc.register_key_server(
                package_id,
                &format!("Test server {}", i),
                &format!("https:://testserver{}.com", i),
                tc.servers[i].public_key,
            )
            .await,
        );
    }

    // Read the public keys from the service objects
    let pks = tc.get_public_keys(&services).await;
    assert_eq!(
        pks,
        tc.servers.iter().map(|s| s.public_key).collect::<Vec<_>>()
    );
    let pks = IBEPublicKeys::BonehFranklinBLS12381(pks);

    // Encrypt a message
    let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    let services = services.to_vec();
    let encryption = seal_encrypt(
        examples_package_id,
        whitelist.to_vec(),
        services.clone(),
        &pks,
        2,
        EncryptionInput::Aes256Gcm {
            data: message.to_vec(),
            aad: None,
        },
    )
    .unwrap()
    .0;

    // Decrypt the message
    let decryption = seal_decrypt(
        &encryption,
        &IBEUserSecretKeys::BonehFranklinBLS12381(services.into_iter().zip([usk0, usk1]).collect()),
        Some(&pks),
    )
    .unwrap();

    assert_eq!(decryption, message);
}
