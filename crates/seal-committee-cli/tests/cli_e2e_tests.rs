// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end CLI tests for seal-committee-cli.
//!
//! This test invokes the actual CLI binary to test the full DKG workflow:
//! - Initial 2-of-3 committee
//! - Rotation to 3-of-4
//! - Rotation to 5-of-5

use anyhow::{anyhow, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use test_cluster::TestClusterBuilder;

/// Helper to get the CLI binary path.
fn get_cli_binary() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../target/release/seal-committee-cli");
    if !path.exists() {
        // Try debug build
        path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../target/debug/seal-committee-cli");
    }
    path
}

/// Helper to run CLI command with optional wallet path.
fn run_cli(args: &[&str], wallet_path: Option<&Path>) -> Result<String> {
    let mut cmd = Command::new(get_cli_binary());
    cmd.args(args);

    if let Some(wallet) = wallet_path {
        cmd.arg("--wallet").arg(wallet);
    }

    let output = cmd.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("CLI command failed: {}", stderr));
    }

    Ok(String::from_utf8(output.stdout)?)
}

/// Helper to create initial config file.
fn create_initial_config(config_path: &Path, members: &[&str], threshold: u16) -> Result<()> {
    let members_yaml = members
        .iter()
        .map(|m| format!("    - {}", m))
        .collect::<Vec<_>>()
        .join("\n");

    let content = format!(
        "init-params:\n  NETWORK: localnet\n  THRESHOLD: {}\n  MEMBERS:\n{}\n",
        threshold, members_yaml
    );

    fs::write(config_path, content)?;
    Ok(())
}

/// Test encryption with key server PK and decryption with committee member shares.
///
/// This validates that:
/// 1. The master public key can encrypt data
/// 2. A threshold of committee member shares can decrypt the data
/// 3. The decrypted data matches the original plaintext
fn test_encrypt_decrypt(
    config_path: &Path,
    num_members: usize,
    threshold: usize,
    version: usize,
) -> Result<()> {
    use crypto::ibe;
    use fastcrypto::encoding::{Encoding, Hex};
    use fastcrypto::groups::bls12381::{G1Element, G2Element};
    use fastcrypto::groups::Scalar as ScalarTrait;
    use fastcrypto::serde_helpers::ToFromByteArray;
    use rand::thread_rng;
    use serde_yaml::Value;

    // Read the config file
    let config_content = fs::read_to_string(config_path)?;
    let config: Value = serde_yaml::from_str(&config_content)?;

    // Extract master public key
    let master_pk_hex = config["MASTER_KEY_PK"]
        .as_str()
        .ok_or_else(|| anyhow!("MASTER_KEY_PK not found"))?;
    let master_pk_bytes = Hex::decode(master_pk_hex.trim_start_matches("0x"))
        .map_err(|e| anyhow!("Failed to decode master PK: {}", e))?;
    let master_pk = <G2Element as ToFromByteArray<96>>::from_byte_array(
        master_pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Invalid master PK length"))?,
    )?;

    // Extract master shares for each member
    let share_key = format!("MASTER_SHARE_V{}", version);
    let mut shares = Vec::new();
    for i in 0..num_members {
        let share_hex = config[&share_key]
            .as_str()
            .ok_or_else(|| anyhow!("{} not found for member {}", share_key, i))?;
        let share_bytes = Hex::decode(share_hex.trim_start_matches("0x"))
            .map_err(|e| anyhow!("Failed to decode share {}: {}", i, e))?;
        let user_secret_key = <G1Element as ToFromByteArray<48>>::from_byte_array(
            share_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("Invalid share length"))?,
        )?;
        shares.push(user_secret_key);
    }

    // Test encryption and decryption
    let test_id = b"test_identity";
    let test_plaintext: [u8; 32] = [42u8; 32];
    let test_info = (sui_sdk_types::Address::ZERO, 0u8);

    // Generate randomness for encryption
    let mut rng = thread_rng();
    let randomness = <ibe::Randomness as ScalarTrait>::rand(&mut rng);

    // Encrypt with master public key
    let (nonce, ciphertexts) = ibe::encrypt_batched_deterministic(
        &randomness,
        &[test_plaintext],
        &[master_pk],
        test_id,
        &[test_info],
    )?;

    println!("  Encrypted test data with master public key");

    // Decrypt with threshold shares
    let mut decrypted_plaintexts = Vec::new();
    for (i, share) in shares.iter().enumerate().take(threshold) {
        let decrypted = ibe::decrypt(&nonce, &ciphertexts[0], share, test_id, &test_info);
        decrypted_plaintexts.push(decrypted);
        println!("  Decrypted with share {}: {:?}", i, &decrypted[..8]);
    }

    // Verify all threshold shares decrypt to the same plaintext
    for (i, decrypted) in decrypted_plaintexts.iter().enumerate() {
        if decrypted != &test_plaintext {
            return Err(anyhow!(
                "Decryption with share {} failed: expected {:?}, got {:?}",
                i,
                &test_plaintext[..8],
                &decrypted[..8]
            ));
        }
    }

    println!(
        "  ✓ All {} threshold shares successfully decrypted the data",
        threshold
    );
    Ok(())
}

#[tokio::test]
async fn test_cli_dkg_2_of_3_then_3_of_4_then_5_of_5() -> Result<()> {
    // Start test cluster
    let cluster = TestClusterBuilder::new()
        .with_num_validators(1)
        .build()
        .await;

    // Get funded test addresses from cluster
    let addresses: Vec<String> = vec![
        cluster.get_address_0(),
        cluster.wallet.get_addresses()[1],
        cluster.wallet.get_addresses()[2],
        cluster.wallet.get_addresses()[3],
        cluster.wallet.get_addresses()[4],
    ]
    .into_iter()
    .map(|a| a.to_string())
    .collect();

    let temp_dir = TempDir::new()?;

    // Get wallet config path from cluster
    let wallet_config_path = cluster.swarm.dir().join("client.yaml");

    // ========================================================================
    // Test Scenario 1: Initial 2-of-3 DKG
    // ========================================================================
    println!("\n=== Test Scenario 1: 2-of-3 Initial DKG ===");

    let state_dirs: Vec<PathBuf> = (0..3)
        .map(|i| temp_dir.path().join(format!("dkg-state-{}", i)))
        .collect();

    // Create state directories and config files
    for dir in &state_dirs {
        fs::create_dir_all(dir)?;
        let config_path = dir.join("dkg.yaml");
        create_initial_config(
            &config_path,
            &[
                addresses[0].as_str(),
                addresses[1].as_str(),
                addresses[2].as_str(),
            ],
            2,
        )?;
    }

    // 1. publish-and-init (using first state dir)
    println!("Running publish-and-init...");
    run_cli(
        &[
            "publish-and-init",
            "-c",
            state_dirs[0].join("dkg.yaml").to_str().unwrap(),
        ],
        Some(&wallet_config_path),
    )?;

    // Copy updated config to all state dirs
    for i in 1..3 {
        fs::copy(
            state_dirs[0].join("dkg.yaml"),
            state_dirs[i].join("dkg.yaml"),
        )?;
    }

    // 2. genkey-and-register for each member
    for i in 0..3 {
        println!("Running genkey-and-register for member {}...", i);
        run_cli(
            &[
                "genkey-and-register",
                "-s",
                state_dirs[i].to_str().unwrap(),
                "-u",
                &format!("http://server{}.example.com", i),
                "-n",
                &format!("server{}", i),
            ],
            Some(&wallet_config_path),
        )?;
    }

    // 3. create-message for each member
    let messages_dir_1 = temp_dir.path().join("dkg-messages-1");
    fs::create_dir_all(&messages_dir_1)?;

    for i in 0..3 {
        println!("Running create-message for member {}...", i);
        run_cli(
            &["create-message", "-s", state_dirs[i].to_str().unwrap()],
            Some(&wallet_config_path),
        )?;

        // Copy message to messages directory
        let src = state_dirs[i].join(format!("message_{}.json", i));
        let dst = messages_dir_1.join(format!("message_{}.json", i));
        if src.exists() {
            fs::copy(&src, &dst)?;
        }
    }

    // 4. process-all-and-propose (by first member)
    println!("Running process-all-and-propose...");
    run_cli(
        &[
            "process-all-and-propose",
            "-s",
            state_dirs[0].to_str().unwrap(),
            "-m",
            messages_dir_1.to_str().unwrap(),
        ],
        Some(&wallet_config_path),
    )?;

    // 5. check-committee
    println!("Running check-committee...");
    let output = run_cli(
        &[
            "check-committee",
            "-c",
            state_dirs[0].join("dkg.yaml").to_str().unwrap(),
        ],
        Some(&wallet_config_path),
    )?;
    println!("Committee status:\n{}", output);

    // 6. Test encrypt/decrypt with master key and shares
    println!("Testing encryption/decryption with 2-of-3 committee...");
    test_encrypt_decrypt(&state_dirs[0].join("dkg.yaml"), 3, 2, 0)?;

    println!("Test Scenario 1 complete!");

    // ========================================================================
    // Test Scenario 2: Rotate to 3-of-4
    // ========================================================================
    println!("\n=== Test Scenario 2: Rotate to 3-of-4 ===");

    let state_dirs_2: Vec<PathBuf> = (0..4)
        .map(|i| temp_dir.path().join(format!("dkg-state-2-{}", i)))
        .collect();

    // Create new state directories and configs
    for dir in &state_dirs_2 {
        fs::create_dir_all(dir)?;
        let config_path = dir.join("dkg.yaml");
        create_initial_config(
            &config_path,
            &[
                addresses[0].as_str(),
                addresses[1].as_str(),
                addresses[2].as_str(),
                addresses[3].as_str(),
            ],
            3,
        )?;
    }

    // 1. init-rotation (using first new state dir)
    println!("Running init-rotation...");
    run_cli(
        &[
            "init-rotation",
            "-c",
            state_dirs_2[0].join("dkg.yaml").to_str().unwrap(),
        ],
        Some(&wallet_config_path),
    )?;

    // Copy updated config to all state dirs
    for i in 1..4 {
        fs::copy(
            state_dirs_2[0].join("dkg.yaml"),
            state_dirs_2[i].join("dkg.yaml"),
        )?;
    }

    // 2. genkey-and-register for all members
    for i in 0..4 {
        println!("Running genkey-and-register for member {} (rotation)...", i);
        run_cli(
            &[
                "genkey-and-register",
                "-s",
                state_dirs_2[i].to_str().unwrap(),
                "-u",
                &format!("http://server{}.example.com", i),
                "-n",
                &format!("server{}", i),
            ],
            Some(&wallet_config_path),
        )?;
    }

    // 3. create-message (continuing members with old shares, new member without)
    let messages_dir_2 = temp_dir.path().join("dkg-messages-2");
    fs::create_dir_all(&messages_dir_2)?;

    for i in 0..3 {
        // Load old share from phase 1 config
        let old_config_path = state_dirs[i].join("dkg.yaml");
        let old_config = fs::read_to_string(&old_config_path)?;

        // Extract MASTER_SHARE_V0 from config (simplified parsing)
        let old_share = old_config
            .lines()
            .find(|line| line.contains("MASTER_SHARE_V0"))
            .and_then(|line| line.split(':').nth(1))
            .map(|s| s.trim())
            .ok_or_else(|| anyhow!("Could not find MASTER_SHARE_V0"))?;

        println!(
            "Running create-message for continuing member {} with old share...",
            i
        );
        run_cli(
            &[
                "create-message",
                "-s",
                state_dirs_2[i].to_str().unwrap(),
                "-o",
                old_share,
            ],
            Some(&wallet_config_path),
        )?;

        let src = state_dirs_2[i].join(format!("message_{}.json", i));
        let dst = messages_dir_2.join(format!("message_{}.json", i));
        if src.exists() {
            fs::copy(&src, &dst)?;
        }
    }

    // Member 3 is new, runs init-state
    println!("Running init-state for new member 3...");
    run_cli(
        &["init-state", "-s", state_dirs_2[3].to_str().unwrap()],
        Some(&wallet_config_path),
    )?;

    // 4. process-all-and-propose
    println!("Running process-all-and-propose (rotation)...");
    run_cli(
        &[
            "process-all-and-propose",
            "-s",
            state_dirs_2[0].to_str().unwrap(),
            "-m",
            messages_dir_2.to_str().unwrap(),
        ],
        Some(&wallet_config_path),
    )?;

    // Test encrypt/decrypt with rotated committee
    println!("Testing encryption/decryption with 3-of-4 committee...");
    test_encrypt_decrypt(&state_dirs_2[0].join("dkg.yaml"), 4, 3, 1)?;

    println!("Test Scenario 2 complete!");

    // ========================================================================
    // Test Scenario 3: Rotate to 5-of-5
    // ========================================================================
    println!("\n=== Test Scenario 3: Rotate to 5-of-5 ===");

    let state_dirs_3: Vec<PathBuf> = (0..5)
        .map(|i| temp_dir.path().join(format!("dkg-state-3-{}", i)))
        .collect();

    // Create new state directories and configs
    for dir in &state_dirs_3 {
        fs::create_dir_all(dir)?;
        let config_path = dir.join("dkg.yaml");
        create_initial_config(
            &config_path,
            &addresses.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            5,
        )?;
    }

    // 1. init-rotation
    println!("Running init-rotation...");
    run_cli(
        &[
            "init-rotation",
            "-c",
            state_dirs_3[0].join("dkg.yaml").to_str().unwrap(),
        ],
        Some(&wallet_config_path),
    )?;

    // Copy config
    for i in 1..5 {
        fs::copy(
            state_dirs_3[0].join("dkg.yaml"),
            state_dirs_3[i].join("dkg.yaml"),
        )?;
    }

    // 2. genkey-and-register
    for i in 0..5 {
        println!(
            "Running genkey-and-register for member {} (rotation 2)...",
            i
        );
        run_cli(
            &[
                "genkey-and-register",
                "-s",
                state_dirs_3[i].to_str().unwrap(),
                "-u",
                &format!("http://server{}.example.com", i),
                "-n",
                &format!("server{}", i),
            ],
            Some(&wallet_config_path),
        )?;
    }

    // 3. create-message
    let messages_dir_3 = temp_dir.path().join("dkg-messages-3");
    fs::create_dir_all(&messages_dir_3)?;

    for i in 0..4 {
        let old_config_path = state_dirs_2[i].join("dkg.yaml");
        let old_config = fs::read_to_string(&old_config_path)?;
        let old_share = old_config
            .lines()
            .find(|line| line.contains("MASTER_SHARE_V1"))
            .and_then(|line| line.split(':').nth(1))
            .map(|s| s.trim())
            .ok_or_else(|| anyhow!("Could not find MASTER_SHARE_V1"))?;

        println!("Running create-message for continuing member {}...", i);
        run_cli(
            &[
                "create-message",
                "-s",
                state_dirs_3[i].to_str().unwrap(),
                "-o",
                old_share,
            ],
            Some(&wallet_config_path),
        )?;

        let src = state_dirs_3[i].join(format!("message_{}.json", i));
        let dst = messages_dir_3.join(format!("message_{}.json", i));
        if src.exists() {
            fs::copy(&src, &dst)?;
        }
    }

    // Member 4 is new
    println!("Running init-state for new member 4...");
    run_cli(
        &["init-state", "-s", state_dirs_3[4].to_str().unwrap()],
        Some(&wallet_config_path),
    )?;

    // 4. process-all-and-propose
    println!("Running process-all-and-propose (rotation 2)...");
    run_cli(
        &[
            "process-all-and-propose",
            "-s",
            state_dirs_3[0].to_str().unwrap(),
            "-m",
            messages_dir_3.to_str().unwrap(),
        ],
        Some(&wallet_config_path),
    )?;

    // Test encrypt/decrypt with final committee
    println!("Testing encryption/decryption with 5-of-5 committee...");
    test_encrypt_decrypt(&state_dirs_3[0].join("dkg.yaml"), 5, 5, 2)?;

    println!("\n=== All 3 test scenarios completed successfully! ===");
    println!("All encryption/decryption tests passed!");
    Ok(())
}
