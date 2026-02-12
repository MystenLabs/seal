// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { fromHex } from "@mysten/bcs";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { getFullnodeUrl, SuiClient } from "@mysten/sui/client";
import { SealClient, SessionKey } from "@mysten/seal";
import assert from "assert";
import { parseArgs } from "node:util";

const PACKAGE_ID = "0x9e96366200f7811e52e741e395c200d280886913d40114d5c59b1e5ed8c3733a";

interface DecryptResult {
  callId: number;
  decryptTimeMs: number;
  success: boolean;
  error?: string;
}

// Helper function to generate random data
function generateRandomData(size: number): Uint8Array {
  const MAX_CHUNK_SIZE = 65536;
  const data = new Uint8Array(size);

  for (let offset = 0; offset < size; offset += MAX_CHUNK_SIZE) {
    const chunkSize = Math.min(MAX_CHUNK_SIZE, size - offset);
    crypto.getRandomValues(data.subarray(offset, offset + chunkSize));
  }

  return data;
}

async function runConcurrentDecryptTest(
  network: "testnet" | "mainnet",
  serverConfigs: Array<{
    objectId: string;
    aggregatorUrl?: string;
    apiKeyName?: string;
    apiKey?: string;
    weight: number;
  }>,
  threshold: number,
  concurrentCalls: number = 20,
): Promise<DecryptResult[]> {
  // Setup
  const keypair = Ed25519Keypair.generate();
  const suiAddress = keypair.getPublicKey().toSuiAddress();
  const suiClient = new SuiClient({ url: getFullnodeUrl(network) });

  console.log(`Test address: ${suiAddress}`);
  console.log(`Network: ${network}`);
  console.log(`Threshold: ${threshold}/${serverConfigs.length}`);
  console.log(`Concurrent calls: ${concurrentCalls}`);
  console.log("---\n");

  // Create client
  const client = new SealClient({
    suiClient,
    serverConfigs,
    verifyKeyServers: false,
  });

  // Generate 1KB test data
  console.log("Generating test data (1KB)...");
  const testData = generateRandomData(1024);
  console.log("Test data generated\n");

  // Encrypt once to get encrypted data to use for all decrypt calls
  console.log("Encrypting data...");
  const { encryptedObject: encryptedBytes } = await client.encrypt({
    threshold,
    packageId: PACKAGE_ID,
    id: suiAddress,
    data: testData,
  });
  console.log("Encryption complete\n");

  // Create session key for decryption
  console.log("Creating session key...");
  const sessionKey = await SessionKey.create({
    address: suiAddress,
    packageId: PACKAGE_ID,
    ttlMin: 10,
    signer: keypair,
    suiClient,
  });
  console.log("Session key created\n");

  // Construct transaction bytes for seal_approve
  const tx = new Transaction();
  const keyIdArg = tx.pure.vector("u8", fromHex(suiAddress));
  tx.moveCall({
    target: `${PACKAGE_ID}::account_based::seal_approve`,
    arguments: [keyIdArg],
  });
  const txBytes = await tx.build({
    client: suiClient,
    onlyTransactionKind: true,
  });

  // Perform concurrent decrypt calls
  console.log(`Starting ${concurrentCalls} concurrent decrypt calls...\n`);

  const decryptPromises = Array.from({ length: concurrentCalls }, (_, i) =>
    (async (): Promise<DecryptResult> => {
      const callId = i + 1;
      try {
        const decryptStart = performance.now();
        const decryptedData = await client.decrypt({
          data: encryptedBytes,
          sessionKey,
          txBytes,
        });
        const decryptEnd = performance.now();
        const decryptTimeMs = decryptEnd - decryptStart;

        // Verify data integrity
        assert.deepEqual(decryptedData, testData);

        console.log(`Call ${callId}: ${decryptTimeMs.toFixed(2)}ms ✅`);

        return {
          callId,
          decryptTimeMs,
          success: true,
        };
      } catch (error) {
        console.error(`Call ${callId}: FAILED ❌`, error);
        return {
          callId,
          decryptTimeMs: 0,
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    })(),
  );

  const results = await Promise.all(decryptPromises);

  return results;
}

function printResults(results: DecryptResult[]) {
  console.log("\n");
  console.log("=".repeat(80));
  console.log("CONCURRENT DECRYPT TEST RESULTS");
  console.log("=".repeat(80));
  console.log();

  const successfulResults = results.filter((r) => r.success);
  const failedResults = results.filter((r) => !r.success);

  if (successfulResults.length > 0) {
    console.log("Successful Decrypts:");
    console.log("Call ID  Decrypt Time");
    console.log("-".repeat(40));

    for (const result of successfulResults) {
      console.log(
        `${result.callId.toString().padStart(7)}  ${result.decryptTimeMs.toFixed(2).padStart(12)}ms`,
      );
    }

    // Calculate statistics
    const times = successfulResults.map((r) => r.decryptTimeMs);
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const min = Math.min(...times);
    const max = Math.max(...times);
    const median = times.sort((a, b) => a - b)[Math.floor(times.length / 2)];

    console.log("\nStatistics:");
    console.log(`  Total calls:     ${results.length}`);
    console.log(`  Successful:      ${successfulResults.length}`);
    console.log(`  Failed:          ${failedResults.length}`);
    console.log(`  Average time:    ${avg.toFixed(2)}ms`);
    console.log(`  Median time:     ${median.toFixed(2)}ms`);
    console.log(`  Min time:        ${min.toFixed(2)}ms`);
    console.log(`  Max time:        ${max.toFixed(2)}ms`);
    console.log(`  Range:           ${(max - min).toFixed(2)}ms`);
  }

  if (failedResults.length > 0) {
    console.log("\nFailed Decrypts:");
    for (const result of failedResults) {
      console.log(`  Call ${result.callId}: ${result.error}`);
    }
  }
}

// Parse command line arguments
const args = process.argv.slice(2).filter((arg) => arg !== "--");

const { values } = parseArgs({
  args,
  options: {
    network: {
      type: "string",
      default: "testnet",
    },
    servers: {
      type: "string",
    },
    threshold: {
      type: "string",
    },
    concurrent: {
      type: "string",
      default: "20",
    },
  },
});

const network = values.network as "testnet" | "mainnet";
if (network !== "testnet" && network !== "mainnet") {
  console.error('Error: network must be either "testnet" or "mainnet"');
  process.exit(1);
}

// Parse servers (JSON format)
if (!values.servers) {
  console.error("Error: --servers is required");
  console.error(
    'Example: --servers \'[{"objectId":"0x8a0e2e09a4c5255336d234b11014642b350634f07d07df6fc4c17bf07430c872","aggregatorUrl":"http://localhost:3000"}]\' --threshold 11',
  );
  process.exit(1);
}

type ServerConfig = {
  objectId: string;
  aggregatorUrl?: string;
  apiKeyName?: string;
  apiKey?: string;
  weight?: number;
};

let serverConfigs: ServerConfig[];

try {
  serverConfigs = JSON.parse(values.servers);
  if (!Array.isArray(serverConfigs) || serverConfigs.length === 0) {
    console.error("Error: servers must be a non-empty JSON array");
    process.exit(1);
  }
  for (const config of serverConfigs) {
    if (!config.objectId) {
      console.error("Error: each server must have an objectId");
      process.exit(1);
    }
  }
} catch (error) {
  console.error("Error: failed to parse servers JSON:", error);
  process.exit(1);
}

// Build server configs with weights
const serverConfigsWithWeights = serverConfigs.map((config) => ({
  ...config,
  weight: config.weight ?? 1,
}));

// Parse threshold (default to number of servers)
let threshold: number;
if (values.threshold) {
  threshold = parseInt(values.threshold, 10);
  if (isNaN(threshold) || threshold <= 0) {
    console.error("Invalid threshold.");
    process.exit(1);
  }
  if (threshold > serverConfigsWithWeights.length) {
    console.error(
      `Error: threshold (${threshold}) cannot exceed number of servers (${serverConfigsWithWeights.length})`,
    );
    process.exit(1);
  }
} else {
  threshold = serverConfigsWithWeights.length;
  console.log(`Using default threshold: ${threshold} (number of servers)`);
}

// Parse concurrent calls
const concurrentCalls = parseInt(values.concurrent!, 10);
if (isNaN(concurrentCalls) || concurrentCalls <= 0) {
  console.error("Invalid concurrent calls value.");
  process.exit(1);
}

runConcurrentDecryptTest(network, serverConfigsWithWeights, threshold, concurrentCalls)
  .then((results) => {
    printResults(results);
    const failedCount = results.filter((r) => !r.success).length;
    if (failedCount === 0) {
      console.log("\n✅ All concurrent decrypt calls completed successfully!");
      process.exit(0);
    } else {
      console.log(`\n⚠️  ${failedCount} out of ${results.length} calls failed.`);
      process.exit(1);
    }
  })
  .catch((error) => {
    console.error("Test failed:", error);
    process.exit(1);
  });
