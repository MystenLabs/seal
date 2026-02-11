// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { fromHex } from "@mysten/bcs";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { getFullnodeUrl, SuiClient } from "@mysten/sui/client";
import { SealClient, SessionKey } from "@mysten/seal";
import assert from "assert";
import { parseArgs } from "node:util";

// Package IDs for different data sizes
const PACKAGE_IDS = {
  "1kb": "0x9e96366200f7811e52e741e395c200d280886913d40114d5c59b1e5ed8c3733a",
  "1mb": "0x31fc37bfd6c585a5a23bdecfadf4d51443ff41415dcaf9955ae6a1096acc8768",
  "10mb": "0xe57b5db1b69f9e01de7c23209583c1c8c74b7a53d5144fa3a92a068a6e2fc922",
  "100mb": "0xacd083a6ab624b73d87052bd1b91cdfe2327485890fa977437653a8bace50358",
};

type DataSize = keyof typeof PACKAGE_IDS;

interface TestResult {
  size: DataSize;
  packageId: string;
  encryptTimeMs: number;
  decryptTimeMs: number;
  encryptMin: number;
  encryptMax: number;
  decryptMin: number;
  decryptMax: number;
  runs: number;
}

// Helper function to generate random data larger than crypto.getRandomValues limit (65536 bytes)
function generateRandomData(size: number): Uint8Array {
  const MAX_CHUNK_SIZE = 65536;
  const data = new Uint8Array(size);

  for (let offset = 0; offset < size; offset += MAX_CHUNK_SIZE) {
    const chunkSize = Math.min(MAX_CHUNK_SIZE, size - offset);
    crypto.getRandomValues(data.subarray(offset, offset + chunkSize));
  }

  return data;
}

async function runLoadTest(
  network: "testnet" | "mainnet",
  serverConfigs: Array<{
    objectId: string;
    aggregatorUrl?: string;
    apiKeyName?: string;
    apiKey?: string;
    weight: number;
  }>,
  threshold: number,
  iterations: number = 3,
): Promise<TestResult[]> {
  const results: TestResult[] = [];

  // Generate test data for each size (before any SDK timing)
  console.log("Generating test data...");
  const dataGenStart = performance.now();
  const dataSizes: Record<DataSize, Uint8Array> = {
    "1kb": generateRandomData(1024),
    "1mb": generateRandomData(1024 * 1024),
    "10mb": generateRandomData(10 * 1024 * 1024),
    "100mb": generateRandomData(100 * 1024 * 1024),
  };
  const dataGenEnd = performance.now();
  console.log(
    `Test data generated in ${(dataGenEnd - dataGenStart).toFixed(2)}ms (not included in SDK timing)\n`,
  );

  // Setup
  const keypair = Ed25519Keypair.generate();
  const suiAddress = keypair.getPublicKey().toSuiAddress();
  const suiClient = new SuiClient({ url: getFullnodeUrl(network) });

  console.log(`Test address: ${suiAddress}`);
  console.log(`Network: ${network}`);
  console.log(`Threshold: ${threshold}/${serverConfigs.length}`);
  console.log("---");

  // Create client
  const client = new SealClient({
    suiClient,
    serverConfigs,
    verifyKeyServers: false,
  });

  // Warm-up run to establish connections and eliminate cold start overhead
  console.log("\nPerforming warm-up run...");
  const warmupData = generateRandomData(1024);
  try {
    await client.encrypt({
      threshold,
      packageId: PACKAGE_IDS["1kb"],
      id: suiAddress,
      data: warmupData,
    });
    console.log("Warm-up complete\n");
  } catch (error) {
    console.log("Warm-up failed (continuing anyway):", error);
  }

  // Test each data size with its corresponding package ID - run multiple iterations
  const sizes = Object.keys(PACKAGE_IDS) as DataSize[];

  for (const size of sizes) {
    const packageId = PACKAGE_IDS[size];
    const testData = dataSizes[size];

    console.log(
      `\nTesting ${size} (${testData.length.toLocaleString()} bytes) - ${iterations} iterations`,
    );

    const encryptTimes: number[] = [];
    const decryptTimes: number[] = [];

    for (let i = 0; i < iterations; i++) {
      console.log(`  Run ${i + 1}/${iterations}:`);

      // Encrypt
      const encryptStart = performance.now();
      const { encryptedObject: encryptedBytes } = await client.encrypt({
        threshold,
        packageId,
        id: suiAddress,
        data: testData,
      });
      const encryptEnd = performance.now();
      const encryptTimeMs = encryptEnd - encryptStart;
      encryptTimes.push(encryptTimeMs);
      console.log(`    Encrypt: ${encryptTimeMs.toFixed(2)}ms`);

      // Create session key for decryption
      const sessionKey = await SessionKey.create({
        address: suiAddress,
        packageId,
        ttlMin: 10,
        signer: keypair,
        suiClient,
      });

      // Construct transaction bytes for seal_approve
      const tx = new Transaction();
      const keyIdArg = tx.pure.vector("u8", fromHex(suiAddress));
      tx.moveCall({
        target: `${packageId}::account_based::seal_approve`,
        arguments: [keyIdArg],
      });
      const txBytes = await tx.build({
        client: suiClient,
        onlyTransactionKind: true,
      });

      // Decrypt
      const decryptStart = performance.now();
      const decryptedData = await client.decrypt({
        data: encryptedBytes,
        sessionKey,
        txBytes,
      });
      const decryptEnd = performance.now();
      const decryptTimeMs = decryptEnd - decryptStart;
      decryptTimes.push(decryptTimeMs);
      console.log(`    Decrypt: ${decryptTimeMs.toFixed(2)}ms`);

      // Verify data integrity
      assert.deepEqual(decryptedData, testData);
      console.log(`    ✅ Verified`);
    }

    // Calculate statistics
    const encryptAvg = encryptTimes.reduce((a, b) => a + b, 0) / iterations;
    const decryptAvg = decryptTimes.reduce((a, b) => a + b, 0) / iterations;

    console.log(`  Summary: Encrypt avg=${encryptAvg.toFixed(2)}ms, Decrypt avg=${decryptAvg.toFixed(2)}ms`);

    results.push({
      size,
      packageId,
      encryptTimeMs: encryptAvg,
      decryptTimeMs: decryptAvg,
      encryptMin: Math.min(...encryptTimes),
      encryptMax: Math.max(...encryptTimes),
      decryptMin: Math.min(...decryptTimes),
      decryptMax: Math.max(...decryptTimes),
      runs: iterations,
    });
  }

  return results;
}

function printResults(results: TestResult[]) {
  console.log("\n");
  console.log("=".repeat(120));
  console.log("LOAD TEST RESULTS");
  console.log("=".repeat(120));
  console.log();

  console.log(
    "Size     Encrypt (avg)  Encrypt (min-max)    Decrypt (avg)  Decrypt (min-max)    Runs",
  );
  console.log("-".repeat(120));

  for (const result of results) {
    const encryptRange = `${result.encryptMin.toFixed(2)}-${result.encryptMax.toFixed(2)}`;
    const decryptRange = `${result.decryptMin.toFixed(2)}-${result.decryptMax.toFixed(2)}`;
    console.log(
      `${result.size.padEnd(8)} ${result.encryptTimeMs.toFixed(2).padStart(12)}ms  ${encryptRange.padStart(16)}ms  ${result.decryptTimeMs.toFixed(2).padStart(12)}ms  ${decryptRange.padStart(16)}ms  ${result.runs.toString().padStart(5)}`,
    );
  }

  console.log("\nPackage IDs:");
  for (const result of results) {
    console.log(`  ${result.size.padEnd(8)} ${result.packageId}`);
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
    iterations: {
      type: "string",
      default: "3",
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

// Parse iterations (default to 3)
const iterations = parseInt(values.iterations!, 10);
if (isNaN(iterations) || iterations <= 0) {
  console.error("Invalid iterations.");
  process.exit(1);
}

runLoadTest(network, serverConfigsWithWeights, threshold, iterations)
  .then((results) => {
    printResults(results);
    console.log("\n✅ Load test completed successfully!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("Load test failed:", error);
    process.exit(1);
  });
