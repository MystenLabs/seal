// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { fromHex } from "@mysten/bcs";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { getFullnodeUrl, SuiClient } from "@mysten/sui/client";
import { SealClient, SessionKey } from "@mysten/seal";
import assert from "assert";
import { parseArgs } from "node:util";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Get SDK version from package.json
const __dirname = dirname(fileURLToPath(import.meta.url));
const packageJson = JSON.parse(
  readFileSync(join(__dirname, "package.json"), "utf-8"),
);
const sealSdkVersion = packageJson.dependencies["@mysten/seal"].replace(
  "^",
  "",
);

const PACKAGE_IDS = {
  testnet: "0x58dce5d91278bceb65d44666ffa225ab397fc3ae9d8398c8c779c5530bd978c2",
  mainnet: "0x7dea8cca3f9970e8c52813d7a0cfb6c8e481fd92e9186834e1e3b58db2068029",
};

async function testCorsHeaders(
  url: string,
  name: string,
  apiKeyName?: string,
  apiKey?: string,
) {
  console.log(`Testing CORS headers for ${name} (${url}) ${sealSdkVersion}`);

  const response = await fetch(`${url}/v1/service`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      "Request-Id": crypto.randomUUID(),
      "Client-Sdk-Type": "typescript",
      "Client-Sdk-Version": sealSdkVersion,
      ...(apiKeyName && apiKey ? { [apiKeyName]: apiKey } : {}),
    },
  });

  const keyServerVersion = response.headers.get("x-keyserver-version");
  const exposedHeaders = response.headers.get("access-control-expose-headers");
  if (
    !keyServerVersion ||
    !exposedHeaders ||
    (!exposedHeaders!.includes("x-keyserver-version") && exposedHeaders !== "*")
  ) {
    throw new Error(
      `Missing CORS headers for ${name}: keyServerVersion=${keyServerVersion}, exposedHeaders=${exposedHeaders}`,
    );
  }
  return keyServerVersion;
}

async function runSingleTest(
  client: SealClient,
  suiClient: SuiClient,
  network: "testnet" | "mainnet",
  threshold: number,
  verbose: boolean = true,
  sharedSessionKey?: SessionKey,
  sharedTxBytes?: Uint8Array,
  sharedAddress?: string,
) {
  // Setup - use shared address or generate new one
  const suiAddress = sharedAddress || Ed25519Keypair.generate().getPublicKey().toSuiAddress();
  const testData = crypto.getRandomValues(new Uint8Array(1000));
  const packageId = PACKAGE_IDS[network];

  // Encrypt data
  if (verbose) console.log(`Encrypting with threshold: ${threshold}`);
  const { encryptedObject: encryptedBytes } = await client.encrypt({
    threshold: threshold,
    packageId,
    id: suiAddress,
    data: testData,
  });

  // Use shared session key (required if using shared address)
  if (!sharedSessionKey) {
    throw new Error("Session key required for load testing");
  }

  // Use shared tx bytes (required if using shared address)
  if (!sharedTxBytes) {
    throw new Error("Transaction bytes required for load testing");
  }

  // Decrypt data
  if (verbose) console.log("Decrypting data...");
  const decryptedData = await client.decrypt({
    data: encryptedBytes,
    sessionKey: sharedSessionKey,
    txBytes: sharedTxBytes,
  });

  assert.deepEqual(decryptedData, testData);
}

async function runTest(
  network: "testnet" | "mainnet",
  serverConfigs: Array<{
    objectId: string;
    aggregatorUrl?: string;
    apiKeyName?: string;
    apiKey?: string;
    weight: number;
  }>,
  options: {
    verifyKeyServers: boolean;
    threshold: number;
    corsTests?: Array<{
      url: string;
      name: string;
      apiKeyName?: string;
      apiKey?: string;
    }>;
  },
) {
  // Setup
  const keypair = Ed25519Keypair.generate();
  const suiAddress = keypair.getPublicKey().toSuiAddress();
  const suiClient = new SuiClient({ url: getFullnodeUrl(network) });
  const packageId = PACKAGE_IDS[network];
  console.log(`packageId: ${packageId}`);
  console.log(`test address: ${suiAddress}`);

  // Create client
  const client = new SealClient({
    suiClient,
    serverConfigs,
    verifyKeyServers: options.verifyKeyServers,
  });

  // Test CORS headers
  if (options.corsTests) {
    for (const { url, name, apiKeyName, apiKey } of options.corsTests) {
      await testCorsHeaders(url, name, apiKeyName, apiKey);
    }
  }
  const keyServers = await client.getKeyServers();
  for (const config of serverConfigs.filter((c) => !c.aggregatorUrl)) {
    const keyServer = keyServers.get(config.objectId)!;
    await testCorsHeaders(
      keyServer.url,
      keyServer.name,
      config.apiKeyName,
      config.apiKey,
    );
  }
  console.log("✅ All servers have proper CORS configuration");

  // For single test, create session key and tx bytes using the existing keypair
  const sessionKey = await SessionKey.create({
    address: suiAddress,
    packageId,
    ttlMin: 10,
    signer: keypair,
    suiClient,
  });

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

  await runSingleTest(client, suiClient, network, options.threshold, true, sessionKey, txBytes, suiAddress);
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
  options: {
    verifyKeyServers: boolean;
    threshold: number;
    concurrent: number;
    duration: number;
    corsTests?: Array<{
      url: string;
      name: string;
      apiKeyName?: string;
      apiKey?: string;
    }>;
  },
) {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`LOAD TEST: ${options.concurrent} concurrent requests for ${options.duration} seconds`);
  console.log(`${"=".repeat(60)}`);

  // Setup shared client (reuse to avoid RPC rate limits)
  const suiClient = new SuiClient({ url: getFullnodeUrl(network) });
  const packageId = PACKAGE_IDS[network];
  console.log(`packageId: ${packageId}`);

  const client = new SealClient({
    suiClient,
    serverConfigs,
    verifyKeyServers: options.verifyKeyServers,
  });

  // Test CORS headers once
  if (options.corsTests) {
    for (const { url, name, apiKeyName, apiKey } of options.corsTests) {
      await testCorsHeaders(url, name, apiKeyName, apiKey);
    }
  }
  const keyServers = await client.getKeyServers();
  for (const config of serverConfigs.filter((c) => !c.aggregatorUrl)) {
    const keyServer = keyServers.get(config.objectId)!;
    await testCorsHeaders(
      keyServer.url,
      keyServer.name,
      config.apiKeyName,
      config.apiKey,
    );
  }
  console.log("✅ All servers have proper CORS configuration\n");

  // Pre-create shared session key and tx bytes (reuse same address for all requests)
  console.log("Creating shared session key and transaction bytes...");
  const sharedKeypair = Ed25519Keypair.generate();
  const sharedAddress = sharedKeypair.getPublicKey().toSuiAddress();

  const sharedSessionKey = await SessionKey.create({
    address: sharedAddress,
    packageId,
    ttlMin: 10,
    signer: sharedKeypair,
    suiClient,
  });

  const tx = new Transaction();
  const keyIdArg = tx.pure.vector("u8", fromHex(sharedAddress));
  tx.moveCall({
    target: `${packageId}::account_based::seal_approve`,
    arguments: [keyIdArg],
  });
  const sharedTxBytes = await tx.build({
    client: suiClient,
    onlyTransactionKind: true,
  });

  console.log("✅ Shared resources created (all requests will use same address)\n");

  const startTime = Date.now();
  const endTime = startTime + options.duration * 1000;

  type Result = {
    latency: number;
    success: boolean;
    error?: string;
    statusCode?: number;
    requestId?: string;
  };
  const results: Result[] = [];
  let activeRequests = 0;

  // Worker function
  const worker = async () => {
    while (Date.now() < endTime) {
      const reqStart = Date.now();
      try {
        await runSingleTest(
          client,
          suiClient,
          network,
          options.threshold,
          false,
          sharedSessionKey,
          sharedTxBytes,
          sharedAddress
        );
        const latency = Date.now() - reqStart;
        results.push({ latency, success: true });
      } catch (error: any) {
        const latency = Date.now() - reqStart;
        results.push({
          latency,
          success: false,
          error: error?.message || (error ? String(error) : "Unknown error"),
          statusCode: error?.status,
          requestId: error?.requestId,
        });
      }
    }
  };

  // Start concurrent workers
  console.log(`Starting ${options.concurrent} concurrent workers...`);
  console.log(`Start time: ${new Date().toISOString()}\n`);

  const workers = Array(options.concurrent).fill(0).map(() => worker());
  await Promise.all(workers);

  console.log(`\nEnd time: ${new Date().toISOString()}`);
  console.log(`\n${"=".repeat(60)}`);
  console.log("📊 PERFORMANCE METRICS");
  console.log(`${"=".repeat(60)}\n`);

  // Calculate metrics
  const total = results.length;
  const successful = results.filter((r) => r.success);
  const failed = results.filter((r) => !r.success);

  console.log(`Total requests: ${total}`);
  console.log(`Successful: ${successful.length} (${((successful.length / total) * 100).toFixed(1)}%)`);
  console.log(`Failed: ${failed.length} (${((failed.length / total) * 100).toFixed(1)}%)`);
  console.log();

  if (successful.length > 0) {
    const latencies = successful.map((r) => r.latency).sort((a, b) => a - b);
    const avg = latencies.reduce((a, b) => a + b, 0) / latencies.length;
    const p50 = latencies[Math.floor(latencies.length * 0.50)];
    const p95 = latencies[Math.floor(latencies.length * 0.95)];
    const p99 = latencies[Math.floor(latencies.length * 0.99)];

    console.log("Latency (milliseconds):");
    console.log(`  Min:    ${latencies[0]}ms`);
    console.log(`  Avg:    ${Math.round(avg)}ms`);
    console.log(`  p50:    ${p50}ms`);
    console.log(`  p95:    ${p95}ms`);
    console.log(`  p99:    ${p99}ms`);
    console.log(`  Max:    ${latencies[latencies.length - 1]}ms`);
    console.log();

    const rps = successful.length / options.duration;
    console.log(`Throughput: ${rps.toFixed(2)} requests/second`);
  }

  // Show sample errors with details
  if (failed.length > 0) {
    console.log();
    console.log(`Sample errors (showing first 5):`);
    console.log(`${"-".repeat(60)}`);
    for (let i = 0; i < Math.min(5, failed.length); i++) {
      const err = failed[i];
      console.log(`\nError ${i + 1}:`);
      console.log(`  Latency: ${err.latency}ms`);
      console.log(`  Status Code: ${err.statusCode || "undefined"}`);
      console.log(`  Request ID: ${err.requestId || "N/A"}`);
      console.log(`  Message: ${err.error || "Unknown error"}`);
    }

    // Show error distribution
    console.log();
    console.log("Error distribution:");
    const errorCounts = failed.reduce((acc, r) => {
      const key = `${r.statusCode || "undefined"}: ${r.error}`;
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    Object.entries(errorCounts)
      .sort((a, b) => b[1] - a[1])
      .forEach(([error, count]) => {
        console.log(`  ${count}x - ${error}`);
      });
  }

  console.log(`\n${"=".repeat(60)}\n`);
}

// Parse command line arguments
// Filter out standalone '--' separator that npm/pnpm adds
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
    loadTest: {
      type: "boolean",
      default: false,
    },
    concurrent: {
      type: "string",
      default: "20",
    },
    duration: {
      type: "string",
      default: "60",
    },
  },
});

const network = values.network as "testnet" | "mainnet";
if (network !== "testnet" && network !== "mainnet") {
  console.error('Error: network must be either "testnet" or "mainnet"');
  process.exit(1);
}

// Parse servers (JSON format or legacy colon-delimited format)
if (!values.servers) {
  console.error("Error: --servers is required");
  console.error(
    'Example (JSON): --servers \'[{"objectId":"0x123","aggregatorUrl":"http://localhost:3000"}]\' --threshold 1',
  );
  console.error(
    'Example (legacy with API keys): --servers "0x123abc:myKey:mySecret,0x456def:otherKey:otherSecret"',
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

// Try JSON format first
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
  // Legacy colon-delimited format (backwards compatibility)
  // Format: "objectId1,objectId2" or "objectId1:apiKeyName:apiKey,objectId2:apiKeyName:apiKey"
  const serverStrings = values.servers.split(",");
  serverConfigs = serverStrings.map((serverStr) => {
    const parts = serverStr.trim().split(":");
    if (parts.length === 1) {
      // Just object ID
      return { objectId: parts[0] };
    } else if (parts.length === 3) {
      // Object ID with API key
      return {
        objectId: parts[0],
        apiKeyName: parts[1],
        apiKey: parts[2],
      };
    } else {
      console.error(
        `Error: Invalid server format "${serverStr}". Expected "objectId" or "objectId:apiKeyName:apiKey"`,
      );
      process.exit(1);
    }
  });

  if (serverConfigs.length === 0) {
    console.error("Error: No servers provided");
    process.exit(1);
  }
}

// Parse threshold
let threshold: number;
if (values.threshold) {
  threshold = parseInt(values.threshold, 10);
  if (isNaN(threshold) || threshold <= 0) {
    console.error("Invalid threshold.");
    process.exit(1);
  }
} else {
  // Default threshold is all servers
  threshold = serverConfigs.length;
}

// Parse load test parameters
const loadTest = values.loadTest || false;
const concurrent = parseInt(values.concurrent || "20", 10);
const duration = parseInt(values.duration || "60", 10);

if (loadTest && (isNaN(concurrent) || concurrent <= 0)) {
  console.error("Invalid --concurrent value");
  process.exit(1);
}
if (loadTest && (isNaN(duration) || duration <= 0)) {
  console.error("Invalid --duration value");
  process.exit(1);
}

console.log(`Running ${loadTest ? "LOAD TEST" : "test"} on ${network}`);
console.log("Servers:", serverConfigs);
console.log(`Threshold: ${threshold}/${serverConfigs.length}`);
if (loadTest) {
  console.log(`Concurrent: ${concurrent}`);
  console.log(`Duration: ${duration}s`);
}

// Build server configs with weights (all weight 1)
const serverConfigsWithWeights = serverConfigs.map((config) => ({
  ...config,
  weight: 1,
}));

// Collect CORS test URLs (for committee servers with aggregatorUrl)
const corsTests = serverConfigs
  .filter((config) => config.aggregatorUrl)
  .map((config) => ({
    url: config.aggregatorUrl!,
    name: `Aggregator (${config.objectId.slice(0, 10)}...)`,
    apiKeyName: config.apiKeyName,
    apiKey: config.apiKey,
  }));

// Run test or load test
const testPromise = loadTest
  ? runLoadTest(network, serverConfigsWithWeights, {
      verifyKeyServers: false,
      threshold,
      concurrent,
      duration,
      corsTests: corsTests.length > 0 ? corsTests : undefined,
    })
  : runTest(network, serverConfigsWithWeights, {
      verifyKeyServers: false,
      threshold,
      corsTests: corsTests.length > 0 ? corsTests : undefined,
    });

testPromise
  .then(() => {
    console.log("✅ Test passed!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("Test failed:", error);
    process.exit(1);
  });
