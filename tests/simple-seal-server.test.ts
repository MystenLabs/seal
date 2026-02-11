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
  const testData = crypto.getRandomValues(new Uint8Array(1000));
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

  // Encrypt data
  console.log(`Encrypting with threshold: ${options.threshold}`);
  const { encryptedObject: encryptedBytes } = await client.encrypt({
    threshold: options.threshold,
    packageId,
    id: suiAddress,
    data: testData,
  });

  // Create session key
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

  // Decrypt data
  console.log("Decrypting data...");
  const decryptedData = await client.decrypt({
    data: encryptedBytes,
    sessionKey,
    txBytes,
  });

  assert.deepEqual(decryptedData, testData);
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

console.log(`Running test on ${network}`);
console.log("Servers:", serverConfigs);
console.log(`Threshold: ${threshold}/${serverConfigs.length}`);

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

runTest(network, serverConfigsWithWeights, {
  verifyKeyServers: false,
  threshold,
  corsTests: corsTests.length > 0 ? corsTests : undefined,
})
  .then(() => {
    console.log("✅ Test passed!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("Test failed:", error);
    process.exit(1);
  });
