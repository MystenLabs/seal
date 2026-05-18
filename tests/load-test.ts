// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { fromHex } from "@mysten/bcs";
import { SealClient, SessionKey } from "@mysten/seal";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { deepStrictEqual } from "node:assert";
import { performance } from "node:perf_hooks";
import { parseArgs } from "node:util";

const PACKAGE_IDS = {
  testnet: "0x58dce5d91278bceb65d44666ffa225ab397fc3ae9d8398c8c779c5530bd978c2",
  mainnet: "0x7dea8cca3f9970e8c52813d7a0cfb6c8e481fd92e9186834e1e3b58db2068029",
};

type Network = keyof typeof PACKAGE_IDS;

type ServerConfig = {
  objectId: string;
  aggregatorUrl?: string;
  apiKeyName?: string;
  apiKey?: string;
  weight?: number;
};

type WeightedServerConfig = ServerConfig & {
  weight: number;
};

type Stats = {
  started: number;
  succeeded: number;
  failed: number;
  latenciesMs: number[];
  decryptLatenciesMs: number[];
  intervalSucceeded: number;
  intervalFailed: number;
  intervalLatenciesMs: number[];
  intervalDecryptLatenciesMs: number[];
  errors: Map<string, number>;
};

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
    concurrency: {
      type: "string",
      default: "100",
    },
    "rate-per-second": {
      type: "string",
    },
    "duration-seconds": {
      type: "string",
      default: "300",
    },
    "report-seconds": {
      type: "string",
      default: "10",
    },
    "data-bytes": {
      type: "string",
      default: "1000",
    },
    timeout: {
      type: "string",
      default: "10000",
    },
  },
});

function parsePositiveInteger(value: string | undefined, name: string): number {
  const parsed = Number.parseInt(value ?? "", 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`--${name} must be a positive integer`);
  }
  return parsed;
}

function parseNetwork(value: string | undefined): Network {
  if (value === "testnet" || value === "mainnet") {
    return value;
  }
  throw new Error('--network must be either "testnet" or "mainnet"');
}

function parseServers(value: string | undefined): ServerConfig[] {
  if (!value) {
    throw new Error("--servers is required");
  }

  const parsed = JSON.parse(value);
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error("--servers must be a non-empty JSON array");
  }

  for (const config of parsed) {
    if (!config.objectId) {
      throw new Error("each server must have an objectId");
    }
  }

  return parsed;
}

function percentile(values: number[], pct: number): number {
  if (values.length === 0) {
    return 0;
  }

  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(
    sorted.length - 1,
    Math.ceil((pct / 100) * sorted.length) - 1,
  );
  return sorted[index];
}

function average(values: number[]): number {
  if (values.length === 0) {
    return 0;
  }
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function formatMs(value: number): string {
  return `${value.toFixed(0)}ms`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function recordError(stats: Stats, error: unknown) {
  const message =
    error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  const trimmed = message.replace(/\s+/g, " ").slice(0, 240);
  stats.errors.set(trimmed, (stats.errors.get(trimmed) ?? 0) + 1);
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let offset = 0; offset < bytes.length; offset += 65536) {
    crypto.getRandomValues(bytes.subarray(offset, offset + 65536));
  }
  return bytes;
}

function printStats(
  label: string,
  stats: Stats,
  totalElapsedSeconds: number,
  rateWindowSeconds: number,
  useIntervalStats: boolean,
) {
  const succeeded = useIntervalStats
    ? stats.intervalSucceeded
    : stats.succeeded;
  const failed = useIntervalStats ? stats.intervalFailed : stats.failed;
  const latencies = useIntervalStats
    ? stats.intervalLatenciesMs
    : stats.latenciesMs;
  const decryptLatencies = useIntervalStats
    ? stats.intervalDecryptLatenciesMs
    : stats.decryptLatenciesMs;
  const completed = succeeded + failed;
  const inFlight = stats.started - stats.succeeded - stats.failed;
  const rps = completed / Math.max(rateWindowSeconds, 1);

  console.log(
    [
      label,
      `elapsed=${totalElapsedSeconds.toFixed(1)}s`,
      `started=${stats.started}`,
      `ok=${succeeded}`,
      `failed=${failed}`,
      `inFlight=${inFlight}`,
      `rps=${rps.toFixed(2)}`,
      `avg=${formatMs(average(latencies))}`,
      `p50=${formatMs(percentile(latencies, 50))}`,
      `p95=${formatMs(percentile(latencies, 95))}`,
      `p99=${formatMs(percentile(latencies, 99))}`,
      `decryptAvg=${formatMs(average(decryptLatencies))}`,
      `decryptP95=${formatMs(percentile(decryptLatencies, 95))}`,
    ].join(" "),
  );

  if (useIntervalStats) {
    stats.intervalSucceeded = 0;
    stats.intervalFailed = 0;
    stats.intervalLatenciesMs = [];
    stats.intervalDecryptLatenciesMs = [];
  }
}

async function runOperation({
  client,
  dataBytes,
  network,
  packageId,
  suiClient,
  threshold,
}: {
  client: SealClient;
  dataBytes: number;
  network: Network;
  packageId: string;
  suiClient: SuiJsonRpcClient;
  threshold: number;
}): Promise<{ decryptLatencyMs: number }> {
  const keypair = Ed25519Keypair.generate();
  const suiAddress = keypair.getPublicKey().toSuiAddress();
  const testData = randomBytes(dataBytes);

  const { encryptedObject } = await client.encrypt({
    threshold,
    packageId,
    id: suiAddress,
    data: testData,
  });

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
    target: `${PACKAGE_IDS[network]}::account_based::seal_approve`,
    arguments: [keyIdArg],
  });
  const txBytes = await tx.build({
    client: suiClient,
    onlyTransactionKind: true,
  });

  const decryptStartedAt = performance.now();
  const decryptedData = await client.decrypt({
    data: encryptedObject,
    sessionKey,
    txBytes,
  });
  const decryptLatencyMs = performance.now() - decryptStartedAt;

  deepStrictEqual(decryptedData, testData);

  return { decryptLatencyMs };
}

async function runAndRecordOperation({
  client,
  dataBytes,
  network,
  packageId,
  stats,
  suiClient,
  threshold,
}: {
  client: SealClient;
  dataBytes: number;
  network: Network;
  packageId: string;
  stats: Stats;
  suiClient: SuiJsonRpcClient;
  threshold: number;
}) {
  stats.started += 1;
  const startedAt = performance.now();

  try {
    const { decryptLatencyMs } = await runOperation({
      client,
      dataBytes,
      network,
      packageId,
      suiClient,
      threshold,
    });
    const latencyMs = performance.now() - startedAt;
    stats.succeeded += 1;
    stats.intervalSucceeded += 1;
    stats.latenciesMs.push(latencyMs);
    stats.intervalLatenciesMs.push(latencyMs);
    stats.decryptLatenciesMs.push(decryptLatencyMs);
    stats.intervalDecryptLatenciesMs.push(decryptLatencyMs);
  } catch (error) {
    stats.failed += 1;
    stats.intervalFailed += 1;
    recordError(stats, error);
  }
}

async function worker({
  client,
  dataBytes,
  deadlineMs,
  network,
  packageId,
  stats,
  suiClient,
  threshold,
}: {
  client: SealClient;
  dataBytes: number;
  deadlineMs: number;
  network: Network;
  packageId: string;
  stats: Stats;
  suiClient: SuiJsonRpcClient;
  threshold: number;
}) {
  while (Date.now() < deadlineMs) {
    await runAndRecordOperation({
      client,
      dataBytes,
      network,
      packageId,
      stats,
      suiClient,
      threshold,
    });
  }
}

async function runFixedRate({
  client,
  dataBytes,
  durationSeconds,
  network,
  packageId,
  ratePerSecond,
  stats,
  suiClient,
  threshold,
}: {
  client: SealClient;
  dataBytes: number;
  durationSeconds: number;
  network: Network;
  packageId: string;
  ratePerSecond: number;
  stats: Stats;
  suiClient: SuiJsonRpcClient;
  threshold: number;
}) {
  const totalRequests = ratePerSecond * durationSeconds;
  const intervalMs = 1000 / ratePerSecond;
  const scheduledStartedAt = performance.now();
  let nextStartAt = scheduledStartedAt;
  const operations: Promise<void>[] = [];

  for (let i = 0; i < totalRequests; i++) {
    const delayMs = nextStartAt - performance.now();
    if (delayMs > 0) {
      await sleep(delayMs);
    }

    operations.push(
      runAndRecordOperation({
        client,
        dataBytes,
        network,
        packageId,
        stats,
        suiClient,
        threshold,
      }),
    );
    nextStartAt += intervalMs;
  }

  await Promise.all(operations);
}

async function main() {
  const network = parseNetwork(values.network);
  const serverConfigs = parseServers(values.servers).map(
    (config): WeightedServerConfig => ({
      ...config,
      weight: config.weight ?? 1,
    }),
  );
  const threshold = values.threshold
    ? parsePositiveInteger(values.threshold, "threshold")
    : serverConfigs.length;
  const concurrency = parsePositiveInteger(values.concurrency, "concurrency");
  const ratePerSecond = values["rate-per-second"]
    ? parsePositiveInteger(values["rate-per-second"], "rate-per-second")
    : undefined;
  const durationSeconds = parsePositiveInteger(
    values["duration-seconds"],
    "duration-seconds",
  );
  const reportSeconds = parsePositiveInteger(
    values["report-seconds"],
    "report-seconds",
  );
  const dataBytes = parsePositiveInteger(values["data-bytes"], "data-bytes");
  const timeout = parsePositiveInteger(values.timeout, "timeout");

  const packageId = PACKAGE_IDS[network];
  const suiClient = new SuiJsonRpcClient({
    url: getJsonRpcFullnodeUrl(network),
    network,
  });
  const client = new SealClient({
    suiClient,
    serverConfigs,
    verifyKeyServers: false,
    timeout,
  });

  console.log(`Running load test on ${network}`);
  console.log("Servers:", serverConfigs);
  console.log(`Threshold: ${threshold}/${serverConfigs.length}`);
  if (ratePerSecond) {
    console.log(
      `Mode: fixed-rate, rate: ${ratePerSecond}/s, duration: ${durationSeconds}s, data: ${dataBytes} bytes, timeout: ${timeout}ms`,
    );
  } else {
    console.log(
      `Mode: concurrency, concurrency: ${concurrency}, duration: ${durationSeconds}s, data: ${dataBytes} bytes, timeout: ${timeout}ms`,
    );
  }

  await client.getKeyServers();

  const stats: Stats = {
    started: 0,
    succeeded: 0,
    failed: 0,
    latenciesMs: [],
    decryptLatenciesMs: [],
    intervalSucceeded: 0,
    intervalFailed: 0,
    intervalLatenciesMs: [],
    intervalDecryptLatenciesMs: [],
    errors: new Map(),
  };
  const startedAt = performance.now();
  let lastReportAt = startedAt;
  const deadlineMs = Date.now() + durationSeconds * 1000;
  const reporter = setInterval(() => {
    const now = performance.now();
    printStats(
      "[interval]",
      stats,
      (now - startedAt) / 1000,
      (now - lastReportAt) / 1000,
      true,
    );
    lastReportAt = now;
  }, reportSeconds * 1000);

  if (ratePerSecond) {
    await runFixedRate({
      client,
      dataBytes,
      durationSeconds,
      network,
      packageId,
      ratePerSecond,
      stats,
      suiClient,
      threshold,
    });
  } else {
    await Promise.all(
      Array.from({ length: concurrency }, () =>
        worker({
          client,
          dataBytes,
          deadlineMs,
          network,
          packageId,
          stats,
          suiClient,
          threshold,
        }),
      ),
    );
  }

  clearInterval(reporter);
  const totalElapsedSeconds = (performance.now() - startedAt) / 1000;
  printStats("[final]", stats, totalElapsedSeconds, totalElapsedSeconds, false);

  if (stats.errors.size > 0) {
    console.log("Errors:");
    for (const [message, count] of [...stats.errors.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)) {
      console.log(`${count}x ${message}`);
    }
  }

  if (stats.failed > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error("Load test failed:", error);
  process.exit(1);
});
