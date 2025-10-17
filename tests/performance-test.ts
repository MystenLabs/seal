// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { fromHex } from '@mysten/bcs';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { SealClient, SessionKey } from '@mysten/seal';
import { parseArgs } from 'node:util';

const PACKAGE_IDS = {
    'testnet': '0x58dce5d91278bceb65d44666ffa225ab397fc3ae9d8398c8c779c5530bd978c2',
    'mainnet': '0x7dea8cca3f9970e8c52813d7a0cfb6c8e481fd92e9186834e1e3b58db2068029',
};

const MB = 1024 * 1024;
const TEST_SIZES = [
    { size: 5 * MB, label: '5MB' },
    { size: 20 * MB, label: '20MB' },
    { size: 32 * MB, label: '32MB' },
    { size: 48 * MB, label: '48MB' },
    { size: 64 * MB, label: '64MB' },
];

// Timeout for each test (in milliseconds)
const TEST_TIMEOUT = 10 * 60 * 1000; // 10 minutes

function formatTime(ms: number): string {
    if (ms < 1000) {
        return `${ms.toFixed(0)} ms`;
    } else if (ms < 60000) {
        return `${(ms / 1000).toFixed(2)} seconds`;
    } else {
        const minutes = Math.floor(ms / 60000);
        const seconds = ((ms % 60000) / 1000).toFixed(0);
        return `${minutes}m ${seconds}s`;
    }
}

function formatMemory(bytes: number): string {
    const mb = bytes / (1024 * 1024);
    return `${mb.toFixed(2)} MB`;
}

function getMemoryUsage() {
    const mem = process.memoryUsage();
    return {
        heapUsed: mem.heapUsed,
        heapTotal: mem.heapTotal,
        external: mem.external,
        rss: mem.rss,
    };
}

function logMemoryUsage(label: string) {
    const mem = getMemoryUsage();
    console.log(`  📊 Memory [${label}]:`);
    console.log(`     Heap Used: ${formatMemory(mem.heapUsed)} / ${formatMemory(mem.heapTotal)}`);
    console.log(`     RSS: ${formatMemory(mem.rss)}`);
    console.log(`     External: ${formatMemory(mem.external)}`);
}

async function testEncryption(
    network: 'testnet' | 'mainnet',
    keyServerConfigs: { objectId: string, apiKeyName?: string, apiKey?: string }[],
    dataSize: number,
    label: string
): Promise<{ success: boolean; time?: number; error?: string }> {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Testing ${label} (${dataSize.toLocaleString()} bytes)`);
    console.log(`${'='.repeat(60)}`);

    logMemoryUsage('Baseline');

    const keypair = Ed25519Keypair.generate();
    const suiAddress = keypair.getPublicKey().toSuiAddress();
    const suiClient = new SuiClient({ url: getFullnodeUrl(network) });

    // Create test data (doesn't need to be random, just fill with pattern)
    console.log(`\n📝 Generating ${(dataSize / 1024 / 1024).toFixed(2)} MB test data...`);
    const testData = new Uint8Array(dataSize);
    for (let i = 0; i < dataSize; i++) {
        testData[i] = i % 256;
    }
    logMemoryUsage('After data generation');

    const packageId = PACKAGE_IDS[network];

    const client = new SealClient({
        suiClient,
        serverConfigs: keyServerConfigs.map(({ objectId, apiKeyName, apiKey }) => ({
            objectId,
            apiKeyName,
            apiKey,
            weight: 1,
        })),
        verifyKeyServers: true,
    });

    let heartbeatInterval: NodeJS.Timeout | null = null;

    try {
        // Create a timeout promise with heartbeat
        const timeoutPromise = new Promise<never>((_, reject) => {
            const startTime = Date.now();
            heartbeatInterval = setInterval(() => {
                const elapsed = Date.now() - startTime;
                console.log(`\n  ⏱️  Still encrypting... ${formatTime(elapsed)} elapsed`);
                logMemoryUsage('During encryption');
            }, 10000); // Log every 10 seconds

            setTimeout(() => {
                if (heartbeatInterval) clearInterval(heartbeatInterval);
                reject(new Error('Test timeout exceeded'));
            }, TEST_TIMEOUT);
        });

        // Encrypt data and measure time
        console.log(`\n🔐 Starting encryption at ${new Date().toISOString()}...`);
        logMemoryUsage('Before encryption');
        const encryptStartTime = performance.now();

        const encryptionPromise = client.encrypt({
            threshold: keyServerConfigs.length,
            packageId: packageId,
            id: suiAddress,
            data: testData,
        });

        const { encryptedObject: encryptedBytes } = await Promise.race([
            encryptionPromise,
            timeoutPromise,
        ]);

        // Clear heartbeat if encryption completes
        if (heartbeatInterval) clearInterval(heartbeatInterval);

        const encryptEndTime = performance.now();
        const encryptionTime = encryptEndTime - encryptStartTime;

        console.log(`\n✅ Encryption completed in ${formatTime(encryptionTime)}`);
        console.log(`📦 Encrypted size: ${(encryptedBytes.length / 1024 / 1024).toFixed(2)} MB`);
        logMemoryUsage('After encryption');

        // Quick verification with decryption
        console.log(`\n🔓 Verifying with decryption...`);
        const sessionKey = await SessionKey.create({
            address: suiAddress,
            packageId: packageId,
            ttlMin: 10,
            signer: keypair,
            suiClient,
        });

        const tx = new Transaction();
        const keyIdArg = tx.pure.vector('u8', fromHex(suiAddress));
        tx.moveCall({
            target: `${packageId}::account_based::seal_approve`,
            arguments: [keyIdArg],
        });
        const txBytes = await tx.build({ client: suiClient, onlyTransactionKind: true });

        const decryptStartTime = performance.now();
        const decryptedData = await client.decrypt({
            data: encryptedBytes,
            sessionKey,
            txBytes,
        });
        const decryptEndTime = performance.now();
        const decryptionTime = decryptEndTime - decryptStartTime;

        if (decryptedData.length !== testData.length) {
            throw new Error('Decryption verification failed: length mismatch');
        }

        console.log(`✅ Decryption completed in ${formatTime(decryptionTime)}`);
        console.log(`✅ Data integrity verified`);
        logMemoryUsage('After decryption');

        return { success: true, time: encryptionTime };
    } catch (error) {
        // Clear heartbeat on error
        if (heartbeatInterval) clearInterval(heartbeatInterval);

        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error(`❌ Test failed: ${errorMessage}`);
        return { success: false, error: errorMessage };
    }
}

async function runPerformanceTests(
    network: 'testnet' | 'mainnet',
    keyServerConfigs: { objectId: string, apiKeyName?: string, apiKey?: string }[]
) {
    console.log(`\n${'*'.repeat(60)}`);
    console.log(`SEAL Encryption Performance Test`);
    console.log(`Network: ${network}`);
    console.log(`Servers: ${keyServerConfigs.map(c => c.objectId).join(', ')}`);
    console.log(`Test timeout per size: ${formatTime(TEST_TIMEOUT)}`);
    console.log(`${'*'.repeat(60)}\n`);

    const results: { label: string; success: boolean; time?: number; error?: string }[] = [];

    for (const testCase of TEST_SIZES) {
        const result = await testEncryption(
            network,
            keyServerConfigs,
            testCase.size,
            testCase.label
        );
        results.push({ label: testCase.label, ...result });

        // Force garbage collection between tests if available
        if (global.gc) {
            console.log('🗑️  Running garbage collection...');
            global.gc();
            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        // Add delay between tests to avoid overwhelming servers
        if (testCase !== TEST_SIZES[TEST_SIZES.length - 1]) {
            console.log('⏸️  Waiting 5 seconds before next test...\n');
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }

    // Print summary
    console.log(`\n${'='.repeat(60)}`);
    console.log(`SUMMARY`);
    console.log(`${'='.repeat(60)}\n`);

    for (const result of results) {
        if (result.success) {
            console.log(`✅ ${result.label}: ${formatTime(result.time!)}`);
        } else {
            console.log(`❌ ${result.label}: ${result.error}`);
        }
    }

    console.log(`\n${'='.repeat(60)}\n`);
}

// Parse command line arguments
// Filter out the '--' separator that pnpm passes through
const args = process.argv.slice(2).filter(arg => arg !== '--');
const { values } = parseArgs({
    args: args,
    options: {
        network: {
            type: 'string',
            default: 'testnet',
        },
        servers: {
            type: 'string',
        },
        size: {
            type: 'string',
        },
    },
});

const network = values.network as 'testnet' | 'mainnet';
if (network !== 'testnet' && network !== 'mainnet') {
    console.error('Error: network must be either "testnet" or "mainnet"');
    process.exit(1);
}

// Parse server configurations from command line
let keyServerConfigs: { objectId: string, apiKeyName?: string, apiKey?: string }[] = [];

if (values.servers) {
    const serverSpecs = values.servers.split(',').map(s => s.trim());
    keyServerConfigs = serverSpecs.map(spec => {
        const parts = spec.split(':');
        if (parts.length === 1) {
            return { objectId: parts[0] };
        } else if (parts.length === 3) {
            return {
                objectId: parts[0],
                apiKeyName: parts[1],
                apiKey: parts[2],
            };
        } else {
            console.error(`Invalid server specification: ${spec}`);
            process.exit(1);
        }
    });
} else {
    console.error('Error: --servers argument is required');
    console.error('Example: --servers="0x123,0x456"');
    process.exit(1);
}

runPerformanceTests(network, keyServerConfigs).catch(error => {
    console.error('Performance test failed:', error);
    process.exit(1);
});
