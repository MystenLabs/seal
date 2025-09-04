// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { fromHex } from '@mysten/bcs';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { SealClient, SessionKey } from '@mysten/seal';
import assert from 'assert';
import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// Get SDK version from package.json
const __dirname = dirname(fileURLToPath(import.meta.url));
const packageJson = JSON.parse(readFileSync(join(__dirname, 'package.json'), 'utf-8'));
const sealSdkVersion = packageJson.dependencies['@mysten/seal'].replace('^', '');

const PACKAGE_IDS = {
    'testnet': '0x58dce5d91278bceb65d44666ffa225ab397fc3ae9d8398c8c779c5530bd978c2',
    'mainnet': '0x7dea8cca3f9970e8c52813d7a0cfb6c8e481fd92e9186834e1e3b58db2068029',
};

async function testCorsHeaders(url: string, name: string, apiKeyName?: string, apiKey?: string) {
    console.log(`Testing CORS headers for ${name} (${url}) ${sealSdkVersion}`);

    const response = await fetch(`${url}/v1/service`, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Request-Id': crypto.randomUUID(),
            'Client-Sdk-Type': 'typescript',
            'Client-Sdk-Version': sealSdkVersion,
            ...(apiKeyName && apiKey ? { [apiKeyName]: apiKey } : {}),
        },
    });

    const keyServerVersion = response.headers.get('x-keyserver-version');
    const exposedHeaders = response.headers.get('access-control-expose-headers');
    if (!keyServerVersion || !exposedHeaders|| !exposedHeaders!.includes('x-keyserver-version') && exposedHeaders !== '*') {
        console.error(`missing header: ${name} ${keyServerVersion} ${exposedHeaders}`);
    }
    return keyServerVersion;
}

async function main(network: 'testnet' | 'mainnet', keyServerConfigs: { objectId: string, apiKeyName?: string, apiKey?: string }[]) {
    const keypair = Ed25519Keypair.generate();
    const suiAddress = keypair.getPublicKey().toSuiAddress();
    const suiClient = new SuiClient({ url: getFullnodeUrl(network) });
    const testData = crypto.getRandomValues(new Uint8Array(1000));
    const packageId = PACKAGE_IDS[network];
    console.log(`packageId: ${packageId}`);
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

    // Test CORS headers for each key server
    const keyServers = await client.getKeyServers();
    for (const config of keyServerConfigs) {
        const keyServer = keyServers.get(config.objectId)!;
        await testCorsHeaders(keyServer.url, keyServer.name, config.apiKeyName, config.apiKey);
    }
    console.log('✅ All key servers have proper CORS configuration');

    // Encrypt data
    const { encryptedObject: encryptedBytes } = await client.encrypt({
        threshold: keyServerConfigs.length,
        packageId: packageId,
        id: suiAddress,
        data: testData,
    });

    // Create session key
    const sessionKey = await SessionKey.create({
        address: suiAddress,
        packageId: packageId,
        ttlMin: 10,
        signer: keypair,
        suiClient,
    });

    // Construct transaction bytes for seal_approve
    const tx = new Transaction();
    const keyIdArg = tx.pure.vector('u8', fromHex(suiAddress));
    tx.moveCall({
        target: `${packageId}::account_based::seal_approve`,
        arguments: [keyIdArg],
    });
    const txBytes = await tx.build({ client: suiClient, onlyTransactionKind: true });

    // Decrypt data
    const decryptedData = await client.decrypt({
        data: encryptedBytes,
        sessionKey,
        txBytes,
    });

    assert.deepEqual(decryptedData, testData);
    console.log('✅ Test passed!');
}

// Parse command line arguments
const { values } = parseArgs({
    args: process.argv.slice(2),
    options: {
        network: {
            type: 'string',
            default: 'testnet',
        },
        servers: {
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
// Format: --servers "objectId1:apiKeyName1:apiKeyValue1,objectId2:apiKeyName2:apiKeyValue2"
let keyServerConfigs: { objectId: string, apiKeyName?: string, apiKey?: string }[] = [];

if (values.servers) {
    const serverSpecs = values.servers.split(',').map(s => s.trim());
    keyServerConfigs = serverSpecs.map(spec => {
        const parts = spec.split(':');
        if (parts.length === 1) {
            // Just object ID
            return { objectId: parts[0] };
        } else if (parts.length === 3) {
            // Object ID, API key name, and API key value
            return {
                objectId: parts[0],
                apiKeyName: parts[1],
                apiKey: parts[2],
            };
        } else {
            console.error(`Invalid server specification: ${spec}. Format should be "objectId" or "objectId:apiKeyName:apiKeyValue"`);
            process.exit(1);
        }
    });
} else {
    console.error('Error: --servers argument is required');
    console.error('Example: --servers="0x123,0x456:myKey:mySecret"');
    process.exit(1);
}

console.log(`Running test on ${network} with servers:`, keyServerConfigs);

main(network, keyServerConfigs).catch(error => {
    console.error('Test failed:', error);
    process.exit(1);
});
