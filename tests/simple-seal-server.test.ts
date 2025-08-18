// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { fromHex } from '@mysten/bcs';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { SealClient, SessionKey } from '@mysten/seal';
import assert from 'assert';
import { parseArgs } from 'node:util';

const TEST_DATA = 
    {'testnet': {
        "packageId": "0x58dce5d91278bceb65d44666ffa225ab397fc3ae9d8398c8c779c5530bd978c2",
        "serverObjectIds": [
            "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75", // mysten testnet-1 server, open
            "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8" // mysten testnet-2 server, open
        ]
    },
    'mainnet': {
        "packageId": "0x7dea8cca3f9970e8c52813d7a0cfb6c8e481fd92e9186834e1e3b58db2068029",
        "serverObjectIds": [
            "0xfabd2fb03a16ba9a8f2f961876675aa7ac2359b863627d7e3b948dc2cb3077ba" // mysten mainnet server, permissioned
        ]
    }};
async function main(network: "testnet" | "mainnet", additionalObjectIds?: string[]) {
    const keypair = Ed25519Keypair.generate();
    const suiAddress = keypair.getPublicKey().toSuiAddress();
    const suiClient = new SuiClient({ url: getFullnodeUrl(network) });
    const testData = crypto.getRandomValues(new Uint8Array(1000));

    const packageId = TEST_DATA[network].packageId;
    const serverObjectIds = additionalObjectIds 
        ? [...TEST_DATA[network].serverObjectIds, ...additionalObjectIds]
        : TEST_DATA[network].serverObjectIds;
    const client = new SealClient({
        suiClient,
        serverConfigs: serverObjectIds.map(objectId => ({
            objectId,
            weight: 1,
        })),
        verifyKeyServers: true,
    });

    // Encrypt data
    const { encryptedObject: encryptedBytes } = await client.encrypt({
        threshold: serverObjectIds.length,
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
        object_ids: {
            type: 'string',
        },
    },
});

const network = values.network as "testnet" | "mainnet";
if (network !== 'testnet' && network !== 'mainnet') {
    console.error('Error: network must be either "testnet" or "mainnet"');
    process.exit(1);
}

const additionalObjectIds = values.object_ids ? values.object_ids.split(',').map(id => id.trim()) : undefined;

console.log(`Running test on ${network}${additionalObjectIds ? ` with additional object IDs: ${additionalObjectIds.join(', ')}` : ''}`);

main(network, additionalObjectIds).catch(error => {
    console.error('Test failed:', error);
    process.exit(1);
});