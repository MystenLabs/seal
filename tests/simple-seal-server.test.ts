// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { fromHex } from '@mysten/bcs';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { SealClient, SessionKey } from '@mysten/seal';
import assert from 'assert';

const TEST_DATA = 
    {'testnet': {
        "packageId": "0x58dce5d91278bceb65d44666ffa225ab397fc3ae9d8398c8c779c5530bd978c2",
        "serverObjectIds": [
            "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75",
            "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8",
            // TODO: add your server object id here
        ]
    },
    'mainnet': {
        "packageId": "0x7dea8cca3f9970e8c52813d7a0cfb6c8e481fd92e9186834e1e3b58db2068029",
        "serverObjectIds": [
            "0xfabd2fb03a16ba9a8f2f961876675aa7ac2359b863627d7e3b948dc2cb3077ba",
            // TODO: add your server object id here
        ]
    }};
async function main(network: "testnet" | "mainnet") {
    const keypair = Ed25519Keypair.fromSecretKey(
        'suiprivkey1qqgzvw5zc2zmga0uyp4rzcgk42pzzw6387zqhahr82pp95yz0scscffh2d8',
    );
    const suiAddress = keypair.getPublicKey().toSuiAddress();
    const suiClient = new SuiClient({ url: getFullnodeUrl(network) });
    const testData = new Uint8Array([1, 2, 3, 4, 5]);

    const packageId = TEST_DATA[network].packageId;
    const serverObjectIds = TEST_DATA[network].serverObjectIds;
    const client = new SealClient({
        suiClient,
        serverConfigs: serverObjectIds.map(objectId => ({
            objectId,
            weight: 1,
        })),
        verifyKeyServers: false,
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

// TODO: select your network
main('testnet').catch(console.error);
// main('mainnet').catch(console.error);