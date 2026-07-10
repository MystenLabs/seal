// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useCurrentNetwork } from '@mysten/dapp-kit-react';
import { TESTNET_PACKAGE_ID } from './constants';

const networkVariables = {
  testnet: {
    packageId: TESTNET_PACKAGE_ID,
    mvrName: '@pkg/seal-demo-1234',
  },
} as const;

type NetworkVariables = (typeof networkVariables)['testnet'];

export function useNetworkVariable<K extends keyof NetworkVariables>(name: K): NetworkVariables[K] {
  const network = useCurrentNetwork();
  return networkVariables[network as keyof typeof networkVariables][name];
}
