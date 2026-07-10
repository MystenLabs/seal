// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Transaction } from '@mysten/sui/transactions';
import { Button, Card, Flex } from '@radix-ui/themes';
import { useDAppKit } from '@mysten/dapp-kit-react';
import { useState } from 'react';
import { useNetworkVariable } from './networkConfig';
import { useNavigate } from 'react-router-dom';

export function CreateAllowlist() {
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const packageId = useNetworkVariable('packageId');
  const dAppKit = useDAppKit();

  async function createAllowlist(name: string) {
    if (name === '') {
      alert('Please enter a name for the allowlist');
      return;
    }
    const tx = new Transaction();
    tx.moveCall({
      target: `${packageId}::allowlist::create_allowlist_entry`,
      arguments: [tx.pure.string(name)],
    });
    const result = await dAppKit.signAndExecuteTransaction({ transaction: tx });
    console.log('res', result);
    if (result.$kind !== 'Transaction') {
      alert('Failed to create allowlist');
      return;
    }
    // Extract the created allowlist object ID from the transaction result
    const createdObjectId = result.Transaction.effects?.changedObjects.find(
      (item) => item.idOperation === 'Created' && item.outputOwner?.$kind === 'Shared',
    )?.objectId;
    if (createdObjectId) {
      window.open(
        `${window.location.origin}/allowlist-example/admin/allowlist/${createdObjectId}`,
        '_blank',
      );
    }
  }

  const handleViewAll = () => {
    navigate(`/allowlist-example/admin/allowlists`);
  };

  return (
    <Card>
      <h2 style={{ marginBottom: '1rem' }}>Admin View: Allowlist</h2>
      <Flex direction="row" gap="2" justify="start">
        <input placeholder="Allowlist Name" onChange={(e) => setName(e.target.value)} />
        <Button
          size="3"
          onClick={() => {
            createAllowlist(name);
          }}
        >
          Create Allowlist
        </Button>
        <Button size="3" onClick={handleViewAll}>
          View All Created Allowlists
        </Button>
      </Flex>
    </Card>
  );
}
