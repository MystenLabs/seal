// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useCurrentAccount, useCurrentClient, useDAppKit } from '@mysten/dapp-kit-react';
import { Transaction } from '@mysten/sui/transactions';
import { Button, Card, Flex } from '@radix-ui/themes';
import { useNetworkVariable } from './networkConfig';
import { useEffect, useState } from 'react';
import { X } from 'lucide-react';
import { useParams } from 'react-router-dom';
import { isValidSuiAddress } from '@mysten/sui/utils';
import { getObjectExplorerLink } from './utils';

export interface Allowlist {
  id: string;
  name: string;
  list: string[];
}

interface AllowlistProps {
  setRecipientAllowlist: React.Dispatch<React.SetStateAction<string>>;
  setCapId: React.Dispatch<React.SetStateAction<string>>;
}

export function Allowlist({ setRecipientAllowlist, setCapId }: AllowlistProps) {
  const packageId = useNetworkVariable('packageId');
  const suiClient = useCurrentClient();
  const dAppKit = useDAppKit();
  const currentAccount = useCurrentAccount();
  const [allowlist, setAllowlist] = useState<Allowlist>();
  const { id } = useParams();
  const [capId, setInnerCapId] = useState<string>();

  useEffect(() => {
    async function getAllowlist() {
      // load all caps
      const res = await suiClient.core.listOwnedObjects({
        owner: currentAccount!.address,
        type: `${packageId}::allowlist::Cap`,
        include: { json: true },
      });

      // find the cap for the given allowlist id
      const capId = res.objects
        .map((obj) => {
          const fields = obj.json as { allowlist_id?: string };
          return {
            id: obj.objectId,
            allowlist_id: fields?.allowlist_id,
          };
        })
        .filter((item) => item.allowlist_id === id)
        .map((item) => item.id) as string[];
      setCapId(capId[0]);
      setInnerCapId(capId[0]);

      // load the allowlist for the given id
      const allowlist = await suiClient.core.getObject({
        objectId: id!,
        include: { json: true },
      });
      const fields = (allowlist.object.json as { name?: string; list?: string[] }) || {};
      setAllowlist({
        id: id!,
        name: fields.name!,
        list: fields.list!,
      });
      setRecipientAllowlist(id!);
    }

    // Call getAllowlist immediately
    getAllowlist();

    // Set up interval to call getAllowlist every 3 seconds
    const intervalId = setInterval(() => {
      getAllowlist();
    }, 3000);

    // Cleanup interval on component unmount
    return () => clearInterval(intervalId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, currentAccount?.address]); // Only depend on id

  const addItem = async (newAddressToAdd: string, wl_id: string, cap_id: string) => {
    if (newAddressToAdd.trim() !== '') {
      if (!isValidSuiAddress(newAddressToAdd.trim())) {
        alert('Invalid address');
        return;
      }
      const tx = new Transaction();
      tx.moveCall({
        arguments: [tx.object(wl_id), tx.object(cap_id), tx.pure.address(newAddressToAdd.trim())],
        target: `${packageId}::allowlist::add`,
      });

      const result = await dAppKit.signAndExecuteTransaction({ transaction: tx });
      console.log('res', result);
    }
  };

  const removeItem = async (addressToRemove: string, wl_id: string, cap_id: string) => {
    if (addressToRemove.trim() !== '') {
      const tx = new Transaction();
      tx.moveCall({
        arguments: [tx.object(wl_id), tx.object(cap_id), tx.pure.address(addressToRemove.trim())],
        target: `${packageId}::allowlist::remove`,
      });

      const result = await dAppKit.signAndExecuteTransaction({ transaction: tx });
      console.log('res', result);
    }
  };

  return (
    <Flex direction="column" gap="2" justify="start">
      <Card key={`${allowlist?.id}`}>
        <h2 style={{ marginBottom: '1rem' }}>
          Admin View: Allowlist {allowlist?.name} (ID{' '}
          {allowlist?.id && getObjectExplorerLink(allowlist.id)})
        </h2>
        <h3 style={{ marginBottom: '1rem' }}>
          Share&nbsp;
          <a
            href={`${window.location.origin}/allowlist-example/view/allowlist/${allowlist?.id}`}
            target="_blank"
            rel="noopener noreferrer"
            style={{ textDecoration: 'underline' }}
          >
            this link
          </a>{' '}
          with users to access the files associated with this allowlist.
        </h3>

        <Flex direction="row" gap="2">
          <input placeholder="Add new address" />
          <Button
            onClick={(e) => {
              const input = e.currentTarget.previousElementSibling as HTMLInputElement;
              addItem(input.value, id!, capId!);
              input.value = '';
            }}
          >
            Add
          </Button>
        </Flex>

        <h4>Allowed Users:</h4>
        {Array.isArray(allowlist?.list) && allowlist?.list.length > 0 ? (
          <ul>
            {allowlist?.list.map((listItem, itemIndex) => (
              <li key={itemIndex}>
                <Flex direction="row" gap="2">
                  <p>{listItem}</p>
                  <Button
                    onClick={(e) => {
                      e.stopPropagation();
                      removeItem(listItem, id!, capId!);
                    }}
                  >
                    <X />
                  </Button>
                </Flex>
              </li>
            ))}
          </ul>
        ) : (
          <p>No user in this allowlist.</p>
        )}
      </Card>
    </Flex>
  );
}
