// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useCurrentAccount, useCurrentClient } from '@mysten/dapp-kit-react';
import { useEffect, useState } from 'react';
import { useNetworkVariable } from './networkConfig';
import { Button, Card } from '@radix-ui/themes';
import { getObjectExplorerLink } from './utils';

export interface Cap {
  id: string;
  service_id: string;
}

export interface CardItem {
  id: string;
  fee: string;
  ttl: string;
  name: string;
  owner: string;
}

export function AllServices() {
  const packageId = useNetworkVariable('packageId');
  const currentAccount = useCurrentAccount();
  const suiClient = useCurrentClient();

  const [cardItems, setCardItems] = useState<CardItem[]>([]);

  useEffect(() => {
    async function getCapObj() {
      // get all owned cap objects
      const res = await suiClient.core.listOwnedObjects({
        owner: currentAccount!.address,
        type: `${packageId}::subscription::Cap`,
        include: { json: true },
      });
      const caps = res.objects
        .map((obj) => {
          const fields = obj.json as { service_id?: string };
          return {
            id: obj.objectId,
            service_id: fields?.service_id,
          };
        })
        .filter((item) => item !== null) as Cap[];

      // get all services of all the owned cap objects
      const cardItems: CardItem[] = await Promise.all(
        caps.map(async (cap) => {
          const service = await suiClient.core.getObject({
            objectId: cap.service_id,
            include: { json: true },
          });
          const fields =
            (service.object.json as {
              fee?: string;
              ttl?: string;
              owner?: string;
              name?: string;
            }) || {};
          return {
            id: cap.service_id,
            fee: fields.fee!,
            ttl: fields.ttl!,
            owner: fields.owner!,
            name: fields.name!,
          };
        }),
      );
      setCardItems(cardItems);
    }

    // Call getCapObj immediately
    getCapObj();

    // Set up interval to call getCapObj every 3 seconds
    const intervalId = setInterval(() => {
      getCapObj();
    }, 3000);

    // Cleanup interval on component unmount
    return () => clearInterval(intervalId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentAccount?.address]); // Empty dependency array since we don't need any external values

  return (
    <div>
      <h2 style={{ marginBottom: '1rem' }}>Admin View: Owned Subscription Services</h2>
      <p style={{ marginBottom: '2rem' }}>
        This is all the services that you have created. Click manage to upload new files to the
        service.
      </p>
      {cardItems.map((item) => (
        <Card key={`${item.id}`}>
          <p>
            <strong>
              {item.name} (ID {getObjectExplorerLink(item.id)})
            </strong>
          </p>
          <p>Subscription Fee: {item.fee} MIST</p>
          <p>Subscription Duration: {item.ttl ? parseInt(item.ttl) / 60 / 1000 : 'null'} minutes</p>
          <Button
            onClick={() => {
              window.open(
                `${window.location.origin}/subscription-example/admin/service/${item.id}`,
                '_blank',
              );
            }}
          >
            Manage
          </Button>
        </Card>
      ))}
    </div>
  );
}
