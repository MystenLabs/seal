// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useCurrentAccount, useCurrentClient } from '@mysten/dapp-kit-react';
import { Card, Flex } from '@radix-ui/themes';
import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { useNetworkVariable } from './networkConfig';
import { getObjectExplorerLink } from './utils';

export interface Service {
  id: string;
  fee: string;
  ttl: string;
  owner: string;
  name: string;
}

interface AllowlistProps {
  setRecipientAllowlist: React.Dispatch<React.SetStateAction<string>>;
  setCapId: React.Dispatch<React.SetStateAction<string>>;
}

export function Service({ setRecipientAllowlist, setCapId }: AllowlistProps) {
  const suiClient = useCurrentClient();
  const packageId = useNetworkVariable('packageId');
  const currentAccount = useCurrentAccount();
  const [service, setService] = useState<Service>();
  const { id } = useParams();

  useEffect(() => {
    async function getService() {
      // load the service for the given id
      const service = await suiClient.core.getObject({
        objectId: id!,
        include: { json: true },
      });
      const fields =
        (service.object.json as { fee?: string; ttl?: string; owner?: string; name?: string }) ||
        {};
      setService({
        id: id!,
        fee: fields.fee!,
        ttl: fields.ttl!,
        owner: fields.owner!,
        name: fields.name!,
      });
      setRecipientAllowlist(id!);

      // load all caps
      const res = await suiClient.core.listOwnedObjects({
        owner: currentAccount!.address,
        type: `${packageId}::subscription::Cap`,
        include: { json: true },
      });

      // find the cap for the given service id
      const capId = res.objects
        .map((obj) => {
          const fields = obj.json as { service_id?: string };
          return {
            id: obj.objectId,
            service_id: fields?.service_id,
          };
        })
        .filter((item) => item.service_id === id)
        .map((item) => item.id) as string[];
      setCapId(capId[0]);
    }

    // Call getService immediately
    getService();

    // Set up interval to call getService every 3 seconds
    const intervalId = setInterval(() => {
      getService();
    }, 3000);

    // Cleanup interval on component unmount
    return () => clearInterval(intervalId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]); // Only depend on id since it's needed for the API calls

  return (
    <Flex direction="column" gap="2" justify="start">
      <Card key={`${service?.id}`}>
        <h2 style={{ marginBottom: '1rem' }}>
          Admin View: Service {service?.name} (ID {service?.id && getObjectExplorerLink(service.id)}
          )
        </h2>
        <h3 style={{ marginBottom: '1rem' }}>
          Share&nbsp;
          <a
            href={`${window.location.origin}/subscription-example/view/service/${service?.id}`}
            target="_blank"
            rel="noopener noreferrer"
            style={{ textDecoration: 'underline' }}
            aria-label="Download encrypted blob"
          >
            this link
          </a>{' '}
          with other users to subscribe to this service and access its files.
        </h3>

        <Flex direction="column" gap="2" justify="start">
          <p>
            <strong>Subscription duration:</strong>{' '}
            {service?.ttl ? parseInt(service.ttl) / 60 / 1000 : 'null'} minutes
          </p>
          <p>
            <strong>Subscription fee:</strong> {service?.fee} MIST
          </p>
        </Flex>
      </Card>
    </Flex>
  );
}
