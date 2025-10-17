// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react';
import {
  useCurrentAccount,
  useSignAndExecuteTransaction,
  useSignPersonalMessage,
  useSuiClient,
} from '@mysten/dapp-kit';
import { useNetworkVariable } from './networkConfig';
import { AlertDialog, Button, Card, Dialog, Flex } from '@radix-ui/themes';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';
import { fromHex, SUI_CLOCK_OBJECT_ID } from '@mysten/sui/utils';
import { SealClient, SessionKey } from '@mysten/seal';
import { useParams } from 'react-router-dom';
import { downloadAndDecrypt, getObjectExplorerLink, MoveCallConstructor } from './utils';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';

const TTL_MIN = 10;
export interface FeedData {
  id: string;
  fee: string;
  ttl: string;
  owner: string;
  name: string;
  blobIds: string[];
  subscriptionId?: string;
}

const FeedsToSubscribe: React.FC<{ suiAddress: string }> = ({ suiAddress }) => {
  const suiClient = useSuiClient();
  const { id } = useParams();
  const serverObjectIds = ["0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75", "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8"];

  const client = new SealClient({
    suiClient,
    serverConfigs: serverObjectIds.map((id) => ({
      objectId: id,
      weight: 1,
    })),
    verifyKeyServers: false,
  });
  const [feed, setFeed] = useState<FeedData>();
  const [decryptedFileUrls, setDecryptedFileUrls] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const packageId = useNetworkVariable('packageId');
  const currentAccount = useCurrentAccount();
  const [currentSessionKey, setCurrentSessionKey] = useState<SessionKey | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [isDialogOpen, setIsDialogOpen] = useState(false);

  const { mutate: signPersonalMessage } = useSignPersonalMessage();

  const { mutate: signAndExecute } = useSignAndExecuteTransaction({
    execute: async ({ bytes, signature }) =>
      await suiClient.executeTransactionBlock({
        transactionBlock: bytes,
        signature,
        options: {
          showRawEffects: true,
          showEffects: true,
        },
      }),
  });

  useEffect(() => {
    // Call getFeed immediately
    getFeed();

    // Set up interval to call getFeed every 3 seconds
    const intervalId = setInterval(() => {
      getFeed();
    }, 3000);

    // Cleanup interval on component unmount
    return () => clearInterval(intervalId);
  }, [id, suiAddress, packageId, suiClient]);

  async function getFeed() {
    // get all encrypted objects for the given service id
    const encryptedObjects = await suiClient
      .getDynamicFields({
        parentId: id!,
      })
      .then((res) => res.data.map((obj) => obj.name.value as string));

    // get the current service object
    const service = await suiClient.getObject({
      id: id!,
      options: { showContent: true },
    });
    const service_fields = (service.data?.content as { fields: any })?.fields || {};

    // get all subscriptions for the given sui address
    const res = await suiClient.getOwnedObjects({
      owner: suiAddress,
      options: {
        showContent: true,
        showType: true,
      },
      filter: {
        StructType: `${packageId}::subscription::Subscription`,
      },
    });

    // get the current timestamp
    const clock = await suiClient.getObject({
      id: '0x6',
      options: { showContent: true },
    });
    const fields = (clock.data?.content as { fields: any })?.fields || {};
    const current_ms = fields.timestamp_ms;

    // find an expired subscription for the given service if exists.
    const valid_subscription = res.data
      .map((obj) => {
        const fields = (obj!.data!.content as { fields: any }).fields;
        const x = {
          id: fields?.id.id,
          created_at: parseInt(fields?.created_at),
          service_id: fields?.service_id,
        };
        return x;
      })
      .filter((item) => item.service_id === service_fields.id.id)
      .find((item) => {
        return item.created_at + parseInt(service_fields.ttl) > current_ms;
      });

    const feed = {
      ...service_fields,
      id: service_fields.id.id,
      blobIds: encryptedObjects,
      subscriptionId: valid_subscription?.id,
    } as FeedData;
    setFeed(feed);
  }

  function constructMoveCall(
    packageId: string,
    serviceId: string,
    subscriptionId: string,
  ): MoveCallConstructor {
    return (tx: Transaction, id: string) => {
      tx.moveCall({
        target: `${packageId}::subscription::seal_approve`,
        arguments: [
          tx.pure.vector('u8', fromHex(id)),
          tx.object(subscriptionId),
          tx.object(serviceId),
          tx.object(SUI_CLOCK_OBJECT_ID),
        ],
      });
    };
  }

  async function handleSubscribe(serviceId: string, fee: number) {
    const address = currentAccount?.address!;
    const tx = new Transaction();
    tx.setGasBudget(10000000);
    tx.setSender(address);
    const subscription = tx.moveCall({
      target: `${packageId}::subscription::subscribe`,
      arguments: [
        coinWithBalance({
          balance: BigInt(fee),
        }),
        tx.object(serviceId),
        tx.object(SUI_CLOCK_OBJECT_ID),
      ],
    });
    tx.moveCall({
      target: `${packageId}::subscription::transfer`,
      arguments: [tx.object(subscription), tx.pure.address(address)],
    });

    signAndExecute(
      {
        transaction: tx,
      },
      {
        onSuccess: async (result) => {
          console.log('res', result);
          getFeed();
        },
      },
    );
  }

  const onView = async (
    blobIds: string[],
    serviceId: string,
    fee: number,
    subscriptionId?: string,
  ) => {
    if (!subscriptionId) {
      return handleSubscribe(serviceId, fee);
    }

    if (
      currentSessionKey &&
      !currentSessionKey.isExpired() &&
      currentSessionKey.getAddress() === suiAddress
    ) {
      const moveCallConstructor = constructMoveCall(packageId, serviceId, subscriptionId);
      downloadAndDecrypt(
        blobIds,
        currentSessionKey,
        suiClient,
        client,
        moveCallConstructor,
        setError,
        setDecryptedFileUrls,
        setIsDialogOpen,
        setReloadKey,
      );
      return;
    }
    setCurrentSessionKey(null);

    const sessionKey = await SessionKey.create({
      address: suiAddress,
      packageId,
      ttlMin: TTL_MIN,
      suiClient,
    });

    try {
      signPersonalMessage(
        {
          message: sessionKey.getPersonalMessage(),
        },
        {
          onSuccess: async (result) => {
            await sessionKey.setPersonalMessageSignature(result.signature);
            const moveCallConstructor = await constructMoveCall(
              packageId,
              serviceId,
              subscriptionId,
            );
            await downloadAndDecrypt(
              blobIds,
              sessionKey,
              suiClient,
              client,
              moveCallConstructor,
              setError,
              setDecryptedFileUrls,
              setIsDialogOpen,
              setReloadKey,
            );
            setCurrentSessionKey(sessionKey);
          },
        },
      );
    } catch (error: any) {
      console.error('Error:', error);
    }
  };

  return (
    <Card>
      {feed === undefined ? (
        <p>Waiting for files...</p>
      ) : (
        <Card key={feed!.id}>
          <h2 style={{ marginBottom: '1rem' }}>
            Files for subscription service {feed!.name} (ID {getObjectExplorerLink(feed!.id)})
          </h2>
          <Flex direction="column" gap="2">
            {feed!.blobIds.length === 0 ? (
              <p>No Files yet.</p>
            ) : (
              <Dialog.Root open={isDialogOpen} onOpenChange={setIsDialogOpen}>
                <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
                  <Dialog.Trigger>
                    <Button
                      onClick={() =>
                        onView(feed!.blobIds, feed!.id, Number(feed!.fee), feed!.subscriptionId)
                      }
                    >
                      {feed!.subscriptionId ? (
                        <div>Download And Decrypt All Files</div>
                      ) : (
                        <div>
                          Subscribe for {feed!.fee} MIST for{' '}
                          {Math.floor(parseInt(feed!.ttl) / 60 / 1000)} minutes
                        </div>
                      )}
                    </Button>
                  </Dialog.Trigger>
                </div>
                {decryptedFileUrls.length > 0 && (
                  <Dialog.Content maxWidth="450px" key={reloadKey}>
                    <Dialog.Title>View all files retrieved from Walrus</Dialog.Title>
                    <Flex direction="column" gap="2">
                      {decryptedFileUrls.map((decryptedFileUrl, index) => (
                        <div key={index}>
                          <img src={decryptedFileUrl} alt={`Decrypted image ${index + 1}`} />
                        </div>
                      ))}
                    </Flex>
                    <Flex gap="3" mt="4" justify="end">
                      <Dialog.Close>
                        <Button
                          variant="soft"
                          color="gray"
                          onClick={() => setDecryptedFileUrls([])}
                        >
                          Close
                        </Button>
                      </Dialog.Close>
                    </Flex>
                  </Dialog.Content>
                )}
              </Dialog.Root>
            )}
          </Flex>
        </Card>
      )}
      <AlertDialog.Root open={!!error} onOpenChange={() => setError(null)}>
        <AlertDialog.Content maxWidth="450px">
          <AlertDialog.Title>Error</AlertDialog.Title>
          <AlertDialog.Description size="2">{error}</AlertDialog.Description>

          <Flex gap="3" mt="4" justify="end">
            <AlertDialog.Action>
              <Button variant="solid" color="gray" onClick={() => setError(null)}>
                Close
              </Button>
            </AlertDialog.Action>
          </Flex>
        </AlertDialog.Content>
      </AlertDialog.Root>
    </Card>
  );
};

export default FeedsToSubscribe;
