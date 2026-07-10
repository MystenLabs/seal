// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useMemo, useState } from 'react';
import { useCurrentAccount, useCurrentClient, useDAppKit } from '@mysten/dapp-kit-react';
import { useNetworkVariable } from './networkConfig';
import { AlertDialog, Button, Card, Dialog, Flex } from '@radix-ui/themes';
import { coinWithBalance, Transaction } from '@mysten/sui/transactions';
import { fromHex, SUI_CLOCK_OBJECT_ID } from '@mysten/sui/utils';
import { bcs } from '@mysten/sui/bcs';
import { SealClient, SessionKey } from '@mysten/seal';
import { useParams } from 'react-router-dom';
import {
  downloadAndDecrypt,
  getObjectExplorerLink,
  MoveCallConstructor,
  DECENTRALIZED_KEY_SERVER_OBJ_ID,
} from './utils';

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
  const suiClient = useCurrentClient();
  const dAppKit = useDAppKit();
  const { id } = useParams();

  const client = useMemo(
    () =>
      new SealClient({
        suiClient,
        // Refer to https://seal-docs.wal.app/UsingSeal#choosing-key-servers for other config options
        serverConfigs: [
          {
            objectId: DECENTRALIZED_KEY_SERVER_OBJ_ID,
            weight: 1,
            aggregatorUrl: 'https://seal-aggregator-testnet.mystenlabs.com', // aggregatorUrl is only needed for decentralized key server
          },
        ],
        verifyKeyServers: false,
      }),
    [suiClient],
  );
  const [feed, setFeed] = useState<FeedData>();
  const [decryptedFileUrls, setDecryptedFileUrls] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const packageId = useNetworkVariable('packageId');
  const currentAccount = useCurrentAccount();
  const [currentSessionKey, setCurrentSessionKey] = useState<SessionKey | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [isDialogOpen, setIsDialogOpen] = useState(false);

  useEffect(() => {
    // Call getFeed immediately
    getFeed();

    // Set up interval to call getFeed every 3 seconds
    const intervalId = setInterval(() => {
      getFeed();
    }, 3000);

    // Cleanup interval on component unmount
    return () => clearInterval(intervalId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, suiAddress, packageId, suiClient]);

  async function getFeed() {
    // get all encrypted objects for the given service id
    // (dynamic field names are Move Strings — the Walrus blob IDs — decode them from BCS)
    const encryptedObjects = await suiClient.core
      .listDynamicFields({
        parentId: id!,
      })
      .then((res) => res.dynamicFields.map((df) => bcs.string().parse(df.name.bcs)));

    // get the current service object
    const service = await suiClient.core.getObject({
      objectId: id!,
      include: { json: true },
    });
    const service_fields =
      (service.object.json as { fee?: string; ttl?: string; owner?: string; name?: string }) || {};

    // get all subscriptions for the given sui address
    const res = await suiClient.core.listOwnedObjects({
      owner: suiAddress,
      type: `${packageId}::subscription::Subscription`,
      include: { json: true },
    });

    // get the current timestamp
    const clock = await suiClient.core.getObject({
      objectId: '0x6',
      include: { json: true },
    });
    const clock_fields = (clock.object.json as { timestamp_ms?: string }) || {};
    const current_ms = Number(clock_fields.timestamp_ms);

    // find a valid subscription for the given service if exists.
    const valid_subscription = res.objects
      .map((obj) => {
        const fields = obj.json as { created_at?: string; service_id?: string };
        return {
          id: obj.objectId,
          created_at: parseInt(fields.created_at!),
          service_id: fields.service_id,
        };
      })
      .filter((item) => item.service_id === service.object.objectId)
      .find((item) => {
        return item.created_at + parseInt(service_fields.ttl!) > current_ms;
      });

    const feed = {
      ...service_fields,
      id: service.object.objectId,
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
    const address = currentAccount!.address;
    const tx = new Transaction();
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

    const result = await dAppKit.signAndExecuteTransaction({ transaction: tx });
    console.log('res', result);
    if (result.$kind === 'Transaction') {
      // wait for the fullnode to index the transaction before refetching
      await suiClient.core.waitForTransaction({ digest: result.Transaction.digest });
      getFeed();
    }
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
      const { signature } = await dAppKit.signPersonalMessage({
        message: sessionKey.getPersonalMessage(),
      });
      await sessionKey.setPersonalMessageSignature(signature);
      const moveCallConstructor = constructMoveCall(packageId, serviceId, subscriptionId);
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
    } catch (error) {
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
