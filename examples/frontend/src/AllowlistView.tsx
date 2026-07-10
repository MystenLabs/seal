// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useMemo, useState } from 'react';
import { useCurrentClient, useDAppKit } from '@mysten/dapp-kit-react';
import { useNetworkVariable } from './networkConfig';
import { AlertDialog, Button, Card, Dialog, Flex, Grid } from '@radix-ui/themes';
import { fromHex } from '@mysten/sui/utils';
import { bcs } from '@mysten/sui/bcs';
import { Transaction } from '@mysten/sui/transactions';
import { SealClient, SessionKey, type ExportedSessionKey } from '@mysten/seal';
import { useParams } from 'react-router-dom';
import {
  downloadAndDecrypt,
  getObjectExplorerLink,
  MoveCallConstructor,
  DECENTRALIZED_KEY_SERVER_OBJ_ID,
} from './utils';
import { set, get } from 'idb-keyval';

const TTL_MIN = 10;
export interface FeedData {
  allowlistId: string;
  allowlistName: string;
  blobIds: string[];
}

function constructMoveCall(packageId: string, allowlistId: string): MoveCallConstructor {
  return (tx: Transaction, id: string) => {
    tx.moveCall({
      target: `${packageId}::allowlist::seal_approve`,
      arguments: [tx.pure.vector('u8', fromHex(id)), tx.object(allowlistId)],
    });
  };
}

const Feeds: React.FC<{ suiAddress: string }> = ({ suiAddress }) => {
  const suiClient = useCurrentClient();
  const dAppKit = useDAppKit();
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
  const packageId = useNetworkVariable('packageId');
  const mvrName = useNetworkVariable('mvrName');

  const [feed, setFeed] = useState<FeedData>();
  const [decryptedFileUrls, setDecryptedFileUrls] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const { id } = useParams();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

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
  }, [id, suiClient, packageId]); // Add all dependencies that getFeed uses

  async function getFeed() {
    const allowlist = await suiClient.core.getObject({
      objectId: id!,
      include: { json: true },
    });
    // Dynamic field names are Move Strings (the Walrus blob IDs) — decode them from BCS.
    const encryptedObjects = await suiClient.core
      .listDynamicFields({
        parentId: id!,
      })
      .then((res) => res.dynamicFields.map((df) => bcs.string().parse(df.name.bcs)));
    const fields = (allowlist.object.json as { name?: string }) || {};
    const feedData = {
      allowlistId: id!,
      allowlistName: fields.name!,
      blobIds: encryptedObjects,
    };
    setFeed(feedData);
  }

  const onView = async (blobIds: string[], allowlistId: string) => {
    const imported: ExportedSessionKey = await get('sessionKey');

    if (imported) {
      try {
        const currentSessionKey = await SessionKey.import(imported, suiClient);
        console.log('loaded currentSessionKey', currentSessionKey);
        if (
          currentSessionKey &&
          !currentSessionKey.isExpired() &&
          currentSessionKey.getAddress() === suiAddress
        ) {
          const moveCallConstructor = constructMoveCall(packageId, allowlistId);
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
      } catch (error) {
        console.log('Imported session key is expired', error);
      }
    }

    set('sessionKey', null);

    const sessionKey = await SessionKey.create({
      address: suiAddress,
      packageId,
      ttlMin: TTL_MIN,
      suiClient,
      mvrName,
    });

    try {
      const { signature } = await dAppKit.signPersonalMessage({
        message: sessionKey.getPersonalMessage(),
      });
      await sessionKey.setPersonalMessageSignature(signature);
      const moveCallConstructor = constructMoveCall(packageId, allowlistId);
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
      set('sessionKey', sessionKey.export());
    } catch (error) {
      console.error('Error:', error);
    }
  };

  return (
    <Card>
      <h2 style={{ marginBottom: '1rem' }}>
        Files for Allowlist {feed?.allowlistName} (ID{' '}
        {feed?.allowlistId && getObjectExplorerLink(feed.allowlistId)})
      </h2>
      {feed === undefined ? (
        <p>No files found for this allowlist.</p>
      ) : (
        <Grid columns="2" gap="3">
          <Card key={feed!.allowlistId}>
            <Flex direction="column" align="start" gap="2">
              {feed!.blobIds.length === 0 ? (
                <p>No files found for this allowlist.</p>
              ) : (
                <Dialog.Root open={isDialogOpen} onOpenChange={setIsDialogOpen}>
                  <Dialog.Trigger>
                    <Button onClick={() => onView(feed!.blobIds, feed!.allowlistId)}>
                      Download And Decrypt All Files
                    </Button>
                  </Dialog.Trigger>
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
        </Grid>
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

export default Feeds;
