# Example patterns

This page summarizes common Seal patterns from the [Move patterns repository](https://github.com/MystenLabs/seal/tree/main/move/patterns/sources). It isn’t exhaustive - for additional patterns and the latest updates, see the repository directly.

## Private data

[Move source](https://github.com/MystenLabs/seal/blob/main/move/patterns/sources/private_data.move)

Use this pattern when a single owner should control encrypted content. You store the ciphertext as an owned object; only the current owner can decrypt, and ownership transfer moves custody without exposing the data. It’s a fit for personal key storage, private NFTs, or user-held credentials that must remain private yet portable.

## Allowlist

[Move source](https://github.com/MystenLabs/seal/blob/main/move/patterns/sources/whitelist.move)

Use this pattern to share encrypted content with a defined group or list of approved users. You manage access by adding or removing members on the list, and those changes apply to future decryptions without touching the encrypted data. It’s great for subscriptions, partner-only data rooms, or early-access drops, and can optionally switch to public access after a set time.

## Subscription

[Move source](https://github.com/MystenLabs/seal/blob/main/move/patterns/sources/subscription.move)

Use this pattern to offer time-limited access to encrypted content or services. You define a service with a price and duration; when someone subscribes, their identity gets a pass that lets them decrypt the service’s content until it expires. There's no need to re-encrypt or move data. Ideal for premium media, data feeds, or paid API / AI model access.

## Time-lock encryption

[Move source](https://github.com/MystenLabs/seal/blob/main/move/patterns/sources/tle.move)

Use this pattern to publish encrypted content that unlocks automatically at a specific time. You encrypt once with an unlock timestamp; before that moment, no one can open it, and after it passes, anyone (or your intended audience) can. No re-encryption or per-user distribution is needed. Ideal for coordinated reveals (drops, auctions), MEV-resilient trading, and secure voting; an optional variant lets an authorized party extend the unlock time before it expires.

## Secure voting

[Move source](https://github.com/MystenLabs/seal/blob/main/move/patterns/sources/voting.move)

Use this pattern to run a vote where ballots stay encrypted until the process completes. You define eligible voters; each submits an encrypted choice, and once all votes are in, the system releases the decryption needed to produce a verifiable on-chain tally. Invalid or tampered ballots are ignored. It can be useful for governance, sealed-bid auctions, or time-locked voting.

## Pre-signed URL

[Move source](https://github.com/MystenLabs/seal/blob/main/move/patterns/sources/presigned_url.move)

Use this pattern to share an encrypted Walrus blob via a time-limited, bearer link. You publish a small “window” object that names the blob and an expiry; anyone with the link can request decryption until the deadline, and no one can after. You encrypt once (key-id includes the blob’s ID), avoid per-user setup, and keep a clean audit trail. It's great for limited-time downloads, drops, press kits, or trial content.
