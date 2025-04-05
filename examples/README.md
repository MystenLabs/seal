# Examples

This reference application includes two different functionalities to showcase Seal's capabilities:

**Allowlist-Based Access**

An allowlist enables a creator to manage a set of authorized addresses by adding or removing members as needed. The creator can associate encrypted files with the allowlist, ensuring that only designated members can access the content.

To gain access, a user must sign a personal message, which is then verified against the allowlist. Upon successful verification, the user retrieves two key shares from two independent servers. If the membership check is validated, the user combines these key shares to derive the decryption key, which allows them to access and view the decrypted content.

**Subscription-Based Access**

A subscription service allows a creator to define a service with a specified price (denominated in MIST) and a time period (X minutes). When a user purchases a subscription, it is represented as a non-fungible token (NFT) stored on-chain.

To access the service, the user must sign a personal message, which is then validated by the servers. The servers verify whether the subscription is active for the next X minutes by referencing the on-chain Sui clock and ensuring the user holds a valid subscription NFT. If the conditions are met, the user retrieves the decryption key, enabling access to the decrypted content.

> **IMPORTANT**
> This reference application serves as a demonstration of Seal's capabilities and is intended solely as a playground environment. It does not provide guarantees of uptime, reliability, or correctness. Users are strongly advised not to connect their primary wallets or upload any sensitive content while utilizing this application.
>
> By accessing and using this reference application, you acknowledge and accept the inherent risks associated with cryptographic and blockchain-based systems. You confirm that you possess a working knowledge of Digital Assets and understand the implications of their usage.
>
> You further acknowledge that you are solely responsible for all actions taken within this application, including but not limited to connecting your wallet, adding content, or providing approvals or permissions by cryptographically signing blockchain messages or transactions.
>
> Mysten Labs, Inc., along with its affiliates and employees, assumes no responsibility for the security, integrity, or compliance of any content added or actions performed within this reference application. Users must exercise caution and use this application at their own risk.

## Run locally

```bash
cd frontendcd frontend
pnpm install
pnpm dev
pnpm install
pnpm dev
```
