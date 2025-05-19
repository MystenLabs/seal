## Table of Contents:

- [Introduction](README.md)
- [Seal Design](Design.md)
- [Using Seal](UsingSeal.md)
- [Seal Beta Terms of Service](TermsOfService.md)

# Security best practices and risk mitigations

When using Seal to manage encrypted data and access policies, it’s important to understand and mitigate certain risks associated with key management, data availability, and operational trust. This section outlines recommendations for developers to follow when integrating Seal into production systems, especially for use cases involving sensitive or long-lived data.

## Choose an appropriate threshold configuration

Seal supports **threshold encryption** using multiple independent key servers. When encrypting data, developers must select a threshold configuration (for example, `2-of-3` or `3-of-5`) based on the sensitivity of the data and how long it needs to remain accessible.

A poorly chosen threshold can result in unintended data loss. If too many key servers in a configuration go offline or become unavailable in the future, users may not be able to obtain enough decryption shares to recover their keys. Always ensure that the configuration balances fault tolerance with desired security guarantees.

## Vet and establish relationships with key server providers

Each key server in a Seal threshold configuration plays a critical role in data availability. As Seal is permissionless, anyone can run a key server. However, developers should treat key server selection as a trust decision.

To reduce operational risk, you should:

* Choose key servers operated by organizations or parties that you can trust.
* Establish a clear business or legal agreement with each provider, if possible.
* Ensure that terms of service specify obligations around availability, incident response, and service continuity.

Legal agreements can serve as a deterrent to unilateral service disruptions and provide a recourse mechanism if a provider fails to meet expectations.

## Use layered encryption for critical or large data

If you're handling data that is highly sensitive, large in size, or difficult to re-encrypt frequently, consider using **envelope encryption**.

In this approach:

* You generate your own symmetric encryption key for the data.
* Encrypt the data with that key.
* Use Seal to encrypt and manage access to that key.

This setup gives you the ability to **rotate or update** the Seal key servers in your threshold configuration, without needing to re-encrypt the data itself. You only need to re-encrypt the small, symmetric key. This is particularly useful for data that must remain accessible for years, or that is stored immutably on systems like Walrus.

## Understand the risks of leaked decryption keys

Seal uses **client-side encryption** by default. That means applications or users retrieve the decryption key from Seal’s key servers and use it locally to decrypt the data.

If a user or application leaks the decryption key - intentionally or not - the encrypted data could be decrypted by unauthorized parties. Because Seal key servers do not emit on-chain logs of key delivery events, there is no on-chain audit trail showing which user or wallet obtained the key.

To help detect or respond to such incidents:

* Implement audit logging or telemetry in your application.
* Log key access attempts, decryption events, and user behavior.
* Store logs in a tamper-evident system such as Walrus, or anchor them to the chain if required.

This can support transparency, internal review, or regulatory compliance in high-trust scenarios.

[Back to table of contents](#table-of-contents)
