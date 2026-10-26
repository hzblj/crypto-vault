# @hzblj/crypto-vault

## 0.1.0

### Minor Changes

- [`4b7e312`](https://github.com/hzblj/crypto-vault/commit/4b7e3123d6e781013d2010be9b06c7919339ac52) Thanks [@hzblj](https://github.com/hzblj)! - A wallet kept by the phone's security hardware. `createVault(crypto)` seals a wallet's BIP-39 entropy under a key the Secure Enclave (a P-256 key, ECIES) or StrongBox (an AES-256-GCM key, or the trusted environment where there is no StrongBox) holds, and `unlock` opens it after the system's biometric prompt straight into the `@hzblj/nitro-crypto` engine, as an `EphemeralWallet`: JavaScript never receives the entropy. `create` draws fresh entropy natively, `importMnemonic` seals words a user restores from, `revealMnemonic` returns the words for backup, `protection` says what holds each entry's key (measured, `software` on a simulator), and entries stay on the device, outside backups, and are lost when the enrolled biometrics change (ADR 0001). Needs `@hzblj/nitro-crypto` 0.1.3.
