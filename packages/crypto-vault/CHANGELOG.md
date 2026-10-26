# @hzblj/crypto-vault

## 0.2.0

### Minor Changes

- [#2](https://github.com/hzblj/crypto-vault/pull/2) [`662b4c6`](https://github.com/hzblj/crypto-vault/commit/662b4c64bc011964156f9411d69ad9efb2ff73af) Thanks [@hzblj](https://github.com/hzblj)! - Backups under a password. `vault.backup(id, {password, prompt})` opens an entry after the system prompt and has the `@hzblj/nitro-crypto` engine seal its entropy natively (Argon2id at 64 MiB, XChaCha20-Poly1305): 87 to 103 bytes that are safe to store anywhere, as only the password opens them. `vault.restore(id, backup, {password, access?, prompt?})` opens a backup natively, straight into a new entry under this device's hardware; JavaScript never holds the entropy either way. Passwords are NFC-normalized and need at least 8 characters (`MIN_PASSWORD_LENGTH`). New error codes `WEAK_PASSWORD`, `WRONG_PASSWORD` and `INVALID_BACKUP`; `vault.backupSupported` says whether the engine seals backups (ADR 0002). Needs `@hzblj/nitro-crypto` 0.1.4.

## 0.1.0

### Minor Changes

- [`4b7e312`](https://github.com/hzblj/crypto-vault/commit/4b7e3123d6e781013d2010be9b06c7919339ac52) Thanks [@hzblj](https://github.com/hzblj)! - A wallet kept by the phone's security hardware. `createVault(crypto)` seals a wallet's BIP-39 entropy under a key the Secure Enclave (a P-256 key, ECIES) or StrongBox (an AES-256-GCM key, or the trusted environment where there is no StrongBox) holds, and `unlock` opens it after the system's biometric prompt straight into the `@hzblj/nitro-crypto` engine, as an `EphemeralWallet`: JavaScript never receives the entropy. `create` draws fresh entropy natively, `importMnemonic` seals words a user restores from, `revealMnemonic` returns the words for backup, `protection` says what holds each entry's key (measured, `software` on a simulator), and entries stay on the device, outside backups, and are lost when the enrolled biometrics change (ADR 0001). Needs `@hzblj/nitro-crypto` 0.1.3.
