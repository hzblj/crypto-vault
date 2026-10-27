# @hzblj/crypto-vault

## 0.3.0

### Minor Changes

- [#5](https://github.com/hzblj/crypto-vault/pull/5) [`155dbfb`](https://github.com/hzblj/crypto-vault/commit/155dbfb1584e7fafbb217bcaf20563919a5ea8b7) Thanks [@hzblj](https://github.com/hzblj)! - A BIP-39 passphrase, backups under a passkey, and the device credential before Android 11. `vault.unlock(id, {prompt, passphrase})` opens the wallet the words make under a passphrase, which crosses as bytes the vault overwrites, is NFKD-normalized natively and is never stored. `createVault(crypto, {relyingParty})` names the app's associated domain, and `vault.backup(id, {passkey: {name} | true, prompt})` seals an entry under a passkey's PRF output (iOS 18, Android 9 through Credential Manager), which goes from the platform to the engine without reaching JavaScript; `vault.restore(id, backup, {passkey: true})` opens it with the passkey the person picks. A backup's kind is read before anything is asked (`vault.backupKind`), and the wrong secret is refused with `NEEDS_PASSKEY` or `NEEDS_PASSWORD`. New error codes `WRONG_PASSKEY`, `PASSKEY_UNSUPPORTED` and `PASSKEY_NOT_FOUND`; `vault.passkeySupported` says whether the system and engine have what it takes (ADR 0003). On Android 7 to 10, an entry opened with the passcode too gets a key that works for 5 seconds after the person authenticates with biometrics or the device credential, instead of biometrics only (ADR 0004). Needs `@hzblj/nitro-crypto` 0.1.5.

- [#5](https://github.com/hzblj/crypto-vault/pull/5) [`bef251a`](https://github.com/hzblj/crypto-vault/commit/bef251a2f14a020df534806cc35e2b2c97914d69) Thanks [@hzblj](https://github.com/hzblj)! - A wrong BIP-39 passphrase fails instead of opening another wallet. BIP-39 has no checksum for a passphrase, so an entry given one keeps the 4-byte BIP-32 fingerprint of its wallet sealed with the entropy (inside the Secure Enclave's ECIES or the Keystore's AES-GCM, never in readable metadata, never the passphrase), and `unlock` refuses a wallet of another fingerprint with `WRONG_PASSPHRASE`, disposing it natively; leaving the passphrase out is checked as the empty one. `create`, `importMnemonic` and `restore` take `passphrase`, and `setPassphrase(id, {passphrase, prompt})` gives an existing entry a check or, with `null`, takes it away. `unlock(id, {verifyPassphrase: false})` skips the check, for whoever keeps decoy or hidden wallets under other passphrases, as a stored fingerprint tells anyone who can open the entry which passphrase is real. A wrong passphrase passes once in about 2^32. Ask for the passphrase twice where it is set. Backups still hold the entropy alone. Entries sealed by earlier versions open as before, with no check; an entry sealed by this version does not open in an earlier one (ADR 0005).

## 0.2.1

### Patch Changes

- [`b1c5446`](https://github.com/hzblj/crypto-vault/commit/b1c5446db28f4c4c6c0a82448eadd63f073dc4fa) Thanks [@hzblj](https://github.com/hzblj)! - The README shows the example app on iOS and Android.

## 0.2.0

### Minor Changes

- [#2](https://github.com/hzblj/crypto-vault/pull/2) [`662b4c6`](https://github.com/hzblj/crypto-vault/commit/662b4c64bc011964156f9411d69ad9efb2ff73af) Thanks [@hzblj](https://github.com/hzblj)! - Backups under a password. `vault.backup(id, {password, prompt})` opens an entry after the system prompt and has the `@hzblj/nitro-crypto` engine seal its entropy natively (Argon2id at 64 MiB, XChaCha20-Poly1305): 87 to 103 bytes that are safe to store anywhere, as only the password opens them. `vault.restore(id, backup, {password, access?, prompt?})` opens a backup natively, straight into a new entry under this device's hardware; JavaScript never holds the entropy either way. Passwords are NFC-normalized and need at least 8 characters (`MIN_PASSWORD_LENGTH`). New error codes `WEAK_PASSWORD`, `WRONG_PASSWORD` and `INVALID_BACKUP`; `vault.backupSupported` says whether the engine seals backups (ADR 0002). Needs `@hzblj/nitro-crypto` 0.1.4.

## 0.1.0

### Minor Changes

- [`4b7e312`](https://github.com/hzblj/crypto-vault/commit/4b7e3123d6e781013d2010be9b06c7919339ac52) Thanks [@hzblj](https://github.com/hzblj)! - A wallet kept by the phone's security hardware. `createVault(crypto)` seals a wallet's BIP-39 entropy under a key the Secure Enclave (a P-256 key, ECIES) or StrongBox (an AES-256-GCM key, or the trusted environment where there is no StrongBox) holds, and `unlock` opens it after the system's biometric prompt straight into the `@hzblj/nitro-crypto` engine, as an `EphemeralWallet`: JavaScript never receives the entropy. `create` draws fresh entropy natively, `importMnemonic` seals words a user restores from, `revealMnemonic` returns the words for backup, `protection` says what holds each entry's key (measured, `software` on a simulator), and entries stay on the device, outside backups, and are lost when the enrolled biometrics change (ADR 0001). Needs `@hzblj/nitro-crypto` 0.1.3.
