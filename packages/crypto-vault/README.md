# @hzblj/crypto-vault

[![npm](https://img.shields.io/npm/v/@hzblj/crypto-vault.svg)](https://www.npmjs.com/package/@hzblj/crypto-vault)
[![license](https://img.shields.io/npm/l/@hzblj/crypto-vault.svg)](https://github.com/hzblj/crypto-vault/blob/main/LICENSE)

A wallet's BIP-39 entropy sealed by the Secure Enclave or StrongBox, for React Native and Expo. Each entry opens only
after the system's biometric prompt, straight into the [`@hzblj/nitro-crypto`](https://github.com/hzblj/nitro-crypto)
engine: the seed is made natively, and JavaScript receives a wallet, never the entropy or the words behind it.

```sh
npx expo install @hzblj/crypto-vault @hzblj/nitro-crypto react-native-nitro-modules
```

Then a development build (`npx expo prebuild`, `npx expo run:ios`): the vault is native code, not in Expo Go. On iOS,
add the Face ID usage description (`ios.infoPlist.NSFaceIDUsageDescription` in the app config).

## The API

```ts
import {createVault, isVaultError} from '@hzblj/crypto-vault'

const vault = createVault(crypto) // over the engine the app already made, with its chains
```

| | |
| --- | --- |
| `vault.create(id, {words?, access?, prompt?})` | A fresh wallet (12 to 24 words), its entropy drawn and sealed natively |
| `vault.importMnemonic(id, words, {access?, prompt?})` | A wallet restored from its words, sealed under `id`; the words cross as bytes the vault overwrites |
| `vault.unlock(id, {prompt})` | After the system prompt, the entry as an `EphemeralWallet` in the engine |
| `vault.revealMnemonic(id, {prompt})` | After the system prompt, the entry's words, for the user to write down |
| `vault.has(id)`, `vault.protection(id)`, `vault.access(id)` | Whether there is an entry, what holds its key, who opens it |
| `vault.availableProtection` | What a new entry gets on this device |
| `vault.remove(id)` | Deletes the entry and its key |

An `id` is 1 to 64 letters, digits, `-`, `_` or `.`. `access` is `'biometrics'` (the default) or
`'biometrics-or-passcode'`. `prompt` is what the system's prompt says: why the app asks. iOS seals without asking; an
Android key works only after the person, so sealing shows a prompt there too.

Every error is a `VaultError` with a `code`:

| Code | When |
| --- | --- |
| `CANCELLED` | The person dismissed the prompt |
| `INVALIDATED` | The enrolled biometrics changed since the entry was sealed: its key is gone, and the words are the way back |
| `UNAVAILABLE` | No biometrics, or no passcode, set up for what the entry asks |
| `NOT_FOUND`, `EXISTS` | No entry under that id, or one already |
| `INVALID_MNEMONIC`, `MNEMONIC_CHECKSUM` | The words to import are not BIP-39 English, or their checksum fails |
| `UNSUPPORTED` | The linked `@hzblj/nitro-crypto` is older than 0.1.3 (no `bip39-entropy`) |
| `INVALID_ARGUMENT`, `FAILED` | A malformed call, or anything else the platform reported |

## What protects an entry

| `protection` | Where |
| --- | --- |
| `'secure-enclave'` | iOS: a P-256 key in the Secure Enclave; the entropy sealed to it with ECIES |
| `'strongbox'` | Android: an AES-256-GCM key in a StrongBox security chip |
| `'tee'` | Android: the same key in the processor's trusted environment |
| `'software'` | The iOS simulator, an Android emulator, or a phone without secure hardware |

Each is measured from the key itself. Both platforms keep an entry on this device only, never in a backup, and lose it
when the enrolled biometrics change (an entry opened with the passcode too survives that through the passcode).

## Not in this version

Moving a wallet to another device: the words are the way, until encrypted backup and recovery come in a package of their
own. A BIP-39 passphrase. Android's device-credential fallback before API 30.

[Security](https://github.com/hzblj/crypto-vault/blob/main/SECURITY.md) · [ADR 0001](https://github.com/hzblj/crypto-vault/blob/main/docs/adr/0001-hardware-sealed-entropy.md)
