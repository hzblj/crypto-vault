# @hzblj/crypto-vault

The published package: a Nitro module that seals a wallet's BIP-39 entropy under a key the device's security hardware
holds, and opens it into `@hzblj/nitro-crypto`'s engine natively. One entry point, `.` (`src/index.ts`): `createVault`,
the types, `VaultError`.

| Path | What it is |
| --- | --- |
| `src/specs/crypto-vault.nitro.ts` | The Nitro spec: `CryptoVault`, `VaultSeed` (nitro-crypto's `NitroSeed`, an external Hybrid Object), `Protection`, `Access`, `BackupKind`. `yarn codegen` regenerates `nitrogen/generated`, which is checked in. |
| `cpp/` | `HybridCryptoVault` (the binding: checks arguments, draws entropy from the engine, calls the platform, makes the seed under a passphrase the platform normalized, seals and opens backups under a password or a passkey's PRF output through `<NitroCrypto/NitroCryptoInterop.hpp>`, reads a backup's kind, wipes every buffer; `kPasskeySalt`); `VaultPlatform.h` (the C interface of the platform halves). No cryptography. |
| `ios/VaultPlatform.swift` | The iOS half, as `@_cdecl` functions: a Secure Enclave P-256 key per entry, ECIES, the Keychain, LocalAuthentication's prompt; a passphrase's NFKD. |
| `ios/VaultPasskey.swift` | A passkey's PRF output through AuthenticationServices (iOS 18): registration, an assertion when the provider gives no output at registration, the main actor and a semaphore for the pool thread that waits. |
| `android/` | `VaultKeystore.kt` (the Android half: a Keystore AES-GCM key per entry, StrongBox where there is one, BiometricPrompt with the cipher as CryptoObject, and before API 30 a time-bound key for an entry the passcode opens too; the no-backup directory); `VaultPasskey.kt` (a passkey's PRF output through Credential Manager, JSON in and out); `VaultPassphrase.kt` (NFKD); `src/main/cpp/VaultPlatformAndroid.cpp` (the C interface over JNI); `CMakeLists.txt` links nitro-crypto's prefab package `NitroCrypto`. |
| `src/` | The facade: `vault.ts` (`createVaultOn`: normalizes and wipes words and passwords, wipes passphrases, checks the relying party and passkey choice, says a backup's kind before restoring, maps errors, wraps a `VaultSeed` as an `EphemeralWallet`), `errors.ts`, `index.ts` (the native host, once). |
| `test/` | node:test on the facade, over a stand-in host and nitro-crypto's WebAssembly engine. |

## Rules

- **The binding is the only caller of the platform.** Nothing in `ios/` or `android/` is a Hybrid Object or reachable
  from JavaScript. Keep it so: an entry's bytes, and a passkey's PRF output, must have no way to JavaScript but
  `revealMnemonic`'s words, and `backup`'s seal, which the engine makes natively.
- **Passkeys: user verification required, the passkey before the entry, this device's passkey to seal.** The PRF
  output differs without user verification; a dismissed sheet must leave the entry unopened; a passkey used over hybrid
  (`cross-platform`) is refused for sealing (ADR 0003). The salt never changes.
- **Wipe what you own.** `StackSecret` and `SecretBytes` (nitro-crypto's bridge) in C++, `fill(0)` on Kotlin arrays and
  the JNI copies, zeros written through the pointer of the Security framework's returned buffer. A new path that
  touches entropy, a passphrase or a PRF output wipes too.
- **The two platforms say the same thing.** Status, protection and access numbers are `VaultPlatform.h`'s, mirrored
  as constants in Swift and Kotlin; a new one goes into all three and into `errors.ts`.
- **The facade imports `@hzblj/nitro-crypto/adapter` at runtime,** never the root entry: that loads native code, and
  the tests run in Node.
- **Prompts are the app's words.** `unlock`, `revealMnemonic` and `backup` require one; seal prompts are Android's only.

## Commands

```bash
yarn test         # node:test with the source condition
yarn tsc:check
yarn codegen      # nitrogen, after editing the spec
yarn build        # build/ for npm
```
