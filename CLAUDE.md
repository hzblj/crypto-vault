# crypto-vault

Turborepo + Yarn 4 workspaces for **`@hzblj/crypto-vault`**: a wallet's BIP-39 entropy sealed by the Secure Enclave or
StrongBox for React Native and Expo, opened after the system's biometric prompt and handed to the
[`@hzblj/nitro-crypto`](https://github.com/hzblj/nitro-crypto) engine natively, so no secret passes through JavaScript.

Every package has its own `CLAUDE.md`: read that one before touching it.

| Path | Package | What lives there |
| --- | --- | --- |
| `packages/crypto-vault/` | `@hzblj/crypto-vault` | The Nitro module: the spec, the C++ binding (`cpp/`), the platform halves (`ios/` Swift, `android/` Kotlin and JNI), the facade (`src/`). ADRs 0001 to 0004. |
| `apps/example/` | `crypto-vault-example` (private) | Expo Router app built with `@hzblj/kara-ui`: create or import a wallet, see what protects it, unlock it (under a passphrase too) and sign, show its words, back it up under a password or a passkey and restore it, remove it. See its `CLAUDE.md`. |
| `scripts/` | | `pack-check.mjs`, `sync-versions.mjs`. |
| `docs/` | | The decisions (`adr/`). `SECURITY.md` is at the root. |

Dependencies point down: example → `@hzblj/crypto-vault` → (`@hzblj/nitro-crypto`'s native interop and engine, Nitro).
The cryptography is nitro-crypto's Zig engine; the vault adds no cryptography of its own, only the hardware's.

## Commands

```bash
yarn test                    # the facade's tests, on @hzblj/nitro-crypto/testing (the engine as WebAssembly)
yarn typecheck / yarn lint   # tsc, Biome
yarn codegen                 # nitrogen, after editing the spec (nitrogen/generated is checked in)
yarn prebuild                # a clean `expo prebuild` of the example
yarn ios / yarn android      # the example (dev client), Metro included
yarn pack:check              # what npm receives, and a consumer type-check
yarn changeset               # describe a change for the next release
```

## Conventions that bite

**nitro-crypto comes first.** The vault needs `@hzblj/nitro-crypto` 0.1.5 or later: its `bip39-entropy`,
`backup-argon2id` and `backup-hkdf-sha256` capabilities and native interop, `seedFromEntropy` under a passphrase among
it (ADRs 0008 to 0010 there). A change the vault needs in the engine is a release there first.

**Nothing JavaScript can call returns entropy, or a passkey's PRF output.** The C++ binding is the only caller of the
platform halves (`cpp/VaultPlatform.h`); they are not Hybrid Objects, so JavaScript cannot create one. `revealMnemonic`
is the one call that returns a secret, the words, and the facade wipes the buffer once it has decoded them.

**The passkey salt is part of the format.** `kPasskeySalt` in `cpp/HybridCryptoVault.cpp` is what every passkey backup
was sealed under (ADR 0003): changing it loses them all. A new one is a `v2` evaluated beside it.

**Status names, never messages.** Native code throws `CV_ERR_*` (or the engine's `NC_ERR_*`); the facade maps the name
to a `VaultError` code and drops the rest.

**The platform halves agree.** `ios/VaultPlatform.swift` and `VaultPasskey.swift`, and `android/.../VaultKeystore.kt`,
`VaultPasskey.kt` and `VaultPassphrase.kt`, implement the same C interface and the same status, protection, access and
passkey mode numbers; a change goes into both, and into the header.

**Docs copy has no em dashes.** Not in the READMEs, the JSDoc in `src/`, changesets or the example's captions.

**Commits are Jan's alone.** Author `Jan Blazej <hello@janblazej.dev>` (set locally in this repo), no co-author or
generated-by lines.

Code style is Biome-enforced (`@hzblj/biome-config`): 2 spaces, 120 cols, single quotes, no semicolons, sorted imports
and object keys. Named exports and `const` arrow functions; `type` over `interface` (the Nitro spec excepted).
