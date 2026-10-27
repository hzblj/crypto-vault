# example

The example app for `@hzblj/crypto-vault`: one wallet in the vault, end to end. Create one or restore one from words,
see what protects it, unlock it (Face ID or the fingerprint, under a BIP-39 passphrase if one is typed, and its
fingerprint shown) and sign an Ethereum message with it, show its words, back it up under a password or a new passkey,
remove it and restore it from the backup. Built from `@hzblj/kara-ui` like every hzblj example. Private; never
published.

| Path | What it is |
| --- | --- |
| `app/` | Expo Router: one stack under a native large title, `index` the vault screen. Route files only re-export a screen from `src/`. |
| `src/features/vault/` | The vault screen. |
| `src/core/engine.ts` | The engine (`@hzblj/crypto-ethereum` registered) and the vault over it, once per run, with the passkey domain from the app config; a missing native module is a message, not a crash. |
| `e2e/` | Maestro: `vault` (create, unlock and sign, words, restore from words) and `backup` (back up, a wrong password, restore), over `steps/`; `run.mjs` runs them. |
| `src/components/` | `Page`, `Section`, `Rows`, `Notice`, `PhraseGrid`, as the other hzblj examples draw them. |
| `src/config/theme.ts` | The amber accent, apart from the other examples' emerald and indigo. |
| `assets/` | The icon (a vault on amber) and the Material Symbols in `icons/`, native assets through kara's plugin. |

**The vault runs from source; nitro-crypto from npm.** `metro.config.js` maps the workspace package to its `source`
export.

**Passkeys need a domain:** build with `VAULT_PASSKEY_DOMAIN=<domain>` (app.config.ts adds
`webcredentials:<domain>` to the iOS entitlements and hands the domain to `createVault`). The domain serves an
apple-app-site-association naming `<team id>.com.hzblj.cryptovault.example` and an assetlinks.json naming the package
with the signing certificate's SHA-256 (the debug keystore's, for a debug build). Without it the passkey buttons stay
off. No Maestro flow covers passkeys: the system's sheet needs a signed build on a device.

**Face ID on the simulator:** Features, Face ID, Enrolled; then Matching Face when the prompt is up. The simulator has
no Secure Enclave, so its entries say `software`; an iPhone's say `secure-enclave`.

**Native changes need a rebuild**: `yarn prebuild`, then a native run.
