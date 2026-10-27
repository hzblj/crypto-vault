# @hzblj/crypto-vault

[![npm](https://img.shields.io/npm/v/@hzblj/crypto-vault.svg)](https://www.npmjs.com/package/@hzblj/crypto-vault)
[![license](https://img.shields.io/npm/l/@hzblj/crypto-vault.svg)](https://github.com/hzblj/crypto-vault/blob/main/LICENSE)

A wallet's BIP-39 entropy sealed by the Secure Enclave or StrongBox, for React Native and Expo. Each entry opens only
after the system's biometric prompt, straight into the [`@hzblj/nitro-crypto`](https://github.com/hzblj/nitro-crypto)
engine: the seed is made natively, and JavaScript receives a wallet, never the entropy or the words behind it.

<p>
  <img alt="The example on the iOS simulator: a wallet in the vault, opened with Face ID. The simulator has no Secure Enclave, so it says Software only" height="560" src="https://raw.githubusercontent.com/hzblj/crypto-vault/main/media/ios-vault.png" />
  <img alt="The same on the Android emulator, where the entry opens with the fingerprint or the device PIN" height="560" src="https://raw.githubusercontent.com/hzblj/crypto-vault/main/media/android-vault.png" />
</p>

```sh
npx expo install @hzblj/crypto-vault @hzblj/nitro-crypto react-native-nitro-modules
```

Then a development build (`npx expo prebuild`, `npx expo run:ios`): the vault is native code, not in Expo Go. On iOS,
add the Face ID usage description (`ios.infoPlist.NSFaceIDUsageDescription` in the app config). Needs
`@hzblj/nitro-crypto` 0.1.5 or later. Backups under a passkey need a domain associated with the app as well
([below](#backups-under-a-passkey)).

## The API

```ts
import {createVault, isVaultError} from '@hzblj/crypto-vault'

const vault = createVault(crypto) // over the engine the app already made, with its chains
// For passkey backups, with the domain the app is associated with: createVault(crypto, {relyingParty: 'example.com'})
```

| | |
| --- | --- |
| `vault.create(id, {words?, access?, prompt?, passphrase?})` | A fresh wallet (12 to 24 words), its entropy drawn and sealed natively, with a passphrase check if given |
| `vault.importMnemonic(id, words, {access?, prompt?, passphrase?})` | A wallet restored from its words, sealed under `id`; the words cross as bytes the vault overwrites |
| `vault.unlock(id, {prompt, passphrase?, verifyPassphrase?})` | After the system prompt, the entry as an `EphemeralWallet` in the engine, under a BIP-39 passphrase if given: `WRONG_PASSPHRASE` for another than the entry's |
| `vault.setPassphrase(id, {passphrase, prompt})` | After the system prompt, the passphrase `unlock` checks from now on, or none for `null` |
| `vault.revealMnemonic(id, {prompt})` | After the system prompt, the entry's words, for the user to write down |
| `vault.backup(id, {password, prompt})` | After the system prompt, the entry sealed under a password: a `Uint8Array` that is safe to store anywhere |
| `vault.backup(id, {passkey, prompt})` | The same under a passkey's PRF output: `{name}` registers a new passkey, `true` takes one the person has |
| `vault.restore(id, backup, {password, access?, prompt?, passphrase?})` | A wallet restored from a backup, sealed under `id`, the entropy never in JavaScript |
| `vault.restore(id, backup, {passkey: true, access?, prompt?, passphrase?})` | The same for a backup sealed under a passkey, which the person picks |
| `vault.backupKind(backup)` | `'password'` or `'passkey'`: what opens a backup, read from its header |
| `vault.has(id)`, `vault.protection(id)`, `vault.access(id)` | Whether there is an entry, what holds its key, who opens it |
| `vault.availableProtection`, `vault.backupSupported`, `vault.passkeySupported` | What a new entry gets on this device; whether the engine seals backups; whether passkey backups work here |
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
| `WEAK_PASSWORD` | A backup password shorter than 8 characters |
| `WRONG_PASSWORD` | The password does not open the backup, or the backup was changed (the two fail alike) |
| `WRONG_PASSKEY` | The passkey the person picked does not open the backup, or the backup was changed |
| `WRONG_PASSPHRASE` | The entry was given another BIP-39 passphrase: the wallet this one makes is not its wallet |
| `NEEDS_PASSKEY`, `NEEDS_PASSWORD` | The backup is sealed under the other kind of secret: said before anything is asked |
| `PASSKEY_UNSUPPORTED` | No passkeys with the PRF extension here (before iOS 18 or Android 9), a provider without it, or, when sealing, a passkey on another device |
| `PASSKEY_NOT_FOUND` | Android: no passkey of the relying party on this device (iOS shows its own sheet instead) |
| `INVALID_BACKUP` | The bytes to restore are not a backup this engine reads |
| `UNSUPPORTED` | The linked `@hzblj/nitro-crypto` is older than 0.1.3 (no `bip39-entropy`), than 0.1.4 for backups, or than 0.1.5 for passkey backups |
| `INVALID_ARGUMENT`, `FAILED` | A malformed call, or anything else the platform reported |

`CANCELLED` covers the passkey sheet too.

## What protects an entry

| `protection` | Where |
| --- | --- |
| `'secure-enclave'` | iOS: a P-256 key in the Secure Enclave; the entropy sealed to it with ECIES |
| `'strongbox'` | Android: an AES-256-GCM key in a StrongBox security chip |
| `'tee'` | Android: the same key in the processor's trusted environment |
| `'software'` | The iOS simulator, an Android emulator, or a phone without secure hardware |

Each is measured from the key itself. Both platforms keep an entry on this device only, never in a backup, and lose it
when the enrolled biometrics change (an entry opened with the passcode too survives that through the passcode).

On Android before API 30, BiometricPrompt takes no device credential beside a key that needs the person for every
use, so an entry opened with the passcode too gets a key that works for 5 seconds after the person authenticates, with
biometrics or the device PIN, pattern or password, and the vault makes its cipher inside that window
([ADR 0004](https://github.com/hzblj/crypto-vault/blob/main/docs/adr/0004-device-credential-before-api-30.md)). API 30
and later keep a key for every use.

## A BIP-39 passphrase

```ts
// Ask the person for it twice: the vault cannot tell a typo from another wallet's passphrase.
await vault.importMnemonic('main', words, {passphrase})
await vault.setPassphrase('main', {passphrase, prompt: 'Check your passphrase'}) // an entry that has none yet

const wallet = await vault.unlock('main', {passphrase, prompt: 'Unlock your wallet'}) // WRONG_PASSPHRASE for a typo
await vault.unlock('main', {passphrase: decoy, prompt: 'Unlock', verifyPassphrase: false}) // any passphrase's wallet
await vault.setPassphrase('main', {passphrase: null, prompt: 'Stop checking'}) // no check from now on
```

The passphrase (the "25th word") makes another seed from the same entropy, so the same words make a different wallet
for every passphrase. BIP-39 gives a passphrase no checksum: a mistyped one makes a valid, empty wallet, and nothing in
the words can tell. So the vault remembers what to expect. When an entry is given a passphrase (`create`,
`importMnemonic` and `restore` take one, `setPassphrase` gives or takes it later), the vault computes the BIP-32
fingerprint of the wallet it makes, natively, and seals those 4 bytes with the entropy, inside the Secure Enclave's
ECIES or the Keystore's AES-GCM: not in the entry's readable metadata, and never the passphrase itself. `unlock` opens
the entry, makes the seed and compares fingerprints; another passphrase's wallet is disposed before JavaScript sees it,
and the call fails with `WRONG_PASSPHRASE`. Leaving the passphrase out is the empty passphrase, which is checked like
any other.

- **Ask for it twice.** What `create`, `importMnemonic`, `restore` or `setPassphrase` is given is the passphrase
  `unlock` holds every other to: a typo there is the one it accepts.
- **One in 2^32.** The fingerprint is 4 bytes, so a wrong passphrase passes the check about once in four billion tries.
  That catches typos, not a search: the passphrase is no secret the check protects.
- **Hidden wallets.** A stored fingerprint says which passphrase is the real one to anyone who can open the entry (it
  takes the person's biometrics or passcode). Whoever keeps decoy or hidden wallets under other passphrases unlocks
  with `verifyPassphrase: false`, or gives the entry no passphrase at all.
- **Entries from before 0.3.0,** and entries given none, hold no check and open under any passphrase, as before: show
  `wallet.fingerprint` for the person to compare. `setPassphrase` gives one a check (Android asks twice, once to open
  and once to seal again; iOS once).
- **Backups hold the entropy alone.** A restored wallet needs its passphrase again: pass it to `restore` to check it
  there too.

It crosses into native code as UTF-8 bytes the vault overwrites, as typed words do; the platform NFKD-normalizes it
(Foundation on iOS, `java.text.Normalizer` on Android), as BIP-39 requires, so the same characters typed on any
keyboard make the seed other wallets make. At most 1024 bytes once normalized. An empty passphrase is no passphrase.

## Moving a wallet to another device

An entry stays on its device. Two ways take a wallet elsewhere: its words, and a backup. `backup` opens the entry
after the system prompt and has the engine seal its entropy under a password (Argon2id at 64 MiB, then
XChaCha20-Poly1305, nitro-crypto's ADR 0009): 87 to 103 bytes that only the password opens, safe in iCloud Keychain,
Android Block Store ([`@hzblj/crypto-recovery`](https://github.com/hzblj/crypto-recovery) keeps them there) or a file.
`restore` opens a backup natively, straight into a new entry under this device's hardware.

```ts
const backup = await vault.backup('main', {password, prompt: 'Back up your wallet'})
// on the new device
await vault.restore('main', backup, {password})
```

The password is NFC-normalized and needs at least 8 characters; an app should ask for more. It is a string in
JavaScript on its way in, as typed words are, and crosses as bytes the vault overwrites.

## Backups under a passkey

A passkey can take the password's place: nothing to remember. The vault asks the system for a passkey of the app's
relying party, evaluates its PRF extension natively, and has the engine seal the entropy under the 32-byte output
(HKDF-SHA256, then XChaCha20-Poly1305, nitro-crypto's ADR 0010): 78 to 94 bytes, as safe to store anywhere as a
password backup. The output never reaches JavaScript.

```ts
const vault = createVault(crypto, {relyingParty: 'wallet.example.com'})

if (vault.passkeySupported) {
  // A new passkey, named for the person's passwords app; `passkey: true` takes one they already have.
  const backup = await vault.backup('main', {passkey: {name: 'Main wallet'}, prompt: 'Back up your wallet'})
  // On the new phone, once the passkey has synced: the person picks it from the system's sheet.
  await vault.restore('main', backup, {passkey: true})
}

vault.backupKind(backup) // 'passkey' or 'password': what to ask for before restoring
```

- **iOS 18 and Android 9** (Credential Manager, through Google Play services before Android 14), and a passwords app
  whose passkeys evaluate the PRF extension: iCloud Keychain and Google Password Manager do; a provider that does not
  is `PASSKEY_UNSUPPORTED` when its passkey answers. `passkeySupported` reports the system and the engine only.
- **The person picks the passkey** (a discoverable credential): nothing but the backup has to reach the new phone. A
  wrong pick is `WRONG_PASSKEY`, and nothing is lost; the name given at registration tells the app's passkeys apart.
- **The PRF salt is fixed:** the 32 ASCII bytes `hzblj/crypto-vault/backup-key/v1`, for every backup and id, so the
  same passkey gives the same output on any device it syncs to. The engine's own salt, fresh per backup, gives each
  backup a key of its own.
- **Only a passkey on this device seals.** One used from another device over a QR code is refused for sealing
  (`PASSKEY_UNSUPPORTED`): platforms have returned different PRF outputs over that transport. Restoring with one is
  allowed.
- **Some providers give the output only at sign-in,** so the first backup may show the passkey sheet twice (the new
  passkey, then the same one again) before the entry's own prompt.
- **The backup is as safe as the passkey,** and as lost: whoever can use the passkey (a device it synced to, the
  provider's account) opens it. Offer the words or a password backup beside it. iCloud Keychain's passkeys stay on Apple
  devices and Google Password Manager's on Android: a backup crosses platforms only with a provider that syncs to both.

### App setup

The relying party is a domain the app is associated with, both ways:

- **iOS:** the Associated Domains capability with `webcredentials:wallet.example.com`. In Expo, the app config's
  `ios.associatedDomains: ['webcredentials:wallet.example.com']` (no plugin needed); in a bare app, the
  `com.apple.developer.associated-domains` entitlement. The domain serves `/.well-known/apple-app-site-association`:

  ```json
  {"webcredentials": {"apps": ["ABCDE12345.com.example.wallet"]}}
  ```

- **Android:** the domain serves `/.well-known/assetlinks.json` naming the app's package and the SHA-256 of every
  certificate that signs it (the debug keystore's too, to try it in development):

  ```json
  [{
    "relation": ["delegate_permission/common.handle_all_urls", "delegate_permission/common.get_login_creds"],
    "target": {"namespace": "android_app", "package_name": "com.example.wallet", "sha256_cert_fingerprints": ["AB:CD:…"]}
  }]
  ```

  Nothing goes into the app's manifest. Credential Manager comes with the vault's Android dependencies.

A domain that does not name the app fails as `FAILED` from the platform, before anything is sealed. Passkeys need a
build signed with the entitlement and a passwords app signed in to its account: try them on a device.

## Not in this version

A credential id to send the person straight to one passkey (the system's sheet lists the relying party's). Removing a
passkey a provider without the PRF extension made: neither platform lets an app delete one.

[Security](https://github.com/hzblj/crypto-vault/blob/main/SECURITY.md) · [ADR 0001](https://github.com/hzblj/crypto-vault/blob/main/docs/adr/0001-hardware-sealed-entropy.md) · [ADR 0002](https://github.com/hzblj/crypto-vault/blob/main/docs/adr/0002-password-sealed-backup.md) · [ADR 0003](https://github.com/hzblj/crypto-vault/blob/main/docs/adr/0003-passkey-sealed-backup.md) · [ADR 0004](https://github.com/hzblj/crypto-vault/blob/main/docs/adr/0004-device-credential-before-api-30.md) · [ADR 0005](https://github.com/hzblj/crypto-vault/blob/main/docs/adr/0005-passphrase-check.md)
