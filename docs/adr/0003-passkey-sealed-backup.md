# 3. A backup sealed under a passkey's PRF output

Accepted. Amends [0002](0002-password-sealed-backup.md).

## Context

A backup sealed under a password (ADR 0002) is as good as the password, and the person has to keep it for years. A
passkey can take its place. WebAuthn's PRF extension (CTAP2's `hmac-secret` underneath) evaluates a pseudo-random
function inside the authenticator, keyed by a secret bound to the credential, over an input the relying party
supplies, and returns 32 bytes: the same for the same credential and input on every device the passkey syncs to,
behind the platform's own user verification. Native apps reach it on iOS 18 (AuthenticationServices,
`ASAuthorizationPublicKeyCredentialPRF*`) and on Android through Credential Manager (the `prf` extension in the request
JSON, `clientExtensionResults.prf` in the response).

nitro-crypto 0.1.5 seals entropy under a 32-byte key for native callers (its ADR 0010: HKDF-SHA256 with a fresh salt,
then XChaCha20-Poly1305, 78 to 94 bytes in the `ncbk` format, key derivation 2) and reads which kind a backup is
without opening it (`backupKeyDerivation`). The vault holds the entropy natively; the PRF output must stay native too.

## Decision

- **The PRF output never reaches JavaScript.** The platform half asks for the passkey (`cv_platform_passkey_key`,
  `ios/VaultPasskey.swift`, `VaultPasskey.kt`) and writes its output into a buffer the C++ binding owns, which hands it
  to `interop::backupSealWithKey` or `backupOpenWithKey` and wipes it. JavaScript gets the sealed backup and nothing
  else, as with a password. On Android, Credential Manager answers in JSON, so the output arrives inside a string the
  JVM keeps until it collects it: it is decoded into an array that is overwritten, and the strings are beyond the
  vault, as the Security framework's buffers are (ADR 0001).
- **The relying party is the app's.** `createVault(crypto, {relyingParty})` names the domain the app is associated
  with: the `webcredentials:` associated domain and its apple-app-site-association on iOS, Digital Asset Links
  (`delegate_permission/common.get_login_creds`) on Android. A passkey belongs to a domain and the domain to the app's
  owner, so the vault picks none; it checks that the value is a domain and lowercases it. Passwords need no relying
  party, and a vault without one refuses only passkey calls (`INVALID_ARGUMENT`).
- **One salt, fixed and versioned.** The PRF is evaluated over the 32 ASCII bytes `hzblj/crypto-vault/backup-key/v1`,
  the same on both platforms, for every backup and every id. A new phone derives the same output from the passkey
  alone: nothing travels beside the backup. The salt is not a secret; it separates this use from any other the app
  makes of its passkeys' PRF, which gets an unrelated output from another input. The engine's HKDF salt, fresh per
  backup, still gives each backup a key of its own though they share the PRF output. Thirty-two bytes, so the input
  is valid however a platform passes it on (WebAuthn hashes it with the `WebAuthn PRF` prefix; raw `hmac-secret` takes
  exactly 32 bytes). A later salt would be the PRF's second input in the same ceremony, not a guess.
  - Not a salt per id: a backup restored under another id would never open, and the id would have to travel.
  - Not a random salt kept beside the backup: the engine's format has no room for it, and a second record would have
    to travel with the backup and stay in step with it.
- **Discoverable credentials: the person picks the passkey.** `backup(id, {passkey: {name}})` registers a new passkey
  (resident key, platform attachment, the person's name for it in their passwords app) and seals under it;
  `{passkey: true}` and every restore ask for a passkey of the relying party with an empty allow list, and the person
  picks from the system's sheet. No credential id is returned or kept: a new phone has what the store carried and what
  the passkey provider synced, and the PRF output itself binds a backup to its passkey, so a wrong pick fails as
  `WRONG_PASSKEY` and loses nothing. The name is how the person tells the app's passkeys apart.
  - Not a credential id beside the backup: one more record for `@hzblj/crypto-recovery` to carry, and the same failure
    as a wrong pick when it goes missing. It can come later, as an optional hint.
- **A fresh user handle for every new passkey.** A passkey with the same relying party and user handle replaces the
  one before it, and every backup sealed under that one would be lost with it.
- **User verification is always required.** The PRF extension keys its output differently with and without it (CTAP2
  `hmac-secret` has a secret for each), so a backup must open the way it was sealed.
- **Registration asks for the output, then signs in when it must.** The registration request carries the salt; a
  provider that returns the output at once is used at once. One that only says it supports the extension
  (`prf.enabled`, `isSupported`: iOS 18's iCloud Keychain among them) is asked again straight away for the passkey just
  made, its credential id in the allow list: a second sheet. A provider that does not support it is
  `PASSKEY_UNSUPPORTED`, and the passkey it made stays in the person's passwords app: neither platform lets an app
  delete one.
- **Only this device's passkeys seal.** A passkey used over the hybrid transport, from another device by a QR code,
  answers with the attachment `cross-platform`, and sealing refuses it (`PASSKEY_UNSUPPORTED`). Apple confirmed a bug
  that returned other PRF outputs over hybrid than on the device itself (fixed between its own devices in iOS 18.4),
  and mismatches with other platforms are still reported: a backup sealed under such an output might never open again.
  Restoring over hybrid is allowed, as the worst it can do is `WRONG_PASSKEY`.
- **The kinds do not cross, and say so first.** `restore` reads a backup's kind (`backupKeyDerivation`, also
  `vault.backupKind`) before any prompt, Argon2id or passkey sheet, and refuses the other method: `NEEDS_PASSKEY`,
  `NEEDS_PASSWORD`.
- **The passkey first, then the entry.** A sheet the person dismisses leaves the entry unopened. A missing entry fails
  before any sheet, and above all before a passkey is made for a backup that cannot be.
- **No server.** The challenge is random and nobody checks the signature: the vault wants the PRF output, which the
  authenticator gives only after user verification. An app that signs people in with passkeys keeps doing that against
  its server; the backup's passkey is a credential of its own under the same relying party.
- **Errors say what to do.** `CANCELLED` (the sheet dismissed), `PASSKEY_UNSUPPORTED` (before iOS 18 or Android 9, a
  provider without the extension, or a passkey on another device when sealing), `PASSKEY_NOT_FOUND` (Android: no
  passkey of the relying party here; iOS shows its own sheet instead), `WRONG_PASSKEY` (the passkey does not open the
  backup, or the backup was changed), `UNSUPPORTED` (an engine older than 0.1.5). `passkeySupported` reports the engine
  and the system; whether a provider evaluates the extension only that provider's passkey can say.

## Consequences

- A wallet can be backed up with nothing to remember. The backup is as safe as the passkey: whoever can use the passkey
  (a device it synced to, the provider's account recovery) can open it, and losing the passkey loses the backup. An app
  offers the words, or a password backup, beside it.
- iCloud Keychain keeps passkeys on Apple devices and Google Password Manager on Android and Chrome: a backup sealed on
  an iPhone opens on an Android phone only through a provider that syncs to both and evaluates the extension.
- The first backup can ask three times: the new passkey, the passkey again where its provider gives no output at
  registration, and the entry.
- The app's domain must name the app (apple-app-site-association, assetlinks.json); a mismatch is the platform's
  failure, `FAILED`, before anything is sealed.
- Changing the salt would lose every backup sealed under it: it is part of the format, versioned in its last bytes.
