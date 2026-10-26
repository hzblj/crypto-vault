# 2. A backup sealed under a password by the engine, restored natively

Accepted. Amends [0001](0001-hardware-sealed-entropy.md).

## Context

An entry is this device's only (ADR 0001): a new phone, a lost one or a reset is the end of it, and the words are the
one way back. Most wallets offer a second: an encrypted backup the platform keeps in its own end-to-end encrypted store,
restored on another device with a password.

nitro-crypto 0.1.4 seals BIP-39 entropy under a password (its ADR 0009: Argon2id, XChaCha20-Poly1305, a versioned
format) for native callers. The vault is one: it holds the entropy natively, and must keep it native on its way into a
backup and out of it.

## Decision

- **`backup(id, password, prompt)`** opens the entry after the system prompt, as `unlock` does, and has the engine seal
  its entropy under the password through `interop::backupSeal`. It returns the sealed bytes, 87 to 103 of them, to
  JavaScript: what keeps them is the password, so they may go anywhere.
- **`restore(id, backup, password, access, prompt)`** opens a backup through `interop::backupOpen` and seals the
  entropy under a new hardware key for `id`, as `importMnemonic` does with words. The entropy goes from the engine to
  the platform half on the stack and is zeroed; JavaScript never holds it. An `id` that is taken fails before Argon2id
  runs and before any prompt.
- **Where a backup goes is not the vault's concern.** It returns bytes and takes bytes. Keeping them in iCloud Keychain
  or Block Store is [`@hzblj/crypto-recovery`](https://github.com/hzblj/crypto-recovery)'s job, which never sees a
  password or entropy.
- **The password is NFC-normalized UTF-8, at least 8 characters.** NFC is RFC 8265's OpaqueString: the same password
  typed on another keyboard opens what this one sealed. The facade counts characters, not bytes, refuses fewer with
  `WEAK_PASSWORD`, and overwrites the bytes it handed over once the bridge has its copy, as it does with words.
- **Errors say what to do.** `WRONG_PASSWORD` (the engine's `NC_ERR_VERIFICATION_FAILED`, which a changed backup gives
  too), `INVALID_BACKUP` (bytes that are no backup this engine reads), `UNSUPPORTED` (an engine older than 0.1.4).

## Consequences

- A wallet survives its device: through its words, or through a backup and its password.
- A backup is as strong as its password. Argon2id makes each guess cost about half a second and 64 MiB; an app should
  ask for more than the minimum, and say that the password cannot be recovered.
- The backup password is a string in JavaScript on its way in, as typed words are (nitro-crypto's ADR 0005).
- A passkey (WebAuthn's PRF) in place of the password is a later key derivation in the engine's format.
