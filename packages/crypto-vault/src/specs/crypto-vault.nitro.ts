import type {NitroSeed} from '@hzblj/nitro-crypto'
import type {HybridObject} from 'react-native-nitro-modules'

/**
 * The native boundary. Nitrogen generates the C++ spec from this file; `cpp/` implements it over nitro-crypto's
 * native interop and the platform half (`ios/`, `android/`). No call here takes or returns a wallet's entropy, or a
 * passkey's PRF output: `unlock` hands back a seed the engine made natively, `backup` and `backupWithPasskey` hand
 * back the entropy sealed under a password or a passkey, and only `revealMnemonic` returns a secret, the words, for
 * the moment a user writes them down.
 *
 * Errors thrown across it carry a status name (`CV_ERR_CANCELLED`, `NC_ERR_MNEMONIC_CHECKSUM`), never an input.
 */

type Native = {android: 'c++'; ios: 'c++'}

/**
 * What holds the key an entry is sealed under: the Secure Enclave (iOS), a StrongBox security chip or the processor's
 * trusted environment (Android), or nothing but the operating system's software (a simulator, an old phone).
 */
export type Protection = 'secure-enclave' | 'strongbox' | 'tee' | 'software'

/** Who opens an entry: biometrics only, or biometrics with the device passcode as the fallback. */
export type Access = 'biometrics' | 'biometrics-or-passcode'

/**
 * What opens a backup: the password it was sealed under (Argon2id, nitro-crypto's ADR 0009), or the passkey whose PRF
 * output it was sealed under (HKDF-SHA256, its ADR 0010).
 */
export type BackupKind = 'password' | 'passkey'

/** An unsealed entry: the seed inside the engine and the length of the mnemonic behind it. */
export interface VaultSeed {
  readonly seed: NitroSeed
  readonly words: number
}

/** The vault. One per runtime, created by name through `NitroModules`. */
export interface CryptoVault extends HybridObject<Native> {
  /** The strongest protection this device gives a new entry. */
  readonly availableProtection: Protection
  /** Whether the linked nitro-crypto engine has what the vault needs (`bip39-entropy`). */
  readonly supported: boolean
  /** Whether it seals backups too (`backup-argon2id`, nitro-crypto 0.1.4). */
  readonly backupSupported: boolean
  /**
   * Whether backups under a passkey work here: the engine seals under a key (`backup-hkdf-sha256`, nitro-crypto 0.1.5)
   * and the system has passkeys with the PRF extension (iOS 18, Android 9 with Credential Manager).
   */
  readonly passkeySupported: boolean

  /** Whether an entry exists under `id`. */
  has(id: string): boolean
  /** What protects the entry under `id`. Throws `CV_ERR_NOT_FOUND`. */
  protection(id: string): Protection
  /** Who opens the entry under `id`. Throws `CV_ERR_NOT_FOUND`. */
  access(id: string): Access

  /**
   * Fresh entropy for a mnemonic of `words` words, from the engine's CSPRNG, sealed under `id`. Android asks for the
   * person first (`prompt`): its keys open for encryption too only after them. A `passphrase` (UTF-8, empty for none)
   * is sealed with the entropy as the fingerprint of the wallet it makes, for `unlock` to check. Throws `CV_ERR_EXISTS`.
   */
  create(id: string, words: number, access: Access, prompt: string, passphrase: ArrayBuffer): Promise<void>
  /**
   * The entropy of `mnemonic` (NFKD-normalized UTF-8, single spaces) sealed under `id`: a wallet restored from words,
   * with a passphrase check as `create` seals one. The bridge copies the bytes before it returns; the facade overwrites
   * its own.
   */
  importMnemonic(
    id: string,
    mnemonic: ArrayBuffer,
    access: Access,
    prompt: string,
    passphrase: ArrayBuffer
  ): Promise<void>
  /**
   * After the system prompt, the entry's seed, made natively in nitro-crypto's engine under `passphrase` (UTF-8, empty
   * for none), which the platform NFKD-normalizes first. When the entry holds a passphrase check and `verifyPassphrase`
   * is true, a seed of another fingerprint is disposed and `CV_ERR_WRONG_PASSPHRASE` thrown. The bridge copies the
   * passphrase before it returns; the facade overwrites its own.
   */
  unlock(id: string, prompt: string, passphrase: ArrayBuffer, verifyPassphrase: boolean): Promise<VaultSeed>
  /**
   * After the system prompt, the entry re-sealed with the check of `passphrase` (UTF-8), or with none for an empty one:
   * the same entropy, under the same key. Android's key asks once more to seal.
   */
  setPassphrase(id: string, passphrase: ArrayBuffer, prompt: string): Promise<void>
  /** After the system prompt, the entry's words as UTF-8, for the user to write down. The facade wipes the buffer. */
  revealMnemonic(id: string, prompt: string): Promise<ArrayBuffer>
  /**
   * After the system prompt, the entry's entropy sealed under `password` (NFC-normalized UTF-8) by the engine: a
   * backup that is safe to store anywhere, as the password keeps it. Argon2id takes about half a second, natively. The
   * bridge copies the password before it returns; the facade overwrites its own.
   */
  backup(id: string, password: ArrayBuffer, prompt: string): Promise<ArrayBuffer>
  /**
   * The entropy `backup` holds under `password`, sealed under `id`: a wallet restored from a backup, without the
   * entropy passing through JavaScript. Throws `CV_ERR_EXISTS` before it opens anything, `CV_ERR_INVALID_BACKUP` for
   * bytes that are no backup this engine reads, `CV_ERR_NEEDS_PASSKEY` for a backup sealed under a passkey, and
   * `NC_ERR_VERIFICATION_FAILED` for a wrong password or a changed backup alike. A `passphrase` (UTF-8, empty for
   * none) is sealed as its check, as `create` seals one: a backup holds the entropy alone.
   */
  restore(
    id: string,
    backup: ArrayBuffer,
    password: ArrayBuffer,
    access: Access,
    prompt: string,
    passphrase: ArrayBuffer
  ): Promise<void>
  /**
   * After the system's passkey sheet for `relyingParty` and the entry's prompt, the entry's entropy sealed by the engine
   * under the passkey's PRF output, which never leaves native code. `name` registers a new passkey under that name
   * first; empty uses one the person picks, which must be on this device. Throws `CV_ERR_NOT_FOUND` before any sheet.
   */
  backupWithPasskey(id: string, relyingParty: string, name: string, prompt: string): Promise<ArrayBuffer>
  /**
   * The entropy `backup` holds under a passkey of `relyingParty`, sealed under `id`. Throws `CV_ERR_EXISTS`,
   * `CV_ERR_INVALID_BACKUP` and `CV_ERR_NEEDS_PASSWORD` before any sheet, and `CV_ERR_WRONG_PASSKEY` when the passkey
   * the person picked does not open it. A `passphrase` is sealed as its check, as `create` seals one.
   */
  restoreWithPasskey(
    id: string,
    backup: ArrayBuffer,
    relyingParty: string,
    access: Access,
    prompt: string,
    passphrase: ArrayBuffer
  ): Promise<void>
  /** What opens `backup`, read from its header by the engine. Throws `CV_ERR_INVALID_BACKUP`. */
  backupKind(backup: ArrayBuffer): BackupKind
  /** Deletes the entry and the key it is sealed under. Idempotent. */
  remove(id: string): void
}
