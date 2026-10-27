import type {CryptoEngine, EphemeralWallet, MnemonicLength} from '@hzblj/nitro-crypto'
// The entry that loads no native code, so the facade runs in tests too.
import {utf8} from '@hzblj/nitro-crypto/adapter'

import {native, nativeAsync, VaultError} from './errors'
import type {Access, BackupKind, CryptoVault, Protection} from './specs/crypto-vault.nitro'

export type VaultOptions = {
  /**
   * The relying party passkey backups belong to: the domain the app is associated with (`webcredentials:` on iOS,
   * Digital Asset Links on Android), such as `wallet.example.com`. Only passkey backups need it.
   */
  readonly relyingParty?: string
}

export type SealOptions = {
  /** Who opens the entry: biometrics only (the default), or biometrics with the device passcode as the fallback. */
  readonly access?: Access
  /** What Android's prompt says: its keys open for sealing too only after the person. iOS asks no one to seal. */
  readonly prompt?: string
}

export type CreateOptions = SealOptions & {
  /** The length of the mnemonic behind the entry: 12 (the default) to 24 words. */
  readonly words?: MnemonicLength
}

export type PromptOptions = {
  /** What the system's prompt says: why the app asks. */
  readonly prompt: string
}

export type UnlockOptions = PromptOptions & {
  /**
   * A BIP-39 passphrase, the "25th word": the wallet the words make under it, which the vault never stores. Every
   * passphrase opens a wallet, so a mistyped one opens a different, empty wallet, silently: show `wallet.fingerprint`
   * so the person can tell. NFKD-normalized natively, at most 1024 bytes of UTF-8 after that.
   */
  readonly passphrase?: string
}

/**
 * Which passkey seals a backup: a new one, registered under `name` (what the person's passwords app lists, such as
 * "Main wallet"), or `true` for one the person already has for the app, on this device.
 */
export type PasskeyChoice = true | {readonly name: string}

export type PasswordBackupOptions = PromptOptions & {
  /** What seals the backup, and the only thing that opens it again: at least 8 characters. */
  readonly password: string
  readonly passkey?: never
}

export type PasskeyBackupOptions = PromptOptions & {
  /** The passkey whose PRF output seals the backup, and the only thing that opens it again. */
  readonly passkey: PasskeyChoice
  readonly password?: never
}

export type BackupOptions = PasswordBackupOptions | PasskeyBackupOptions

type RestoreTarget = {
  /** Who opens the restored entry: biometrics only (the default), or biometrics with the device passcode. */
  readonly access?: Access
  /** What Android's prompt says: its keys open for sealing too only after the person. */
  readonly prompt?: string
}

export type PasswordRestoreOptions = RestoreTarget & {
  /** The password the backup was sealed under. */
  readonly password: string
  readonly passkey?: never
}

export type PasskeyRestoreOptions = RestoreTarget & {
  /** The passkey the backup was sealed under, which the person picks from the system's sheet. */
  readonly passkey: true
  readonly password?: never
}

export type RestoreOptions = PasswordRestoreOptions | PasskeyRestoreOptions

/**
 * A device's vault of wallets: each entry a wallet's BIP-39 entropy, sealed under a key the Secure Enclave or StrongBox
 * holds (or the platform's software, where there is neither, and `protection` says so), opened only after the system's
 * biometric prompt. Unlocking hands the engine a seed natively: JavaScript receives a wallet and never a word or byte
 * of what is behind it. Only `revealMnemonic` returns a secret, the words, for the moment a user writes them down.
 * `backup` returns the entropy sealed under a password or a passkey, which is safe to store anywhere, and `restore`
 * opens it straight into a new entry.
 */
export type Vault<Chains> = {
  /** The strongest protection this device gives a new entry. */
  readonly availableProtection: Protection
  readonly has: (id: string) => boolean
  /** What protects the entry under `id`. */
  readonly protection: (id: string) => Protection
  /** Who opens the entry under `id`. */
  readonly access: (id: string) => Access
  /** A fresh wallet, generated and sealed natively under `id`. */
  readonly create: (id: string, options?: CreateOptions) => Promise<void>
  /** A wallet restored from its words, sealed under `id`. The words cross as bytes this package overwrites afterwards. */
  readonly importMnemonic: (id: string, mnemonic: string, options?: SealOptions) => Promise<void>
  /** After the system prompt, the entry under `id` as a wallet in the engine, under a BIP-39 passphrase if given. */
  readonly unlock: (id: string, options: UnlockOptions) => Promise<EphemeralWallet<Chains>>
  /** After the system prompt, the words of the entry under `id`, for the user to write down. */
  readonly revealMnemonic: (id: string, options: PromptOptions) => Promise<string>
  /** Whether the linked engine seals backups (`@hzblj/nitro-crypto` 0.1.4 and later). */
  readonly backupSupported: boolean
  /**
   * Whether backups under a passkey work here: the engine seals under a key (`@hzblj/nitro-crypto` 0.1.5) and the
   * system has passkeys with the PRF extension (iOS 18, Android 9). Whether a given passkey's provider evaluates it,
   * only that passkey says: `PASSKEY_UNSUPPORTED` when it does not.
   */
  readonly passkeySupported: boolean
  /**
   * After the system prompt, the entry under `id` sealed under a password (87 to 103 bytes; Argon2id makes each guess
   * cost about half a second and 64 MiB, natively) or under a passkey's PRF output (78 to 94 bytes, after the system's
   * passkey sheet). Either is safe to store anywhere (iCloud Keychain, Block Store, a file): the password or the
   * passkey keeps it.
   */
  readonly backup: (id: string, options: BackupOptions) => Promise<Uint8Array>
  /**
   * A wallet restored from a backup, sealed under `id`: with the password or the passkey it was sealed under, and
   * `NEEDS_PASSKEY` or `NEEDS_PASSWORD` before anything is asked when the backup is the other kind. The entropy goes
   * from the engine to the hardware natively.
   */
  readonly restore: (id: string, backup: Uint8Array, options: RestoreOptions) => Promise<void>
  /** What opens `backup`, its password or its passkey, read from its header without opening it. */
  readonly backupKind: (backup: Uint8Array) => BackupKind
  /** Deletes the entry under `id` and its key. Idempotent. */
  readonly remove: (id: string) => void
}

const DEFAULT_SEAL_PROMPT = 'Protect your wallet'

/** As other wallets read words: NFKD, lowercase, single spaces. The engine checks them. */
const normalize = (mnemonic: string) => mnemonic.normalize('NFKD').trim().toLowerCase().split(/\s+/).join(' ')

/** A backup password's minimum, in characters. */
export const MIN_PASSWORD_LENGTH = 8

/**
 * A password as the engine takes it: NFC (RFC 8265's OpaqueString), so the same characters typed on another keyboard
 * seal and open alike, then UTF-8, in a buffer of its own the caller overwrites.
 */
const passwordBytes = (password: unknown) => {
  if (typeof password !== 'string' || [...password.normalize('NFC')].length < MIN_PASSWORD_LENGTH) {
    throw new VaultError('WEAK_PASSWORD')
  }

  const bytes = utf8.encode(password.normalize('NFC'))

  return {buffer: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer, bytes}
}

/** Runs `call` with the password's bytes, and overwrites them once the bridge has its copy, success or not. */
const withPassword = async <T>(password: unknown, call: (buffer: ArrayBuffer) => Promise<T>): Promise<T> => {
  const {buffer, bytes} = passwordBytes(password)

  try {
    return await nativeAsync(() => call(buffer))
  } finally {
    bytes.fill(0)
    new Uint8Array(buffer).fill(0)
  }
}

/**
 * Runs `call` with a passphrase's UTF-8 bytes as typed (the platform NFKD-normalizes them), empty for none, and
 * overwrites them once the bridge has its copy, success or not.
 */
const withPassphrase = async <T>(passphrase: unknown, call: (buffer: ArrayBuffer) => Promise<T>): Promise<T> => {
  if (passphrase !== undefined && typeof passphrase !== 'string') {
    throw new VaultError('INVALID_ARGUMENT', 'A passphrase is a string.')
  }
  const bytes = utf8.encode(passphrase ?? '')
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer

  try {
    return await nativeAsync(() => call(buffer))
  } finally {
    bytes.fill(0)
    new Uint8Array(buffer).fill(0)
  }
}

/** A domain, as WebAuthn takes a relying party's id: labels of letters, digits and hyphens, at least two of them. */
const RELYING_PARTY = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

const checkedRelyingParty = (relyingParty: unknown) => {
  if (relyingParty === undefined) {
    return undefined
  }
  if (typeof relyingParty !== 'string' || !RELYING_PARTY.test(relyingParty.toLowerCase())) {
    throw new VaultError(
      'INVALID_ARGUMENT',
      'A relying party is the domain the app is associated with, such as example.com.'
    )
  }

  return relyingParty.toLowerCase()
}

/** The longest name a new passkey takes, in characters: what a passwords app shows in a row. */
export const MAX_PASSKEY_NAME_LENGTH = 64

/** The name to register a new passkey under, or empty for one the person already has. */
const passkeyName = (choice: unknown) => {
  if (choice === true) {
    return ''
  }
  const name = typeof choice === 'object' && choice !== null ? (choice as {name?: unknown}).name : undefined
  if (typeof name !== 'string' || name.trim() === '' || [...name.trim()].length > MAX_PASSKEY_NAME_LENGTH) {
    throw new VaultError(
      'INVALID_ARGUMENT',
      `A passkey is true (one the person has) or {name}, 1 to ${MAX_PASSKEY_NAME_LENGTH} characters (a new one).`
    )
  }

  return name.trim()
}

/** A backup's bytes in a buffer of their own, as the bridge takes them. */
const backupBuffer = (backup: unknown) => {
  if (!(backup instanceof Uint8Array)) {
    throw new VaultError('INVALID_BACKUP')
  }

  return backup.buffer.slice(backup.byteOffset, backup.byteOffset + backup.byteLength) as ArrayBuffer
}

const bothSecrets = () => new VaultError('INVALID_ARGUMENT', 'A backup has a password or a passkey, not both.')

const prompt = (options: PromptOptions | undefined) => {
  if (typeof options?.prompt !== 'string' || options.prompt.trim() === '') {
    throw new VaultError('INVALID_ARGUMENT', 'Unlocking and revealing say why: pass a prompt.')
  }

  return options.prompt
}

/** A vault over a host: the native module on a device, a stand-in in tests. */
export const createVaultOn = <Chains>(
  host: CryptoVault,
  crypto: CryptoEngine<Chains>,
  options: VaultOptions = {}
): Vault<Chains> => {
  const configured = checkedRelyingParty(options.relyingParty)
  const relyingParty = () => {
    if (configured === undefined) {
      throw new VaultError(
        'INVALID_ARGUMENT',
        'Passkey backups need the relying party: createVault(crypto, {relyingParty: "example.com"}).'
      )
    }

    return configured
  }

  return Object.freeze({
    access: (id: string) => native(() => host.access(id)),
    get availableProtection() {
      return native(() => host.availableProtection)
    },
    backup: async (id: string, options: BackupOptions) => {
      const text = prompt(options)
      // As JavaScript may pass them, not as the types allow.
      const {passkey, password} = options as {passkey?: unknown; password?: unknown}

      if (passkey !== undefined) {
        if (password !== undefined) {
          throw bothSecrets()
        }
        const party = relyingParty()
        const name = passkeyName(passkey)
        const sealed = await nativeAsync(() => host.backupWithPasskey(id, party, name, text))

        return new Uint8Array(sealed)
      }

      const sealed = await withPassword(password, buffer => host.backup(id, buffer, text))

      return new Uint8Array(sealed)
    },
    backupKind: (backup: Uint8Array) => {
      const sealed = backupBuffer(backup)

      return native(() => host.backupKind(sealed))
    },
    get backupSupported() {
      return native(() => host.backupSupported)
    },
    create: (id: string, options: CreateOptions = {}) =>
      nativeAsync(() =>
        host.create(id, options.words ?? 12, options.access ?? 'biometrics', options.prompt ?? DEFAULT_SEAL_PROMPT)
      ),
    has: (id: string) => native(() => host.has(id)),
    importMnemonic: async (id: string, mnemonic: string, options: SealOptions = {}) => {
      const bytes = utf8.encode(normalize(mnemonic))
      // The bridge copies these bytes before the call returns, so they are overwritten once it has.
      const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer

      try {
        await nativeAsync(() =>
          host.importMnemonic(id, buffer, options.access ?? 'biometrics', options.prompt ?? DEFAULT_SEAL_PROMPT)
        )
      } finally {
        bytes.fill(0)
        new Uint8Array(buffer).fill(0)
      }
    },
    get passkeySupported() {
      return native(() => host.passkeySupported)
    },
    protection: (id: string) => native(() => host.protection(id)),
    remove: (id: string) => native(() => host.remove(id)),
    restore: async (id: string, backup: Uint8Array, options: RestoreOptions) => {
      const sealed = backupBuffer(backup)
      // As JavaScript may pass them, not as the types allow.
      const {passkey, password} = (options ?? {}) as {passkey?: unknown; password?: unknown}
      const access = options?.access ?? 'biometrics'
      const sealPrompt = options?.prompt ?? DEFAULT_SEAL_PROMPT

      if (passkey !== undefined) {
        if (password !== undefined) {
          throw bothSecrets()
        }
        if (passkey !== true) {
          throw new VaultError('INVALID_ARGUMENT', 'A backup is restored with {passkey: true}.')
        }
        const party = relyingParty()
        // The kind first: a password's backup says so before any passkey sheet.
        if (native(() => host.backupKind(sealed)) === 'password') {
          throw new VaultError('NEEDS_PASSWORD')
        }
        await nativeAsync(() => host.restoreWithPasskey(id, sealed, party, access, sealPrompt))
        return
      }

      // And a passkey's says so before a password is weighed.
      if (native(() => host.backupKind(sealed)) === 'passkey') {
        throw new VaultError('NEEDS_PASSKEY')
      }
      await withPassword(password, buffer => host.restore(id, sealed, buffer, access, sealPrompt))
    },
    revealMnemonic: async (id: string, options: PromptOptions) => {
      const buffer = await nativeAsync(() => host.revealMnemonic(id, prompt(options)))
      const bytes = new Uint8Array(buffer)

      try {
        return utf8.decode(bytes)
      } finally {
        bytes.fill(0)
      }
    },
    unlock: async (id: string, options: UnlockOptions) => {
      const text = prompt(options)
      const {seed, words} = await withPassphrase(options.passphrase, buffer => host.unlock(id, text, buffer))

      return crypto.createEphemeralWallet({seed, words: words as MnemonicLength})
    },
  })
}
