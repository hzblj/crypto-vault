import type {CryptoEngine, EphemeralWallet, MnemonicLength} from '@hzblj/nitro-crypto'
// The entry that loads no native code, so the facade runs in tests too.
import {utf8} from '@hzblj/nitro-crypto/adapter'

import {native, nativeAsync, VaultError} from './errors'
import type {Access, CryptoVault, Protection} from './specs/crypto-vault.nitro'

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

export type BackupOptions = PromptOptions & {
  /** What seals the backup, and the only thing that opens it again: at least 8 characters. */
  readonly password: string
}

export type RestoreOptions = {
  /** Who opens the restored entry: biometrics only (the default), or biometrics with the device passcode. */
  readonly access?: Access
  /** The password the backup was sealed under. */
  readonly password: string
  /** What Android's prompt says: its keys open for sealing too only after the person. */
  readonly prompt?: string
}

/**
 * A device's vault of wallets: each entry a wallet's BIP-39 entropy, sealed under a key the Secure Enclave or StrongBox
 * holds (or the platform's software, where there is neither, and `protection` says so), opened only after the system's
 * biometric prompt. Unlocking hands the engine a seed natively: JavaScript receives a wallet and never a word or byte
 * of what is behind it. Only `revealMnemonic` returns a secret, the words, for the moment a user writes them down.
 * `backup` returns the entropy sealed under a password, which is safe to store anywhere, and `restore` opens it
 * straight into a new entry.
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
  /** After the system prompt, the entry under `id` as a wallet in the engine. */
  readonly unlock: (id: string, options: PromptOptions) => Promise<EphemeralWallet<Chains>>
  /** After the system prompt, the words of the entry under `id`, for the user to write down. */
  readonly revealMnemonic: (id: string, options: PromptOptions) => Promise<string>
  /** Whether the linked engine seals backups (`@hzblj/nitro-crypto` 0.1.4 and later). */
  readonly backupSupported: boolean
  /**
   * After the system prompt, the entry under `id` sealed under a password: 87 to 103 bytes that are safe to store
   * anywhere (iCloud Keychain, Block Store, a file), as the password keeps them. Argon2id makes each guess cost about
   * half a second and 64 MiB, natively.
   */
  readonly backup: (id: string, options: BackupOptions) => Promise<Uint8Array>
  /** A wallet restored from a backup, sealed under `id`. The entropy goes from the engine to the hardware natively. */
  readonly restore: (id: string, backup: Uint8Array, options: RestoreOptions) => Promise<void>
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

const prompt = (options: PromptOptions | undefined) => {
  if (typeof options?.prompt !== 'string' || options.prompt.trim() === '') {
    throw new VaultError('INVALID_ARGUMENT', 'Unlocking and revealing say why: pass a prompt.')
  }

  return options.prompt
}

/** A vault over a host: the native module on a device, a stand-in in tests. */
export const createVaultOn = <Chains>(host: CryptoVault, crypto: CryptoEngine<Chains>): Vault<Chains> =>
  Object.freeze({
    access: (id: string) => native(() => host.access(id)),
    get availableProtection() {
      return native(() => host.availableProtection)
    },
    backup: async (id: string, options: BackupOptions) => {
      const text = prompt(options)
      const sealed = await withPassword(options.password, buffer => host.backup(id, buffer, text))

      return new Uint8Array(sealed)
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
    protection: (id: string) => native(() => host.protection(id)),
    remove: (id: string) => native(() => host.remove(id)),
    restore: async (id: string, backup: Uint8Array, options: RestoreOptions) => {
      if (!(backup instanceof Uint8Array)) {
        throw new VaultError('INVALID_BACKUP')
      }
      const sealed = backup.buffer.slice(backup.byteOffset, backup.byteOffset + backup.byteLength) as ArrayBuffer

      await withPassword(options?.password, buffer =>
        host.restore(id, sealed, buffer, options.access ?? 'biometrics', options.prompt ?? DEFAULT_SEAL_PROMPT)
      )
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
    unlock: async (id: string, options: PromptOptions) => {
      const {seed, words} = await nativeAsync(() => host.unlock(id, prompt(options)))

      return crypto.createEphemeralWallet({seed, words: words as MnemonicLength})
    },
  })
