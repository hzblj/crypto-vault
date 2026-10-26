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

/**
 * A device's vault of wallets: each entry a wallet's BIP-39 entropy, sealed under a key the Secure Enclave or StrongBox
 * holds (or the platform's software, where there is neither, and `protection` says so), opened only after the system's
 * biometric prompt. Unlocking hands the engine a seed natively: JavaScript receives a wallet and never a word or byte
 * of what is behind it. Only `revealMnemonic` returns a secret, the words, for the moment a user writes them down.
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
  /** Deletes the entry under `id` and its key. Idempotent. */
  readonly remove: (id: string) => void
}

const DEFAULT_SEAL_PROMPT = 'Protect your wallet'

/** As other wallets read words: NFKD, lowercase, single spaces. The engine checks them. */
const normalize = (mnemonic: string) => mnemonic.normalize('NFKD').trim().toLowerCase().split(/\s+/).join(' ')

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
