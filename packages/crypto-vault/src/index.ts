import type {CryptoEngine} from '@hzblj/nitro-crypto'
import {NitroModules} from 'react-native-nitro-modules'

import {VaultError} from './errors'
import type {CryptoVault} from './specs/crypto-vault.nitro'
import {createVaultOn, type Vault, type VaultOptions} from './vault'

let host: CryptoVault | undefined

/**
 * The device's vault, over the engine `crypto` runs on: the wallets it unlocks are that engine's, with its chains.
 * Refuses to start on an engine without the `bip39-entropy` capability (`@hzblj/nitro-crypto` 0.1.3 and later);
 * backups need `backup-argon2id` too (0.1.4), which `backupSupported` says, and passkey backups `backup-hkdf-sha256`
 * (0.1.5) and the app's relying party, `options.relyingParty`, which `passkeySupported` does not check.
 */
export const createVault = <Chains>(crypto: CryptoEngine<Chains>, options?: VaultOptions): Vault<Chains> => {
  host ??= NitroModules.createHybridObject<CryptoVault>('CryptoVault')

  if (!host.supported) {
    throw new VaultError('UNSUPPORTED')
  }

  return createVaultOn(host, crypto, options)
}

export {isVaultError, VAULT_ERROR_CODES, VaultError, type VaultErrorCode} from './errors'
export type {Access, BackupKind, Protection} from './specs/crypto-vault.nitro'
export {
  type BackupOptions,
  type CreateOptions,
  MAX_PASSKEY_NAME_LENGTH,
  MIN_PASSWORD_LENGTH,
  type PasskeyBackupOptions,
  type PasskeyChoice,
  type PasskeyRestoreOptions,
  type PassphraseOptions,
  type PasswordBackupOptions,
  type PasswordRestoreOptions,
  type PromptOptions,
  type RestoreOptions,
  type SealOptions,
  type UnlockOptions,
  type Vault,
  type VaultOptions,
} from './vault'
export {VERSION} from './version'
