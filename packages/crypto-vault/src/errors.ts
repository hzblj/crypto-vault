/**
 * The vault's errors. Native code throws status names (`CV_ERR_CANCELLED`, and the engine's `NC_ERR_*` from
 * importing words and opening backups) and they are mapped here; no message ever carries an input, let alone a secret.
 */

export const VAULT_ERROR_CODES = [
  'CANCELLED',
  'EXISTS',
  'FAILED',
  'INVALID_ARGUMENT',
  'INVALID_BACKUP',
  'INVALID_MNEMONIC',
  'INVALIDATED',
  'MNEMONIC_CHECKSUM',
  'NOT_FOUND',
  'UNAVAILABLE',
  'UNSUPPORTED',
  'WEAK_PASSWORD',
  'WRONG_PASSWORD',
] as const

export type VaultErrorCode = (typeof VAULT_ERROR_CODES)[number]

const DEFAULT_MESSAGES: Record<VaultErrorCode, string> = {
  CANCELLED: 'The person dismissed the prompt.',
  EXISTS: 'An entry is already sealed under this id.',
  FAILED: 'The platform could not complete the operation.',
  INVALID_ARGUMENT: 'An argument is not one the vault takes.',
  INVALID_BACKUP: 'These bytes are not a backup this engine reads.',
  INVALID_MNEMONIC: 'The mnemonic is not BIP-39 English.',
  INVALIDATED: 'The enrolled biometrics changed, and the entry went with its key. Restore it from its words.',
  MNEMONIC_CHECKSUM: 'The mnemonic checksum does not match.',
  NOT_FOUND: 'No entry is sealed under this id.',
  UNAVAILABLE: 'This device has no biometrics or passcode set up for what the entry asks.',
  UNSUPPORTED:
    'The linked @hzblj/nitro-crypto engine lacks a capability the vault needs (bip39-entropy, or backup-argon2id for backups).',
  WEAK_PASSWORD: 'A backup password needs at least 8 characters.',
  WRONG_PASSWORD: 'The password does not open this backup, or the backup was changed.',
}

export class VaultError extends Error {
  readonly code: VaultErrorCode

  constructor(code: VaultErrorCode, message: string = DEFAULT_MESSAGES[code], options?: {cause?: unknown}) {
    super(message, options)
    this.name = 'VaultError'
    this.code = code
  }
}

export const isVaultError = (error: unknown): error is VaultError => error instanceof VaultError

const ENGINE_STATUSES: Partial<Record<string, VaultErrorCode>> = {
  NC_ERR_INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  NC_ERR_INVALID_LENGTH: 'INVALID_ARGUMENT',
  NC_ERR_INVALID_MNEMONIC: 'INVALID_MNEMONIC',
  NC_ERR_MNEMONIC_CHECKSUM: 'MNEMONIC_CHECKSUM',
  NC_ERR_VERIFICATION_FAILED: 'WRONG_PASSWORD',
}

const STATUS_PATTERN = /(?:CV|NC)_ERR_[A-Z_]+/

/**
 * A `VaultError` for whatever native code threw. Nitro prefixes the message with the method
 * ("`CryptoVault.unlock(...)`: CV_ERR_CANCELLED"); only the status name is read, and an error without one is
 * `INVALID_ARGUMENT` (an enum or a type Nitro could not convert).
 */
export const toVaultError = (error: unknown): VaultError => {
  if (isVaultError(error)) {
    return error
  }

  const status = error instanceof Error ? STATUS_PATTERN.exec(error.message)?.[0] : undefined

  if (status === undefined) {
    return new VaultError('INVALID_ARGUMENT')
  }

  if (status.startsWith('CV_ERR_')) {
    const code = status.slice('CV_ERR_'.length)

    return new VaultError((VAULT_ERROR_CODES as readonly string[]).includes(code) ? (code as VaultErrorCode) : 'FAILED')
  }

  return new VaultError(ENGINE_STATUSES[status] ?? 'FAILED')
}

export const native = <T>(call: () => T): T => {
  try {
    return call()
  } catch (error) {
    throw toVaultError(error)
  }
}

export const nativeAsync = async <T>(call: () => Promise<T>): Promise<T> => {
  try {
    return await call()
  } catch (error) {
    throw toVaultError(error)
  }
}
