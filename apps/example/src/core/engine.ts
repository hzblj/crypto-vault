import {ethereumAdapter} from '@hzblj/crypto-ethereum'
import {createVault, isVaultError, type Vault, VaultError} from '@hzblj/crypto-vault'
import {CryptoError, createCryptoEngine, isCryptoError} from '@hzblj/nitro-crypto'
import Constants from 'expo-constants'

const createEngine = () => createCryptoEngine({adapters: [ethereumAdapter()]})

export type ExampleCrypto = ReturnType<typeof createEngine>

type Engine =
  | {readonly crypto: ExampleCrypto; readonly vault: Vault<ExampleCrypto['chains']>}
  | {readonly error: CryptoError | VaultError}

let engine: Engine | undefined

/** The domain passkey backups belong to, `VAULT_PASSKEY_DOMAIN` at build time (app.config.ts), or none. */
export const PASSKEY_DOMAIN: string | undefined = Constants.expoConfig?.extra?.passkeyDomain ?? undefined

/** The engine and the vault over it, once per run: a missing native module is a message on screen, not a crash. */
export const exampleEngine = (): Engine => {
  if (!engine) {
    try {
      const crypto = createEngine()
      engine = {crypto, vault: createVault(crypto, {relyingParty: PASSKEY_DOMAIN})}
    } catch (error) {
      engine = {
        error:
          isCryptoError(error) || isVaultError(error)
            ? error
            : new CryptoError('NATIVE_UNAVAILABLE', undefined, {cause: error}),
      }
    }
  }
  return engine
}

/** The one entry the example keeps. */
export const ENTRY = 'main'
