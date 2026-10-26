import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import path from 'node:path'
import {describe, test} from 'node:test'

import type {NitroSeed} from '@hzblj/nitro-crypto'
import {createTestCryptoEngine, testHost} from '@hzblj/nitro-crypto/testing'
import {entropyToMnemonic, mnemonicToEntropy} from '@scure/bip39'
import {wordlist} from '@scure/bip39/wordlists/english.js'

import {isVaultError, VaultError} from '../src/errors'
import type {Access, CryptoVault, Protection} from '../src/specs/crypto-vault.nitro'
import {createVaultOn} from '../src/vault'
import {VERSION} from '../src/version'

const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

const crypto = createTestCryptoEngine()

/**
 * The native vault, played in memory: what the bridge and the platform do, with the test engine making the seeds.
 * Not a model of the hardware, only of the contract the facade relies on.
 */
const fakeHost = () => {
  const entries = new Map<string, {access: Access; entropy: Uint8Array}>()
  // What the engine's seal would hold, by the backup's bytes: the entropy and the password that opens it.
  const backups = new Map<string, {entropy: Uint8Array; password: string}>()
  const calls = {imported: [] as ArrayBuffer[], passwords: [] as ArrayBuffer[], revealed: [] as ArrayBuffer[]}
  let failNext: string | undefined

  const fail = () => {
    if (failNext) {
      const status = failNext
      failNext = undefined
      throw new Error(`CryptoVault.call(...): ${status}`)
    }
  }
  const entry = (id: string) => {
    const found = entries.get(id)
    if (!found) {
      throw new Error('CryptoVault.call(...): CV_ERR_NOT_FOUND')
    }
    return found
  }
  const seal = (id: string, entropy: Uint8Array, access: Access) => {
    if (entries.has(id)) {
      throw new Error('CryptoVault.call(...): CV_ERR_EXISTS')
    }
    entries.set(id, {access, entropy})
  }
  const hex = (bytes: ArrayBuffer) => Buffer.from(bytes).toString('hex')

  const host = {
    access: (id: string) => entry(id).access,
    availableProtection: 'secure-enclave' as Protection,
    backup: async (id: string, password: ArrayBuffer) => {
      calls.passwords.push(password)
      fail()
      const {entropy} = entry(id)
      const sealed = globalThis.crypto.getRandomValues(new Uint8Array(55 + entropy.length + 16)).buffer as ArrayBuffer
      backups.set(hex(sealed), {entropy: entropy.slice(), password: hex(password)})
      return sealed
    },
    backupSupported: true,
    create: async (id: string, words: number, access: Access) => {
      fail()
      seal(id, globalThis.crypto.getRandomValues(new Uint8Array((words * 4) / 3)), access)
    },
    has: (id: string) => entries.has(id),
    importMnemonic: async (id: string, mnemonic: ArrayBuffer, access: Access) => {
      calls.imported.push(mnemonic)
      fail()
      const words = new TextDecoder().decode(mnemonic)
      let entropy: Uint8Array
      try {
        entropy = mnemonicToEntropy(words, wordlist)
      } catch {
        throw new Error('CryptoVault.importMnemonic(...): NC_ERR_MNEMONIC_CHECKSUM')
      }
      seal(id, entropy, access)
    },
    protection: (id: string) => (entry(id), 'secure-enclave' as Protection),
    remove: (id: string) => {
      entries.delete(id)
    },
    restore: async (id: string, backup: ArrayBuffer, password: ArrayBuffer, access: Access) => {
      calls.passwords.push(password)
      if (entries.has(id)) {
        throw new Error('CryptoVault.restore(...): CV_ERR_EXISTS')
      }
      const found = backups.get(hex(backup))
      if (!found) {
        throw new Error('CryptoVault.restore(...): CV_ERR_INVALID_BACKUP')
      }
      if (found.password !== hex(password)) {
        throw new Error('CryptoVault.restore(...): NC_ERR_VERIFICATION_FAILED')
      }
      seal(id, found.entropy.slice(), access)
    },
    revealMnemonic: async (id: string) => {
      fail()
      const buffer = new TextEncoder().encode(entropyToMnemonic(entry(id).entropy, wordlist)).buffer as ArrayBuffer
      calls.revealed.push(buffer)
      return buffer
    },
    supported: true,
    unlock: async (id: string) => {
      fail()
      const {entropy} = entry(id)
      const words = new TextEncoder().encode(entropyToMnemonic(entropy, wordlist))
      const seed: NitroSeed = await testHost().seedFromMnemonic(words.buffer as ArrayBuffer, new ArrayBuffer(0))
      return {seed, words: (entropy.length * 3) / 4}
    },
  }

  return {calls, failNext: (status: string) => (failNext = status), host: host as unknown as CryptoVault}
}

const rejectsCode = (run: () => Promise<unknown>, code: string) =>
  assert.rejects(run, error => isVaultError(error) && error.code === code, code)

describe('the vault', () => {
  test('creates, unlocks into a wallet of the engine, and removes', async () => {
    const {host} = fakeHost()
    const vault = createVaultOn(host, crypto)
    const baseline = crypto.liveHandles()

    await vault.create('main', {words: 24})
    assert.equal(vault.has('main'), true)
    assert.equal(vault.protection('main'), 'secure-enclave')
    assert.equal(vault.access('main'), 'biometrics')

    const wallet = await vault.unlock('main', {prompt: 'Unlock your wallet'})
    assert.equal(wallet.origin, 'seed')
    assert.equal(wallet.words, 24)

    // The words it shows are the wallet's: they restore the same fingerprint.
    const words = await vault.revealMnemonic('main', {prompt: 'Show your recovery phrase'})
    assert.equal(words.split(' ').length, 24)
    const restored = await crypto.createEphemeralWallet({mnemonic: words})
    assert.equal(restored.fingerprint, wallet.fingerprint)

    restored.dispose()
    wallet.dispose()
    assert.equal(crypto.liveHandles(), baseline)

    vault.remove('main')
    assert.equal(vault.has('main'), false)
    vault.remove('main')
  })

  test('imports words as other wallets read them, and overwrites the bytes it handed over', async () => {
    const {calls, host} = fakeHost()
    const vault = createVaultOn(host, crypto)

    await vault.importMnemonic('restored', `  ${ABANDON.toUpperCase().replaceAll(' ', ' \n ')} `, {
      access: 'biometrics-or-passcode',
    })
    assert.equal(vault.access('restored'), 'biometrics-or-passcode')
    const wallet = await vault.unlock('restored', {prompt: 'Unlock'})
    assert.equal(wallet.fingerprint, 0x73c5da0a)
    wallet.dispose()

    assert.equal(calls.imported.length, 1)
    assert.ok(new Uint8Array(calls.imported[0] as ArrayBuffer).every(byte => byte === 0))
  })

  test('wipes the words it reveals once they are decoded', async () => {
    const {calls, host} = fakeHost()
    const vault = createVaultOn(host, crypto)
    await vault.importMnemonic('main', ABANDON)

    assert.equal(await vault.revealMnemonic('main', {prompt: 'Show'}), ABANDON)
    assert.ok(new Uint8Array(calls.revealed[0] as ArrayBuffer).every(byte => byte === 0))
  })

  test('maps native status names, and asks for a prompt to unlock or reveal', async () => {
    const {failNext, host} = fakeHost()
    const vault = createVaultOn(host, crypto)
    await vault.create('main')

    failNext('CV_ERR_CANCELLED')
    await rejectsCode(() => vault.unlock('main', {prompt: 'Unlock'}), 'CANCELLED')
    failNext('CV_ERR_INVALIDATED')
    await rejectsCode(() => vault.revealMnemonic('main', {prompt: 'Show'}), 'INVALIDATED')
    failNext('CV_ERR_SOMETHING_NEW')
    await rejectsCode(() => vault.create('other'), 'FAILED')

    await rejectsCode(() => vault.create('main'), 'EXISTS')
    await rejectsCode(() => vault.unlock('missing', {prompt: 'Unlock'}), 'NOT_FOUND')
    await rejectsCode(() => vault.importMnemonic('bad', ABANDON.replace('about', 'abandon')), 'MNEMONIC_CHECKSUM')
    await rejectsCode(() => vault.unlock('main', {prompt: ' '}), 'INVALID_ARGUMENT')
    await rejectsCode(() => vault.unlock('main', undefined as never), 'INVALID_ARGUMENT')
    assert.throws(
      () => vault.protection('missing'),
      error => error instanceof VaultError && error.code === 'NOT_FOUND'
    )
  })

  test('backs a wallet up under a password and restores it into a new entry', async () => {
    const {calls, host} = fakeHost()
    const vault = createVaultOn(host, crypto)
    await vault.importMnemonic('main', ABANDON)
    assert.equal(vault.backupSupported, true)

    const backup = await vault.backup('main', {password: 'correct horse', prompt: 'Back up your wallet'})
    assert.ok(backup instanceof Uint8Array)
    assert.equal(backup.length, 55 + 16 + 16)

    vault.remove('main')
    await vault.restore('main', backup, {access: 'biometrics-or-passcode', password: 'correct horse'})
    assert.equal(vault.access('main'), 'biometrics-or-passcode')
    const wallet = await vault.unlock('main', {prompt: 'Unlock'})
    assert.equal(wallet.fingerprint, 0x73c5da0a)
    wallet.dispose()

    // Both passwords crossed as bytes this package overwrote once the bridge had them.
    assert.equal(calls.passwords.length, 2)
    for (const password of calls.passwords) {
      assert.ok(new Uint8Array(password).every(byte => byte === 0))
    }
  })

  test('normalizes passwords to NFC and counts characters, not bytes', async () => {
    const {host} = fakeHost()
    const vault = createVaultOn(host, crypto)
    await vault.create('main')

    // Eight characters, eleven bytes: long enough. Composed and decomposed, the same password.
    const backup = await vault.backup('main', {password: 'žluťoučk', prompt: 'Back up'})
    const decomposed = 'z\u030Clut\u030Couc\u030Ck'
    assert.notEqual(decomposed, 'žluťoučk')
    await vault.restore('copy', backup, {password: decomposed})
    assert.equal(vault.has('copy'), true)

    await rejectsCode(() => vault.backup('main', {password: 'seven 7', prompt: 'Back up'}), 'WEAK_PASSWORD')
    await rejectsCode(() => vault.backup('main', {password: undefined as never, prompt: 'Back up'}), 'WEAK_PASSWORD')
    await rejectsCode(() => vault.backup('main', {password: 'correct horse', prompt: ''}), 'INVALID_ARGUMENT')
  })

  test('maps what restoring can go wrong with', async () => {
    const {host} = fakeHost()
    const vault = createVaultOn(host, crypto)
    await vault.create('main')
    const backup = await vault.backup('main', {password: 'correct horse', prompt: 'Back up'})

    await rejectsCode(() => vault.restore('main', backup, {password: 'correct horse'}), 'EXISTS')
    await rejectsCode(() => vault.restore('other', backup, {password: 'battery staple'}), 'WRONG_PASSWORD')
    await rejectsCode(() => vault.restore('other', backup.slice(1), {password: 'correct horse'}), 'INVALID_BACKUP')
    await rejectsCode(() => vault.restore('other', 'backup' as never, {password: 'correct horse'}), 'INVALID_BACKUP')
    assert.equal(vault.has('other'), false)
  })

  test('VERSION matches package.json', () => {
    const manifest = JSON.parse(readFileSync(path.join(import.meta.dirname, '../package.json'), 'utf8')) as {
      version: string
    }
    assert.equal(VERSION, manifest.version)
  })
})
