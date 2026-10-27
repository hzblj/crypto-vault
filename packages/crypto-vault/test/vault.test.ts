import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import path from 'node:path'
import {describe, test} from 'node:test'

import type {NitroSeed} from '@hzblj/nitro-crypto'
import {createTestCryptoEngine, testHost} from '@hzblj/nitro-crypto/testing'
import {entropyToMnemonic, mnemonicToEntropy} from '@scure/bip39'
import {wordlist} from '@scure/bip39/wordlists/english.js'

import {isVaultError, toVaultError, VAULT_ERROR_CODES, VaultError} from '../src/errors'
import type {Access, BackupKind, CryptoVault, Protection} from '../src/specs/crypto-vault.nitro'
import {createVaultOn, MAX_PASSKEY_NAME_LENGTH} from '../src/vault'
import {VERSION} from '../src/version'

const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

const crypto = createTestCryptoEngine()

const RELYING_PARTY = 'wallet.example.com'

/** The `ncbk` header's first six bytes: the magic, version 1, and the key derivation (1 a password, 2 a key). */
const header = (kdf: number) => [0x6e, 0x63, 0x62, 0x6b, 1, kdf]

/** Bytes shaped like the engine's backup of `entropy`: its header, then random bytes of a sealed backup's length. */
const sealedBackup = (kdf: number, entropy: Uint8Array) => {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array((kdf === 1 ? 55 : 46) + entropy.length + 16))
  bytes.set(header(kdf))
  return bytes.buffer as ArrayBuffer
}

/** What `nc_backup_kdf` reads: the key derivation of a backup's header, or the status for bytes that are none. */
const kindOf = (backup: ArrayBuffer): BackupKind => {
  const bytes = new Uint8Array(backup)
  const kdf = bytes[5]
  const known = header(1)
    .slice(0, 5)
    .every((byte, index) => bytes[index] === byte)
  if (
    !known ||
    (kdf !== 1 && kdf !== 2) ||
    bytes.length < (kdf === 1 ? 87 : 78) ||
    bytes.length > (kdf === 1 ? 103 : 94)
  ) {
    throw new Error('CryptoVault.backupKind(...): CV_ERR_INVALID_BACKUP')
  }
  return kdf === 1 ? 'password' : 'passkey'
}

/**
 * The native vault, played in memory: what the bridge and the platform do, with the test engine making the seeds.
 * Not a model of the hardware, only of the contract the facade relies on.
 */
const fakeHost = () => {
  const entries = new Map<string, {access: Access; entropy: Uint8Array}>()
  // What the engine's seal would hold, by the backup's bytes: the entropy and the password or passkey output that
  // opens it.
  const backups = new Map<string, {entropy: Uint8Array; password?: string; key?: string}>()
  // The passkeys the platform keeps, by relying party: a name and a PRF output. `pick` is the one the person picks.
  const passkeys = new Map<string, {name: string; output: string}[]>()
  let pick: string | undefined
  const calls = {
    imported: [] as ArrayBuffer[],
    passkeys: [] as {mode: 'create' | 'existing' | 'open'; name: string; relyingParty: string}[],
    passphrases: [] as ArrayBuffer[],
    passwords: [] as ArrayBuffer[],
    revealed: [] as ArrayBuffer[],
  }
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
  /** The PRF output of the passkey the person uses: a new one under `name`, or the one they pick. */
  const passkeyOutput = (relyingParty: string, name: string) => {
    const known = passkeys.get(relyingParty) ?? []
    if (name !== '') {
      const output = hex(globalThis.crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer)
      passkeys.set(relyingParty, [...known, {name, output}])
      pick = name
      return output
    }
    const picked = known.find(passkey => passkey.name === pick)
    if (!picked) {
      throw new Error('CryptoVault.call(...): CV_ERR_PASSKEY_NOT_FOUND')
    }
    return picked.output
  }

  const host = {
    access: (id: string) => entry(id).access,
    availableProtection: 'secure-enclave' as Protection,
    backup: async (id: string, password: ArrayBuffer) => {
      calls.passwords.push(password)
      fail()
      const {entropy} = entry(id)
      const sealed = sealedBackup(1, entropy)
      backups.set(hex(sealed), {entropy: entropy.slice(), password: hex(password)})
      return sealed
    },
    backupKind: kindOf,
    backupSupported: true,
    backupWithPasskey: async (id: string, relyingParty: string, name: string) => {
      const {entropy} = entry(id)
      calls.passkeys.push({mode: name === '' ? 'existing' : 'create', name, relyingParty})
      fail()
      const key = passkeyOutput(relyingParty, name)
      const sealed = sealedBackup(2, entropy)
      backups.set(hex(sealed), {entropy: entropy.slice(), key})
      return sealed
    },
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
    passkeySupported: true,
    protection: (id: string) => (entry(id), 'secure-enclave' as Protection),
    remove: (id: string) => {
      entries.delete(id)
    },
    restore: async (id: string, backup: ArrayBuffer, password: ArrayBuffer, access: Access) => {
      calls.passwords.push(password)
      if (entries.has(id)) {
        throw new Error('CryptoVault.restore(...): CV_ERR_EXISTS')
      }
      if (kindOf(backup) === 'passkey') {
        throw new Error('CryptoVault.restore(...): CV_ERR_NEEDS_PASSKEY')
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
    restoreWithPasskey: async (id: string, backup: ArrayBuffer, relyingParty: string, access: Access) => {
      if (entries.has(id)) {
        throw new Error('CryptoVault.restoreWithPasskey(...): CV_ERR_EXISTS')
      }
      if (kindOf(backup) === 'password') {
        throw new Error('CryptoVault.restoreWithPasskey(...): CV_ERR_NEEDS_PASSWORD')
      }
      calls.passkeys.push({mode: 'open', name: '', relyingParty})
      fail()
      const key = passkeyOutput(relyingParty, '')
      const found = backups.get(hex(backup))
      if (!found) {
        throw new Error('CryptoVault.restoreWithPasskey(...): CV_ERR_INVALID_BACKUP')
      }
      if (found.key !== key) {
        throw new Error('CryptoVault.restoreWithPasskey(...): CV_ERR_WRONG_PASSKEY')
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
    unlock: async (id: string, _prompt: string, passphrase: ArrayBuffer) => {
      calls.passphrases.push(passphrase)
      fail()
      const {entropy} = entry(id)
      const words = new TextEncoder().encode(entropyToMnemonic(entropy, wordlist))
      // As the platform does: NFKD, then the bytes the engine hashes.
      const normalized = new TextEncoder().encode(new TextDecoder().decode(passphrase).normalize('NFKD'))
      const seed: NitroSeed = await testHost().seedFromMnemonic(
        words.buffer as ArrayBuffer,
        normalized.buffer as ArrayBuffer
      )
      return {seed, words: (entropy.length * 3) / 4}
    },
  }

  return {
    calls,
    failNext: (status: string) => (failNext = status),
    host: host as unknown as CryptoVault,
    pickPasskey: (name: string | undefined) => (pick = name),
  }
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
    assert.equal(vault.backupKind(backup), 'password')

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

  test('unlocks under a BIP-39 passphrase, normalized as the platform does, and overwrites the bytes it handed over', async () => {
    const {calls, host} = fakeHost()
    const vault = createVaultOn(host, crypto)
    await vault.importMnemonic('main', ABANDON)

    const plain = await vault.unlock('main', {prompt: 'Unlock'})
    const empty = await vault.unlock('main', {passphrase: '', prompt: 'Unlock'})
    const trezor = await vault.unlock('main', {passphrase: 'TREZOR', prompt: 'Unlock'})
    const expected = await crypto.createEphemeralWallet({mnemonic: ABANDON, passphrase: 'TREZOR'})

    // No passphrase and an empty one are the same wallet; any other is another, which nothing can call wrong.
    assert.equal(plain.fingerprint, 0x73c5da0a)
    assert.equal(empty.fingerprint, plain.fingerprint)
    assert.equal(trezor.fingerprint, expected.fingerprint)
    assert.notEqual(trezor.fingerprint, plain.fingerprint)

    // Composed or decomposed, the same characters are the same wallet.
    const composed = await vault.unlock('main', {passphrase: 'žluťoučký kůň', prompt: 'Unlock'})
    const decomposed = await vault.unlock('main', {
      passphrase: 'z\u030Clut\u030Couc\u030Cky\u0301 ku\u030An\u030C',
      prompt: 'Unlock',
    })
    assert.equal(composed.fingerprint, decomposed.fingerprint)

    for (const wallet of [plain, empty, trezor, expected, composed, decomposed]) {
      wallet.dispose()
    }

    // Every passphrase crossed as bytes this package overwrote once the bridge had them, and never normalized here.
    assert.equal(calls.passphrases.length, 5)
    for (const passphrase of calls.passphrases) {
      assert.ok(new Uint8Array(passphrase).every(byte => byte === 0))
    }

    await rejectsCode(() => vault.unlock('main', {passphrase: 42 as never, prompt: 'Unlock'}), 'INVALID_ARGUMENT')
    await rejectsCode(() => vault.unlock('main', {passphrase: 'TREZOR', prompt: ''}), 'INVALID_ARGUMENT')
  })

  test('backs a wallet up under a new passkey and restores it with the passkey', async () => {
    const {calls, host} = fakeHost()
    const vault = createVaultOn(host, crypto, {relyingParty: 'Wallet.Example.com'})
    await vault.importMnemonic('main', ABANDON)
    assert.equal(vault.passkeySupported, true)

    const backup = await vault.backup('main', {passkey: {name: ' Main wallet '}, prompt: 'Back up your wallet'})
    assert.ok(backup instanceof Uint8Array)
    assert.equal(backup.length, 46 + 16 + 16)
    assert.equal(vault.backupKind(backup), 'passkey')

    // Another wallet, sealed under the passkey the person already has.
    await vault.create('savings', {words: 24})
    const savings = await vault.backup('savings', {passkey: true, prompt: 'Back up your savings'})
    assert.equal(savings.length, 46 + 32 + 16)

    vault.remove('main')
    await vault.restore('main', backup, {access: 'biometrics-or-passcode', passkey: true})
    assert.equal(vault.access('main'), 'biometrics-or-passcode')
    const wallet = await vault.unlock('main', {prompt: 'Unlock'})
    assert.equal(wallet.fingerprint, 0x73c5da0a)
    wallet.dispose()

    // The relying party went to the platform as a domain, and the name as trimmed; the PRF output never came here.
    assert.deepEqual(calls.passkeys, [
      {mode: 'create', name: 'Main wallet', relyingParty: RELYING_PARTY},
      {mode: 'existing', name: '', relyingParty: RELYING_PARTY},
      {mode: 'open', name: '', relyingParty: RELYING_PARTY},
    ])
  })

  test('says which secret opens a backup before anything is asked', async () => {
    const {calls, host} = fakeHost()
    const vault = createVaultOn(host, crypto, {relyingParty: RELYING_PARTY})
    await vault.create('main')
    const password = await vault.backup('main', {password: 'correct horse', prompt: 'Back up'})
    const passkey = await vault.backup('main', {passkey: {name: 'Main wallet'}, prompt: 'Back up'})
    const passkeyCalls = calls.passkeys.length
    const passwordCalls = calls.passwords.length

    await rejectsCode(() => vault.restore('other', password, {passkey: true}), 'NEEDS_PASSWORD')
    // Even a password too short to weigh: the backup's kind comes first.
    await rejectsCode(() => vault.restore('other', passkey, {password: ''}), 'NEEDS_PASSKEY')
    await rejectsCode(() => vault.restore('other', passkey, {password: 'correct horse'}), 'NEEDS_PASSKEY')
    assert.equal(calls.passkeys.length, passkeyCalls)
    assert.equal(calls.passwords.length, passwordCalls)
    assert.equal(vault.has('other'), false)

    assert.throws(
      () => vault.backupKind(password.slice(1)),
      error => isVaultError(error) && error.code === 'INVALID_BACKUP'
    )
    assert.throws(
      () => vault.backupKind('backup' as never),
      error => isVaultError(error) && error.code === 'INVALID_BACKUP'
    )
  })

  test('maps what a passkey backup can go wrong with', async () => {
    const {calls, failNext, host, pickPasskey} = fakeHost()
    const vault = createVaultOn(host, crypto, {relyingParty: RELYING_PARTY})
    await vault.create('main')
    const backup = await vault.backup('main', {passkey: {name: 'Main wallet'}, prompt: 'Back up'})
    await vault.backup('main', {passkey: {name: 'Login'}, prompt: 'Back up'})

    // The person picks another passkey of the app: the backup does not open, and nothing is restored.
    pickPasskey('Login')
    await rejectsCode(() => vault.restore('other', backup, {passkey: true}), 'WRONG_PASSKEY')
    pickPasskey(undefined)
    await rejectsCode(() => vault.restore('other', backup, {passkey: true}), 'PASSKEY_NOT_FOUND')
    failNext('CV_ERR_CANCELLED')
    await rejectsCode(() => vault.restore('other', backup, {passkey: true}), 'CANCELLED')
    failNext('CV_ERR_PASSKEY_UNSUPPORTED')
    await rejectsCode(
      () => vault.backup('main', {passkey: {name: 'Main wallet'}, prompt: 'Back up'}),
      'PASSKEY_UNSUPPORTED'
    )
    await rejectsCode(() => vault.restore('main', backup, {passkey: true}), 'EXISTS')
    await rejectsCode(() => vault.backup('missing', {passkey: true, prompt: 'Back up'}), 'NOT_FOUND')
    assert.equal(vault.has('other'), false)

    // Malformed calls fail before the platform hears of them.
    const before = calls.passkeys.length
    for (const passkey of [
      false,
      {name: ''},
      {name: '   '},
      {name: 'w'.repeat(MAX_PASSKEY_NAME_LENGTH + 1)},
      {},
      'yes',
    ]) {
      await rejectsCode(() => vault.backup('main', {passkey: passkey as never, prompt: 'Back up'}), 'INVALID_ARGUMENT')
    }
    await rejectsCode(
      () => vault.backup('main', {passkey: true, password: 'correct horse', prompt: 'Back up'} as never),
      'INVALID_ARGUMENT'
    )
    await rejectsCode(() => vault.backup('main', {passkey: true, prompt: ''}), 'INVALID_ARGUMENT')
    await rejectsCode(
      () => vault.restore('other', backup, {passkey: {name: 'Main wallet'}} as never),
      'INVALID_ARGUMENT'
    )
    await rejectsCode(
      () => vault.restore('other', backup, {passkey: true, password: 'correct horse'} as never),
      'INVALID_ARGUMENT'
    )
    assert.equal(calls.passkeys.length, before)
  })

  test("needs the app's relying party, as a domain, for passkeys only", async () => {
    const {calls, host} = fakeHost()
    const vault = createVaultOn(host, crypto)
    await vault.create('main')

    await rejectsCode(() => vault.backup('main', {passkey: true, prompt: 'Back up'}), 'INVALID_ARGUMENT')
    const backup = await vault.backup('main', {password: 'correct horse', prompt: 'Back up'})
    vault.remove('main')
    await vault.restore('main', backup, {password: 'correct horse'})
    assert.equal(calls.passkeys.length, 0)

    for (const relyingParty of ['', 'localhost', 'https://example.com', 'example.com/path', '-example.com', 42]) {
      assert.throws(
        () => createVaultOn(host, crypto, {relyingParty: relyingParty as string}),
        error => isVaultError(error) && error.code === 'INVALID_ARGUMENT',
        String(relyingParty)
      )
    }
  })

  test('maps the new status names', () => {
    for (const code of [
      'NEEDS_PASSKEY',
      'NEEDS_PASSWORD',
      'PASSKEY_NOT_FOUND',
      'PASSKEY_UNSUPPORTED',
      'WRONG_PASSKEY',
    ]) {
      assert.ok((VAULT_ERROR_CODES as readonly string[]).includes(code))
      assert.equal(toVaultError(new Error(`CryptoVault.backup(...): CV_ERR_${code}`)).code, code)
    }
    // A wrong password stays the engine's verification failure.
    assert.equal(toVaultError(new Error('CryptoVault.restore(...): NC_ERR_VERIFICATION_FAILED')).code, 'WRONG_PASSWORD')
  })

  test('VERSION matches package.json', () => {
    const manifest = JSON.parse(readFileSync(path.join(import.meta.dirname, '../package.json'), 'utf8')) as {
      version: string
    }
    assert.equal(VERSION, manifest.version)
  })
})
