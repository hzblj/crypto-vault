import {type Access, isVaultError, type Protection} from '@hzblj/crypto-vault'
import {Button, Island, LabeledContent, RnText, SegmentedControl, TextField, VStack} from '@hzblj/kara-ui'
import {useFocusEffect} from 'expo-router'
import {useCallback, useState} from 'react'

import {Lead, Notice, Page, PhraseGrid, RowDivider, Rows, Section} from '../../components'
import {ENTRY, exampleEngine, PASSKEY_DOMAIN} from '../../core/engine'

const PROTECTION: Record<Protection, string> = {
  'secure-enclave': 'Secure Enclave',
  software: 'Software only',
  strongbox: 'StrongBox',
  tee: 'Trusted environment',
}

const ACCESS: readonly {label: string; value: Access}[] = [
  {label: 'Biometrics', value: 'biometrics'},
  {label: 'Or passcode', value: 'biometrics-or-passcode'},
]

const MESSAGE = 'Hello from the vault'

/** What the new passkey is called in the person's passwords app. */
const PASSKEY_NAME = 'Vault Example wallet'

type Signed = {address: string; fingerprint: number; passphrase: boolean; verified: boolean}

/** A wallet's BIP-32 fingerprint as wallets show it: eight hex digits. */
const fingerprint = (value: number) => value.toString(16).padStart(8, '0')

/** What unlocking says when the entry was given another passphrase. */
const WRONG_PASSPHRASE =
  'Wrong passphrase: it is not the one this wallet was given. Type it again, exactly as you wrote it down.'

/** What went wrong, for a person: the vault's codes in words, anything else by its message. */
const describe = (error: unknown) => {
  if (isVaultError(error)) {
    return error.code === 'CANCELLED' ? null : error.message
  }
  return error instanceof Error ? error.message : String(error)
}

/**
 * The vault, end to end, on one entry: create or import a wallet, see what protects it, unlock it into the engine (under
 * a BIP-39 passphrase, if one is typed) and sign with it, show its words, back it up under a password or a passkey,
 * remove it and restore it from the backup. Every secret stays native but the words, when asked for; the backup is the
 * engine's seal, held here in memory.
 */
export const VaultScreen = () => {
  const engine = exampleEngine()
  const [, setVersion] = useState(0)
  const [accessIndex, setAccessIndex] = useState(0)
  const [words, setWords] = useState('')
  const [phrase, setPhrase] = useState<string[] | null>(null)
  const [signed, setSigned] = useState<Signed | null>(null)
  const [password, setPassword] = useState('')
  // Kara's fields are uncontrolled: a new key mounts the password fields empty again.
  const [passwordField, setPasswordField] = useState(0)
  const [passphrase, setPassphrase] = useState('')
  const [wrongPassphrase, setWrongPassphrase] = useState(false)
  // The passphrase to check from now on, typed twice; a new key mounts both fields empty again.
  const [checked, setChecked] = useState('')
  const [checkedAgain, setCheckedAgain] = useState('')
  const [checkFields, setCheckFields] = useState(0)
  const [backup, setBackup] = useState<Uint8Array | null>(null)
  const [problem, setProblem] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  // Leaving the screen forgets the words on it.
  useFocusEffect(useCallback(() => () => setPhrase(null), []))

  if ('error' in engine) {
    return (
      <Page testID="vault">
        <Notice text={engine.error.message} title="The vault is not available" tone="destructive" />
      </Page>
    )
  }

  const {crypto, vault} = engine
  const refresh = () => setVersion(version => version + 1)
  const access = ACCESS[accessIndex]?.value ?? 'biometrics'

  const run = async (operation: () => Promise<void>) => {
    setBusy(true)
    setProblem(null)
    try {
      await operation()
    } catch (error) {
      setProblem(describe(error))
    } finally {
      setBusy(false)
      refresh()
    }
  }

  const unlockAndSign = () =>
    run(async () => {
      setWrongPassphrase(false)
      let wallet: Awaited<ReturnType<typeof vault.unlock>>
      try {
        wallet = await vault.unlock(ENTRY, {passphrase, prompt: 'Unlock your wallet'})
      } catch (error) {
        if (isVaultError(error) && error.code === 'WRONG_PASSPHRASE') {
          setSigned(null)
          setWrongPassphrase(true)
          return
        }
        throw error
      }
      try {
        const account = await wallet.deriveAccount({chain: 'ethereum', index: 0})
        const signature = await account.signMessage({message: MESSAGE})
        setSigned({
          address: account.address,
          fingerprint: wallet.fingerprint,
          passphrase: passphrase !== '',
          verified: await account.verifyMessage({message: MESSAGE, signature}),
        })
      } finally {
        wallet.dispose()
      }
    })

  const reveal = () =>
    run(async () => setPhrase((await vault.revealMnemonic(ENTRY, {prompt: 'Show your recovery phrase'})).split(' ')))

  // Sealed with the entry from now on, or no longer: the fields empty again either way.
  const checkPassphrase = (next: string | null) =>
    run(async () => {
      await vault.setPassphrase(ENTRY, {passphrase: next, prompt: 'Check your passphrase'})
      setChecked('')
      setCheckedAgain('')
      setCheckFields(field => field + 1)
    })

  // Once the password has done its work, it goes from the screen.
  const forgetPassword = () => {
    setPassword('')
    setPasswordField(field => field + 1)
  }

  const backUp = () =>
    run(async () => {
      setBackup(await vault.backup(ENTRY, {password, prompt: 'Back up your wallet'}))
      forgetPassword()
    })

  const backUpWithPasskey = () =>
    run(async () => {
      setBackup(await vault.backup(ENTRY, {passkey: {name: PASSKEY_NAME}, prompt: 'Back up your wallet'}))
    })

  const restore = (sealed: Uint8Array) =>
    run(async () => {
      await vault.restore(ENTRY, sealed, {access, password})
      forgetPassword()
    })

  const restoreWithPasskey = (sealed: Uint8Array) => run(() => vault.restore(ENTRY, sealed, {access, passkey: true}))

  const remove = () => {
    vault.remove(ENTRY)
    // The restore field starts empty, so the password typed for the backup goes too.
    setPassword('')
    setPhrase(null)
    setSigned(null)
    setWrongPassphrase(false)
    refresh()
  }

  const sealed = vault.has(ENTRY)
  const passkeys = vault.passkeySupported && PASSKEY_DOMAIN !== undefined
  const backupKind = backup ? vault.backupKind(backup) : null
  const passkeyCaption = PASSKEY_DOMAIN
    ? `A passkey of ${PASSKEY_DOMAIN}, the one key: nothing to remember. Needs iOS 18 or Android 9, and a passwords app with the PRF extension.`
    : 'Build with VAULT_PASSKEY_DOMAIN set to a domain associated with this app to try a passkey.'

  return (
    <Page testID="vault">
      <Lead>
        A wallet's entropy, sealed by a key the device's hardware holds, opened only after Face ID or the fingerprint,
        and handed to the engine natively: JavaScript never sees a word of it, unless you ask to see the words.
      </Lead>

      <Section title="This device">
        <Island>
          <Rows>
            <LabeledContent label="New entries" value={PROTECTION[vault.availableProtection]} />
            <RowDivider />
            <LabeledContent label="Secrets in the engine" value={String(crypto.liveHandles())} />
          </Rows>
        </Island>
      </Section>

      {problem ? <Notice testID="vault-problem" text={problem} tone="destructive" /> : null}

      {sealed ? (
        <>
          <Section
            caption="Unlocking derives the first Ethereum account and signs a message with it. A passphrase makes another wallet: once the vault checks one (below), any other is refused; until then, compare the fingerprint."
            title="Wallet"
          >
            <Island>
              <Rows>
                <LabeledContent label="Protected by" value={PROTECTION[vault.protection(ENTRY)]} />
                <RowDivider />
                <LabeledContent
                  label="Opens with"
                  value={vault.access(ENTRY) === 'biometrics' ? 'Biometrics' : 'Biometrics or passcode'}
                />
              </Rows>
            </Island>
            <Island>
              <VStack spacing="s12" wide>
                <TextField
                  label="Passphrase (optional)"
                  onChangeText={setPassphrase}
                  secure
                  testID="vault-unlock-passphrase"
                />
                <Button disabled={busy} label="Unlock and sign" onPress={unlockAndSign} testID="vault-unlock" />
                <Button
                  disabled={busy}
                  label="Show recovery phrase"
                  onPress={reveal}
                  testID="vault-reveal"
                  variant="secondary"
                />
              </VStack>
            </Island>
            {wrongPassphrase ? (
              <Notice
                testID="vault-wrong-passphrase"
                text={WRONG_PASSPHRASE}
                title="Wrong passphrase"
                tone="destructive"
              />
            ) : null}
          </Section>

          {signed ? (
            <Section title="Signed">
              <Island>
                <Rows>
                  <LabeledContent label="Address" value={`${signed.address.slice(0, 8)}…${signed.address.slice(-6)}`} />
                  <RowDivider />
                  <LabeledContent label="Fingerprint" value={fingerprint(signed.fingerprint)} />
                  <RowDivider />
                  <LabeledContent label="Passphrase" value={signed.passphrase ? 'Yes' : 'None'} />
                  <RowDivider />
                  <LabeledContent label="Signature verifies" value={signed.verified ? 'Yes' : 'No'} />
                </Rows>
              </Island>
            </Section>
          ) : null}

          <Section
            caption="The vault seals the fingerprint of this passphrase's wallet with the entropy, never the passphrase, and unlocking refuses any other. Type it twice: a typo here would be the passphrase it checks."
            title="Passphrase check"
          >
            <Island>
              <VStack spacing="s12" wide>
                <TextField
                  key={`check-${checkFields}`}
                  label="Passphrase"
                  onChangeText={setChecked}
                  secure
                  testID="vault-check-passphrase"
                />
                <TextField
                  key={`again-${checkFields}`}
                  label="Passphrase again"
                  onChangeText={setCheckedAgain}
                  secure
                  testID="vault-check-passphrase-again"
                />
                <Button
                  disabled={busy || checked === '' || checked !== checkedAgain}
                  label="Check this passphrase at unlock"
                  onPress={() => checkPassphrase(checked)}
                  testID="vault-check"
                  variant="secondary"
                />
                <Button
                  disabled={busy}
                  label="Stop checking a passphrase"
                  onPress={() => checkPassphrase(null)}
                  testID="vault-uncheck"
                  variant="secondary"
                />
              </VStack>
            </Island>
          </Section>

          {phrase ? (
            <Section title="Recovery phrase">
              <Notice text="Anyone who reads these words can sign for the wallet, from any device." tone="warning" />
              <PhraseGrid testID="vault-words" words={phrase} />
            </Section>
          ) : null}

          <Section
            caption="Sealed by the engine under the password (Argon2id, then XChaCha20-Poly1305) or the passkey's PRF output (HKDF-SHA256, then the same): safe to store anywhere, and only what sealed it opens it. Kept in memory here; @hzblj/crypto-recovery keeps it in iCloud Keychain or Block Store."
            title="Backup"
          >
            <Island>
              <VStack spacing="s12" wide>
                <TextField
                  key={passwordField}
                  label="Password"
                  onChangeText={setPassword}
                  secure
                  testID="vault-backup-password"
                />
                <Button
                  disabled={busy || password.length === 0}
                  label="Back up under this password"
                  onPress={backUp}
                  testID="vault-backup"
                  variant="secondary"
                />
              </VStack>
            </Island>
            <Island>
              <Button
                disabled={busy || !passkeys}
                label="Back up with a new passkey"
                onPress={backUpWithPasskey}
                testID="vault-backup-passkey"
                variant="secondary"
              />
            </Island>
            {backup ? (
              <Island>
                <Rows>
                  <LabeledContent label="Backup" value={`${backup.length} bytes, sealed`} />
                  <RowDivider />
                  <LabeledContent
                    label="Opens with"
                    value={backupKind === 'passkey' ? 'Its passkey' : 'Its password'}
                  />
                </Rows>
              </Island>
            ) : null}
            <RnText color="content.tertiary" variant="footnote">
              {passkeyCaption}
            </RnText>
          </Section>

          <Island>
            <Button label="Remove from this device" onPress={remove} testID="vault-remove" variant="destructive" />
          </Island>
        </>
      ) : (
        <>
          <Section title="Opens with">
            <SegmentedControl
              onChange={setAccessIndex}
              selectedIndex={accessIndex}
              testID="vault-access"
              values={ACCESS.map(option => option.label)}
            />
          </Section>
          <Section caption="Twelve words of fresh entropy from the engine, sealed before anything else sees them.">
            <Island>
              <Button
                disabled={busy}
                label="Create a wallet"
                onPress={() => run(() => vault.create(ENTRY, {access}))}
                testID="vault-create"
              />
            </Island>
          </Section>
          {backup && backupKind === 'password' ? (
            <Section
              caption={`${backup.length} bytes, opened natively straight into a new entry.`}
              title="Or restore the backup"
            >
              <Island>
                <VStack spacing="s12" wide>
                  <TextField
                    key={passwordField}
                    label="Password"
                    onChangeText={setPassword}
                    secure
                    testID="vault-restore-password"
                  />
                  <Button
                    disabled={busy || password.length === 0}
                    label="Restore the backup"
                    onPress={() => restore(backup)}
                    testID="vault-restore"
                  />
                </VStack>
              </Island>
            </Section>
          ) : null}
          {backup && backupKind === 'passkey' ? (
            <Section
              caption={`${backup.length} bytes, sealed under a passkey: the passkey's sheet asks for it, and the vault opens the backup natively, straight into a new entry.`}
              title="Or restore the backup"
            >
              <Island>
                <Button
                  disabled={busy || !passkeys}
                  label="Restore with the passkey"
                  onPress={() => restoreWithPasskey(backup)}
                  testID="vault-restore-passkey"
                />
              </Island>
            </Section>
          ) : null}
          <Section title="Or restore one">
            <Island>
              <VStack spacing="s12" wide>
                <TextField label="Words" multiline onChangeText={setWords} testID="vault-import-words" />
                <Button
                  disabled={busy || words.trim() === ''}
                  label="Seal these words"
                  onPress={() => run(() => vault.importMnemonic(ENTRY, words, {access}))}
                  testID="vault-import"
                  variant="secondary"
                />
              </VStack>
            </Island>
          </Section>
        </>
      )}

      <RnText color="content.tertiary" variant="footnote">
        {`Unlocked wallets are disposed after signing: the engine holds ${crypto.liveHandles()} secrets now.`}
      </RnText>
    </Page>
  )
}
