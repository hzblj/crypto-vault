import {type Access, isVaultError, type Protection} from '@hzblj/crypto-vault'
import {Button, Island, LabeledContent, RnText, SegmentedControl, TextField, VStack} from '@hzblj/kara-ui'
import {useFocusEffect} from 'expo-router'
import {useCallback, useState} from 'react'

import {Lead, Notice, Page, PhraseGrid, RowDivider, Rows, Section} from '../../components'
import {ENTRY, exampleEngine} from '../../core/engine'

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

type Signed = {address: string; verified: boolean}

/** What went wrong, for a person: the vault's codes in words, anything else by its message. */
const describe = (error: unknown) => {
  if (isVaultError(error)) {
    return error.code === 'CANCELLED' ? null : error.message
  }
  return error instanceof Error ? error.message : String(error)
}

/**
 * The vault, end to end, on one entry: create or import a wallet, see what protects it, unlock it into the engine and
 * sign with it, show its words, back it up under a password, remove it and restore it from the backup. Every secret
 * stays native but the words, when asked for; the backup is the engine's seal, held here in memory.
 */
export const VaultScreen = () => {
  const engine = exampleEngine()
  const [, setVersion] = useState(0)
  const [accessIndex, setAccessIndex] = useState(0)
  const [words, setWords] = useState('')
  const [phrase, setPhrase] = useState<string[] | null>(null)
  const [signed, setSigned] = useState<Signed | null>(null)
  const [password, setPassword] = useState('')
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
      const wallet = await vault.unlock(ENTRY, {prompt: 'Unlock your wallet'})
      try {
        const account = await wallet.deriveAccount({chain: 'ethereum', index: 0})
        const signature = await account.signMessage({message: MESSAGE})
        setSigned({address: account.address, verified: await account.verifyMessage({message: MESSAGE, signature})})
      } finally {
        wallet.dispose()
      }
    })

  const reveal = () =>
    run(async () => setPhrase((await vault.revealMnemonic(ENTRY, {prompt: 'Show your recovery phrase'})).split(' ')))

  const backUp = () => run(async () => setBackup(await vault.backup(ENTRY, {password, prompt: 'Back up your wallet'})))

  const restore = (sealed: Uint8Array) => run(() => vault.restore(ENTRY, sealed, {access, password}))

  const remove = () => {
    vault.remove(ENTRY)
    // The restore field starts empty, so the password typed for the backup goes too.
    setPassword('')
    setPhrase(null)
    setSigned(null)
    refresh()
  }

  const sealed = vault.has(ENTRY)

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
          <Section caption="Unlocking derives the first Ethereum account and signs a message with it." title="Wallet">
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
          </Section>

          {signed ? (
            <Section title="Signed">
              <Island>
                <Rows>
                  <LabeledContent label="Address" value={`${signed.address.slice(0, 8)}…${signed.address.slice(-6)}`} />
                  <RowDivider />
                  <LabeledContent label="Signature verifies" value={signed.verified ? 'Yes' : 'No'} />
                </Rows>
              </Island>
            </Section>
          ) : null}

          {phrase ? (
            <Section title="Recovery phrase">
              <Notice text="Anyone who reads these words can sign for the wallet, from any device." tone="warning" />
              <PhraseGrid testID="vault-words" words={phrase} />
            </Section>
          ) : null}

          <Section
            caption="Sealed by the engine under the password (Argon2id, then XChaCha20-Poly1305): safe to store anywhere, and only the password opens it. Kept in memory here; @hzblj/crypto-recovery keeps it in iCloud Keychain or Block Store."
            title="Backup"
          >
            <Island>
              <VStack spacing="s12" wide>
                <TextField label="Password" onChangeText={setPassword} secure testID="vault-backup-password" />
                <Button
                  disabled={busy || password.length === 0}
                  label="Back up under this password"
                  onPress={backUp}
                  testID="vault-backup"
                  variant="secondary"
                />
              </VStack>
            </Island>
            {backup ? (
              <Island>
                <Rows>
                  <LabeledContent label="Backup" value={`${backup.length} bytes, sealed`} />
                </Rows>
              </Island>
            ) : null}
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
          {backup ? (
            <Section
              caption={`${backup.length} bytes, opened natively straight into a new entry.`}
              title="Or restore the backup"
            >
              <Island>
                <VStack spacing="s12" wide>
                  <TextField label="Password" onChangeText={setPassword} secure testID="vault-restore-password" />
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
