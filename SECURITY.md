# Security

> [!WARNING]
> **Not security audited. Do not use with real funds.** crypto-vault is a foundation and a demonstration: it uses the
> platforms' security hardware as their documentation says to, but no independent party has reviewed this code.

## Reporting a vulnerability

Please report privately, through GitHub's [private vulnerability reporting](https://github.com/hzblj/crypto-vault/security/advisories/new)
on this repository, not in a public issue. Include what you found, how to reproduce it, and which version. You will get
an acknowledgement, and a fix or an explanation, as soon as it can be worked out; a confirmed issue is disclosed in the
changelog and a GitHub advisory once a fixed version is published.

Seeds, keys, signatures and the entropy functions the vault calls are [`@hzblj/nitro-crypto`](https://github.com/hzblj/nitro-crypto)'s
engine: report anything about them there.

## What the vault protects

`@hzblj/crypto-vault` keeps a wallet's BIP-39 entropy sealed under a key the device's security hardware holds, and
opens it only for the person whose biometrics enrolled that key ([ADR 0001](docs/adr/0001-hardware-sealed-entropy.md)):

- **The key never leaves the hardware.** On iOS a P-256 key in the Secure Enclave, the entropy sealed to it with ECIES;
  on Android an AES-256-GCM key in StrongBox, or in the processor's trusted environment where there is no StrongBox.
  A copy of the app's storage, on this device or any other, opens nothing.
- **Every open needs the person.** The iOS key works only after Face ID or Touch ID (or the passcode, for an entry
  that allows it); each Android seal and open is one BiometricPrompt authorizing that one cipher operation. Changing
  the enrolled biometrics deletes or invalidates the key, and the entry is lost: its words are the way back.
- **This device only, never in a backup.** iOS: the key and the sealed bytes are Keychain items accessible only while
  the device has a passcode, on this device only. Android: the sealed bytes live in the no-backup directory.
- **No entropy in JavaScript.** Creating draws it in native code from the engine's CSPRNG; unlocking unseals it
  natively and hands the engine a seed through nitro-crypto's interop (its ADR 0008); JavaScript receives a wallet,
  never a byte of what is behind it. The words come out on purpose only, through `revealMnemonic`, and the words a user
  types to restore cross as bytes the facade overwrites.
- **Protection is reported, not assumed.** Each entry says what holds its key (`secure-enclave`, `strongbox`, `tee`
  or `software`), measured from the key. A simulator or an emulator says `software`, and an app should say so too.

## Out of scope

- An attacker with code execution in the app's process, or a compromised or rooted device: such an attacker can wait
  for the person to unlock and read native memory as easily as JavaScript's.
- Signing in the hardware: neither the Secure Enclave nor StrongBox holds secp256k1 or Ed25519 keys, so signing stays
  in nitro-crypto's engine, after the entry is opened.
- What the platform keeps inside its own calls: the Security framework's and the JVM's buffers of the plaintext they
  return. The vault wipes every buffer it owns, and the words it returns after decoding them.
- Moving a wallet to another device: an entry is this device's only. Recovery is the words, or an encrypted backup.

## Known limitations

- **Android before API 30** has no device-credential fallback for a key that needs authentication for every use: an
  entry asked to open with the passcode too opens with biometrics only there.
- **The simulator has no Secure Enclave,** and the emulator's Keystore is software: both work, and say `software`.
