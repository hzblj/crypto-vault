# 1. A wallet's entropy sealed by the device's hardware, opened into the engine natively

Accepted.

## Context

`@hzblj/nitro-crypto` keeps seeds and keys in native memory and persists nothing. An app that keeps a wallet across
launches decides where, and the least it can do is what nitro-crypto's example does: the recovery phrase as text in
the Keychain behind Face ID, read into JavaScript to unlock. A string in JavaScript cannot be wiped, and the phrase
sits in the Keychain as the phrase.

Neither the Secure Enclave nor StrongBox holds secp256k1 or Ed25519 keys, and BIP-32 needs the seed itself, so a
phone cannot sign for these chains in its security hardware. What the hardware can do is hold a key that never leaves
it and works only for the person whose biometrics enrolled it, and seal a few bytes under that key.

## Decision

- **What the vault seals is BIP-39 entropy,** 16 to 32 bytes: from it come both the seed and, when the user asks, the
  words. Not the seed (no words for backup) and not the words (four times longer, and text).
- **iOS:** a P-256 key in the Secure Enclave per entry, made with `.privateKeyUsage` and `.biometryCurrentSet` (or
  `.biometryCurrentSet` or `.devicePasscode`), accessible when the device has a passcode, on this device only. The
  entropy is sealed to its public half with ECIES (`eciesEncryptionCofactorVariableIVX963SHA256AESGCM`): sealing asks no
  one, opening needs the key, which needs the person, and iOS deletes the key when the enrolled biometrics change. The
  sealed bytes are a Keychain item of the same accessibility. On a device without a Secure Enclave (the simulator),
  the same key lives in the Keychain's software, and the entry says `software`.
- **Android:** an AES-256-GCM key in the Android Keystore per entry, in StrongBox where the phone has one, with user
  authentication required for every use (strong biometrics, or the device credential too on API 30 and later), and
  invalidated when the enrolled biometrics change. Each seal and each open is one BiometricPrompt with the cipher as
  its CryptoObject. The sealed bytes are a file in the app's no-backup directory.
- **Protection is measured and said:** `secure-enclave`, `strongbox`, `tee` or `software`, per entry, from the key
  itself (Android's `KeyInfo`), never assumed from the device.
- **No entropy reaches JavaScript.** Creating draws it from the engine's CSPRNG in native code; importing takes the
  words the user typed (a string the app already had) as bytes the facade overwrites; unlocking unseals natively and
  hands nitro-crypto's engine the entropy through its interop (nitro-crypto ADR 0008), which returns the `NitroSeed`
  JavaScript receives and the facade wraps as an `EphemeralWallet`. The one secret that goes to JavaScript is the
  words, from `revealMnemonic`, for the moment a user writes them down.
- **Languages by what each part touches:** the cryptography is nitro-crypto's Zig engine; the Nitro binding is C++
  (Nitro Hybrid Objects are C++, Swift or Kotlin, and returning nitro-crypto's C++ `NitroSeed` takes C++), with no
  cryptography in it; the platform halves are Swift (the Security framework) and Kotlin (the Keystore and
  BiometricPrompt), behind one C interface (`cpp/VaultPlatform.h`). The binding is C++ and not a Swift or Kotlin Hybrid
  Object so that nothing JavaScript can create opens an entry and returns its bytes.

## Consequences

- A wallet survives restarts, opens only for the enrolled person, and a copy of the app's storage on another device
  opens nothing: the key stayed in the first device's hardware.
- Changing the enrolled biometrics loses every entry sealed with `biometrics`, by design (`INVALIDATED`): the words are
  the way back, and the vault says so. `biometrics-or-passcode` entries survive it through the passcode.
- An entry is this device's only. Moving to a new phone is recovery's job: the words, or an encrypted backup (the next
  decision).
- What the platform does with the plaintext inside its own calls (Security's buffers, the JVM's arrays) is beyond the
  vault, which wipes every buffer it owns.
