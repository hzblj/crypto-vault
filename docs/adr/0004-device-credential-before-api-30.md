# 4. The device credential on Android before API 30, through a time-bound key

Accepted. Amends [0001](0001-hardware-sealed-entropy.md).

## Context

ADR 0001 gives every Android entry a Keystore key that needs the person for every use, authorized by one BiometricPrompt
with the cipher as its CryptoObject. Before API 30, a CryptoObject prompt takes strong biometrics only: the Keystore
has no per-use authorization by the device credential (`setUserAuthenticationParameters` is API 30), and androidx's
BiometricPrompt refuses `DEVICE_CREDENTIAL` beside a CryptoObject there. An entry asked to open with the passcode too
opened with biometrics only on API 24 to 29, and the README said so.

What those versions do have is a key bound to time: `setUserAuthenticationValidityDurationSeconds(n)` makes a key work
for `n` seconds after the person authenticates by any means the lock screen takes, biometrics or the device credential.

## Decision

- **On API 24 to 29, an entry that allows the passcode gets a time-bound key** that works for 5 seconds after the
  person authenticates. An entry for biometrics only keeps the per-use key, and API 30 and later keep ADR 0001's path
  unchanged.
- **Every seal and open still asks first.** BiometricPrompt without a CryptoObject, `BIOMETRIC_WEAK | DEVICE_CREDENTIAL`
  (androidx's combination for those versions, which shows the device credential where biometrics are not set up), then
  the cipher is made inside the window. A biometric too weak to unlock a key, or a window outlasted, makes the cipher
  fail with `UserNotAuthenticatedException`: the device credential screen
  (`KeyguardManager.createConfirmDeviceCredentialIntent`) follows, once, and the cipher is made again.
- **The key says which it is.** `KeyInfo.getUserAuthenticationValidityDurationSeconds()` above 0 is a time-bound key;
  entries sealed before this change, and every entry on API 30 and later, are per-use keys and open as they did.

## Consequences

- The README's limitation goes: `biometrics-or-passcode` means the same on every supported version.
- A time-bound key is not invalidated when the enrolled biometrics change (the Keystore invalidates only keys that need
  biometrics for every use): such an entry survives a new fingerprint, as an iOS entry that allows the passcode does.
- For the 5 seconds after any authentication, the device's own unlock included, the key works without a prompt for
  code in the app's process. The vault always prompts first; code running in the app's process is outside what it
  protects against (SECURITY.md), and the window is kept as short as one cipher needs.
