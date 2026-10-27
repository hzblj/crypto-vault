# 5. A passphrase check sealed with the entropy

Accepted. Amends [0001](0001-hardware-sealed-entropy.md).

## Context

A BIP-39 passphrase makes another seed from the same entropy, so the same words make a wallet for every passphrase.
BIP-39 gives it no checksum: a mistyped passphrase makes a valid, empty wallet, and the person sees a balance of zero
where their funds should be, or, worse, receives funds into a wallet they cannot open again. The vault applied a
passphrase natively and stored nothing, so it could not tell either.

The engine knows a seed's BIP-32 fingerprint (`nc_seed_fingerprint`), and the `NitroSeed` that
`interop::seedFromEntropy` returns carries it: 4 public bytes that name a wallet. Remembering the fingerprint of the
wallet the person meant is enough to refuse every other.

## Decision

- **The fingerprint is sealed with the entropy.** An entry given a passphrase holds the fingerprint of the wallet it
  makes beside the entropy, inside what the Secure Enclave's ECIES or the Keystore's AES-GCM seals: no metadata the
  platform stores in the clear, so reading it takes the same prompt as reading the entropy. The passphrase itself is
  never stored.
- **A versioned payload.** What an entry seals becomes version 2 (`cpp/VaultPayload.hpp`): the version, flags (a check
  or not), the entropy, and 4 bytes of fingerprint, zeros without a check. Version 1, every entry sealed before, is
  the entropy alone; the two never share a length (16 to 32 bytes against 22 to 38), so old entries open as they did,
  with no check. Every new entry is version 2, with a check or without, so the ciphertext's length says nothing of a
  passphrase. The platform halves seal and open bytes and never look inside; `test/payload.cpp` holds the format to
  its layouts with the system's compiler.
- **Set where the entropy is sealed.** `create`, `importMnemonic` and `restore` take a passphrase; the binding
  normalizes it through the platform (NFKD), makes the seed, reads its fingerprint and disposes it, then seals.
  `setPassphrase` opens an entry after its prompt and seals it again with a check, or without one for `null`, under
  the same key: `cv_platform_reseal` replaces the sealed bytes whole (one Keychain update on iOS, which seals with the
  public half and asks no one; on Android a second prompt, to seal, and a file written beside the entry and moved over
  it). An empty passphrase is no passphrase, and no check.
- **Checked at unlock, natively.** `unlock` makes the seed under the passphrase it is given (none is the empty
  passphrase) and compares fingerprints; another wallet's seed is disposed before it reaches JavaScript, and the call
  fails with `WRONG_PASSPHRASE`. `verifyPassphrase: false` skips the comparison.
- **Backups hold the entropy alone.** A check stays with its entry; `restore` takes the passphrase to set one again.

## Consequences

- A mistyped passphrase fails instead of opening an empty wallet. The app asks for the passphrase twice where it is
  set, as the check accepts whatever it was given there.
- A wrong passphrase passes about once in 2^32: a check against typos, not a guard. The passphrase was never a secret
  the vault kept from someone who can open the entry, who has the entropy anyway.
- The stored fingerprint confirms which passphrase is the real one to anyone who can open the entry. For a person who
  keeps decoy or hidden wallets under other passphrases, that defeats the point: they give the entry no passphrase, or
  unlock with `verifyPassphrase: false`.
- A fingerprint costs a PBKDF2 where a passphrase is set: tens of milliseconds, natively, before the prompt.
- An entry sealed by this version does not open in an older vault, which reads only version 1.
