//
// HybridCryptoVault.cpp
//

#include "HybridCryptoVault.hpp"
#include "VaultPlatform.h"

#include <NitroCrypto/NitroCryptoInterop.hpp>

#include <cstring>
#include <stdexcept>
#include <vector>

namespace margelo::nitro::cryptovault {

namespace interop = margelo::nitro::nitrocrypto::interop;
using margelo::nitro::nitrocrypto::bridge::SecretBytes;
using margelo::nitro::nitrocrypto::bridge::StackSecret;
using margelo::nitro::nitrocrypto::bridge::view;
using margelo::nitro::nitrocrypto::bridge::wipe;

namespace {

const char* statusName(cv_result status) {
  switch (status) {
    case CV_ERR_INVALID_ARGUMENT:
      return "CV_ERR_INVALID_ARGUMENT";
    case CV_ERR_NOT_FOUND:
      return "CV_ERR_NOT_FOUND";
    case CV_ERR_EXISTS:
      return "CV_ERR_EXISTS";
    case CV_ERR_CANCELLED:
      return "CV_ERR_CANCELLED";
    case CV_ERR_INVALIDATED:
      return "CV_ERR_INVALIDATED";
    case CV_ERR_UNAVAILABLE:
      return "CV_ERR_UNAVAILABLE";
    case CV_ERR_BUFFER_TOO_SMALL:
      return "CV_ERR_BUFFER_TOO_SMALL";
    case CV_ERR_PASSKEY_UNSUPPORTED:
      return "CV_ERR_PASSKEY_UNSUPPORTED";
    case CV_ERR_PASSKEY_NOT_FOUND:
      return "CV_ERR_PASSKEY_NOT_FOUND";
    default:
      return "CV_ERR_FAILED";
  }
}

/// Throws the status's name, as nitro-crypto's bridge does: the facade maps the name to an error code, and nothing
/// else goes into the message.
void check(cv_result status) {
  if (status != CV_OK) {
    throw std::runtime_error(statusName(status));
  }
}

/// An id names a Keychain item and a Keystore alias: short, and made of what both take as is.
const std::string& checkedId(const std::string& id) {
  if (id.empty() || id.size() > 64) {
    throw std::runtime_error(statusName(CV_ERR_INVALID_ARGUMENT));
  }
  for (const char character : id) {
    const bool allowed = (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                         (character >= '0' && character <= '9') || character == '-' || character == '_' ||
                         character == '.';
    if (!allowed) {
      throw std::runtime_error(statusName(CV_ERR_INVALID_ARGUMENT));
    }
  }
  return id;
}

/// Refuses to start on an engine without the entropy functions, rather than fail at the first seal.
void checkEngine() {
  if (!interop::supported()) {
    throw std::runtime_error("CV_ERR_UNSUPPORTED");
  }
}

/// Refuses a backup on an engine that cannot seal one, before anything prompts.
void checkBackupEngine() {
  if (!interop::backupSupported()) {
    throw std::runtime_error("CV_ERR_UNSUPPORTED");
  }
}

/// Refuses a passkey backup on an engine that cannot seal under a key, or a system without passkeys that evaluate the
/// PRF extension, before any sheet.
void checkPasskeys() {
  if (!interop::backupWithKeySupported()) {
    throw std::runtime_error("CV_ERR_UNSUPPORTED");
  }
  if (cv_platform_passkey_supported() == 0) {
    throw std::runtime_error(statusName(CV_ERR_PASSKEY_UNSUPPORTED));
  }
}

/// A relying party is a domain the app is associated with: the facade checks its form, this only its bounds.
const std::string& checkedRelyingParty(const std::string& relyingParty) {
  if (relyingParty.empty() || relyingParty.size() > 253) {
    throw std::runtime_error(statusName(CV_ERR_INVALID_ARGUMENT));
  }
  return relyingParty;
}

/// What a passkey's PRF is evaluated over for a backup: 32 ASCII bytes, the same on both platforms, for every backup
/// and every id, so a new phone derives the same output with nothing but the passkey. Not a secret, and not the key:
/// the engine's HKDF draws a fresh salt per backup, so each backup has a key of its own (docs/adr/0003). A later salt
/// would be the PRF's second input in the same ceremony, and the version says which one sealed a backup.
constexpr char kPasskeySalt[] = "hzblj/crypto-vault/backup-key/v1";
constexpr size_t kPasskeySaltLength = sizeof(kPasskeySalt) - 1;
static_assert(kPasskeySaltLength == 32, "the PRF salt is 32 bytes on both platforms");

/// The PRF output of the passkey the person uses, from the platform into `key`: it goes to the engine and nowhere else.
void passkeyKey(const std::string& relyingParty, int32_t mode, const std::string& name,
                StackSecret<CV_PASSKEY_KEY_LENGTH>& key) {
  check(cv_platform_passkey_key(relyingParty.data(), relyingParty.size(), mode, name.data(), name.size(),
                                reinterpret_cast<const uint8_t*>(kPasskeySalt), kPasskeySaltLength, key.bytes,
                                CV_PASSKEY_KEY_LENGTH));
}

/// `passphrase` as BIP-39 hashes it, NFKD-normalized by the platform into `out`: its length. Past the engine's 1024
/// bytes it is a malformed call, not a buffer of the bridge's too small.
size_t normalizedPassphrase(const SecretBytes& passphrase, StackSecret<CV_PASSPHRASE_MAX_LENGTH>& out) {
  size_t written = 0;
  const cv_result status = cv_platform_normalize_passphrase(reinterpret_cast<const uint8_t*>(passphrase.chars()),
                                                            passphrase.size(), out.bytes, CV_PASSPHRASE_MAX_LENGTH,
                                                            &written);
  check(status == CV_ERR_BUFFER_TOO_SMALL ? CV_ERR_INVALID_ARGUMENT : status);
  return written;
}

int32_t toPlatform(Access access) {
  return access == Access::BIOMETRICS_OR_PASSCODE ? CV_ACCESS_BIOMETRICS_OR_PASSCODE : CV_ACCESS_BIOMETRICS;
}

Protection toProtection(int32_t protection) {
  switch (protection) {
    case CV_PROTECTION_SECURE_ENCLAVE:
      return Protection::SECURE_ENCLAVE;
    case CV_PROTECTION_STRONGBOX:
      return Protection::STRONGBOX;
    case CV_PROTECTION_TEE:
      return Protection::TEE;
    default:
      return Protection::SOFTWARE;
  }
}

/// 16 bytes of entropy for 12 words, 4 more for every 3 words after.
size_t entropyLength(double words) {
  if (words == 12 || words == 15 || words == 18 || words == 21 || words == 24) {
    return static_cast<size_t>(words) * 4 / 3;
  }
  throw std::runtime_error(statusName(CV_ERR_INVALID_ARGUMENT));
}

/// The entry under `id`, opened into `entropy`: its length.
size_t open(const std::string& id, const std::string& prompt, StackSecret<NC_ENTROPY_MAX_LENGTH>& entropy) {
  size_t written = 0;
  check(cv_platform_open(id.data(), id.size(), prompt.data(), prompt.size(), entropy.bytes, NC_ENTROPY_MAX_LENGTH,
                         &written));
  return written;
}

void seal(const std::string& id, const uint8_t* entropy, size_t length, Access access, const std::string& prompt) {
  check(cv_platform_seal(id.data(), id.size(), entropy, length, toPlatform(access), prompt.data(), prompt.size()));
}

/// Runs `call` on a backup's bytes. The engine reads a header it does not know, and parameters out of its bounds, as
/// an invalid argument; here that is bytes that are no backup. A failed tag is `wrongSecret` when there is one: the
/// password's stays the engine's NC_ERR_VERIFICATION_FAILED, the passkey's is the vault's own.
template <typename Call>
auto readingBackup(Call&& call, const char* wrongSecret = nullptr) -> decltype(call()) {
  try {
    return call();
  } catch (const std::runtime_error& error) {
    if (std::strcmp(error.what(), "NC_ERR_INVALID_ARGUMENT") == 0 ||
        std::strcmp(error.what(), "NC_ERR_INVALID_LENGTH") == 0) {
      throw std::runtime_error("CV_ERR_INVALID_BACKUP");
    }
    if (wrongSecret != nullptr && std::strcmp(error.what(), "NC_ERR_VERIFICATION_FAILED") == 0) {
      throw std::runtime_error(wrongSecret);
    }
    throw;
  }
}

/// What opens a backup, from the engine's reading of its header (NC_BACKUP_KDF_*). An engine that seals nothing under
/// a key reads nothing sealed under one either: every backup it opens is a password's.
uint32_t keyDerivation(const uint8_t* backup, size_t length) {
  if (!interop::backupWithKeySupported()) {
    return NC_BACKUP_KDF_ARGON2ID;
  }
  return readingBackup([&] { return interop::backupKeyDerivation(backup, length); });
}

/// Refuses a backup that `expected` does not open, before any key derivation or prompt, and says what does.
void checkKeyDerivation(const std::vector<uint8_t>& backup, uint32_t expected) {
  const uint32_t found = keyDerivation(backup.data(), backup.size());
  if (found == expected) {
    return;
  }
  if (found == NC_BACKUP_KDF_KEY) {
    throw std::runtime_error("CV_ERR_NEEDS_PASSKEY");
  }
  if (found == NC_BACKUP_KDF_ARGON2ID) {
    throw std::runtime_error("CV_ERR_NEEDS_PASSWORD");
  }
  throw std::runtime_error("CV_ERR_INVALID_BACKUP");
}

/// A password backup opened into `entropy`: its length.
size_t openBackup(const std::vector<uint8_t>& backup, const SecretBytes& password,
                  StackSecret<NC_ENTROPY_MAX_LENGTH>& entropy) {
  return readingBackup([&] {
    return interop::backupOpen(backup.data(), backup.size(), password.chars(), password.size(), entropy.bytes,
                               NC_ENTROPY_MAX_LENGTH);
  });
}

/// A passkey backup opened under the PRF output `key` into `entropy`: its length.
size_t openBackupWithKey(const std::vector<uint8_t>& backup, const StackSecret<CV_PASSKEY_KEY_LENGTH>& key,
                         StackSecret<NC_ENTROPY_MAX_LENGTH>& entropy) {
  return readingBackup(
      [&] {
        return interop::backupOpenWithKey(backup.data(), backup.size(), key.bytes, CV_PASSKEY_KEY_LENGTH,
                                          entropy.bytes, NC_ENTROPY_MAX_LENGTH);
      },
      "CV_ERR_WRONG_PASSKEY");
}

/// A JS-owned backup, copied while the call still owns the buffer.
std::shared_ptr<std::vector<uint8_t>> copied(const std::shared_ptr<ArrayBuffer>& backup) {
  const auto bytes = view(backup);
  return std::make_shared<std::vector<uint8_t>>(bytes.data, bytes.data + bytes.size);
}

} // namespace

Protection HybridCryptoVault::getAvailableProtection() {
  return toProtection(cv_platform_available_protection());
}

bool HybridCryptoVault::getSupported() {
  return interop::supported();
}

bool HybridCryptoVault::getBackupSupported() {
  return interop::backupSupported();
}

bool HybridCryptoVault::getPasskeySupported() {
  return interop::backupWithKeySupported() && cv_platform_passkey_supported() != 0;
}

bool HybridCryptoVault::has(const std::string& id) {
  int32_t protection = 0;
  int32_t access = 0;
  const cv_result status = cv_platform_info(checkedId(id).data(), id.size(), &protection, &access);
  if (status == CV_ERR_NOT_FOUND) {
    return false;
  }
  check(status);
  return true;
}

Protection HybridCryptoVault::protection(const std::string& id) {
  int32_t protection = 0;
  int32_t access = 0;
  check(cv_platform_info(checkedId(id).data(), id.size(), &protection, &access));
  return toProtection(protection);
}

Access HybridCryptoVault::access(const std::string& id) {
  int32_t protection = 0;
  int32_t access = 0;
  check(cv_platform_info(checkedId(id).data(), id.size(), &protection, &access));
  return access == CV_ACCESS_BIOMETRICS_OR_PASSCODE ? Access::BIOMETRICS_OR_PASSCODE : Access::BIOMETRICS;
}

std::shared_ptr<Promise<void>> HybridCryptoVault::create(const std::string& id, double words, Access access,
                                                         const std::string& prompt) {
  checkEngine();
  const size_t length = entropyLength(words);
  return Promise<void>::async([id = checkedId(id), length, access, prompt]() {
    StackSecret<NC_ENTROPY_MAX_LENGTH> entropy;
    interop::randomBytes(entropy.bytes, length);
    seal(id, entropy.bytes, length, access, prompt);
  });
}

std::shared_ptr<Promise<void>> HybridCryptoVault::importMnemonic(const std::string& id,
                                                                 const std::shared_ptr<ArrayBuffer>& mnemonic,
                                                                 Access access, const std::string& prompt) {
  checkEngine();
  // Copied while the call still owns the JS buffer; zeroized when the last copy goes, after the pool thread is done.
  auto words = std::make_shared<SecretBytes>(mnemonic);
  return Promise<void>::async([id = checkedId(id), words, access, prompt]() {
    StackSecret<NC_ENTROPY_MAX_LENGTH> entropy;
    const size_t length = interop::entropyFromMnemonic(words->chars(), words->size(), entropy.bytes,
                                                       NC_ENTROPY_MAX_LENGTH);
    seal(id, entropy.bytes, length, access, prompt);
  });
}

std::shared_ptr<Promise<VaultSeed>> HybridCryptoVault::unlock(const std::string& id, const std::string& prompt,
                                                             const std::shared_ptr<ArrayBuffer>& passphrase) {
  checkEngine();
  // Copied while the call still owns the JS buffer; zeroized when the last copy goes, after the pool thread is done.
  auto secret = std::make_shared<SecretBytes>(passphrase);
  return Promise<VaultSeed>::async([id = checkedId(id), prompt, secret]() {
    // Normalized first: a passphrase the engine would refuse fails before the prompt, not after it.
    StackSecret<CV_PASSPHRASE_MAX_LENGTH> normalized;
    const size_t normalizedLength = secret->size() == 0 ? 0 : normalizedPassphrase(*secret, normalized);
    StackSecret<NC_ENTROPY_MAX_LENGTH> entropy;
    const size_t length = open(id, prompt, entropy);
    // The words behind it: 12 for 16 bytes, 3 more for every 4 bytes after. Under no passphrase, or under one: a
    // different seed, and a different wallet, for every passphrase, which nothing here can call wrong.
    return VaultSeed(interop::seedFromEntropy(entropy.bytes, length, reinterpret_cast<const char*>(normalized.bytes),
                                              normalizedLength),
                     static_cast<double>(length * 3 / 4));
  });
}

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridCryptoVault::revealMnemonic(const std::string& id,
                                                                                        const std::string& prompt) {
  checkEngine();
  return Promise<std::shared_ptr<ArrayBuffer>>::async([id = checkedId(id), prompt]() {
    StackSecret<NC_ENTROPY_MAX_LENGTH> entropy;
    const size_t length = open(id, prompt, entropy);
    StackSecret<NC_MNEMONIC_MAX_LENGTH> sentence;
    const size_t written = interop::mnemonicFromEntropy(entropy.bytes, length, reinterpret_cast<char*>(sentence.bytes),
                                                        NC_MNEMONIC_MAX_LENGTH);
    // The one secret that goes to JavaScript, on purpose: the facade decodes the words and overwrites this buffer.
    return ArrayBuffer::copy(sentence.bytes, written);
  });
}

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridCryptoVault::backup(
    const std::string& id, const std::shared_ptr<ArrayBuffer>& password, const std::string& prompt) {
  checkBackupEngine();
  // Copied while the call still owns the JS buffer; zeroized when the last copy goes, after the pool thread is done.
  auto secret = std::make_shared<SecretBytes>(password);
  return Promise<std::shared_ptr<ArrayBuffer>>::async([id = checkedId(id), secret, prompt]() {
    StackSecret<NC_ENTROPY_MAX_LENGTH> entropy;
    const size_t length = open(id, prompt, entropy);
    uint8_t sealed[NC_BACKUP_MAX_LENGTH];
    const size_t written =
        interop::backupSeal(entropy.bytes, length, secret->chars(), secret->size(), sealed, NC_BACKUP_MAX_LENGTH);
    // Sealed, so JavaScript may hold it: what keeps it is the password.
    return ArrayBuffer::copy(sealed, written);
  });
}

std::shared_ptr<Promise<void>> HybridCryptoVault::restore(const std::string& id,
                                                          const std::shared_ptr<ArrayBuffer>& backup,
                                                          const std::shared_ptr<ArrayBuffer>& password, Access access,
                                                          const std::string& prompt) {
  checkBackupEngine();
  auto sealed = copied(backup);
  auto secret = std::make_shared<SecretBytes>(password);
  // Taken already: no half a second of Argon2id, and no prompt, for an entry that cannot be written.
  if (has(id)) {
    throw std::runtime_error(statusName(CV_ERR_EXISTS));
  }
  // Sealed under a passkey: no password opens it, so none is tried.
  checkKeyDerivation(*sealed, NC_BACKUP_KDF_ARGON2ID);
  return Promise<void>::async([id = checkedId(id), sealed, secret, access, prompt]() {
    StackSecret<NC_ENTROPY_MAX_LENGTH> entropy;
    const size_t length = openBackup(*sealed, *secret, entropy);
    seal(id, entropy.bytes, length, access, prompt);
  });
}

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridCryptoVault::backupWithPasskey(
    const std::string& id, const std::string& relyingParty, const std::string& name, const std::string& prompt) {
  checkPasskeys();
  // No entry: no passkey sheet, and above all no new passkey, for a backup that cannot be made.
  if (!has(id)) {
    throw std::runtime_error(statusName(CV_ERR_NOT_FOUND));
  }
  return Promise<std::shared_ptr<ArrayBuffer>>::async(
      [id = checkedId(id), relyingParty = checkedRelyingParty(relyingParty), name, prompt]() {
        // The passkey first: a sheet the person dismisses leaves the entry unopened.
        StackSecret<CV_PASSKEY_KEY_LENGTH> key;
        passkeyKey(relyingParty, name.empty() ? CV_PASSKEY_SEAL : CV_PASSKEY_CREATE, name, key);
        StackSecret<NC_ENTROPY_MAX_LENGTH> entropy;
        const size_t length = open(id, prompt, entropy);
        uint8_t sealed[NC_BACKUP_MAX_LENGTH];
        const size_t written = interop::backupSealWithKey(entropy.bytes, length, key.bytes, CV_PASSKEY_KEY_LENGTH,
                                                          sealed, NC_BACKUP_MAX_LENGTH);
        // Sealed, so JavaScript may hold it: what keeps it is the passkey.
        return ArrayBuffer::copy(sealed, written);
      });
}

std::shared_ptr<Promise<void>> HybridCryptoVault::restoreWithPasskey(const std::string& id,
                                                                     const std::shared_ptr<ArrayBuffer>& backup,
                                                                     const std::string& relyingParty, Access access,
                                                                     const std::string& prompt) {
  checkPasskeys();
  auto sealed = copied(backup);
  // Taken already, no backup, or a password's: said before any sheet.
  if (has(id)) {
    throw std::runtime_error(statusName(CV_ERR_EXISTS));
  }
  checkKeyDerivation(*sealed, NC_BACKUP_KDF_KEY);
  return Promise<void>::async(
      [id = checkedId(id), sealed, relyingParty = checkedRelyingParty(relyingParty), access, prompt]() {
        StackSecret<CV_PASSKEY_KEY_LENGTH> key;
        passkeyKey(relyingParty, CV_PASSKEY_OPEN, std::string(), key);
        StackSecret<NC_ENTROPY_MAX_LENGTH> entropy;
        const size_t length = openBackupWithKey(*sealed, key, entropy);
        seal(id, entropy.bytes, length, access, prompt);
      });
}

BackupKind HybridCryptoVault::backupKind(const std::shared_ptr<ArrayBuffer>& backup) {
  const auto bytes = view(backup);
  return keyDerivation(bytes.data, bytes.size) == NC_BACKUP_KDF_KEY ? BackupKind::PASSKEY : BackupKind::PASSWORD;
}

void HybridCryptoVault::remove(const std::string& id) {
  check(cv_platform_remove(checkedId(id).data(), id.size()));
}

} // namespace margelo::nitro::cryptovault
