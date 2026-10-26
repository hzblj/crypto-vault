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

/// A backup opened into `entropy`: its length. The engine reads a header it does not know, and parameters out of its
/// bounds, as an invalid argument; here that is bytes that are no backup. A wrong password stays the engine's
/// NC_ERR_VERIFICATION_FAILED.
size_t openBackup(const std::vector<uint8_t>& backup, const SecretBytes& password,
                  StackSecret<NC_ENTROPY_MAX_LENGTH>& entropy) {
  try {
    return interop::backupOpen(backup.data(), backup.size(), password.chars(), password.size(), entropy.bytes,
                               NC_ENTROPY_MAX_LENGTH);
  } catch (const std::runtime_error& error) {
    if (std::strcmp(error.what(), "NC_ERR_INVALID_ARGUMENT") == 0 ||
        std::strcmp(error.what(), "NC_ERR_INVALID_LENGTH") == 0) {
      throw std::runtime_error("CV_ERR_INVALID_BACKUP");
    }
    throw;
  }
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

std::shared_ptr<Promise<VaultSeed>> HybridCryptoVault::unlock(const std::string& id, const std::string& prompt) {
  checkEngine();
  return Promise<VaultSeed>::async([id = checkedId(id), prompt]() {
    StackSecret<NC_ENTROPY_MAX_LENGTH> entropy;
    const size_t length = open(id, prompt, entropy);
    // The words behind it: 12 for 16 bytes, 3 more for every 4 bytes after.
    return VaultSeed(interop::seedFromEntropy(entropy.bytes, length), static_cast<double>(length * 3 / 4));
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
  const auto bytes = view(backup);
  auto sealed = std::make_shared<std::vector<uint8_t>>(bytes.data, bytes.data + bytes.size);
  auto secret = std::make_shared<SecretBytes>(password);
  // Taken already: no half a second of Argon2id, and no prompt, for an entry that cannot be written.
  if (has(id)) {
    throw std::runtime_error(statusName(CV_ERR_EXISTS));
  }
  return Promise<void>::async([id = checkedId(id), sealed, secret, access, prompt]() {
    StackSecret<NC_ENTROPY_MAX_LENGTH> entropy;
    const size_t length = openBackup(*sealed, *secret, entropy);
    seal(id, entropy.bytes, length, access, prompt);
  });
}

void HybridCryptoVault::remove(const std::string& id) {
  check(cv_platform_remove(checkedId(id).data(), id.size()));
}

} // namespace margelo::nitro::cryptovault
