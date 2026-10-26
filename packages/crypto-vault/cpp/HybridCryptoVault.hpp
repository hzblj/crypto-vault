//
// HybridCryptoVault.hpp
// The vault's Nitro binding: JavaScript's calls in, the platform half (VaultPlatform.h) and nitro-crypto's engine
// (NitroCryptoInterop.hpp) out. No cryptography here, and no secret ever goes back to JavaScript but the words
// `revealMnemonic` is asked for: a backup is the engine's seal, safe anywhere.
//

#pragma once

#include "HybridCryptoVaultSpec.hpp"

namespace margelo::nitro::cryptovault {

class HybridCryptoVault : public HybridCryptoVaultSpec {
public:
  HybridCryptoVault() : HybridObject(TAG) {}

  Protection getAvailableProtection() override;
  bool getSupported() override;
  bool getBackupSupported() override;

  bool has(const std::string& id) override;
  Protection protection(const std::string& id) override;
  Access access(const std::string& id) override;

  std::shared_ptr<Promise<void>> create(const std::string& id, double words, Access access,
                                        const std::string& prompt) override;
  std::shared_ptr<Promise<void>> importMnemonic(const std::string& id, const std::shared_ptr<ArrayBuffer>& mnemonic,
                                                Access access, const std::string& prompt) override;
  std::shared_ptr<Promise<VaultSeed>> unlock(const std::string& id, const std::string& prompt) override;
  std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> revealMnemonic(const std::string& id,
                                                                         const std::string& prompt) override;
  std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> backup(const std::string& id,
                                                                 const std::shared_ptr<ArrayBuffer>& password,
                                                                 const std::string& prompt) override;
  std::shared_ptr<Promise<void>> restore(const std::string& id, const std::shared_ptr<ArrayBuffer>& backup,
                                         const std::shared_ptr<ArrayBuffer>& password, Access access,
                                         const std::string& prompt) override;
  void remove(const std::string& id) override;
};

} // namespace margelo::nitro::cryptovault
