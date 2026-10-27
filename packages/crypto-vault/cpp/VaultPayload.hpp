//
// VaultPayload.hpp
// What an entry's sealed bytes hold, the platform's ciphertext opened: the format the binding writes and reads, with
// nothing in it but plain C++, so test/payload.cpp holds it to its layouts. The platform halves never look inside.
//
// Version 1, every entry sealed before 0.3.0: the BIP-39 entropy alone, 16 to 32 bytes.
// Version 2:
//
//   offset  length
//   0       1       version, 2
//   1       1       flags: bit 0, a passphrase check follows the entropy
//   2       n       the entropy (16 to 32 bytes)
//   2 + n   4       the BIP-32 fingerprint of the wallet the entry's passphrase makes, big-endian; zeros without a check
//
// A version 2 payload is as long with a check as without one, so the ciphertext's length says nothing of a passphrase.
// The two versions never share a length: 16 to 32 bytes in steps of 4 is version 1, 22 to 38 in steps of 4 is 2.
//

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace margelo::nitro::cryptovault::payload {

constexpr uint8_t kVersion = 2;
constexpr uint8_t kChecked = 0x01;
constexpr size_t kHeaderLength = 2;
constexpr size_t kFingerprintLength = 4;
constexpr size_t kEntropyMaxLength = 32;
constexpr size_t kMaxLength = kHeaderLength + kEntropyMaxLength + kFingerprintLength;

/// A length BIP-39 entropy has: 16 bytes for 12 words, 4 more for every 3 words after, up to 32.
constexpr bool isEntropyLength(size_t length) {
  return length >= 16 && length <= kEntropyMaxLength && length % 4 == 0;
}

/// The passphrase check an entry holds, if any: the fingerprint its passphrase's wallet has.
struct Check {
  bool present = false;
  uint32_t fingerprint = 0;
};

/// The version 2 payload of `entropy` and `check` into `out` (kMaxLength bytes): its length, or 0 for entropy of a
/// length BIP-39 does not have.
inline size_t write(const uint8_t* entropy, size_t length, Check check, uint8_t* out) {
  if (entropy == nullptr || out == nullptr || !isEntropyLength(length)) {
    return 0;
  }
  out[0] = kVersion;
  out[1] = check.present ? kChecked : 0;
  std::memcpy(out + kHeaderLength, entropy, length);
  const uint32_t fingerprint = check.present ? check.fingerprint : 0;
  uint8_t* tail = out + kHeaderLength + length;
  tail[0] = static_cast<uint8_t>(fingerprint >> 24);
  tail[1] = static_cast<uint8_t>(fingerprint >> 16);
  tail[2] = static_cast<uint8_t>(fingerprint >> 8);
  tail[3] = static_cast<uint8_t>(fingerprint);
  return kHeaderLength + length + kFingerprintLength;
}

/// The entropy a payload of `length` bytes holds, into `entropy` (kEntropyMaxLength bytes), and its check through
/// `check`: the entropy's length, or 0 for bytes that are neither version.
inline size_t read(const uint8_t* payload, size_t length, uint8_t* entropy, Check& check) {
  check = Check{};
  if (payload == nullptr || entropy == nullptr) {
    return 0;
  }
  if (isEntropyLength(length)) {
    std::memcpy(entropy, payload, length);
    return length;
  }
  if (length < kHeaderLength + kFingerprintLength) {
    return 0;
  }
  const size_t entropyLength = length - kHeaderLength - kFingerprintLength;
  if (payload[0] != kVersion || (payload[1] & ~kChecked) != 0 || !isEntropyLength(entropyLength)) {
    return 0;
  }
  std::memcpy(entropy, payload + kHeaderLength, entropyLength);
  const uint8_t* tail = payload + kHeaderLength + entropyLength;
  check.present = (payload[1] & kChecked) != 0;
  check.fingerprint = check.present ? (static_cast<uint32_t>(tail[0]) << 24) | (static_cast<uint32_t>(tail[1]) << 16) |
                                          (static_cast<uint32_t>(tail[2]) << 8) | static_cast<uint32_t>(tail[3])
                                    : 0;
  return entropyLength;
}

} // namespace margelo::nitro::cryptovault::payload
