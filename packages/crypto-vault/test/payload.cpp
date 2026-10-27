//
// payload.cpp
// cpp/VaultPayload.hpp held to its layouts: every entry sealed before 0.3.0 (the entropy alone) still reads as it did,
// version 2 reads back what it wrote, a check costs no length, and nothing else reads at all. test/payload.test.ts
// compiles and runs it with the system's C++ compiler.
//

#include "VaultPayload.hpp"

#include <cstdio>
#include <cstdlib>

namespace payload = margelo::nitro::cryptovault::payload;

namespace {

int failures = 0;

void expect(bool condition, const char* what) {
  if (!condition) {
    std::fprintf(stderr, "payload: %s\n", what);
    failures++;
  }
}

void fill(uint8_t* bytes, size_t length, uint8_t seed) {
  for (size_t index = 0; index < length; index++) {
    bytes[index] = static_cast<uint8_t>(seed + index * 7);
  }
}

} // namespace

int main() {
  uint8_t entropy[payload::kEntropyMaxLength];
  uint8_t sealed[payload::kMaxLength + 8];
  uint8_t opened[payload::kEntropyMaxLength];
  payload::Check check;

  for (size_t length = 16; length <= 32; length += 4) {
    // Version 1: the entropy alone, whatever its first byte, even the version 2 marker.
    fill(entropy, length, 0x02);
    expect(payload::read(entropy, length, opened, check) == length, "version 1 reads its entropy's length");
    expect(std::memcmp(opened, entropy, length) == 0, "version 1 reads its entropy");
    expect(!check.present, "version 1 holds no check");

    // Version 2 without a check, and with one: the same length, and back what was written.
    fill(entropy, length, 0x41);
    const size_t plain = payload::write(entropy, length, payload::Check{}, sealed);
    expect(plain == length + 6, "version 2 is the entropy and 6 bytes");
    expect(payload::read(sealed, plain, opened, check) == length, "version 2 reads its entropy's length");
    expect(std::memcmp(opened, entropy, length) == 0, "version 2 reads its entropy");
    expect(!check.present && check.fingerprint == 0, "version 2 without a check reads none");

    const size_t checked = payload::write(entropy, length, payload::Check{true, 0x73c5da0a}, sealed);
    expect(checked == plain, "a check costs no length");
    expect(sealed[0] == 2 && sealed[1] == 1, "version 2's header");
    expect(sealed[length + 2] == 0x73 && sealed[length + 5] == 0x0a, "the fingerprint is big-endian");
    expect(payload::read(sealed, checked, opened, check) == length, "a checked payload reads its entropy's length");
    expect(check.present && check.fingerprint == 0x73c5da0a, "a checked payload reads its fingerprint");

    // A zero fingerprint is a fingerprint: the flag says there is a check, not the bytes.
    payload::write(entropy, length, payload::Check{true, 0}, sealed);
    expect(payload::read(sealed, checked, opened, check) == length && check.present, "a zero fingerprint is a check");

    // Another version, unknown flags, or a length neither version has: no payload.
    payload::write(entropy, length, payload::Check{true, 1}, sealed);
    sealed[0] = 3;
    expect(payload::read(sealed, checked, opened, check) == 0, "another version reads as nothing");
    sealed[0] = 2;
    sealed[1] = 0x81;
    expect(payload::read(sealed, checked, opened, check) == 0, "unknown flags read as nothing");
    expect(payload::read(sealed, checked + 1, opened, check) == 0, "a longer payload reads as nothing");
    expect(payload::read(sealed, checked - 3, opened, check) == 0, "a shorter payload reads as nothing");
  }

  // The two versions never share a length.
  for (size_t length = 0; length <= payload::kMaxLength + 4; length++) {
    const bool first = payload::isEntropyLength(length);
    const bool second = length >= 6 && payload::isEntropyLength(length - 6);
    expect(!(first && second), "no length is both versions");
  }

  expect(payload::write(entropy, 15, payload::Check{}, sealed) == 0, "no entropy of 15 bytes is written");
  expect(payload::write(entropy, 36, payload::Check{}, sealed) == 0, "no entropy of 36 bytes is written");
  expect(payload::read(sealed, 0, opened, check) == 0, "nothing reads as nothing");

  if (failures == 0) {
    std::printf("payload: ok\n");
  }
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
