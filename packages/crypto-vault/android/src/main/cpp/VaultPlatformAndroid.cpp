//
// VaultPlatformAndroid.cpp
// The C functions of VaultPlatform.h over JNI: each calls a static method on VaultKeystore, VaultPasskey or
// VaultPassphrase (Kotlin), from whatever pool thread the bridge runs on, with the app's class loader. A secret
// crosses into the JVM and back as byte arrays, which this side overwrites once the call returns.
//

#include "VaultPlatform.h"

#include <fbjni/fbjni.h>

#include <string>
#include <vector>

namespace {

using namespace facebook;

struct JVaultKeystore : jni::JavaClass<JVaultKeystore> {
  static constexpr auto kJavaDescriptor = "Lcom/margelo/nitro/cryptovault/VaultKeystore;";
};

struct JVaultPasskey : jni::JavaClass<JVaultPasskey> {
  static constexpr auto kJavaDescriptor = "Lcom/margelo/nitro/cryptovault/VaultPasskey;";
};

struct JVaultPassphrase : jni::JavaClass<JVaultPassphrase> {
  static constexpr auto kJavaDescriptor = "Lcom/margelo/nitro/cryptovault/VaultPassphrase;";
};

std::string text(const char* pointer, size_t length) {
  return pointer == nullptr ? std::string() : std::string(pointer, length);
}

/// Runs `call` on the JVM with the app's class loader (a pool thread has only the system's), mapping anything the
/// JVM throws, which VaultKeystore itself never should, to CV_ERR_FAILED.
template <typename Call>
int32_t onJvm(Call&& call) {
  int32_t status = CV_ERR_FAILED;
  jni::ThreadScope::WithClassLoader([&] {
    try {
      status = call();
    } catch (...) {
      status = CV_ERR_FAILED;
    }
  });
  return status;
}

/// Overwrites a byte array the JVM holds: one this side made, or one a call returned.
template <typename Array>
void wipe(Array& array) {
  const size_t size = array->size();
  if (size > 0) {
    const std::vector<jbyte> zeros(size, 0);
    array->setRegion(0, size, zeros.data());
  }
}

/// A JVM byte array `[status, ...bytes]` into `out`, its length through `written`, and overwritten either way.
template <typename Array>
int32_t unpack(Array& result, uint8_t* out, size_t out_len, size_t* written) {
  const size_t size = result->size();
  if (size == 0) {
    return static_cast<int32_t>(CV_ERR_FAILED);
  }
  jbyte status = 0;
  result->getRegion(0, 1, &status);
  if (status == CV_OK) {
    const size_t length = size - 1;
    if (length > out_len) {
      status = CV_ERR_BUFFER_TOO_SMALL;
    } else {
      if (length > 0) {
        result->getRegion(1, length, reinterpret_cast<jbyte*>(out));
      }
      *written = length;
    }
  }
  wipe(result);
  return static_cast<int32_t>(status);
}

} // namespace

extern "C" int32_t cv_platform_available_protection(void) {
  return onJvm([] {
    static const auto method = JVaultKeystore::javaClassStatic()->getStaticMethod<jint()>("availableProtection");
    return static_cast<int32_t>(method(JVaultKeystore::javaClassStatic()));
  });
}

extern "C" cv_result cv_platform_seal(const char* id, size_t id_len, const uint8_t* secret, size_t secret_len,
                                      int32_t access, const char* prompt, size_t prompt_len) {
  if (id == nullptr || secret == nullptr || secret_len == 0) {
    return CV_ERR_INVALID_ARGUMENT;
  }
  return onJvm([&] {
    static const auto method = JVaultKeystore::javaClassStatic()
                                   ->getStaticMethod<jint(jstring, jni::JArrayByte::javaobject, jint, jstring)>("seal");
    auto bytes = jni::JArrayByte::newArray(secret_len);
    bytes->setRegion(0, secret_len, reinterpret_cast<const jbyte*>(secret));
    const jint status = method(JVaultKeystore::javaClassStatic(), jni::make_jstring(text(id, id_len)).get(),
                               bytes.get(), access, jni::make_jstring(text(prompt, prompt_len)).get());
    wipe(bytes);
    return static_cast<int32_t>(status);
  });
}

extern "C" cv_result cv_platform_open(const char* id, size_t id_len, const char* prompt, size_t prompt_len,
                                      uint8_t* out, size_t out_len, size_t* written) {
  if (id == nullptr || out == nullptr || written == nullptr) {
    return CV_ERR_INVALID_ARGUMENT;
  }
  return onJvm([&] {
    static const auto method =
        JVaultKeystore::javaClassStatic()->getStaticMethod<jni::JArrayByte::javaobject(jstring, jstring)>("open");
    auto result = method(JVaultKeystore::javaClassStatic(), jni::make_jstring(text(id, id_len)).get(),
                         jni::make_jstring(text(prompt, prompt_len)).get());
    const size_t size = result->size();
    if (size == 0) {
      return static_cast<int32_t>(CV_ERR_FAILED);
    }
    jbyte status = 0;
    result->getRegion(0, 1, &status);
    if (status == CV_OK) {
      const size_t length = size - 1;
      if (length > out_len) {
        status = CV_ERR_BUFFER_TOO_SMALL;
      } else {
        result->getRegion(1, length, reinterpret_cast<jbyte*>(out));
        *written = length;
      }
    }
    wipe(result);
    return static_cast<int32_t>(status);
  });
}

extern "C" cv_result cv_platform_info(const char* id, size_t id_len, int32_t* protection, int32_t* access) {
  if (id == nullptr || protection == nullptr || access == nullptr) {
    return CV_ERR_INVALID_ARGUMENT;
  }
  return onJvm([&] {
    static const auto method =
        JVaultKeystore::javaClassStatic()->getStaticMethod<jni::JArrayInt::javaobject(jstring)>("info");
    auto result = method(JVaultKeystore::javaClassStatic(), jni::make_jstring(text(id, id_len)).get());
    jint values[3] = {CV_ERR_FAILED, 0, 0};
    if (result->size() == 3) {
      result->getRegion(0, 3, values);
    }
    *protection = values[1];
    *access = values[2];
    return static_cast<int32_t>(values[0]);
  });
}

extern "C" cv_result cv_platform_remove(const char* id, size_t id_len) {
  if (id == nullptr) {
    return CV_ERR_INVALID_ARGUMENT;
  }
  return onJvm([&] {
    static const auto method = JVaultKeystore::javaClassStatic()->getStaticMethod<jint(jstring)>("remove");
    return static_cast<int32_t>(
        method(JVaultKeystore::javaClassStatic(), jni::make_jstring(text(id, id_len)).get()));
  });
}

extern "C" int32_t cv_platform_passkey_supported(void) {
  return onJvm([] {
    static const auto method = JVaultPasskey::javaClassStatic()->getStaticMethod<jboolean()>("supported");
    return method(JVaultPasskey::javaClassStatic()) ? 1 : 0;
  });
}

extern "C" cv_result cv_platform_passkey_key(const char* rp_id, size_t rp_id_len, int32_t mode, const char* name,
                                             size_t name_len, const uint8_t* salt, size_t salt_len, uint8_t* key,
                                             size_t key_len) {
  if (rp_id == nullptr || salt == nullptr || salt_len == 0 || key == nullptr) {
    return CV_ERR_INVALID_ARGUMENT;
  }
  return onJvm([&] {
    static const auto method =
        JVaultPasskey::javaClassStatic()
            ->getStaticMethod<jni::JArrayByte::javaobject(jstring, jint, jstring, jni::JArrayByte::javaobject)>("key");
    auto input = jni::JArrayByte::newArray(salt_len);
    input->setRegion(0, salt_len, reinterpret_cast<const jbyte*>(salt));
    auto result = method(JVaultPasskey::javaClassStatic(), jni::make_jstring(text(rp_id, rp_id_len)).get(), mode,
                         jni::make_jstring(text(name, name_len)).get(), input.get());
    size_t written = 0;
    const int32_t status = unpack(result, key, key_len, &written);
    // Exactly a key's length, or nothing the engine should seal under.
    return status == CV_OK && written != key_len ? static_cast<int32_t>(CV_ERR_PASSKEY_UNSUPPORTED) : status;
  });
}

extern "C" cv_result cv_platform_normalize_passphrase(const uint8_t* passphrase, size_t passphrase_len, uint8_t* out,
                                                      size_t out_len, size_t* written) {
  if (out == nullptr || written == nullptr || (passphrase == nullptr && passphrase_len > 0)) {
    return CV_ERR_INVALID_ARGUMENT;
  }
  if (passphrase_len == 0) {
    *written = 0;
    return CV_OK;
  }
  return onJvm([&] {
    static const auto method =
        JVaultPassphrase::javaClassStatic()->getStaticMethod<jni::JArrayByte::javaobject(jni::JArrayByte::javaobject)>(
            "normalize");
    auto input = jni::JArrayByte::newArray(passphrase_len);
    input->setRegion(0, passphrase_len, reinterpret_cast<const jbyte*>(passphrase));
    auto result = method(JVaultPassphrase::javaClassStatic(), input.get());
    wipe(input);
    return unpack(result, out, out_len, written);
  });
}
