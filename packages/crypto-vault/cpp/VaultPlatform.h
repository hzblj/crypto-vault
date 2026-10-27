/*
 * VaultPlatform.h
 * The platform half of the vault, in the C ABI's manner: pointers and lengths in, a status out. Each platform seals
 * a few bytes under a key its hardware holds and opens them again after its own prompt: Swift over the Security
 * framework on iOS (ios/VaultPlatform.swift, as @_cdecl functions), Kotlin over the Android Keystore and
 * BiometricPrompt on Android (android/src/main/cpp/VaultPlatformAndroid.cpp, over JNI). It also evaluates a passkey's
 * PRF extension, through AuthenticationServices (ios/VaultPasskey.swift) or Credential Manager (VaultPasskey.kt), and
 * NFKD-normalizes a BIP-39 passphrase. The C++ bridge is the only caller, and it never hands these bytes to
 * JavaScript.
 *
 * Strings are UTF-8 and not NUL-terminated. Every call may block on the system prompt: never on the JS thread.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t cv_result;

#define CV_OK 0
#define CV_ERR_INVALID_ARGUMENT 1
#define CV_ERR_NOT_FOUND 2       /* no entry under that id */
#define CV_ERR_EXISTS 3          /* an entry is already sealed under that id */
#define CV_ERR_CANCELLED 4       /* the person dismissed the prompt */
#define CV_ERR_INVALIDATED 5     /* the biometrics enrolled changed: the key is gone, the entry with it */
#define CV_ERR_UNAVAILABLE 6     /* no biometrics or passcode set up for what the entry asks */
#define CV_ERR_BUFFER_TOO_SMALL 7
#define CV_ERR_FAILED 8          /* anything else the platform reported */
#define CV_ERR_PASSKEY_UNSUPPORTED 9 /* no passkeys with the PRF extension here, or a passkey that gives no output */
#define CV_ERR_PASSKEY_NOT_FOUND 10  /* no passkey of the relying party on this device */

#define CV_PROTECTION_SOFTWARE 0
#define CV_PROTECTION_TEE 1
#define CV_PROTECTION_STRONGBOX 2
#define CV_PROTECTION_SECURE_ENCLAVE 3

#define CV_ACCESS_BIOMETRICS 0
#define CV_ACCESS_BIOMETRICS_OR_PASSCODE 1

#define CV_PASSKEY_CREATE 0 /* a new passkey under `name`, made on this device */
#define CV_PASSKEY_SEAL 1   /* a passkey the person picks, which must be on this device: its output seals */
#define CV_PASSKEY_OPEN 2   /* a passkey the person picks, on this device or another: its output opens */

/** A passkey's PRF output: 32 bytes. */
#define CV_PASSKEY_KEY_LENGTH 32
/** A BIP-39 passphrase, once NFKD-normalized, at most: the engine's limit. */
#define CV_PASSPHRASE_MAX_LENGTH 1024

/** The strongest CV_PROTECTION_* a new entry gets on this device. */
int32_t cv_platform_available_protection(void);

/**
 * Seals `secret` under a new key for `id`, which only the CV_ACCESS_* `access` opens. iOS seals with the key's public
 * half and asks no one; Android's keys work only after the person, so it shows `prompt` first. CV_ERR_EXISTS when
 * `id` is taken.
 */
cv_result cv_platform_seal(const char *id, size_t id_len, const uint8_t *secret, size_t secret_len, int32_t access,
                           const char *prompt, size_t prompt_len);

/** Shows `prompt` and opens the entry under `id` into `out`, its length through `written`. */
cv_result cv_platform_open(const char *id, size_t id_len, const char *prompt, size_t prompt_len, uint8_t *out,
                           size_t out_len, size_t *written);

/** The CV_PROTECTION_* and CV_ACCESS_* of the entry under `id`, without opening it. CV_ERR_NOT_FOUND when none. */
cv_result cv_platform_info(const char *id, size_t id_len, int32_t *protection, int32_t *access);

/** Deletes the entry under `id` and its key. CV_OK when there was none. */
cv_result cv_platform_remove(const char *id, size_t id_len);

/** 1 when the system has passkeys with the PRF extension (iOS 18, Android 9 with Credential Manager), else 0. */
int32_t cv_platform_passkey_supported(void);

/**
 * Shows the system's passkey sheet for the relying party `rp_id` and writes the PRF output of the passkey the person
 * uses, evaluated over `salt`, into `key` (CV_PASSKEY_KEY_LENGTH bytes), which the caller zeroes. CV_PASSKEY_CREATE
 * registers a new passkey under `name` first (a fresh user handle, so it replaces none), and asks for it again at once
 * when its provider gives no output at registration. User verification is always required. CV_ERR_CANCELLED when the
 * person dismisses the sheet, CV_ERR_PASSKEY_UNSUPPORTED when the passkey gives no PRF output (or, for CREATE and
 * SEAL, lives on another device), CV_ERR_PASSKEY_NOT_FOUND when the platform says there is none to pick.
 */
cv_result cv_platform_passkey_key(const char *rp_id, size_t rp_id_len, int32_t mode, const char *name, size_t name_len,
                                  const uint8_t *salt, size_t salt_len, uint8_t *key, size_t key_len);

/**
 * `passphrase` (UTF-8) NFKD-normalized by the platform, as BIP-39 requires, into `out`; its length through `written`.
 * CV_ERR_INVALID_ARGUMENT for bytes that are not UTF-8, CV_ERR_BUFFER_TOO_SMALL past `out_len`. The caller zeroes
 * `out`; the platform's own strings are beyond it.
 */
cv_result cv_platform_normalize_passphrase(const uint8_t *passphrase, size_t passphrase_len, uint8_t *out,
                                           size_t out_len, size_t *written);

#ifdef __cplusplus
}
#endif
