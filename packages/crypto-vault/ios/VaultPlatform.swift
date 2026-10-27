//
//  VaultPlatform.swift
//  The iOS half of the vault (cpp/VaultPlatform.h), as C functions the C++ bridge calls.
//
//  Each entry is two Keychain items. A P-256 private key, made in the Secure Enclave where there is one (every iPhone;
//  not the simulator), which only the person who enrolled Face ID or Touch ID can use, and which iOS deletes when
//  the enrolled biometrics change (`.biometryCurrentSet`). And the entry itself: the secret sealed to that key's public
//  half with ECIES (ephemeral ECDH, X9.63 SHA-256, AES-GCM), so sealing asks no one and opening needs the key, which
//  needs the person. Both live on this device only, while it has a passcode, and never in a backup.
//

import CryptoKit
import Foundation
import LocalAuthentication
import Security

// The values of VaultPlatform.h, which Swift cannot import from C++ sources. Internal: VaultPasskey.swift says them
// too.
let statusOk: Int32 = 0
let statusInvalidArgument: Int32 = 1
let statusNotFound: Int32 = 2
let statusExists: Int32 = 3
let statusCancelled: Int32 = 4
let statusInvalidated: Int32 = 5
let statusUnavailable: Int32 = 6
let statusBufferTooSmall: Int32 = 7
let statusFailed: Int32 = 8
let statusPasskeyUnsupported: Int32 = 9
let statusPasskeyNotFound: Int32 = 10

private let protectionSoftware: Int32 = 0
private let protectionSecureEnclave: Int32 = 3

private let accessBiometricsOrPasscode: Int32 = 1

/// The Keychain service of every entry, and the prefix of every key's tag.
private let service = "com.hzblj.cryptovault"
/// What the entry's metadata starts with, so a later format can tell its own entries apart.
private let entryVersion: UInt8 = 1
private let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

// The simulator has no passcode to set, so items accessible only while there is one cannot be added there, and what
// it offers as a Secure Enclave is an emulation: its entries are software, they say so, and they need no passcode.
#if targetEnvironment(simulator)
  private let onSimulator = true
#else
  private let onSimulator = false
#endif

private let accessibility = onSimulator
  ? kSecAttrAccessibleWhenUnlockedThisDeviceOnly : kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly

private var hasSecureEnclave: Bool {
  !onSimulator && SecureEnclave.isAvailable
}

/// A UTF-8 argument of the C interface as a string: nil for a null pointer with a length.
func text(_ pointer: UnsafePointer<CChar>?, _ length: Int) -> String? {
  if length == 0 {
    return ""
  }
  guard let pointer, length > 0 else {
    return nil
  }
  return String(decoding: UnsafeRawBufferPointer(start: pointer, count: length), as: UTF8.self)
}

private func keyQuery(_ id: String) -> [String: Any] {
  [
    kSecClass as String: kSecClassKey,
    kSecAttrApplicationTag as String: Data("\(service).key.\(id)".utf8),
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
  ]
}

private func entryQuery(_ id: String) -> [String: Any] {
  [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: service,
    kSecAttrAccount as String: id,
  ]
}

private struct Entry {
  let sealed: Data
  let protection: Int32
  let access: Int32
}

/// The entry under `id`, read without the person: the sealed bytes are useless without the key.
private func readEntry(_ id: String) -> Entry? {
  var query = entryQuery(id)
  query[kSecReturnData as String] = true
  query[kSecReturnAttributes as String] = true
  query[kSecMatchLimit as String] = kSecMatchLimitOne

  var result: CFTypeRef?
  guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
        let item = result as? [String: Any],
        let sealed = item[kSecValueData as String] as? Data,
        let metadata = item[kSecAttrGeneric as String] as? Data,
        metadata.count == 3, metadata[metadata.startIndex] == entryVersion
  else {
    return nil
  }
  return Entry(sealed: sealed, protection: Int32(metadata[metadata.startIndex + 1]),
               access: Int32(metadata[metadata.startIndex + 2]))
}

/// What a failed Security or LocalAuthentication call meant, in the vault's terms.
private func status(of error: Unmanaged<CFError>?) -> Int32 {
  guard let error = error?.takeRetainedValue() else {
    return statusFailed
  }
  let domain = CFErrorGetDomain(error) as String
  let code = CFErrorGetCode(error)

  if domain == LAErrorDomain {
    switch LAError.Code(rawValue: code) {
    case .userCancel, .appCancel, .systemCancel, .userFallback:
      return statusCancelled
    case .biometryNotEnrolled, .biometryNotAvailable, .passcodeNotSet:
      return statusUnavailable
    default:
      return statusFailed
    }
  }
  if domain == (NSOSStatusErrorDomain as String) {
    switch OSStatus(code) {
    case errSecUserCanceled:
      return statusCancelled
    case errSecItemNotFound:
      return statusInvalidated
    default:
      return statusFailed
    }
  }
  return statusFailed
}

@_cdecl("cv_platform_available_protection")
public func cvPlatformAvailableProtection() -> Int32 {
  hasSecureEnclave ? protectionSecureEnclave : protectionSoftware
}

@_cdecl("cv_platform_seal")
public func cvPlatformSeal(
  _ id: UnsafePointer<CChar>?, _ idLength: Int,
  _ secret: UnsafePointer<UInt8>?, _ secretLength: Int,
  _ access: Int32,
  _: UnsafePointer<CChar>?, _: Int
) -> Int32 {
  guard let id = text(id, idLength), !id.isEmpty, let secret, secretLength > 0 else {
    return statusInvalidArgument
  }
  if readEntry(id) != nil {
    return statusExists
  }
  // A key an earlier attempt left behind goes first.
  SecItemDelete(keyQuery(id) as CFDictionary)

  let flags: SecAccessControlCreateFlags = access == accessBiometricsOrPasscode
    ? [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode]
    : [.privateKeyUsage, .biometryCurrentSet]
  var error: Unmanaged<CFError>?
  guard let control = SecAccessControlCreateWithFlags(nil, accessibility, flags, &error) else {
    return status(of: error)
  }

  let enclave = hasSecureEnclave
  var attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecPrivateKeyAttrs as String: [
      kSecAttrIsPermanent as String: true,
      kSecAttrApplicationTag as String: Data("\(service).key.\(id)".utf8),
      kSecAttrAccessControl as String: control,
    ] as [String: Any],
  ]
  if enclave {
    attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
  }

  guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
    // Without a passcode the access control cannot hold: there is no one to ask.
    let reason = status(of: error)
    return reason == statusFailed && !LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
      ? statusUnavailable : reason
  }
  guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
    SecItemDelete(keyQuery(id) as CFDictionary)
    return statusFailed
  }

  // The caller's buffer as it is: no copy of the secret on the Swift side for anyone to forget to wipe.
  guard let plaintext = CFDataCreateWithBytesNoCopy(nil, secret, secretLength, kCFAllocatorNull),
        let sealed = SecKeyCreateEncryptedData(publicKey, algorithm, plaintext, &error) as Data?
  else {
    SecItemDelete(keyQuery(id) as CFDictionary)
    return statusFailed
  }

  var item = entryQuery(id)
  item[kSecValueData as String] = sealed
  item[kSecAttrGeneric as String] = Data([
    entryVersion, UInt8(enclave ? protectionSecureEnclave : protectionSoftware), UInt8(truncatingIfNeeded: access),
  ])
  item[kSecAttrAccessible as String] = accessibility

  let added = SecItemAdd(item as CFDictionary, nil)
  guard added == errSecSuccess else {
    SecItemDelete(keyQuery(id) as CFDictionary)
    return added == errSecDuplicateItem ? statusExists : statusFailed
  }
  return statusOk
}

@_cdecl("cv_platform_open")
public func cvPlatformOpen(
  _ id: UnsafePointer<CChar>?, _ idLength: Int,
  _ prompt: UnsafePointer<CChar>?, _ promptLength: Int,
  _ out: UnsafeMutablePointer<UInt8>?, _ outLength: Int,
  _ written: UnsafeMutablePointer<Int>?
) -> Int32 {
  guard let id = text(id, idLength), !id.isEmpty, let reason = text(prompt, promptLength), let out, let written else {
    return statusInvalidArgument
  }
  guard let entry = readEntry(id) else {
    return statusNotFound
  }

  // The prompt iOS shows when the decryption below asks for the key.
  let context = LAContext()
  context.localizedReason = reason
  var query = keyQuery(id)
  query[kSecReturnRef as String] = true
  query[kSecUseAuthenticationContext as String] = context

  var result: CFTypeRef?
  let found = SecItemCopyMatching(query as CFDictionary, &result)
  if found == errSecItemNotFound {
    // The entry is here and its key is not: iOS deleted it when the enrolled biometrics changed.
    return statusInvalidated
  }
  guard found == errSecSuccess, let result, CFGetTypeID(result) == SecKeyGetTypeID() else {
    return statusFailed
  }
  let privateKey = result as! SecKey // swiftlint:disable:this force_cast

  var error: Unmanaged<CFError>?
  guard let plaintext = SecKeyCreateDecryptedData(privateKey, algorithm, entry.sealed as CFData, &error) else {
    return status(of: error)
  }
  let length = CFDataGetLength(plaintext)
  // Best effort: the buffer is the Security framework's, and this is the last anyone reads of it. The pointer has
  // escaped into a CFData, so the stores are not dead to the optimizer.
  defer {
    if let bytes = CFDataGetBytePtr(plaintext) {
      UnsafeMutablePointer(mutating: bytes).update(repeating: 0, count: length)
    }
  }
  guard length <= outLength else {
    return statusBufferTooSmall
  }
  CFDataGetBytes(plaintext, CFRange(location: 0, length: length), out)
  written.pointee = length
  return statusOk
}

/// The entry under `id` sealed anew to its own key's public half, which asks no one: the Keychain item's data is
/// replaced in one update, its metadata kept, so the entry is the old one or the new one, never neither.
@_cdecl("cv_platform_reseal")
public func cvPlatformReseal(
  _ id: UnsafePointer<CChar>?, _ idLength: Int,
  _ secret: UnsafePointer<UInt8>?, _ secretLength: Int,
  _: UnsafePointer<CChar>?, _: Int
) -> Int32 {
  guard let id = text(id, idLength), !id.isEmpty, let secret, secretLength > 0 else {
    return statusInvalidArgument
  }
  guard readEntry(id) != nil else {
    return statusNotFound
  }

  // A reference to the key, which needs no one: using the private half would, and sealing uses the public half only.
  let context = LAContext()
  context.interactionNotAllowed = true
  var query = keyQuery(id)
  query[kSecReturnRef as String] = true
  query[kSecUseAuthenticationContext as String] = context
  var result: CFTypeRef?
  let found = SecItemCopyMatching(query as CFDictionary, &result)
  if found == errSecItemNotFound {
    return statusInvalidated
  }
  guard found == errSecSuccess, let result, CFGetTypeID(result) == SecKeyGetTypeID() else {
    return statusFailed
  }
  let privateKey = result as! SecKey // swiftlint:disable:this force_cast
  guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
    return statusFailed
  }

  // The caller's buffer as it is, as in cv_platform_seal.
  var error: Unmanaged<CFError>?
  guard let plaintext = CFDataCreateWithBytesNoCopy(nil, secret, secretLength, kCFAllocatorNull),
        let sealed = SecKeyCreateEncryptedData(publicKey, algorithm, plaintext, &error) as Data?
  else {
    return statusFailed
  }

  let updated = SecItemUpdate(entryQuery(id) as CFDictionary, [kSecValueData as String: sealed] as CFDictionary)
  switch updated {
  case errSecSuccess:
    return statusOk
  case errSecItemNotFound:
    return statusNotFound
  default:
    return statusFailed
  }
}

@_cdecl("cv_platform_info")
public func cvPlatformInfo(
  _ id: UnsafePointer<CChar>?, _ idLength: Int,
  _ protection: UnsafeMutablePointer<Int32>?, _ access: UnsafeMutablePointer<Int32>?
) -> Int32 {
  guard let id = text(id, idLength), !id.isEmpty, let protection, let access else {
    return statusInvalidArgument
  }
  guard let entry = readEntry(id) else {
    return statusNotFound
  }
  protection.pointee = entry.protection
  access.pointee = entry.access
  return statusOk
}

@_cdecl("cv_platform_remove")
public func cvPlatformRemove(_ id: UnsafePointer<CChar>?, _ idLength: Int) -> Int32 {
  guard let id = text(id, idLength), !id.isEmpty else {
    return statusInvalidArgument
  }
  let entry = SecItemDelete(entryQuery(id) as CFDictionary)
  let key = SecItemDelete(keyQuery(id) as CFDictionary)
  let gone = [entry, key].allSatisfy { $0 == errSecSuccess || $0 == errSecItemNotFound }
  return gone ? statusOk : statusFailed
}

/// BIP-39 asks for NFKD, and the engine hashes the bytes it is given: the passphrase as Foundation decomposes it, so
/// the same characters typed on any keyboard make the same seed, and the seed other wallets make.
@_cdecl("cv_platform_normalize_passphrase")
public func cvPlatformNormalizePassphrase(
  _ passphrase: UnsafePointer<UInt8>?, _ passphraseLength: Int,
  _ out: UnsafeMutablePointer<UInt8>?, _ outLength: Int,
  _ written: UnsafeMutablePointer<Int>?
) -> Int32 {
  guard let out, let written, passphraseLength >= 0 else {
    return statusInvalidArgument
  }
  if passphraseLength == 0 {
    written.pointee = 0
    return statusOk
  }
  guard let passphrase,
        let typed = String(bytes: UnsafeBufferPointer(start: passphrase, count: passphraseLength), encoding: .utf8)
  else {
    return statusInvalidArgument
  }
  // The strings are Swift's and cannot be overwritten; the bytes the engine gets can.
  var normalized = Array(typed.decomposedStringWithCompatibilityMapping.utf8)
  defer {
    normalized.withUnsafeMutableBufferPointer { $0.update(repeating: 0) }
  }
  guard normalized.count <= outLength else {
    return statusBufferTooSmall
  }
  normalized.withUnsafeBufferPointer { bytes in
    if let base = bytes.baseAddress {
      out.update(from: base, count: bytes.count)
    }
  }
  written.pointee = normalized.count
  return statusOk
}
