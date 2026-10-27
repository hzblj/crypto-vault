//
//  VaultPasskey.swift
//  The iOS half of a passkey backup (cpp/VaultPlatform.h): the PRF extension of a passkey, evaluated by
//  AuthenticationServices over the vault's salt, and its 32-byte output handed to the C++ bridge, which seals or opens
//  a backup with it in nitro-crypto's engine. The output never becomes a Swift string, an NSData of the vault's, or
//  anything JavaScript can reach.
//
//  A passkey of the app's relying party (its associated domain, `webcredentials:`), with user verification required:
//  the PRF extension keys its output differently with and without it, and a backup must open the way it was sealed.
//  Registration asks for the output at once; providers that give it only at sign-in (iOS 18's iCloud Keychain among
//  them) are asked again straight after, for the passkey just made. Sealing takes only a passkey on this device: a
//  passkey used over a QR code from another one is refused, as platforms have returned different PRF outputs over that
//  transport, and a backup sealed under one of them might never open again.
//

import AuthenticationServices
import CryptoKit
import Foundation
import Security
import UIKit

// The CV_PASSKEY_* modes of VaultPlatform.h.
private let modeCreate: Int32 = 0
private let modeSeal: Int32 = 1

/// What a challenge and a user handle are made of. Neither is a secret, and no server checks the challenge: the vault
/// wants the PRF output, which the passkey gives only after the person, not a signature.
private func randomData(_ count: Int) -> Data? {
  var bytes = Data(count: count)
  let status = bytes.withUnsafeMutableBytes { buffer in
    SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
  }
  return status == errSecSuccess ? bytes : nil
}

/// The window the system's passkey sheet shows over: the key window of the active scene.
@MainActor
private func presentationWindow() -> UIWindow? {
  let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
  let active = scenes.filter { $0.activationState == .foregroundActive }
  let windows = active.flatMap(\.windows) + scenes.flatMap(\.windows)
  return windows.first(where: \.isKeyWindow) ?? windows.first
}

/// One AuthenticationServices request, on the main actor, kept alive until it answers: the controller holds its
/// delegate weakly.
@available(iOS 18.0, *)
@MainActor
private final class PasskeyCeremony: NSObject, ASAuthorizationControllerDelegate,
  ASAuthorizationControllerPresentationContextProviding
{
  private let anchor: ASPresentationAnchor
  private var controller: ASAuthorizationController?
  private var completion: ((Result<ASAuthorization, Error>) -> Void)?

  init(anchor: ASPresentationAnchor) {
    self.anchor = anchor
  }

  func perform(_ request: ASAuthorizationRequest, completion: @escaping (Result<ASAuthorization, Error>) -> Void) {
    self.completion = completion
    let controller = ASAuthorizationController(authorizationRequests: [request])
    controller.delegate = self
    controller.presentationContextProvider = self
    self.controller = controller
    controller.performRequests()
  }

  func authorizationController(controller _: ASAuthorizationController,
                               didCompleteWithAuthorization authorization: ASAuthorization)
  {
    finish(.success(authorization))
  }

  func authorizationController(controller _: ASAuthorizationController, didCompleteWithError error: Error) {
    finish(.failure(error))
  }

  func presentationAnchor(for _: ASAuthorizationController) -> ASPresentationAnchor {
    anchor
  }

  private func finish(_ result: Result<ASAuthorization, Error>) {
    let completion = completion
    self.completion = nil
    controller = nil
    completion?(result)
  }
}

/// What the main actor hands back to the pool thread waiting for it.
private final class Outcome: @unchecked Sendable {
  var authorization: ASAuthorization?
  var status: Int32 = statusFailed
  var ceremony: AnyObject?
}

/// What a failed request meant, in the vault's terms.
private func passkeyStatus(of error: Error) -> Int32 {
  let error = error as NSError
  guard error.domain == ASAuthorizationErrorDomain else {
    return statusFailed
  }
  switch error.code {
  case ASAuthorizationError.Code.canceled.rawValue:
    return statusCancelled
  case 1010: // ASAuthorizationError.deviceNotConfiguredForPasskeyCreation (iOS 26): nowhere to keep a passkey
    return statusPasskeyUnsupported
  default:
    // Among them, `failed` for an app the relying party's domain does not name in its apple-app-site-association.
    return statusFailed
  }
}

/// Shows `request` over the app's window and blocks the calling thread (a pool thread, never the JS or main thread)
/// until the person answers.
@available(iOS 18.0, *)
private func authorize(_ request: @escaping @MainActor () -> ASAuthorizationRequest) -> Outcome {
  let outcome = Outcome()
  let done = DispatchSemaphore(value: 0)
  DispatchQueue.main.async {
    MainActor.assumeIsolated {
      guard let window = presentationWindow() else {
        done.signal()
        return
      }
      let ceremony = PasskeyCeremony(anchor: window)
      outcome.ceremony = ceremony
      ceremony.perform(request()) { result in
        switch result {
        case let .success(authorization):
          outcome.authorization = authorization
          outcome.status = statusOk
        case let .failure(error):
          outcome.status = passkeyStatus(of: error)
        }
        outcome.ceremony = nil
        done.signal()
      }
    }
  }
  done.wait()
  return outcome
}

/// The PRF output into `key`: exactly 32 bytes, or the passkey is not one the vault can use.
private func write(_ output: SymmetricKey, to key: UnsafeMutablePointer<UInt8>, _ length: Int) -> Int32 {
  output.withUnsafeBytes { bytes in
    guard bytes.count == length, let base = bytes.baseAddress else {
      return statusPasskeyUnsupported
    }
    key.update(from: base.assumingMemoryBound(to: UInt8.self), count: length)
    return statusOk
  }
}

@available(iOS 18.0, *)
private func assertion(
  _ provider: ASAuthorizationPlatformPublicKeyCredentialProvider,
  credential: Data?, salt: Data, onThisDevice: Bool,
  key: UnsafeMutablePointer<UInt8>, _ length: Int
) -> Int32 {
  guard let challenge = randomData(32) else {
    return statusFailed
  }
  let outcome = authorize {
    let request = provider.createCredentialAssertionRequest(challenge: challenge)
    request.userVerificationPreference = .required
    if let credential {
      request.allowedCredentials = [ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: credential)]
    }
    request.prf = .inputValues(.init(saltInput1: salt))
    return request
  }
  guard outcome.status == statusOk else {
    return outcome.status
  }
  guard let signedIn = outcome.authorization?.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
    return statusFailed
  }
  if onThisDevice && signedIn.attachment != .platform {
    return statusPasskeyUnsupported
  }
  guard let output = signedIn.prf?.first else {
    return statusPasskeyUnsupported
  }
  return write(output, to: key, length)
}

@available(iOS 18.0, *)
private func registration(
  _ provider: ASAuthorizationPlatformPublicKeyCredentialProvider,
  name: String, salt: Data,
  key: UnsafeMutablePointer<UInt8>, _ length: Int
) -> Int32 {
  // A fresh user handle every time: a passkey with the same relying party and handle replaces the one before it,
  // and with it every backup sealed under it.
  guard let challenge = randomData(32), let user = randomData(16) else {
    return statusFailed
  }
  let outcome = authorize {
    let request = provider.createCredentialRegistrationRequest(challenge: challenge, name: name, userID: user)
    request.displayName = name
    request.userVerificationPreference = .required
    request.prf = .inputValues(.init(saltInput1: salt))
    return request
  }
  guard outcome.status == statusOk else {
    return outcome.status
  }
  guard let made = outcome.authorization?.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
    return statusFailed
  }
  guard made.attachment == .platform, let prf = made.prf else {
    return statusPasskeyUnsupported
  }
  if let output = prf.first {
    return write(output, to: key, length)
  }
  guard prf.isSupported else {
    return statusPasskeyUnsupported
  }
  // Supported, but evaluated only at sign-in: the passkey just made, asked once more.
  return assertion(provider, credential: made.credentialID, salt: salt, onThisDevice: true, key: key, length)
}

@_cdecl("cv_platform_passkey_supported")
public func cvPlatformPasskeySupported() -> Int32 {
  if #available(iOS 18.0, *) {
    return 1
  }
  return 0
}

@_cdecl("cv_platform_passkey_key")
public func cvPlatformPasskeyKey(
  _ relyingParty: UnsafePointer<CChar>?, _ relyingPartyLength: Int,
  _ mode: Int32,
  _ name: UnsafePointer<CChar>?, _ nameLength: Int,
  _ salt: UnsafePointer<UInt8>?, _ saltLength: Int,
  _ key: UnsafeMutablePointer<UInt8>?, _ keyLength: Int
) -> Int32 {
  guard #available(iOS 18.0, *) else {
    return statusPasskeyUnsupported
  }
  guard let relyingParty = text(relyingParty, relyingPartyLength), !relyingParty.isEmpty,
        let name = text(name, nameLength), let salt, saltLength > 0, let key, keyLength > 0
  else {
    return statusInvalidArgument
  }
  if mode == modeCreate && name.isEmpty {
    return statusInvalidArgument
  }
  let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: relyingParty)
  let input = Data(bytes: salt, count: saltLength)
  if mode == modeCreate {
    return registration(provider, name: name, salt: input, key: key, keyLength)
  }
  return assertion(provider, credential: nil, salt: input, onThisDevice: mode == modeSeal, key: key, keyLength)
}
