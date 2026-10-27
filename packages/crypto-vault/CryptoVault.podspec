require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "CryptoVault"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]
  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/hzblj/crypto-vault.git", :tag => "#{s.version}" }

  # The bridge (C++, no cryptography) and the platform half it calls (Swift over the Security framework, and
  # AuthenticationServices for a passkey's PRF output).
  s.source_files = ["cpp/**/*.{h,hpp,cpp}", "ios/**/*.swift"]
  s.frameworks   = ["AuthenticationServices", "CryptoKit", "LocalAuthentication", "Security", "UIKit"]

  load "nitrogen/generated/ios/CryptoVault+autolinking.rb"
  add_nitrogen_files(s)

  # nitro-crypto's engine and its native interop (<NitroCrypto/NitroCryptoInterop.hpp>): the seeds this vault
  # unseals are made in that engine, the one the app's JavaScript already talks to.
  s.dependency "NitroCrypto"
  s.dependency "React-jsi"
  s.dependency "React-callinvoker"
  install_modules_dependencies(s)
end
