import type {ExpoConfig} from 'expo/config'

// The generated Xcode target and scheme are `VaultExample`: apart from the other hzblj examples', so all install.
const NAME = 'Vault Example'
const BUNDLE_ID = 'com.hzblj.cryptovault.example'
// The middle of the icon's amber: what the Android icon's vault sits on.
const ICON_BACKGROUND = '#b45309'
// The domain passkey backups belong to (their relying party), from the environment: one whose
// /.well-known/apple-app-site-association names `<team id>.com.hzblj.cryptovault.example` under `webcredentials`, and
// whose /.well-known/assetlinks.json names the package with its signing certificate's SHA-256. Without one, the example
// offers no passkey backup.
const PASSKEY_DOMAIN = process.env.VAULT_PASSKEY_DOMAIN || undefined

export default {
  android: {
    adaptiveIcon: {
      backgroundColor: ICON_BACKGROUND,
      foregroundImage: './assets/adaptive-icon.png',
    },
    package: BUNDLE_ID,
  },
  experiments: {
    typedRoutes: true,
  },
  extra: {
    passkeyDomain: PASSKEY_DOMAIN ?? null,
  },
  icon: './assets/icon.png',
  ios: {
    // A passkey of the relying party works in an app the domain names, and that names the domain back.
    ...(PASSKEY_DOMAIN ? {associatedDomains: [`webcredentials:${PASSKEY_DOMAIN}`]} : {}),
    bundleIdentifier: BUNDLE_ID,
    infoPlist: {
      // The Secure Enclave key of every entry opens only after Face ID: iOS shows this the first time it asks.
      NSFaceIDUsageDescription: 'Allow $(PRODUCT_NAME) to use Face ID to open the wallets its vault keeps.',
    },
    supportsTablet: true,
  },
  name: NAME,
  orientation: 'portrait',
  plugins: [
    'expo-router',
    // The example's icons (Material Symbols): every SVG in assets/icons becomes a native asset on both platforms, and
    // its name a type in native-icons.d.ts.
    ['@hzblj/kara-ui', {icons: {source: './assets/icons'}}],
    // The scene life cycle, which apps built with the iOS 27 SDK need or they stop at launch: Expo 57's template has
    // none, so React Native starts from Expo's scene delegate instead. Remove it with the move to Expo 58.
    ['expo-build-properties', {ios: {enableSceneSupport: true}}],
  ],
  scheme: 'crypto-vault-example',
  slug: 'crypto-vault-example',
  userInterfaceStyle: 'automatic',
  version: '1.0.0',
} satisfies ExpoConfig
