package com.margelo.nitro.cryptovault

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.margelo.nitro.NitroModules
import java.io.File
import java.security.KeyStore
import java.util.concurrent.CountDownLatch
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * The Android half of the vault (cpp/VaultPlatform.h), called over JNI by VaultPlatformAndroid.cpp, never by
 * JavaScript.
 *
 * Each entry is an AES-256-GCM key in the Android Keystore, in StrongBox where the phone has one, which works only
 * for the person (strong biometrics, or the device credential when the entry allows it) and which the Keystore
 * invalidates when the enrolled biometrics change. And the entry itself: the secret sealed by that key, in the app's
 * no-backup directory, so it never leaves the device in a backup. Every use of the key goes through BiometricPrompt
 * with the cipher as its CryptoObject: the key works for that one operation, after that one prompt.
 */
object VaultKeystore {
  // The values of VaultPlatform.h.
  private const val OK = 0
  private const val INVALID_ARGUMENT = 1
  private const val NOT_FOUND = 2
  private const val EXISTS = 3
  private const val CANCELLED = 4
  private const val INVALIDATED = 5
  private const val UNAVAILABLE = 6
  private const val FAILED = 8

  private const val PROTECTION_SOFTWARE = 0
  private const val PROTECTION_TEE = 1
  private const val PROTECTION_STRONGBOX = 2

  private const val ACCESS_BIOMETRICS_OR_PASSCODE = 1

  private const val KEYSTORE = "AndroidKeyStore"
  private const val TRANSFORMATION = "AES/GCM/NoPadding"
  private const val TAG_BITS = 128
  private const val ENTRY_VERSION: Byte = 1

  private class VaultException(val status: Int) : Exception()

  private fun alias(id: String) = "com.hzblj.cryptovault.$id"

  private fun file(id: String): File {
    val context = NitroModules.applicationContext ?: throw VaultException(FAILED)
    return File(File(context.noBackupFilesDir, "crypto-vault"), id)
  }

  private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

  /** What the person may use: strong biometrics, and the device credential too where the entry allows it (API 30+). */
  private fun authenticators(access: Int): Int =
    if (access == ACCESS_BIOMETRICS_OR_PASSCODE && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL
    } else {
      Authenticators.BIOMETRIC_STRONG
    }

  private fun protectionOf(key: SecretKey, strongBox: Boolean): Int {
    val info = SecretKeyFactory.getInstance(key.algorithm, KEYSTORE).getKeySpec(key, KeyInfo::class.java) as KeyInfo
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
      return when (info.securityLevel) {
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> PROTECTION_STRONGBOX
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> PROTECTION_TEE
        else -> PROTECTION_SOFTWARE
      }
    }
    @Suppress("DEPRECATION")
    return when {
      !info.isInsideSecureHardware -> PROTECTION_SOFTWARE
      strongBox -> PROTECTION_STRONGBOX
      else -> PROTECTION_TEE
    }
  }

  private fun generate(id: String, access: Int, strongBox: Boolean): SecretKey {
    val spec = KeyGenParameterSpec.Builder(alias(id), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setUserAuthenticationRequired(true)
      .setInvalidatedByBiometricEnrollment(true)
      .apply {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          // 0: for every use, the one BiometricPrompt authorizes with this cipher.
          setUserAuthenticationParameters(
            0,
            if (access == ACCESS_BIOMETRICS_OR_PASSCODE) {
              KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            } else {
              KeyProperties.AUTH_BIOMETRIC_STRONG
            },
          )
        } else {
          @Suppress("DEPRECATION")
          setUserAuthenticationValidityDurationSeconds(-1)
        }
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          setIsStrongBoxBacked(true)
        }
      }
      .build()
    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).run {
      init(spec)
      generateKey()
    }
  }

  private fun hasStrongBox(): Boolean {
    val context = NitroModules.applicationContext ?: return false
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
      context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
  }

  /**
   * Shows BiometricPrompt for `cipher` and blocks the calling thread (a pool thread, never the JS or main thread)
   * until the person answers: the cipher the prompt authorized, ready for its one operation.
   */
  private fun authorize(cipher: Cipher, prompt: String, access: Int): Cipher {
    val activity = NitroModules.applicationContext?.currentActivity as? FragmentActivity
      ?: throw VaultException(FAILED)
    val done = CountDownLatch(1)
    var authorized: Cipher? = null
    var status = FAILED

    activity.runOnUiThread {
      val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          authorized = result.cryptoObject?.cipher
          status = OK
          done.countDown()
        }

        override fun onAuthenticationError(code: Int, message: CharSequence) {
          status = when (code) {
            BiometricPrompt.ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
            BiometricPrompt.ERROR_CANCELED,
            -> CANCELLED
            BiometricPrompt.ERROR_NO_BIOMETRICS,
            BiometricPrompt.ERROR_HW_NOT_PRESENT,
            BiometricPrompt.ERROR_HW_UNAVAILABLE,
            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
            -> UNAVAILABLE
            else -> FAILED
          }
          done.countDown()
        }
      }

      val allowed = authenticators(access)
      val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(prompt)
        .setAllowedAuthenticators(allowed)
        .apply {
          if (allowed and Authenticators.DEVICE_CREDENTIAL == 0) {
            setNegativeButtonText(activity.getString(android.R.string.cancel))
          }
        }
        .build()
      BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
        .authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    done.await()
    return authorized ?: throw VaultException(if (status == OK) FAILED else status)
  }

  private fun statusOf(error: Throwable): Int = when (error) {
    is VaultException -> error.status
    is KeyPermanentlyInvalidatedException -> INVALIDATED
    else -> FAILED
  }

  /**
   * Measured once, not assumed: a throwaway key with no authentication, made the way an entry's would be, asked
   * where it lives, and deleted. An emulator's Keystore is software, whatever the device claims.
   */
  private val measured: Int by lazy {
    val probe = "com.hzblj.cryptovault.probe"
    try {
      var strongBox = hasStrongBox()
      val generate = { inStrongBox: Boolean ->
        val spec = KeyGenParameterSpec.Builder(probe, KeyProperties.PURPOSE_ENCRYPT)
          .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
          .setKeySize(256)
          .apply {
            if (inStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
              setIsStrongBoxBacked(true)
            }
          }
          .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).run {
          init(spec)
          generateKey()
        }
      }
      val key = try {
        generate(strongBox)
      } catch (unavailable: StrongBoxUnavailableException) {
        strongBox = false
        generate(false)
      }
      protectionOf(key, strongBox)
    } catch (error: Throwable) {
      PROTECTION_SOFTWARE
    } finally {
      runCatching { keyStore().deleteEntry(probe) }
    }
  }

  @JvmStatic
  fun availableProtection(): Int = measured

  @JvmStatic
  fun seal(id: String, secret: ByteArray, access: Int, prompt: String): Int {
    if (id.isEmpty() || secret.isEmpty()) {
      return INVALID_ARGUMENT
    }
    return try {
      val target = file(id)
      if (target.exists()) {
        return EXISTS
      }
      val store = keyStore()
      store.deleteEntry(alias(id))

      var strongBox = hasStrongBox()
      val key = try {
        generate(id, access, strongBox)
      } catch (unavailable: StrongBoxUnavailableException) {
        strongBox = false
        generate(id, access, false)
      }
      val protection = protectionOf(key, strongBox)

      val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
      val sealed = try {
        authorize(cipher, prompt, access).doFinal(secret)
      } catch (error: Throwable) {
        store.deleteEntry(alias(id))
        throw error
      }
      val iv = cipher.iv

      target.parentFile?.mkdirs()
      target.writeBytes(
        byteArrayOf(ENTRY_VERSION, protection.toByte(), access.toByte(), iv.size.toByte()) + iv + sealed,
      )
      OK
    } catch (error: Throwable) {
      statusOf(error)
    }
  }

  /** The entry opened, behind a status byte: `[status, ...secret]`. The caller wipes it. */
  @JvmStatic
  fun open(id: String, prompt: String): ByteArray {
    if (id.isEmpty()) {
      return byteArrayOf(INVALID_ARGUMENT.toByte())
    }
    return try {
      val target = file(id)
      if (!target.exists()) {
        return byteArrayOf(NOT_FOUND.toByte())
      }
      val entry = target.readBytes()
      if (entry.size < 4 || entry[0] != ENTRY_VERSION) {
        return byteArrayOf(FAILED.toByte())
      }
      val access = entry[2].toInt()
      val ivLength = entry[3].toInt()
      val iv = entry.copyOfRange(4, 4 + ivLength)
      val sealed = entry.copyOfRange(4 + ivLength, entry.size)

      val key = keyStore().getKey(alias(id), null) as? SecretKey ?: return byteArrayOf(INVALIDATED.toByte())
      val cipher = Cipher.getInstance(TRANSFORMATION).apply {
        init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
      }
      val secret = authorize(cipher, prompt, access).doFinal(sealed)
      val result = byteArrayOf(OK.toByte()) + secret
      secret.fill(0)
      result
    } catch (error: Throwable) {
      byteArrayOf(statusOf(error).toByte())
    }
  }

  /** `[status, protection, access]` without opening anything. */
  @JvmStatic
  fun info(id: String): IntArray {
    if (id.isEmpty()) {
      return intArrayOf(INVALID_ARGUMENT, 0, 0)
    }
    return try {
      val target = file(id)
      if (!target.exists()) {
        return intArrayOf(NOT_FOUND, 0, 0)
      }
      val entry = target.readBytes()
      if (entry.size < 4 || entry[0] != ENTRY_VERSION) intArrayOf(FAILED, 0, 0) else intArrayOf(OK, entry[1].toInt(), entry[2].toInt())
    } catch (error: Throwable) {
      intArrayOf(statusOf(error), 0, 0)
    }
  }

  @JvmStatic
  fun remove(id: String): Int {
    if (id.isEmpty()) {
      return INVALID_ARGUMENT
    }
    return try {
      file(id).delete()
      keyStore().deleteEntry(alias(id))
      OK
    } catch (error: Throwable) {
      statusOf(error)
    }
  }
}
