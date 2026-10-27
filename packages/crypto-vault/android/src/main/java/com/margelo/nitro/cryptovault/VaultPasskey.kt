package com.margelo.nitro.cryptovault

import android.os.Build
import android.util.Base64
import androidx.core.content.ContextCompat
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialNoCreateOptionException
import androidx.credentials.exceptions.CreateCredentialProviderConfigurationException
import androidx.credentials.exceptions.CreateCredentialUnsupportedException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialProviderConfigurationException
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.domerrors.NotAllowedError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import androidx.fragment.app.FragmentActivity
import com.margelo.nitro.NitroModules
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import org.json.JSONArray
import org.json.JSONObject

/**
 * The Android half of a passkey backup (cpp/VaultPlatform.h), called over JNI by VaultPlatformAndroid.cpp, never by
 * JavaScript: the PRF extension of a passkey, evaluated through Credential Manager over the vault's salt, and its
 * 32-byte output handed to the C++ bridge, which seals or opens a backup with it in nitro-crypto's engine.
 *
 * A passkey of the app's relying party (a domain whose Digital Asset Links name this app), with user verification
 * required: the PRF extension keys its output differently with and without it. Registration asks for the output at
 * once (Google Password Manager gives it there); a provider that gives it only at sign-in is asked again straight
 * after, for the passkey just made. Sealing takes only a passkey on this device: platforms have returned different PRF
 * outputs to a passkey used over a QR code from another one, and a backup sealed under one might never open again.
 *
 * Credential Manager answers in JSON, so the output arrives inside a string the JVM keeps until it collects it: it is
 * decoded into an array that is overwritten once the bridge has its copy, and the strings are beyond the vault.
 */
object VaultPasskey {
  // The values of VaultPlatform.h.
  private const val OK = 0
  private const val INVALID_ARGUMENT = 1
  private const val CANCELLED = 4
  private const val FAILED = 8
  private const val PASSKEY_UNSUPPORTED = 9
  private const val PASSKEY_NOT_FOUND = 10

  private const val MODE_CREATE = 0
  private const val MODE_SEAL = 1

  private const val KEY_LENGTH = 32
  private const val TIMEOUT_MILLISECONDS = 300_000
  private const val BASE64URL = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP

  private class PasskeyException(val status: Int) : Exception()

  private val random = SecureRandom()

  private fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, BASE64URL)

  /** A challenge or a user handle: neither secret, and no server checks the challenge. The vault wants the output. */
  private fun randomText(size: Int): String = encode(ByteArray(size).also(random::nextBytes))

  private fun prf(salt: String) = JSONObject().put("prf", JSONObject().put("eval", JSONObject().put("first", salt)))

  /**
   * A new passkey of `relyingParty` under `name`, on this device. A fresh user handle every time: a passkey with the
   * same relying party and handle replaces the one before it, and with it every backup sealed under it.
   */
  private fun registration(relyingParty: String, name: String, salt: String): String =
    JSONObject()
      .put("challenge", randomText(32))
      .put("rp", JSONObject().put("id", relyingParty).put("name", relyingParty))
      .put("user", JSONObject().put("id", randomText(16)).put("name", name).put("displayName", name))
      .put(
        "pubKeyCredParams",
        JSONArray()
          .put(JSONObject().put("type", "public-key").put("alg", -7))
          .put(JSONObject().put("type", "public-key").put("alg", -257)),
      )
      .put("timeout", TIMEOUT_MILLISECONDS)
      .put("attestation", "none")
      .put(
        "authenticatorSelection",
        JSONObject()
          .put("authenticatorAttachment", "platform")
          .put("residentKey", "required")
          .put("requireResidentKey", true)
          .put("userVerification", "required"),
      )
      .put("extensions", prf(salt))
      .toString()

  /** A passkey of `relyingParty`: `credential` (base64url), or any the person picks, a discoverable credential. */
  private fun assertion(relyingParty: String, credential: String?, salt: String): String =
    JSONObject()
      .put("challenge", randomText(32))
      .put("rpId", relyingParty)
      .put("timeout", TIMEOUT_MILLISECONDS)
      .put("userVerification", "required")
      .put(
        "allowCredentials",
        JSONArray().apply {
          if (credential != null) {
            put(JSONObject().put("type", "public-key").put("id", credential))
          }
        },
      )
      .put("extensions", prf(salt))
      .toString()

  private fun activity(): FragmentActivity =
    NitroModules.applicationContext?.currentActivity as? FragmentActivity ?: throw PasskeyException(FAILED)

  private fun statusOf(error: CreateCredentialException): Int = when (error) {
    is CreateCredentialCancellationException -> CANCELLED
    is CreateCredentialNoCreateOptionException,
    is CreateCredentialProviderConfigurationException,
    is CreateCredentialUnsupportedException,
    -> PASSKEY_UNSUPPORTED
    is CreatePublicKeyCredentialDomException -> if (error.domError is NotAllowedError) CANCELLED else FAILED
    else -> FAILED
  }

  private fun statusOf(error: GetCredentialException): Int = when (error) {
    is GetCredentialCancellationException -> CANCELLED
    is NoCredentialException -> PASSKEY_NOT_FOUND
    is GetCredentialProviderConfigurationException,
    is GetCredentialUnsupportedException,
    -> PASSKEY_UNSUPPORTED
    is GetPublicKeyCredentialDomException -> if (error.domError is NotAllowedError) CANCELLED else FAILED
    else -> FAILED
  }

  /**
   * Registers `request` from the main thread and blocks the calling thread (a pool thread, never the JS or main thread)
   * until the person answers: the response JSON.
   */
  private fun create(request: String): JSONObject {
    val activity = activity()
    val done = CountDownLatch(1)
    var response: CreateCredentialResponse? = null
    var status = FAILED
    activity.runOnUiThread {
      CredentialManager.create(activity).createCredentialAsync(
        activity,
        CreatePublicKeyCredentialRequest(request),
        null,
        ContextCompat.getMainExecutor(activity),
        object : CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException> {
          override fun onResult(result: CreateCredentialResponse) {
            response = result
            status = OK
            done.countDown()
          }

          override fun onError(e: CreateCredentialException) {
            status = statusOf(e)
            done.countDown()
          }
        },
      )
    }
    done.await()
    val registered = response as? CreatePublicKeyCredentialResponse
      ?: throw PasskeyException(if (status == OK) FAILED else status)
    return JSONObject(registered.registrationResponseJson)
  }

  /** Signs in with `request` and blocks the calling thread until the person answers: the response JSON. */
  private fun get(request: String): JSONObject {
    val activity = activity()
    val done = CountDownLatch(1)
    var response: GetCredentialResponse? = null
    var status = FAILED
    activity.runOnUiThread {
      CredentialManager.create(activity).getCredentialAsync(
        activity,
        GetCredentialRequest.Builder().addCredentialOption(GetPublicKeyCredentialOption(request)).build(),
        null,
        ContextCompat.getMainExecutor(activity),
        object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
          override fun onResult(result: GetCredentialResponse) {
            response = result
            status = OK
            done.countDown()
          }

          override fun onError(e: GetCredentialException) {
            status = statusOf(e)
            done.countDown()
          }
        },
      )
    }
    done.await()
    val credential = response?.credential as? PublicKeyCredential
      ?: throw PasskeyException(if (status == OK) PASSKEY_UNSUPPORTED else status)
    return JSONObject(credential.authenticationResponseJson)
  }

  /** Where the passkey lives: a passkey from another device, over a QR code, says `cross-platform`. */
  private fun onThisDevice(response: JSONObject) = response.optString("authenticatorAttachment") != "cross-platform"

  private fun prfOf(response: JSONObject): JSONObject? =
    response.optJSONObject("clientExtensionResults")?.optJSONObject("prf")

  /** The first PRF output a response carries, decoded; null when it carries none. The caller overwrites it. */
  private fun outputOf(prf: JSONObject?): ByteArray? {
    val first = prf?.optJSONObject("results")?.takeIf { it.has("first") }?.getString("first") ?: return null
    return Base64.decode(first, BASE64URL)
  }

  /** `[status, ...key]`: the output, behind a status byte, in an array the JNI side overwrites. */
  private fun result(output: ByteArray): ByteArray {
    try {
      if (output.size != KEY_LENGTH) {
        return byteArrayOf(PASSKEY_UNSUPPORTED.toByte())
      }
      return byteArrayOf(OK.toByte()) + output
    } finally {
      output.fill(0)
    }
  }

  /** 1 where Credential Manager has passkeys: Android 9 and later. Whether the provider has PRF, only it can say. */
  @JvmStatic
  fun supported(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P

  /**
   * The PRF output, over `salt`, of a passkey of `relyingParty`, behind a status byte: `[status, ...key]`. The caller
   * wipes it. MODE_CREATE registers a new passkey under `name` first; the other modes take one the person picks.
   */
  @JvmStatic
  fun key(relyingParty: String, mode: Int, name: String, salt: ByteArray): ByteArray {
    if (relyingParty.isEmpty() || salt.isEmpty() || (mode == MODE_CREATE && name.isEmpty())) {
      return byteArrayOf(INVALID_ARGUMENT.toByte())
    }
    if (!supported()) {
      return byteArrayOf(PASSKEY_UNSUPPORTED.toByte())
    }
    return try {
      val input = encode(salt)
      if (mode == MODE_CREATE) {
        val registered = create(registration(relyingParty, name, input))
        if (!onThisDevice(registered)) {
          return byteArrayOf(PASSKEY_UNSUPPORTED.toByte())
        }
        val prf = prfOf(registered)
        outputOf(prf)?.let { return result(it) }
        if (prf?.optBoolean("enabled") != true) {
          return byteArrayOf(PASSKEY_UNSUPPORTED.toByte())
        }
        // Supported, but evaluated only at sign-in: the passkey just made, asked once more.
        val credential = registered.optString("rawId").ifEmpty { registered.getString("id") }
        val signedIn = get(assertion(relyingParty, credential, input))
        if (!onThisDevice(signedIn)) {
          return byteArrayOf(PASSKEY_UNSUPPORTED.toByte())
        }
        return result(outputOf(prfOf(signedIn)) ?: return byteArrayOf(PASSKEY_UNSUPPORTED.toByte()))
      }
      val signedIn = get(assertion(relyingParty, null, input))
      if (mode == MODE_SEAL && !onThisDevice(signedIn)) {
        return byteArrayOf(PASSKEY_UNSUPPORTED.toByte())
      }
      result(outputOf(prfOf(signedIn)) ?: return byteArrayOf(PASSKEY_UNSUPPORTED.toByte()))
    } catch (error: PasskeyException) {
      byteArrayOf(error.status.toByte())
    } catch (error: Throwable) {
      byteArrayOf(FAILED.toByte())
    }
  }
}
