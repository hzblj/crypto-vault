package com.margelo.nitro.cryptovault

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.text.Normalizer

/**
 * A BIP-39 passphrase as the engine hashes it (cpp/VaultPlatform.h), called over JNI by VaultPlatformAndroid.cpp,
 * never by JavaScript. BIP-39 asks for NFKD, and the engine hashes the bytes it is given: the passphrase as the
 * platform decomposes it, so the same characters typed on any keyboard make the same seed, and the seed other wallets
 * make.
 */
object VaultPassphrase {
  // The values of VaultPlatform.h.
  private const val OK = 0
  private const val INVALID_ARGUMENT = 1

  /**
   * `passphrase` (UTF-8) NFKD-normalized, behind a status byte: `[status, ...bytes]`. The caller wipes it, and the
   * arrays here are overwritten; the strings are the JVM's, beyond the vault.
   */
  @JvmStatic
  fun normalize(passphrase: ByteArray): ByteArray {
    val decoder = Charsets.UTF_8.newDecoder()
      .onMalformedInput(CodingErrorAction.REPORT)
      .onUnmappableCharacter(CodingErrorAction.REPORT)
    val typed = try {
      decoder.decode(ByteBuffer.wrap(passphrase))
    } catch (malformed: CharacterCodingException) {
      return byteArrayOf(INVALID_ARGUMENT.toByte())
    }
    val normalized = Normalizer.normalize(typed, Normalizer.Form.NFKD).toByteArray(Charsets.UTF_8)
    if (typed.hasArray()) {
      typed.array().fill('\u0000')
    }
    return try {
      byteArrayOf(OK.toByte()) + normalized
    } finally {
      normalized.fill(0)
    }
  }
}
