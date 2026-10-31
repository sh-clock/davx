/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * Row-store crypto for the "clock" encrypted row protocol (v4.3, see
 * calendar-web/protocol.md in the companion repository):
 *
 *   PASSWORD --PBKDF2-HMAC-SHA256(salt, iters)--> KEK
 *   KEK --AES-256-GCM unwrap(config.wrapped)--> AES1 (32 bytes)
 *   AES1 --HKDF-SHA256(salt="", info="clock-v4/<domain>")--> subkeys
 *
 * Rows: AES-256-GCM under K_data with AAD = UTF-8(id) || u32be(ver).
 * The plaintext of a row is a JSON value; event rows carry the iCalendar
 * text JSON-encoded (a JSON string).
 *
 * Verified against the JavaScript reference implementation
 * (calendar-web/js/crypto.js) and the KAT vectors in
 * calendar-web/test/crypto-parity.mjs.
 */
package at.bitfire.davdroid.resource.rowstore

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

object RowStoreCrypto {

    private const val GCM_TAG_BITS = 128
    private const val GCM_NONCE_LEN = 12
    private const val WRAPPED_LEN = 60      // 12 nonce || 32 ct || 16 tag
    private const val HKDF_INFO_K_DATA = "clock-v4/K_data"
    private const val HKDF_INFO_AUTH_UI = "clock-v4/AUTH_UI"
    // Explicit empty salt per the spec. Java rejects zero-length HMAC keys, so
    // the RFC 5868 "not provided" form is used: HashLen (32) zero bytes. This
    // is byte-identical to WebCrypto's empty-salt HKDF (same ipad/opad after
    // key padding), verified against the JS reference KATs below.
    private val HKDF_SALT = ByteArray(32)

    data class Keys(
        /** AES-256 key for row envelope encryption/decryption. */
        val kData: SecretKey,
        /** AUTH_UI bearer token (hex). */
        val authUiHex: String
    )

    /** Envelope as it appears on the wire. */
    data class Envelope(
        val ver: Long,
        val nonceB64: String,
        val ctB64: String
    )

    private fun hexToBytes(hex: String): ByteArray {
        val clean = if (hex.length % 2 == 0) hex else throw IllegalArgumentException("bad hex length")
        return ByteArray(clean.length / 2) { i ->
            ((Character.digit(clean[i * 2], 16) shl 4) + Character.digit(clean[i * 2 + 1], 16)).toByte()
        }
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) sb.append(String.format("%02x", b))
        return sb.toString()
    }

    /** RFC 5869 HKDF-SHA256 with the explicit empty salt and one-block output. */
    fun hkdf(ikm: ByteArray, info: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // extract: PRK = HMAC(salt, IKM)
        mac.init(SecretKeySpec(HKDF_SALT, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        // expand: T(1) = HMAC(PRK, info || 0x01), one block (32 bytes)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(info.toByteArray(Charsets.UTF_8))
        mac.update(0x01)
        return mac.doFinal()
    }

    /**
     * Full unlock derivation. Throws [javax.crypto.AEADBadTagException]-derived
     * exceptions on a wrong password.
     */
    fun derive(password: String, saltHex: String, iters: Int, wrappedB64: String): Keys {
        val salt = hexToBytes(saltHex)
        val wrapped = Base64.getDecoder().decode(wrappedB64)
        require(wrapped.size == WRAPPED_LEN) { "wrapped must be $WRAPPED_LEN bytes" }

        // PBKDF2 -> KEK (re-wrapped as an AES key: PBE keys report the
        // "PBKDF2" algorithm and would be rejected by the AES/GCM cipher)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val kekBytes = factory.generateSecret(PBEKeySpec(password.toCharArray(), salt, iters, 256)).encoded
        val kek = SecretKeySpec(kekBytes, "AES")

        // AES-GCM unwrap of AES1
        val unwrap = Cipher.getInstance("AES/GCM/NoPadding")
        unwrap.init(Cipher.DECRYPT_MODE, kek, GCMParameterSpec(GCM_TAG_BITS, wrapped.copyOfRange(0, GCM_NONCE_LEN)))
        val aes1 = unwrap.doFinal(wrapped, GCM_NONCE_LEN, wrapped.size - GCM_NONCE_LEN)
        require(aes1.size == 32) { "AES1 must be 32 bytes" }

        // HKDF subkeys
        val kData = hkdf(aes1, HKDF_INFO_K_DATA)
        val authUi = hkdf(aes1, HKDF_INFO_AUTH_UI)
        return Keys(
            kData = SecretKeySpec(kData, "AES"),
            authUiHex = bytesToHex(authUi)
        )
    }

    /** AAD = UTF-8(id) || u32be(ver) (§6). */
    fun rowAad(id: String, ver: Long): ByteArray {
        val idB = id.toByteArray(Charsets.UTF_8)
        val out = ByteArray(idB.size + 4)
        System.arraycopy(idB, 0, out, 0, idB.size)
        out[idB.size] = (ver ushr 24).toByte()
        out[idB.size + 1] = (ver ushr 16).toByte()
        out[idB.size + 2] = (ver ushr 8).toByte()
        out[idB.size + 3] = ver.toByte()
        return out
    }

    private val random = SecureRandom()

    /**
     * Encrypt a row payload. [payloadJson] must ALREADY be JSON (i.e. for event
     * rows: quoteJsonString(iCalendarText)) — the plaintext is a JSON value.
     */
    fun encryptRow(key: SecretKey, id: String, ver: Long, payloadJson: String): Envelope {
        val nonce = ByteArray(GCM_NONCE_LEN).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
        cipher.updateAAD(rowAad(id, ver))
        val ct = cipher.doFinal(payloadJson.toByteArray(Charsets.UTF_8))
        return Envelope(
            ver = ver,
            nonceB64 = Base64.getEncoder().encodeToString(nonce),
            ctB64 = Base64.getEncoder().encodeToString(ct)
        )
    }

    /**
     * Decrypt a row envelope; returns the payload's plaintext, which is a JSON
     * value. For event rows use [unquoteJsonString] on the result to obtain the
     * iCalendar text. Throws on tamper / AAD (rollback) mismatch.
     */
    fun decryptRow(key: SecretKey, id: String, ver: Long, nonceB64: String, ctB64: String): String {
        val nonce = Base64.getDecoder().decode(nonceB64)
        val ct = Base64.getDecoder().decode(ctB64)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
        cipher.updateAAD(rowAad(id, ver))
        return String(cipher.doFinal(ct), Charsets.UTF_8)
    }

    /** JSON-encode a string (the §6 payload encoding for event rows). */
    fun quoteJsonString(s: String): String {
        val sb = StringBuilder(s.length + 2)
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else ->
                    if (c < ' ') sb.append(String.format("\\u%04x", c.code))
                    else sb.append(c)
            }
        }
        sb.append('"')
        return sb.toString()
    }

    /** Decode a JSON-encoded string (minimal reader: no nesting, full escapes). */
    fun unquoteJsonString(json: String): String {
        require(json.length >= 2 && json[0] == '"' && json[json.length - 1] == '"') { "not a JSON string" }
        val body = json.substring(1, json.length - 1)
        val sb = StringBuilder(body.length)
        var i = 0
        while (i < body.length) {
            val c = body[i]
            if (c != '\\') {
                sb.append(c); i++; continue
            }
            i++
            require(i < body.length) { "trailing backslash" }
            when (val e = body[i]) {
                '"' -> sb.append('"')
                '\\' -> sb.append('\\')
                '/' -> sb.append('/')
                'n' -> sb.append('\n')
                'r' -> sb.append('\r')
                't' -> sb.append('\t')
                'b' -> sb.append('\b')
                'f' -> sb.append('\u000C')
                'u' -> {
                    require(i + 4 < body.length) { "bad unicode escape" }
                    sb.append(body.substring(i + 1, i + 5).toInt(16).toChar())
                    i += 4
                }
                else -> throw IllegalArgumentException("bad escape \\$e")
            }
            i++
        }
        return sb.toString()
    }
}
