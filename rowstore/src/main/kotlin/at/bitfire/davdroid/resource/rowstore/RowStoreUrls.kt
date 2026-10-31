/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * Row-store URL grammar (protocol v4.3): one calendar collection is
 * addressed as {server}/clock/{calendar-uuid}/, its members (event files)
 * as {server}/clock/{calendar-uuid}/{event-uid}. Row ids are addressed in
 * API paths as /rows/{percent-encoded row id}.
 *
 * The percent codec mirrors JavaScript's encodeURIComponent/decodeURIComponent
 * EXACTLY (the web client uses encodeURIComponent for /rows/{id} paths and
 * the worker decodes with decodeURIComponent — which, unlike
 * java.net.URLEncoder/URLDecoder, never translates '+' and space into each
 * other). Getting this wrong would address DIFFERENT server rows for UIDs
 * containing '+' or spaces.
 *
 * Shared by the CalDAV adapter (RowStoreCalDavCollection), the account-level
 * calendar listing (RowStoreAccount) and the :core integration so that all
 * three agree on exactly one grammar.
 */
package at.bitfire.davdroid.resource.rowstore

import io.ktor.http.Url

object RowStoreUrls {

    /** Row ids are `cmeta:{uuid}` (calendar metadata, §2). */
    const val CMETA_PREFIX = "cmeta:"

    /** UUID v4, lowercase (same grammar as calendar-core.js UUID_RE). */
    val UUID_RE =
        Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    /** Max event UID length (calendar-core.js UID_MAX; row id budget §21/D9). */
    const val UID_MAX = 200

    /** Collection URL of a calendar: {server}/clock/{uuid}/ (trailing slash). */
    fun collectionUrl(server: Url, calUuid: String): Url =
        Url(server.toString().trimEnd('/') + "/clock/" + calUuid + "/")

    /**
     * Extracts the calendar UUID from a collection URL, or `null` if the URL
     * is not an exact `{...}/clock/{uuid}/` match.
     */
    fun calUuidOf(collectionUrl: Url): String? {
        val m = Regex("^/clock/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/$")
            .find(collectionUrl.encodedPath) ?: return null
        return m.groupValues[1]
    }

    /** `cmeta:{uuid}` row id (§2). */
    fun cmetaRowId(calUuid: String): String = CMETA_PREFIX + calUuid

    /** `cmeta:{uuid}` → uuid, or null (same grammar as calendar-core.js parseCmetaId). */
    fun parseCmetaRowId(rowId: String): String? {
        if (!rowId.startsWith(CMETA_PREFIX)) return null
        val uuid = rowId.removePrefix(CMETA_PREFIX)
        return if (UUID_RE.matches(uuid)) uuid else null
    }

    /**
     * Validates an event UID as a row-store member file name (§2 row id
     * grammar: `evt:{cal}:{uid}`, no ':' inside uid, uid ≤ 200 chars).
     */
    fun isValidUid(fileName: String): Boolean =
        fileName.isNotEmpty() && fileName.length <= UID_MAX && !fileName.contains(':')

    // ---- percent codec (encodeURIComponent / decodeURIComponent parity) ----

    /** Characters encodeURIComponent leaves unescaped. */
    private fun isUnescaped(c: Char) =
        c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' ||
            c == '-' || c == '_' || c == '.' || c == '!' || c == '~' || c == '*' || c == '\'' || c == '(' || c == ')'

    /** JavaScript encodeURIComponent: UTF-8 bytes, escape everything non-unreserved. */
    fun percentEncode(s: String): String {
        val sb = StringBuilder(s.length)
        for (b in s.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt().toChar()
            if (isUnescaped(c))
                sb.append(c)
            else
                sb.append(String.format("%%%02X", b))
        }
        return sb.toString()
    }

    /**
     * JavaScript decodeURIComponent: decodes %XX (UTF-8) sequences and leaves
     * every other character (including '+') untouched.
     */
    fun percentDecode(s: String): String {
        if ('%' !in s) return s
        val bytes = s.toByteArray(Charsets.UTF_8)
        val out = ByteArray(bytes.size)
        var o = 0
        var i = 0
        while (i < bytes.size) {
            val b = bytes[i]
            if (b == '%'.code.toByte() && i + 2 < bytes.size) {
                val hi = Character.digit(bytes[i + 1].toInt() and 0xFF, 16)
                val lo = Character.digit(bytes[i + 2].toInt() and 0xFF, 16)
                if (hi >= 0 && lo >= 0) {
                    out[o++] = ((hi shl 4) or lo).toByte()
                    i += 3
                    continue
                }
            }
            out[o++] = b
            i++
        }
        return String(out, 0, o, Charsets.UTF_8)
    }
}
