/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * Row-store URL grammar (protocol v4.3 §7): one calendar collection is
 * addressed as {server}/clock/{calendar-uuid}/, its members (event files)
 * as {server}/clock/{calendar-uuid}/{event-uid}.
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
}
