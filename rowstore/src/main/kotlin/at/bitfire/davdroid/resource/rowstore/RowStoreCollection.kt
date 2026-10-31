/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * RowStoreCollection — the collection contract of the pure-JVM row-store
 * protocol layer. The method set mirrors core's WebDavCollection (and thus
 * davx5's SyncManager expectations) 1:1; the module-local declaration exists
 * so the protocol layer compiles and is testable on a plain JVM (no Android
 * toolchain). The :core integration class delegates to this interface.
 */
package at.bitfire.davdroid.resource.rowstore

import io.ktor.http.Url
import io.ktor.http.content.OutgoingContent
import kotlinx.coroutines.flow.Flow

interface RowStoreCollection {

    /** Sync-relevant capabilities of the row-store server. */
    data class Capabilities(
        /** max. CalDAV resource size (ciphertext incl. GCM tag): 64 KiB (§2). */
        val maxCalResourceSize: Long = 64 * 1024
    )

    data class PutMemberResult(
        val eTag: String? = null
    )

    data class MemberState(
        val href: Url,
        val eTag: String?
    ) {
        val fileName: String
            get() = href.encodedPath.substringAfterLast('/').let { RowStoreUrls.percentDecode(it) }
    }

    data class MultiGetItem(
        val url: Url,
        val eTag: String,
        val content: String
    )

    // create

    /**
     * Creates a new member (If-None-Match semantics): PUT ver 1; a 412 answer
     * (row exists) surfaces as [at.bitfire.dav4jvm.ktor.exception.PreconditionFailedException].
     */
    suspend fun createMember(
        fileName: String,
        content: OutgoingContent,
        additionalHeaders: Map<String, String> = emptyMap()
    ): PutMemberResult

    // read/query

    /** GET /version — protocol check + capabilities (no collection sync). */
    suspend fun queryCapabilities(): Capabilities

    /** GET /rows manifest filtered to this calendar's rows, as (href, ver-ETag) pairs. */
    fun listFilteredMembers(): Flow<MemberState>

    /** POST /rows:batch (§9b) — downloads and decrypts a batch of members. */
    fun multiget(urls: List<Url>, capabilities: Capabilities = Capabilities()): Flow<MultiGetItem>

    // update

    /**
     * Updates an existing member (If-Match semantics): PUT ver = etag+1;
     * a stale ETag surfaces as PreconditionFailedException, a vanished row
     * as NotFoundException (SyncManager re-downloads in both cases).
     */
    suspend fun updateMember(
        fileName: String,
        content: OutgoingContent,
        ifETag: String? = null,
        additionalHeaders: Map<String, String> = emptyMap()
    ): PutMemberResult

    // delete

    /** DELETE /rows/{id} — idempotent. */
    suspend fun deleteMember(
        fileName: String,
        ifETag: String? = null,
        additionalHeaders: Map<String, String> = emptyMap()
    )
}
