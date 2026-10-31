/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * RowStoreWebDavCollection — the :core integration of the encrypted row store
 * (calendar-web protocol v4.3): implements core's WebDavCollection interface
 * (the contract of davx5's SyncManager) by delegating to the pure-JVM
 * protocol adapter RowStoreCalDavCollection from :rowstore.
 *
 * The [httpClient] must NOT have an authentication plugin installed: the
 * adapter adds its own `Authorization: Bearer AUTH_UI` header per request,
 * and the preemptive Basic/Digest provider would remove and replace it
 * (dav4jvm PreemptiveBasicDigestAuthProvider.addRequestHeaders clears the
 * Authorization header before adding its own).
 */
package at.bitfire.davdroid.resource.remote

import at.bitfire.dav4jvm.ktor.DavCollection
import at.bitfire.davdroid.resource.local.SyncState
import at.bitfire.davdroid.resource.rowstore.RowStoreCalDavCollection
import io.ktor.client.HttpClient
import io.ktor.http.Url
import io.ktor.http.content.OutgoingContent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

class RowStoreWebDavCollection(
    httpClient: HttpClient,
    /** The pure-JVM row-store adapter for one calendar. */
    private val delegate: RowStoreCalDavCollection
) : WebDavCollection {

    /** Present to satisfy the interface; SyncManager never touches it. */
    override val davCollection = DavCollection(httpClient, delegate.collectionUrl)

    /** The calendar this collection exposes (from the collection URL). */
    val calUuid: String get() = delegate.calUuid

    // ---- create ----

    override suspend fun createMember(
        fileName: String,
        content: OutgoingContent,
        additionalHeaders: Map<String, String>
    ): WebDavCollection.PutMemberResult =
        delegate.createMember(fileName, content, additionalHeaders)
            .let { WebDavCollection.PutMemberResult(eTag = it.eTag) }

    // ---- read/query ----

    override suspend fun queryCapabilities(): WebDavCollection.QueryCapabilitiesResult =
        WebDavCollection.QueryCapabilitiesResult(
            // the row store has no sync-token/CTag; the PROPFIND/REPORT
            // algorithm (list + diff) is always used
            syncState = null,
            capabilities = WebDavCollection.Capabilities(
                canCollectionSync = false,
                maxCalResourceSize = delegate.queryCapabilities().maxCalResourceSize
            )
        )

    /** The row store has no sync-token: no sync state to query. */
    override suspend fun querySyncState(): SyncState? = null

    override fun listFilteredMembers(): Flow<InternalMemberState> =
        delegate.listFilteredMembers().map { InternalMemberState(it.href, it.eTag) }

    /**
     * Collection sync (RFC 6578) is not supported by the row store;
     * [WebDavCollection.Capabilities.canCollectionSync] is always false, so
     * SyncManager never calls this.
     */
    override fun listChanges(since: SyncState?): Flow<CollectionSyncItem> =
        throw UnsupportedOperationException("row-store does not support collection sync (RFC 6578)")

    override fun multiget(
        urls: List<Url>,
        capabilities: WebDavCollection.Capabilities
    ): Flow<WebDavCollection.MultiGetItem> =
        delegate.multiget(
            urls,
            at.bitfire.davdroid.resource.rowstore.RowStoreCollection.Capabilities(
                maxCalResourceSize = capabilities.maxCalResourceSize ?: 64L * 1024
            )
        ).map { WebDavCollection.MultiGetItem(url = it.url, eTag = it.eTag, scheduleTag = null, content = it.content) }

    // ---- update ----

    override suspend fun updateMember(
        fileName: String,
        content: OutgoingContent,
        ifETag: String?,
        ifScheduleTag: String?,
        additionalHeaders: Map<String, String>
    ): WebDavCollection.PutMemberResult {
        if (ifScheduleTag != null)
            throw UnsupportedOperationException("row-store does not support Schedule-Tag")
        return delegate.updateMember(fileName, content, ifETag, additionalHeaders)
            .let { WebDavCollection.PutMemberResult(eTag = it.eTag) }
    }

    // ---- delete ----

    override suspend fun deleteMember(
        fileName: String,
        ifETag: String?,
        ifScheduleTag: String?,
        additionalHeaders: Map<String, String>
    ) {
        if (ifScheduleTag != null)
            throw UnsupportedOperationException("row-store does not support Schedule-Tag")
        delegate.deleteMember(fileName, ifETag, additionalHeaders)
    }
}
