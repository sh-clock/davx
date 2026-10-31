/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 */

package at.bitfire.davdroid.sync

import at.bitfire.davdroid.accounts.AccountId
import at.bitfire.davdroid.db.Collection
import at.bitfire.davdroid.db.Service
import at.bitfire.davdroid.resource.local.LocalCalendar
import at.bitfire.davdroid.resource.local.LocalCalendarStore
import at.bitfire.davdroid.resource.remote.CalDavCollection
import at.bitfire.davdroid.resource.remote.CalendarQueryFilter
import at.bitfire.davdroid.resource.remote.RowStoreWebDavCollection
import at.bitfire.davdroid.resource.remote.WebDavCollection
import at.bitfire.davdroid.resource.rowstore.RowStoreAuthenticationException
import at.bitfire.davdroid.resource.rowstore.RowStoreCalDavCollection
import at.bitfire.davdroid.settings.AccountSettingsFactory
import at.bitfire.synctools.storage.LocalStorageClient
import at.bitfire.synctools.storage.calendar.AndroidCalendarProvider
import dagger.assisted.Assisted
import dagger.assisted.AssistedFactory
import dagger.assisted.AssistedInject
import net.fortuna.ical4j.model.Component
import java.time.ZonedDateTime
import java.util.logging.Level

/**
 * Sync logic for calendars
 */
class CalendarSyncer @AssistedInject constructor(
    @Assisted accountId: AccountId,
    @Assisted resync: ResyncType?,
    @Assisted syncResult: SyncResult,
    @Assisted settings: SyncSettings,
    calendarStore: LocalCalendarStore,
    private val accountSettingsFactory: AccountSettingsFactory,
    private val calendarSyncManagerFactory: CalendarSyncManager.Factory
) : Syncer<LocalCalendarStore, LocalCalendar>(accountId, resync, syncResult, settings) {

    @AssistedFactory
    interface Factory {
        fun create(
            accountId: AccountId,
            resyncType: ResyncType?,
            syncResult: SyncResult,
            settings: SyncSettings
        ): CalendarSyncer
    }

    override val dataStore = calendarStore

    override val serviceType: String
        get() = Service.TYPE_CALDAV


    override fun prepare(client: LocalStorageClient): Boolean {
        // Update colors
        val account = androidAccountManager.getAndroidAccount(accountId)
        val calendarProvider = AndroidCalendarProvider(account, client)
        if (settings.eventColors)
            calendarProvider.provideCss3ColorIndices()
        else
            calendarProvider.removeColorIndices()
        return true
    }

    override fun getDbSyncCollections(serviceId: Long): List<Collection> =
        collectionRepository.getSyncCalendars(serviceId)

    /** Outcome of the row-store account check (resolved once per sync run). */
    private sealed interface RowStoreAccess {
        /** Not a row-store account — sync with plain CalDAV. */
        object NotRowStore : RowStoreAccess

        /** Row-store session ready (one client + one key derivation for the whole run). */
        data class Ready(val session: RowStoreSyncSession) : RowStoreAccess

        /** Credentials rejected — [syncResult.authenticationFailed] is set; skip. */
        object AuthenticationFailed : RowStoreAccess
    }

    private var rowStoreAccess: RowStoreAccess? = null

    /**
     * Resolves the row-store access for this sync run. The account settings are
     * read once; the session (auth-free HTTP client + PBKDF2 derivation) is
     * shared by all row-store collections.
     */
    private suspend fun rowStoreAccess(): RowStoreAccess {
        rowStoreAccess?.let { return it }
        val access: RowStoreAccess = try {
            val accountSettings = accountSettingsFactory.create(accountId)
            val server = accountSettings.rowStoreServer
            if (server == null)
                RowStoreAccess.NotRowStore
            else
                RowStoreAccess.Ready(
                    RowStoreSyncSession.open(httpClientBuilder, server, accountSettings.credentials(), logger)
                )
        } catch (e: RowStoreAuthenticationException) {
            // wrong provisioning code / wrong password: same effect as HTTP 401 —
            // set the flag Syncer.syncCollectionContents checks before every
            // collection and show the "credentials were rejected" notification
            logger.log(Level.WARNING, "Row-store authentication failed: ${e.message}", e)
            syncResult.authenticationFailed = true
            RowStoreAccess.AuthenticationFailed
        }
        rowStoreAccess = access
        return access
    }

    override fun close() {
        super.close()
        (rowStoreAccess as? RowStoreAccess.Ready)?.session?.close()
        rowStoreAccess = null
    }

    override suspend fun syncCollection(
        client: LocalStorageClient,
        localCollection: LocalCalendar,
        remoteCollectionInfo: Collection
    ) {
        logger.log(
            Level.INFO,
            "Synchronizing calendar #{0}, DB Collection ID: {1}, URL: {2}",
            arrayOf<Any?>(
                localCollection.androidCalendar.id,
                localCollection.dbCollectionId,
                localCollection.androidCalendar.name
            )
        )

        // calculate time range limit
        val limitStart = settings.timeRangePastDays?.let { pastDays ->
            ZonedDateTime.now().minusDays(pastDays.toLong()).toInstant()
        }

        // Row-store collections (encrypted row store, protocol v4.3) are synced
        // through the row-store adapter; their own auth-free HTTP client is used
        // because the account's Basic/Digest credentials never apply (the worker
        // would treat them as a wrong token and silently drop every request).
        // NOTE: timeRangePastDays is IGNORED for row-store accounts — the row
        // store has no server-side time filter; the whole store syncs.
        val remote: WebDavCollection
        val syncHttpClient: io.ktor.client.HttpClient
        when (val access = rowStoreAccess()) {
            is RowStoreAccess.AuthenticationFailed ->
                // credentials rejected — skip this collection (Syncer checks the
                // flag before every following one)
                return

            RowStoreAccess.NotRowStore -> {
                remote = CalDavCollection(
                    httpClient = httpClient,
                    url = remoteCollectionInfo.url,
                    filter = CalendarQueryFilter(components = listOf(Component.VEVENT), timeRangeStart = limitStart)
                )
                syncHttpClient = httpClient
            }

            is RowStoreAccess.Ready -> {
                val calUuid = access.session.calUuidOf(remoteCollectionInfo.url)
                    ?: throw at.bitfire.dav4jvm.ktor.exception.DavException(
                        "row-store account, but collection URL is not a row-store URL: ${remoteCollectionInfo.url}")
                remote = RowStoreWebDavCollection(
                    httpClient = access.session.httpClient,
                    delegate = RowStoreCalDavCollection(
                        httpClient = access.session.httpClient,
                        server = access.session.server,
                        calUuid = calUuid,
                        authUiHex = access.session.account.keys.authUiHex,
                        rowKey = access.session.account.keys.kData
                    )
                )
                syncHttpClient = access.session.httpClient
                logger.log(Level.INFO, "Syncing row-store calendar {0} via {1}", arrayOf(calUuid, access.session.server))
            }
        }

        val syncManager = calendarSyncManagerFactory.calendarSyncManager(
            accountId = accountId,
            httpClient = syncHttpClient,
            syncResult = syncResult,
            localCalendar = localCollection,
            collectionInfo = remoteCollectionInfo,
            remoteCollection = remote,
            resync = resync,
            settings = settings
        )
        syncManager.performSync()
    }

}
