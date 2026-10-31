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

    /**
     * Row-store session for this sync run (one HTTP client + one key derivation
     * for all row-store collections), or `null` when the account is not a
     * row-store account. Initialized lazily on the first [syncCollection] call.
     */
    private var rowStoreSession: RowStoreSyncSession? = null

    private suspend fun rowStoreSession(): RowStoreSyncSession? {
        rowStoreSession?.let { return it }
        val accountSettings = accountSettingsFactory.create(accountId)
        val server = accountSettings.rowStoreServer ?: return null
        val session = RowStoreSyncSession.open(httpClientBuilder, server, accountSettings.credentials(), logger)
        rowStoreSession = session
        return session
    }

    override fun close() {
        super.close()
        rowStoreSession?.close()
        rowStoreSession = null
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
        val session = rowStoreSession()
        val remote: WebDavCollection
        val syncHttpClient: io.ktor.client.HttpClient
        if (session != null && session.calUuidOf(remoteCollectionInfo.url) != null) {
            val calUuid = session.calUuidOf(remoteCollectionInfo.url)!!
            remote = RowStoreWebDavCollection(
                httpClient = session.httpClient,
                delegate = RowStoreCalDavCollection(
                    httpClient = session.httpClient,
                    server = session.server,
                    calUuid = calUuid,
                    authUiHex = session.account.keys.authUiHex,
                    rowKey = session.account.keys.kData
                )
            )
            syncHttpClient = session.httpClient
            logger.log(Level.INFO, "Syncing row-store calendar {0} via {1}", arrayOf(calUuid, session.server))
        } else {
            remote = CalDavCollection(
                httpClient = httpClient,
                url = remoteCollectionInfo.url,
                filter = CalendarQueryFilter(components = listOf(Component.VEVENT), timeRangeStart = limitStart)
            )
            syncHttpClient = httpClient
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