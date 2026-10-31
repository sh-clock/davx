/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * RowStoreCollectionRefresher — refreshes the collection (= calendar) list of
 * a row-store service from the server's cmeta rows, with the same semantics as
 * the WebDAV refreshers: update found collections, add new ones, remove the
 * ones that are gone.
 *
 * Called by RefreshCollectionsWorker instead of the WebDAV refresh chain
 * (PROPFIND on home sets / homeless collections), which would 404 against the
 * row-store JSON API and DELETE the collections (see
 * CollectionsWithoutHomeSetRefresher, which removes collections on 40x).
 */
package at.bitfire.davdroid.servicedetection

import at.bitfire.davdroid.accounts.AccountId
import at.bitfire.davdroid.db.Collection
import at.bitfire.davdroid.db.Service
import at.bitfire.davdroid.network.HttpClientBuilder
import at.bitfire.davdroid.repository.DavCollectionRepository
import at.bitfire.davdroid.resource.rowstore.RowStoreAccount
import at.bitfire.davdroid.resource.rowstore.RowStoreUrls
import at.bitfire.davdroid.settings.AccountSettingsFactory
import io.ktor.http.Url
import kotlinx.coroutines.flow.toList
import java.util.logging.Level
import java.util.logging.Logger
import javax.inject.Inject

class RowStoreCollectionRefresher @Inject constructor(
    private val accountSettingsFactory: AccountSettingsFactory,
    private val collectionRepository: DavCollectionRepository,
    private val httpClientBuilder: HttpClientBuilder
) {

    private val logger = Logger.getLogger(javaClass.name)

    /**
     * Refreshes the collection list of [service] if the account is a row-store
     * account.
     *
     * @return `true` if the service was refreshed (row-store account — the
     * caller MUST NOT run the WebDAV refresh chain afterwards); `false` if the
     * account is not a row-store account (fall through to WebDAV refresh).
     *
     * @throws at.bitfire.dav4jvm.ktor.exception.DavException on network errors —
     * the caller's generic error handling applies
     * @throws javax.crypto.AEADBadTagException on a wrong (changed) password
     */
    suspend fun refresh(service: Service, accountId: AccountId): Boolean {
        val accountSettings = accountSettingsFactory.create(accountId)
        val server = accountSettings.rowStoreServer ?: return false

        logger.log(Level.INFO, "Refreshing row-store collections of service #{0} from {1}",
            arrayOf(service.id, server))

        val credentials = accountSettings.credentials()
        httpClientBuilder
            .build()
            .use { client ->
                val account = RowStoreAccount.open(
                    client,
                    server,
                    credentials.username ?: throw at.bitfire.dav4jvm.ktor.exception.DavException(
                        "row-store: no provisioning code (username) in account credentials"),
                    credentials.password?.asString() ?: throw at.bitfire.dav4jvm.ktor.exception.DavException(
                        "row-store: no password in account credentials")
                )

                val serverCalendars = account.listCalendars().toList()
                val serverCollections = HashMap<Url, Collection>()
                for (calendar in serverCalendars) {
                    val url = RowStoreUrls.collectionUrl(server, calendar.uuid)
                    serverCollections[url] = Collection(
                        serviceId = service.id,
                        type = Collection.TYPE_CALENDAR,
                        url = url,
                        displayName = calendar.name,
                        color = calendar.colorArgb,
                        supportsVEVENT = true,
                        supportsVTODO = false,
                        supportsVJOURNAL = false
                    )
                }

                // diff against the DB: update existing (remembering sync/forceReadOnly
                // flags), insert new, delete the ones that are gone from the server
                val dbCollections = collectionRepository.getByService(service.id)
                for (dbCollection in dbCollections) {
                    val fresh = serverCollections.remove(dbCollection.url)
                    if (fresh != null)
                        collectionRepository.insertOrUpdateByUrlRememberSync(fresh)
                    else {
                        logger.log(Level.INFO, "Row-store calendar {0} is gone from the server; deleting locally", arrayOf(dbCollection.url))
                        collectionRepository.delete(dbCollection)
                    }
                }
                for (newCollection in serverCollections.values) {
                    logger.log(Level.INFO, "New row-store calendar {0}", arrayOf(newCollection.url))
                    collectionRepository.insertOrUpdateByUrlRememberSync(newCollection)
                }

                logger.log(Level.INFO, "Row-store collection refresh complete: {0} calendar(s)", arrayOf(serverCalendars.size))
            }
        return true
    }
}
