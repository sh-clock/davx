/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * RowStoreCollectionRefresher — refreshes the collection (= calendar) list of
 * a row-store service from the server's cmeta rows, with the same semantics as
 * the WebDAV refreshers: update found collections, add new ones, remove the
 * ones that are gone.
 *
 * Corrupt (present but undecryptable) cmeta rows are NOT treated as deleted —
 * the last-known-good local collection is kept, exactly like the web client's
 * corrupt-row handling (deleting would remove the local calendar + events).
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
import at.bitfire.davdroid.resource.rowstore.RowStoreAuthenticationException
import at.bitfire.davdroid.resource.rowstore.RowStoreSilentDropException
import at.bitfire.davdroid.resource.rowstore.RowStoreUrls
import at.bitfire.davdroid.settings.AccountSettingsFactory
import io.ktor.http.Url
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
     * @throws RowStoreAuthenticationException when the credentials are rejected
     *   (wrong provisioning code / changed password)
     * @throws at.bitfire.dav4jvm.ktor.exception.DavException on other errors —
     *   the caller's generic error handling applies
     */
    suspend fun refresh(service: Service, accountId: AccountId): Boolean {
        val accountSettings = accountSettingsFactory.create(accountId)
        val server = accountSettings.rowStoreServer
            ?: rowStoreServerFromCollectionShape(service)
            ?: return false
        if (accountSettings.rowStoreServer == null)
            logger.warning(
                "rowstore_server marker is missing/unreadable, but the service's collections " +
                    "match the row-store URL shape — treating as row-store (marker would be a silent " +
                    "single point of failure: the WebDAV refresh would DELETE the collections)")

        logger.log(Level.INFO, "Refreshing row-store collections of service #{0} from {1}",
            arrayOf(service.id, server))

        val credentials = accountSettings.credentials()
        val username = credentials.username
            ?: throw RowStoreAuthenticationException("row-store: no provisioning code (username) in account credentials")
        val password = credentials.password
            ?: throw RowStoreAuthenticationException("row-store: no password in account credentials")

        httpClientBuilder
            .build()
            .use { client ->
                val account = try {
                    RowStoreAccount.open(client, server, username, password.asString())
                } catch (e: RowStoreSilentDropException) {
                    throw RowStoreAuthenticationException(
                        "row-store: provisioning code not valid on $server (§4 silent drop)")
                } catch (e: javax.crypto.AEADBadTagException) {
                    throw RowStoreAuthenticationException(
                        "row-store: wrong password for $server (unwrap failed)")
                }

                val listing = account.listCalendars()
                val serverCollections = HashMap<Url, Collection>()
                for (calendar in listing.calendars) {
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
                // corrupt cmeta rows: keep the last-known-good collection
                // (its URL stays untouched) so local calendars + events survive
                val keepUrls = HashSet<Url>(serverCollections.keys)
                for (corruptRowId in listing.corruptRowIds) {
                    val uuid = RowStoreUrls.parseCmetaRowId(corruptRowId) ?: continue
                    keepUrls += RowStoreUrls.collectionUrl(server, uuid)
                }

                // diff against the DB: update existing (remembering sync/forceReadOnly
                // flags), insert new, delete the ones that are gone from the server
                val dbCollections = collectionRepository.getByService(service.id)
                for (dbCollection in dbCollections) {
                    val fresh = serverCollections.remove(dbCollection.url)
                    when {
                        fresh != null ->
                            collectionRepository.insertOrUpdateByUrlRememberSync(fresh)

                        dbCollection.url in keepUrls ->
                            logger.log(Level.INFO, "Row-store calendar {0} has a corrupt cmeta row; keeping the last-known-good entry", arrayOf(dbCollection.url))

                        else -> {
                            logger.log(Level.INFO, "Row-store calendar {0} is gone from the server; deleting locally", arrayOf(dbCollection.url))
                            collectionRepository.delete(dbCollection)
                        }
                    }
                }
                for (newCollection in serverCollections.values) {
                    logger.log(Level.INFO, "New row-store calendar {0}", arrayOf(newCollection.url))
                    collectionRepository.insertOrUpdateByUrlRememberSync(newCollection)
                }

                logger.log(Level.INFO, "Row-store collection refresh complete: {0} calendar(s), {1} corrupt cmeta row(s)",
                    arrayOf(listing.calendars.size, listing.corruptRowIds.size))
            }
        return true
    }

    /**
     * Defense in depth for a missing/unreadable marker: if EVERY collection of
     * the service uses the exact {any}/clock/{uuid-v4}/ shape, the service is
     * row-store. (Only consulted when the marker is null; a real CalDAV server
     * serving that exact shape would be indistinguishable — accepted risk.)
     */
    private fun rowStoreServerFromCollectionShape(service: Service): Url? {
        if (service.type != Service.TYPE_CALDAV)
            return null
        val collections = collectionRepository.getByService(service.id)
        if (collections.isEmpty())
            return null
        val servers = collections.mapNotNull { collection ->
            val calUuid = RowStoreUrls.calUuidOf(collection.url) ?: return@mapNotNull null
            // server = collection URL minus /clock/{uuid}/
            Url(collection.url.toString().removeSuffix("/clock/$calUuid/"))
        }
        if (servers.size != collections.size || servers.distinct().size != 1)
            return null
        return servers.first()
    }
}
