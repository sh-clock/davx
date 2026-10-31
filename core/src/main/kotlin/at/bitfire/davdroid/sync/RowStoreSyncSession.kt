/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * One row-store session per sync run: a single auth-free HTTP client and a
 * single key derivation (PBKDF2 is expensive) shared by all row-store
 * collections of the account. Created by CalendarSyncer when the account is a
 * row-store account (AccountSettings.rowStoreServer set); closed with the sync.
 */
package at.bitfire.davdroid.sync

import at.bitfire.davdroid.network.HttpClientBuilder
import at.bitfire.davdroid.resource.rowstore.RowStoreAccount
import at.bitfire.davdroid.resource.rowstore.RowStoreAuthenticationException
import at.bitfire.davdroid.resource.rowstore.RowStoreSilentDropException
import at.bitfire.davdroid.resource.rowstore.RowStoreUrls
import at.bitfire.davdroid.settings.Credentials
import io.ktor.client.HttpClient
import io.ktor.http.Url
import java.io.Closeable
import java.util.logging.Level
import java.util.logging.Logger

class RowStoreSyncSession private constructor(
    val account: RowStoreAccount
) : Closeable {

    /** Auth-free HTTP client (the adapter adds its own Bearer header per request). */
    val httpClient: HttpClient get() = account.httpClient

    /** Row-store server base URL. */
    val server: Url get() = account.server

    /** The calendar UUID if [url] is a row-store collection URL, else null. */
    fun calUuidOf(url: Url): String? = RowStoreUrls.calUuidOf(url)

    override fun close() {
        httpClient.close()
    }

    companion object {

        /**
         * Opens the session: builds the auth-free client, fetches /config and
         * derives the keys from the account credentials.
         *
         * @throws RowStoreAuthenticationException when the provisioning code is
         *   not valid on the server (§4 silent drop) or the password is wrong
         *   (GCM unwrap fails) — so callers can surface an authentication
         *   failure like they would for HTTP 401
         * @throws at.bitfire.dav4jvm.ktor.exception.DavException on other errors (network, malformed config)
         */
        suspend fun open(
            httpClientBuilder: HttpClientBuilder,
            server: Url,
            credentials: Credentials,
            logger: Logger
        ): RowStoreSyncSession {
            val username = credentials.username
                ?: throw RowStoreAuthenticationException(
                    "row-store: no provisioning code (username) in account credentials")
            val password = credentials.password
                ?: throw RowStoreAuthenticationException(
                    "row-store: no password in account credentials")
            val client = httpClientBuilder.build()
            try {
                logger.log(Level.INFO, "Opening row-store session with $server")
                val account = try {
                    RowStoreAccount.open(client, server, username, password.asString())
                } catch (e: RowStoreSilentDropException) {
                    throw RowStoreAuthenticationException(
                        "row-store: provisioning code not valid on $server (§4 silent drop)")
                } catch (e: javax.crypto.AEADBadTagException) {
                    throw RowStoreAuthenticationException(
                        "row-store: wrong password for $server (unwrap failed)")
                }
                return RowStoreSyncSession(account)
            } catch (t: Throwable) {
                client.close()
                throw t
            }
        }
    }
}
