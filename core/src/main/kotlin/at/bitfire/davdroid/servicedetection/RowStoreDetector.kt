/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * RowStoreDetector — login-time detection of encrypted row-store servers
 * (calendar-web protocol v4.3, the PoC backend of this fork).
 *
 * Credential model (mirrors the web client's provisioning):
 *  - USERNAME  = the AUTH_UI provisioning code (hex64) — the browser analogue
 *    of the web client's ?setup=<hex64> link;
 *  - PASSWORD  = the calendar password that unlocks the row keys.
 *
 * Detection: GET /version with the provisioning code answers
 * {"proto":"4.3"} only for row-store servers (and only for valid codes — a
 * wrong code is a §4 silent drop, indistinguishable from a non-row-store
 * server, so detection falls through to the standard WebDAV path). After the
 * probe, the account is opened (/config + key derivation) and the calendars
 * are listed from the cmeta rows.
 *
 * A wrong password (GCM unwrap fails) is an authentication failure and is
 * reported as [DavResourceFinder.Configuration.encountered401] so the login
 * UI shows the "wrong credentials" message.
 */
package at.bitfire.davdroid.servicedetection

import at.bitfire.dav4jvm.ktor.exception.DavException
import at.bitfire.davdroid.db.Collection
import at.bitfire.davdroid.network.HttpClientBuilder
import at.bitfire.davdroid.resource.rowstore.RowStoreAccount
import at.bitfire.davdroid.resource.rowstore.RowStoreUrls
import at.bitfire.davdroid.settings.Credentials
import io.ktor.client.request.get
import io.ktor.client.request.headers
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.Url
import io.ktor.http.isSuccess
import kotlinx.coroutines.flow.toList
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.util.logging.Level
import java.util.logging.Logger
import javax.inject.Inject

class RowStoreDetector @Inject constructor(
    private val httpClientBuilder: HttpClientBuilder
) {

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Probes [baseUri] for a row-store server.
     *
     * @return the row-store [DavResourceFinder.Configuration] (CalDAV service
     * with one collection per server calendar, plus [DavResourceFinder.Configuration.rowStoreServer]),
     * a Configuration with `encountered401 = true` when the password is wrong,
     * or `null` when the server is not a row-store server (fall through to
     * standard WebDAV detection).
     */
    suspend fun detect(
        baseUri: URI,
        credentials: Credentials?,
        log: Logger
    ): DavResourceFinder.Configuration? {
        val scheme = baseUri.scheme?.lowercase()
        if (scheme != "http" && scheme != "https")
            return null

        // The username must look like a provisioning code (hex64); anything
        // else is a normal CalDAV login — skip the probe entirely (no requests).
        val provisioningCode = credentials?.username?.takeIf { it.matches(HEX64) } ?: run {
            log.fine("Row-store detection skipped: username is not a provisioning code (hex64)")
            return null
        }
        val password = credentials.password ?: run {
            log.fine("Row-store detection skipped: no password")
            return null
        }

        val server = Url(baseUri.toString().trimEnd('/'))
        httpClientBuilder
            .logTo(log)
            .build()
            .use { client ->
                // 1. probe /version with the provisioning code
                val proto = probeVersion(client, server, provisioningCode, log) ?: return null

                // 2. open the account: /config + key derivation
                val account = try {
                    RowStoreAccount.open(client, server, provisioningCode, password.asString())
                } catch (e: DavException) {
                    // /config failed after /version succeeded — server problem;
                    // fall through to standard detection (which will fail with
                    // proper logs) rather than showing a wrong message.
                    log.log(Level.WARNING, "Row-store /config failed after successful /version probe", e)
                    return null
                } catch (e: Exception) {
                    // wrong password: GCM unwrap of config.wrapped fails
                    log.log(Level.INFO, "Row-store unlock failed (wrong password?)", e)
                    return DavResourceFinder.Configuration(
                        cardDAV = null,
                        calDAV = null,
                        encountered401 = true
                    )
                }

                // 3. list the calendars from the cmeta rows
                val calendars = account.listCalendars().toList()
                log.log(Level.INFO, "Row-store server $server (protocol $proto): ${calendars.size} calendar(s)")

                val collections = HashMap<Url, Collection>()
                for (calendar in calendars) {
                    val url = RowStoreUrls.collectionUrl(server, calendar.uuid)
                    collections[url] = Collection(
                        type = Collection.TYPE_CALENDAR,
                        url = url,
                        displayName = calendar.name,
                        color = calendar.colorArgb,
                        // the row store holds whole VCALENDAR event files
                        supportsVEVENT = true,
                        supportsVTODO = false,
                        supportsVJOURNAL = false
                    )
                }

                return DavResourceFinder.Configuration(
                    cardDAV = null,
                    calDAV = DavResourceFinder.Configuration.ServiceInfo(
                        // no principal, no home sets: this is not a WebDAV server.
                        // Collections are addressed directly by their URLs.
                        principal = null,
                        homeSets = HashSet(),
                        collections = collections
                    ),
                    encountered401 = false,
                    rowStoreServer = server
                )
            }
    }

    /**
     * GET {server}/version with the provisioning code; returns the reported
     * protocol string, or null when this is not a row-store server (or the
     * code is not valid on it — a §4 silent drop).
     */
    private suspend fun probeVersion(
        client: io.ktor.client.HttpClient,
        server: Url,
        provisioningCode: String,
        log: Logger
    ): String? = try {
        val response = client.get(server.toString().trimEnd('/') + "/version") {
            headers.append(HttpHeaders.Authorization, "Bearer $provisioningCode")
        }
        if (!response.status.isSuccess())
            return null
        val proto = json.parseToJsonElement(response.bodyAsText()).jsonObject["proto"]?.jsonPrimitive?.content
        if (proto == null) {
            log.fine("/version answered without a proto field — not a row-store server")
            null
        } else
            proto
    } catch (e: Exception) {
        log.log(Level.FINE, "Row-store /version probe failed: ${e.message}")
        null
    }

    companion object {
        private val HEX64 = Regex("^[0-9a-f]{64}$")
    }
}
