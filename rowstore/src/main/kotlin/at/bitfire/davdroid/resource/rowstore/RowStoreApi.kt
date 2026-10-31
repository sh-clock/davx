/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * RowStoreApi — the HTTP request machinery shared by all row-store clients
 * (RowStoreCalDavCollection for one calendar, RowStoreAccount for
 * account-level operations):
 *
 *  - adds the `Authorization: Bearer <AUTH_UI>` header to every request;
 *  - maps the protocol's error shapes (§4 silent drop, §5 capability
 *    violation / not_found, §9c conditional statuses) to dav4jvm's typed
 *    exceptions, exactly like a WebDAV client would;
 *  - lets IOExceptions and CancellationExceptions propagate unchanged, so
 *    davx5's SyncExceptionHandler treats network problems as soft errors
 *    (retry) and cancellation stays cooperative.
 *
 * The HTTP client must NOT have an authentication plugin installed: the
 * preemptive Basic/Digest provider would remove and replace this header
 * (dav4jvm PreemptiveBasicDigestAuthProvider.addRequestHeaders clears
 * Authorization before adding its own).
 */
package at.bitfire.davdroid.resource.rowstore

import at.bitfire.dav4jvm.ktor.exception.DavException
import at.bitfire.dav4jvm.ktor.exception.HttpException
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.headers
import io.ktor.client.request.request
import io.ktor.client.statement.HttpResponse
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.io.IOException

/**
 * §4 silent drop: 404 with an EMPTY body — wrong/missing token or an unknown
 * route. Subclass of [DavException] so callers can branch on it (e.g. the
 * §9b batch fallback for v4.2 servers, where POST /rows:batch is unknown).
 */
class RowStoreSilentDropException(message: String) : DavException(message, 404)

/** Wrong password / provisioning code (GCM unwrap failure or silent drop). */
class RowStoreAuthenticationException(message: String) : DavException(message, 401)

internal class RowStoreApi(
    val httpClient: HttpClient,
    /** Base URL of the row-store server, e.g. https://calendar-poc.sh-clock.workers.dev */
    val server: Url,
    /** AUTH_UI bearer token (hex64). */
    private val authUiHex: String
) {

    val baseUrl: String = server.toString().trimEnd('/')

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Executes [block] with the bearer header; maps §4/§5/§9c error shapes to
     * dav4jvm's typed exceptions (via [HttpException.fromResponse] where a real
     * HTTP status carries CalDAV semantics).
     */
    suspend fun request(block: suspend HttpRequestBuilder.() -> Unit): HttpResponse {
        val response: HttpResponse = try {
            httpClient.request {
                headers.append(io.ktor.http.HttpHeaders.Authorization, "Bearer " + authUiHex)
                block()
            }
        } catch (e: CancellationException) {
            throw e                                   // cancellation must stay cooperative
        } catch (e: IOException) {
            throw e                                   // network error → SyncExceptionHandler soft error (retry)
        } catch (e: Exception) {
            throw DavException("network error: " + (e.message ?: e::class.simpleName), 503)
        }
        val text = bodyAsTextSafe(response)
        when {
            // §4 silent drop: empty 404 = wrong/missing token or unknown route.
            response.status == HttpStatusCode.NotFound && text.isEmpty() ->
                throw RowStoreSilentDropException("silent drop: wrong/missing token or unknown route")

            // §5 capability violation: empty 403.
            response.status == HttpStatusCode.Forbidden && text.isEmpty() ->
                throw DavException("capability violation (read-only token?)", 403)

            // §9c conditional mode: 412 (rebase / exists) carries CalDAV semantics.
            response.status == HttpStatusCode.PreconditionFailed ->
                throw HttpException.fromResponse(response)

            // §5 not_found: 404 WITH our JSON error body (a foreign 404 page must
            // NOT be classified as NotFound — same rule as the web client's api.js).
            response.status == HttpStatusCode.NotFound && text.startsWith("{\"error\":") ->
                throw HttpException.fromResponse(response)

            response.status == HttpStatusCode.Conflict || response.status == HttpStatusCode.Gone ->
                throw HttpException.fromResponse(response)

            !response.status.isSuccess() ->
                throw DavException("row-store error " + response.status.value + ": " + text.take(200), response.status.value)
        }
        return response
    }

    /** Response body as JSON object (empty-body errors are filtered before this). */
    suspend fun bodyAsJson(response: HttpResponse): JsonObject {
        val text = bodyAsTextSafe(response)
        return json.parseToJsonElement(text).jsonObject
    }

    suspend fun bodyAsTextSafe(response: HttpResponse): String = try {
        response.body<String>()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        ""
    }
}
