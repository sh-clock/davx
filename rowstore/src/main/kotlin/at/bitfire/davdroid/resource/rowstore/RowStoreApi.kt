/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * RowStoreApi — the HTTP request machinery shared by all row-store clients
 * (RowStoreCalDavCollection for one calendar, RowStoreAccount for
 * account-level operations):
 *
 *  - adds the `Authorization: Bearer <AUTH_UI>` header to every request;
 *  - maps the protocol's error shapes (§4 silent drop, §5 capability
 *    violation, §9c conditional statuses) to dav4jvm's typed exceptions,
 *    exactly like a WebDAV client would.
 *
 * The HTTP client must NOT have an authentication plugin installed: the
 * preemptive Basic/Digest provider would remove and replace this header
 * (dav4jvm PreemptiveBasicDigestAuthProvider.addRequestHeaders clears
 * Authorization before adding its own).
 *
 * The request/error-mapping code is identical to what RowStoreCalDavCollection
 * used inline (its 15-test suite pins this behavior); it was extracted so the
 * account-level operations share ONE implementation.
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
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.isSuccess
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

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
                headers.append(HttpHeaders.Authorization, "Bearer " + authUiHex)
                block()
            }
        } catch (e: Exception) {
            throw DavException("network error: " + (e.message ?: e::class.simpleName), 503)
        }
        val text = response.bodyAsTextSafe()
        when {
            // §4 silent drop: empty 404 = wrong/missing token or unknown route.
            response.status == HttpStatusCode.NotFound && text.isEmpty() ->
                throw DavException("silent drop: wrong/missing token or unknown route", 404)
            // §5 capability violation: empty 403.
            response.status == HttpStatusCode.Forbidden && text.isEmpty() ->
                throw DavException("capability violation (read-only token?)", 403)
            // §9c conditional mode: these statuses carry CalDAV semantics —
            // map to dav4jvm's typed exceptions (412 → PreconditionFailedException,
            // 404 → NotFoundException) so SyncManager's conflict handling applies.
            response.status == HttpStatusCode.PreconditionFailed ||
            response.status == HttpStatusCode.NotFound ||
            response.status == HttpStatusCode.Conflict ||
            response.status == HttpStatusCode.Gone ->
                throw HttpException.fromResponse(response)
            !response.status.isSuccess() ->
                throw DavException("row-store error " + response.status.value + ": " + text.take(200), response.status.value)
        }
        return response
    }

    suspend fun HttpResponse.bodyAsJson(): JsonObject {
        val text = bodyAsTextSafe()
        return json.parseToJsonElement(text).jsonObject
    }

    suspend fun HttpResponse.bodyAsTextSafe(): String = try {
        body<String>()
    } catch (e: Exception) {
        ""
    }
}
