/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * RowStoreCalDavCollection — implements the row-store protocol layer
 * (protocol v4.3 + §9c conditional mode, calendar-web/protocol.md) for one
 * calendar, mapping CalDAV collection semantics onto the encrypted row store:
 *
 *   CalDAV concept                        row-store mapping
 *   ------------------------------------ -------------------------------------------
 *   collection URL                       {server}/clock/{calendar-uuid}/
 *   member file name                     event UID (row id: evt:{cal}:{uid})
 *   ETag                                 decimal ver string
 *   PROPFIND listing (with ETags)        GET /rows manifest, filtered to the calendar
 *   calendar-multiget REPORT             POST /rows:batch (protocol.md §9b), ≤256 ids per call
 *   PUT with If-Match (update)           §9c: PUT ver = etag+1 with If-Match → 412 on mismatch
 *   PUT with If-None-Match (create)      §9c: PUT ver = 1 with If-None-Match: * → 412 if it exists
 *   DELETE                               DELETE /rows/{id} (idempotent; If-Match not on the wire)
 *   capabilities                         GET /version; no collection sync (RFC 6578)
 *
 * The worker is an untrusted relay: it never sees event data (row payloads are
 * AES-256-GCM ciphertext under K_data, held only by this client).
 *
 * Conflict handling matches davx5's SyncManager: rebase and create-race
 * surface as PreconditionFailedException, so the server's version wins and is
 * re-downloaded (SyncManager: "Upload rejected because of a failed precondition").
 *
 * The HTTP request machinery (bearer header + error mapping) lives in
 * [RowStoreApi]; the URL grammar lives in [RowStoreUrls].
 */
package at.bitfire.davdroid.resource.rowstore

import at.bitfire.dav4jvm.ktor.exception.DavException
import at.bitfire.dav4jvm.ktor.resolve
import io.ktor.client.HttpClient
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.Url
import io.ktor.http.content.OutgoingContent
import io.ktor.http.contentType
import io.ktor.client.statement.HttpResponse
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.util.logging.Logger
import javax.crypto.SecretKey

class RowStoreCalDavCollection(
    httpClient: HttpClient,
    /** Base URL of the row-store server, e.g. https://calendar-poc.sh-clock.workers.dev */
    server: Url,
    /** UUID of the calendar whose evt rows this collection exposes. */
    val calUuid: String,
    /** AUTH_UI bearer token (hex64). */
    authUiHex: String,
    /** Row encryption key (K_data). */
    private val rowKey: SecretKey
) : RowStoreCollection {

    private val logger get() = Logger.getLogger(javaClass.name)

    private val api = RowStoreApi(httpClient, server, authUiHex)

    /** The pseudo-collection URL: members are addressed as {collection}/{uid}. */
    val collectionUrl: Url = RowStoreUrls.collectionUrl(api.server, calUuid)

    /** Row id for a member: evt:{cal}:{uid} */
    internal fun rowId(fileName: String): String = "evt:$calUuid:$fileName"

    /** Extract the UID (file name) from a member URL below [collectionUrl]. */
    internal fun fileNameOf(url: Url): String {
        val base = collectionUrl.encodedPath
        require(url.encodedPath.startsWith(base)) { "member URL $url is not below $collectionUrl" }
        return java.net.URLDecoder.decode(url.encodedPath.removePrefix(base).trimEnd('/'), "UTF-8")
    }

    // ---- create ----

    override suspend fun createMember(
        fileName: String,
        content: OutgoingContent,
        additionalHeaders: Map<String, String>
    ): RowStoreCollection.PutMemberResult {
        val text = content.readAsText()
        val id = rowId(fileName)
        // If-None-Match semantics via §9c: a fresh row is created with ver 1;
        // if the row already exists, the server answers 412 → mapped to
        // PreconditionFailedException (SyncManager downloads the server copy).
        val env = RowStoreCrypto.encryptRow(rowKey, id, 1, RowStoreCrypto.quoteJsonString(text))
        val stored = putRow(id, env, ifNoneMatch = "*")
        return RowStoreCollection.PutMemberResult(eTag = stored.ver.toString())
    }

    // ---- read/query ----

    override suspend fun queryCapabilities(): RowStoreCollection.Capabilities {
        val response = api.request {
            method = HttpMethod.Get
            url(api.baseUrl + "/version")
        }
        val json = api.bodyAsJson(response)
        val proto = json["proto"]?.jsonPrimitive?.content
            ?: throw DavException("server did not report a protocol version")
        if (proto != "4.3")
            logger.warning("Row-store server reports protocol $proto; this adapter targets 4.3")
        return RowStoreCollection.Capabilities()
    }

    override fun listFilteredMembers(): Flow<RowStoreCollection.MemberState> = flow {
        val manifest = api.request {
            method = HttpMethod.Get
            url(api.baseUrl + "/rows")
        }.let { api.bodyAsJson(it) }
        val rows = manifest["rows"]?.jsonArray ?: throw DavException("manifest without rows")
        for (row in rows) {
            val id = row.jsonObject["id"]?.jsonPrimitive?.content ?: continue
            if (!id.startsWith("evt:$calUuid:")) continue
            val ver = row.jsonObject["ver"]?.jsonPrimitive?.content?.toLongOrNull()
                ?: throw DavException("manifest entry without ver: $id")
            val uid = id.removePrefix("evt:$calUuid:")
            emit(
                RowStoreCollection.MemberState(
                    href = collectionUrl.resolve(uid)!!,
                    eTag = ver.toString()
                )
            )
        }
    }

    override fun multiget(
        urls: List<Url>,
        capabilities: RowStoreCollection.Capabilities
    ): Flow<RowStoreCollection.MultiGetItem> = flow {
        if (urls.isEmpty()) return@flow
        val ids = urls.map { rowId(fileNameOf(it)) }
        // §9b: one batch request per ≤256 ids.
        ids.chunked(256).forEach { chunk ->
            val body = buildJsonObject {
                put("ids", kotlinx.serialization.json.buildJsonArray {
                    chunk.forEach { add(JsonPrimitive(it)) }
                })
            }
            val response = api.request {
                method = HttpMethod.Post
                url(api.baseUrl + "/rows:batch")
                contentType(ContentType.Application.Json)
                setBody(body.toString())
            }
            val json = api.bodyAsJson(response)
            val rows = json["rows"]?.jsonArray ?: throw DavException("batch response without rows")
            for (row in rows) {
                val obj = row.jsonObject
                val id = obj["id"]?.jsonPrimitive?.content ?: continue
                if (obj["missing"]?.jsonPrimitive?.content == "true") continue
                val ver = obj["ver"]?.jsonPrimitive?.content?.toLongOrNull()
                    ?: throw DavException("batch entry without ver: $id")
                val nonce = obj["nonce"]?.jsonPrimitive?.content
                    ?: throw DavException("batch entry without nonce: $id")
                val ct = obj["ct"]?.jsonPrimitive?.content
                    ?: throw DavException("batch entry without ct: $id")
                val uid = id.removePrefix("evt:$calUuid:")
                val plain = RowStoreCrypto.decryptRow(rowKey, id, ver, nonce, ct)
                val ical = RowStoreCrypto.unquoteJsonString(plain)
                emit(
                    RowStoreCollection.MultiGetItem(
                        url = collectionUrl.resolve(uid)!!,
                        eTag = ver.toString(),
                        content = ical
                    )
                )
            }
        }
    }

    // ---- update ----

    override suspend fun updateMember(
        fileName: String,
        content: OutgoingContent,
        ifETag: String?,
        additionalHeaders: Map<String, String>
    ): RowStoreCollection.PutMemberResult {
        val text = content.readAsText()
        val id = rowId(fileName)
        // If-Match semantics via §9c: PUT at ver = etag+1 with If-Match: "<etag>".
        // A mismatch (or vanished row) → 412/404 → dav4jvm typed exceptions →
        // the SyncManager re-downloads the server version (standard handling).
        val currentVer = ifETag?.toLongOrNull()
            ?: throw DavException("row-store updates require an If-Match ETag (ver)")
        val newVer = currentVer + 1
        val env = RowStoreCrypto.encryptRow(rowKey, id, newVer, RowStoreCrypto.quoteJsonString(text))
        val stored = putRow(id, env, ifMatchVer = currentVer)
        return RowStoreCollection.PutMemberResult(eTag = stored.ver.toString())
    }

    // ---- delete ----

    override suspend fun deleteMember(
        fileName: String,
        ifETag: String?,
        additionalHeaders: Map<String, String>
    ) {
        // NOTE: the row-store DELETE is idempotent and takes no If-Match
        // (protocol.md §9 documents the semantic loss). A concurrent
        // delete-then-recreate race resolves at the next sync via the manifest.
        api.request {
            method = HttpMethod.Delete
            url(api.baseUrl + "/rows/" + java.net.URLEncoder.encode(rowId(fileName), "UTF-8"))
        }
    }

    // ---- internals ----

    private suspend fun putRow(
        id: String,
        env: RowStoreCrypto.Envelope,
        ifMatchVer: Long? = null,
        ifNoneMatch: String? = null
    ): RowStoreCrypto.Envelope {
        val body = buildJsonObject {
            put("ver", env.ver)
            put("nonce", env.nonceB64)
            put("ct", env.ctB64)
        }
        val response = api.request {
            method = HttpMethod.Put
            url(api.baseUrl + "/rows/" + java.net.URLEncoder.encode(id, "UTF-8"))
            contentType(ContentType.Application.Json)
            ifMatchVer?.let { headers.append(HttpHeaders.IfMatch, "\"$it\"") }
            ifNoneMatch?.let { headers.append(HttpHeaders.IfNoneMatch, it) }
            setBody(body.toString())
        }
        val json = api.bodyAsJson(response)
        val ver = json["ver"]?.jsonPrimitive?.content?.toLongOrNull()
            ?: throw DavException("PUT response without ver: $id")
        val nonce = json["nonce"]?.jsonPrimitive?.content
            ?: throw DavException("PUT response without nonce: $id")
        val ct = json["ct"]?.jsonPrimitive?.content
            ?: throw DavException("PUT response without ct: $id")
        return RowStoreCrypto.Envelope(ver, nonce, ct)
    }

    /** Reads an OutgoingContent (davx5 hands us the iCalendar text as content). */
    private suspend fun OutgoingContent.readAsText(): String = when (this) {
        is OutgoingContent.ByteArrayContent -> String(bytes(), Charsets.UTF_8)
        is OutgoingContent.NoContent -> ""
        else -> throw UnsupportedOperationException(
            "RowStoreCalDavCollection expects ByteArrayContent (iCalendar text); got $this"
        )
    }
}
