/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * RowStoreAccount — account-level operations on the encrypted row store
 * (protocol v4.3): unlocking (GET /config + key derivation) and listing the
 * calendars (cmeta rows via manifest + §9b batch, with per-row GET fallback
 * for v4.2 servers without /rows:batch).
 *
 * Credential model (mirrors the web client's provisioning, app.js unlock()):
 *  - the AUTH_UI token is provisioned out-of-band (the web client's ?setup=
 *    link; in davx5 it is the account USERNAME);
 *  - the PASSWORD unlocks AES1: password → PBKDF2(salt,iters) → KEK →
 *    AES-GCM unwrap(config.wrapped) → AES1 → HKDF → K_data + AUTH_UI;
 *  - after unlocking, the DERIVED AUTH_UI is used for all requests (exactly
 *    like the web client switches to the derived token, app.js:311); a
 *    mismatch with the provisioned token is logged as a warning.
 *
 * Like the web client, this class holds K_data and the plaintext of every
 * row it decrypts in memory only — the worker never sees any of it (L1).
 */
package at.bitfire.davdroid.resource.rowstore

import at.bitfire.dav4jvm.ktor.exception.DavException
import at.bitfire.dav4jvm.ktor.exception.NotFoundException
import io.ktor.client.HttpClient
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.Url
import io.ktor.http.contentType
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.util.logging.Logger

class RowStoreAccount private constructor(
    private val api: RowStoreApi,
    val keys: RowStoreCrypto.Keys
) {

    private val logger get() = Logger.getLogger(javaClass.name)

    val httpClient: HttpClient get() = api.httpClient
    val server: Url get() = api.server

    /** One calendar as advertised by a cmeta row. */
    data class CalendarInfo(
        /** Calendar UUID (row id cmeta:{uuid}). */
        val uuid: String,
        /** Display name (1..100 chars, §2). */
        val name: String,
        /** Color as #RRGGBB (uppercase, §2), or null when absent. */
        val colorHex: String?
    ) {
        /** Color as Android ARGB int, or null. */
        val colorArgb: Int?
            get() = colorHex?.let { hex ->
                (0xFF shl 24) or
                    (Integer.parseInt(hex.substring(1, 3), 16) shl 16) or
                    (Integer.parseInt(hex.substring(3, 5), 16) shl 8) or
                    Integer.parseInt(hex.substring(5, 7), 16)
            }
    }

    /**
     * Result of a calendar listing.
     *
     * @param calendars usable calendars (decrypted + validated cmeta rows)
     * @param corruptRowIds cmeta row ids that EXIST on the server but could not
     *   be decrypted or parsed. These must NOT be treated as "calendar gone"
     *   (deleting them would remove the local calendar + events); callers keep
     *   the last-known-good state, like the web client's corrupt-row handling.
     */
    data class Calendars(
        val calendars: List<CalendarInfo>,
        val corruptRowIds: Set<String> = emptySet()
    )

    /**
     * Lists all calendars from the cmeta rows: manifest (GET /rows) filtered
     * to `cmeta:{uuid}` ids, then §9b batch multiget + decrypt. When the
     * server does not know POST /rows:batch (protocol < 4.3), falls back to
     * per-row GETs — the same degrade as the web client (§5.1c/§5.4).
     */
    suspend fun listCalendars(): Calendars {
        val manifest = api.request {
            method = io.ktor.http.HttpMethod.Get
            url(api.baseUrl + "/rows")
        }.let { api.bodyAsJson(it) }
        val rows = manifest["rows"]?.jsonArray ?: throw DavException("manifest without rows")

        val cmetaIds = rows.mapNotNull { row ->
            val id = row.jsonObject["id"]?.jsonPrimitive?.content ?: return@mapNotNull null
            if (RowStoreUrls.parseCmetaRowId(id) != null) id else null
        }
        if (cmetaIds.isEmpty()) return Calendars(emptyList())

        val envelopes = fetchEnvelopes(cmetaIds)
        val calendars = ArrayList<CalendarInfo>(envelopes.size)
        val corrupt = HashSet<String>()
        for (envelope in envelopes) {
            val id = envelope["id"]?.jsonPrimitive?.content ?: continue
            if (envelope["missing"]?.jsonPrimitive?.content == "true") continue
            val info = decryptCmeta(envelope) ?: run {
                corrupt += id
                continue
            }
            calendars += info
        }
        return Calendars(calendars, corrupt)
    }

    /**
     * Fetches row envelopes for [ids]: one §9b POST /rows:batch (≤256 ids per
     * call); on a silent drop (v4.2 server without the route) falls back to
     * per-row GET /rows/{id} (missing rows are skipped).
     */
    private suspend fun fetchEnvelopes(ids: List<String>): List<Map<String, kotlinx.serialization.json.JsonElement>> {
        val out = ArrayList<Map<String, kotlinx.serialization.json.JsonElement>>(ids.size)
        ids.chunked(256).forEach { chunk ->
            try {
                val body = buildJsonObject {
                    put("ids", kotlinx.serialization.json.buildJsonArray {
                        chunk.forEach { add(JsonPrimitive(it)) }
                    })
                }
                val response = api.request {
                    method = io.ktor.http.HttpMethod.Post
                    url(api.baseUrl + "/rows:batch")
                    contentType(ContentType.Application.Json)
                    setBody(body.toString())
                }
                val json = api.bodyAsJson(response)
                val rows = json["rows"]?.jsonArray ?: throw DavException("batch response without rows")
                for (row in rows)
                    out += row.jsonObject
            } catch (e: RowStoreSilentDropException) {
                // §5.1c/§5.4 degrade: v4.2 server without /rows:batch → per-row GETs
                logger.warning("/rows:batch not available (protocol < 4.3?); falling back to per-row GETs")
                for (id in chunk)
                    getRowEnvelope(id)?.let { out += it }
            }
        }
        return out
    }

    /** GET /rows/{id} — the envelope as a JSON object, or null when missing. */
    private suspend fun getRowEnvelope(id: String): Map<String, kotlinx.serialization.json.JsonElement>? = try {
        val response = api.request {
            method = io.ktor.http.HttpMethod.Get
            url(api.baseUrl + "/rows/" + RowStoreUrls.percentEncode(id))
        }
        api.bodyAsJson(response)
    } catch (e: NotFoundException) {
        null
    }

    private fun decryptCmeta(envelope: Map<String, kotlinx.serialization.json.JsonElement>): CalendarInfo? {
        val id = envelope["id"]?.jsonPrimitive?.content ?: return null
        val uuid = RowStoreUrls.parseCmetaRowId(id) ?: return null
        return try {
            val ver = envelope["ver"]?.jsonPrimitive?.content?.toLongOrNull()
                ?: throw DavException("cmeta entry without ver: $id")
            val nonce = envelope["nonce"]?.jsonPrimitive?.content
                ?: throw DavException("cmeta entry without nonce: $id")
            val ct = envelope["ct"]?.jsonPrimitive?.content
                ?: throw DavException("cmeta entry without ct: $id")
            val plain = RowStoreCrypto.decryptRow(keys.kData, id, ver, nonce, ct)
            // cmeta wire plaintext (§6 + scripts/seed-prod.mjs): JSON.stringify(meta)
            // JSON-encoded — i.e. a JSON STRING whose content is the object text
            // (the web client's decryptRow returns the inner string and it
            // JSON.parses a second time, app.js sync ingest).
            val metaText = RowStoreCrypto.unquoteJsonString(plain)
            val obj = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
                .parseToJsonElement(metaText).jsonObject
            val v = obj["v"]?.jsonPrimitive?.content
            val name = obj["name"]?.jsonPrimitive?.content
            val color = obj["color"]?.jsonPrimitive?.content
            if (v != "1" || name.isNullOrEmpty() || name.length > 100)
                throw DavException("invalid cmeta payload for $id")
            if (color != null && !Regex("^#[0-9A-Fa-f]{6}$").matches(color))
                throw DavException("invalid cmeta color for $id")
            CalendarInfo(uuid, name, color?.uppercase())
        } catch (e: Exception) {
            logger.warning("Skipping corrupt cmeta row $id: ${e.message}")
            null
        }
    }

    companion object {

        /**
         * Opens the account: fetches /config with the provisioning code and
         * derives the subkeys from the password. All further requests use the
         * DERIVED AUTH_UI (web client parity).
         *
         * @param httpClient       HTTP client WITHOUT authentication plugin (the
         *                          Bearer header is added per request, see [RowStoreApi])
         * @param server           row-store server base URL
         * @param provisioningCode AUTH_UI token (hex64) — in davx5: the username
         * @param password         the account password
         *
         * @throws RowStoreSilentDropException when the provisioning code is not valid (§4)
         * @throws DavException on malformed config params
         * @throws javax.crypto.AEADBadTagException on a wrong password (unwrap fails)
         */
        suspend fun open(
            httpClient: HttpClient,
            server: Url,
            provisioningCode: String,
            password: String
        ): RowStoreAccount {
            val bootstrapApi = RowStoreApi(httpClient, server, provisioningCode)
            val response = bootstrapApi.request {
                method = io.ktor.http.HttpMethod.Get
                url(bootstrapApi.baseUrl + "/config")
            }
            val json = bootstrapApi.bodyAsJson(response)
            val salt = json["salt"]?.jsonPrimitive?.content
                ?: throw DavException("config without salt")
            val iters = json["iters"]?.jsonPrimitive?.content?.toIntOrNull()
                ?: throw DavException("config without iters")
            val wrapped = json["wrapped"]?.jsonPrimitive?.content
                ?: throw DavException("config without wrapped")
            // config validation (js/crypto.js deriveKeys parity: a hostile or
            // broken server must not be able to force absurd KDF parameters)
            if (!Regex("^[0-9a-f]{32}$").matches(salt))
                throw DavException("bad config: salt")
            if (iters < 1 || iters > 10_000_000)
                throw DavException("bad config: iters")

            val keys = RowStoreCrypto.derive(password, salt, iters, wrapped)
            if (keys.authUiHex != provisioningCode)
                Logger.getLogger(RowStoreAccount::class.java.name).warning(
                    "Derived AUTH_UI does not match the provisioning code — using the derived token (wrong code or rewrapped server?)."
                )
            // all further requests authenticate with the DERIVED AUTH_UI
            val api = RowStoreApi(httpClient, server, keys.authUiHex)
            return RowStoreAccount(api, keys)
        }
    }
}
