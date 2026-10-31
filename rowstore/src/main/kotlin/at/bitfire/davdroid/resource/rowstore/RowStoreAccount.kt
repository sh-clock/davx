/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * RowStoreAccount — account-level operations on the encrypted row store
 * (protocol v4.3): unlocking (GET /config + key derivation) and listing the
 * calendars (cmeta rows via manifest + §9b batch).
 *
 * Credential model (mirrors the web client's provisioning, app.js unlock()):
 *  - the AUTH_UI token is provisioned out-of-band (the web client's ?setup=
 *    link; in davx5 it is the account USERNAME);
 *  - the PASSWORD unlocks AES1: password → PBKDF2(salt,iters) → KEK →
 *    AES-GCM unwrap(config.wrapped) → AES1 → HKDF → K_data + AUTH_UI;
 *  - the derived AUTH_UI is used for requests (identical to the web client;
 *    a mismatch with the provisioned token is logged as a warning).
 *
 * Like the web client, this class holds K_data and the plaintext of every
 * row it decrypts in memory only — the worker never sees any of it (L1).
 */
package at.bitfire.davdroid.resource.rowstore

import at.bitfire.dav4jvm.ktor.exception.DavException
import io.ktor.client.HttpClient
import io.ktor.http.HttpMethod
import io.ktor.http.Url
import io.ktor.http.contentType
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
     * Lists all calendars from the cmeta rows: manifest (GET /rows) filtered
     * to `cmeta:{uuid}` ids, then §9b batch multiget + decrypt.
     *
     * Corrupt/undecryptable cmeta rows are skipped (with a log) — one bad row
     * must not make the whole account unusable. Does not throw on empty stores.
     */
    fun listCalendars(): Flow<CalendarInfo> = flow {
        val manifest = api.request {
            method = HttpMethod.Get
            url(api.baseUrl + "/rows")
        }.let { api.bodyAsJson(it) }
        val rows = manifest["rows"]?.jsonArray ?: throw DavException("manifest without rows")

        val cmetaIds = rows.mapNotNull { row ->
            val id = row.jsonObject["id"]?.jsonPrimitive?.content ?: return@mapNotNull null
            RowStoreUrls.parseCmetaRowId(id)?.let { uuid -> id to uuid }
        }
        if (cmetaIds.isEmpty()) return@flow

        cmetaIds.map { it.first }.chunked(256).forEach { chunk ->
            val body = buildJsonObject {
                put("ids", kotlinx.serialization.json.buildJsonArray {
                    chunk.forEach { add(JsonPrimitive(it)) }
                })
            }
            val response = api.request {
                method = HttpMethod.Post
                url(api.baseUrl + "/rows:batch")
                contentType(io.ktor.http.ContentType.Application.Json)
                setBody(body.toString())
            }
            val json = api.bodyAsJson(response)
            val batchRows = json["rows"]?.jsonArray ?: throw DavException("batch response without rows")
            for (row in batchRows) {
                val obj = row.jsonObject
                val id = obj["id"]?.jsonPrimitive?.content ?: continue
                if (obj["missing"]?.jsonPrimitive?.content == "true") continue
                val uuid = RowStoreUrls.parseCmetaRowId(id) ?: continue
                val ver = obj["ver"]?.jsonPrimitive?.content?.toLongOrNull() ?: continue
                val nonce = obj["nonce"]?.jsonPrimitive?.content ?: continue
                val ct = obj["ct"]?.jsonPrimitive?.content ?: continue
                val info = decryptCmeta(id, uuid, ver, nonce, ct) ?: continue
                emit(info)
            }
        }
    }

    private fun decryptCmeta(id: String, uuid: String, ver: Long, nonce: String, ct: String): CalendarInfo? = try {
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

    companion object {

        /**
         * Opens the account: fetches /config with the provisioning code and
         * derives the subkeys from the password.
         *
         * @param httpClient       HTTP client WITHOUT authentication plugin (the
         *                          Bearer header is added per request, see [RowStoreApi])
         * @param server           row-store server base URL
         * @param provisioningCode AUTH_UI token (hex64) — in davx5: the username
         * @param password         the account password
         *
         * @throws DavException on §4 silent drop (wrong/invalid provisioning code)
         * @throws javax.crypto.AEADBadTagException on a wrong password (unwrap fails)
         */
        suspend fun open(
            httpClient: HttpClient,
            server: Url,
            provisioningCode: String,
            password: String
        ): RowStoreAccount {
            val api = RowStoreApi(httpClient, server, provisioningCode)
            val response = api.request {
                method = HttpMethod.Get
                url(api.baseUrl + "/config")
            }
            val json = api.bodyAsJson(response)
            val salt = json["salt"]?.jsonPrimitive?.content
                ?: throw DavException("config without salt")
            val iters = json["iters"]?.jsonPrimitive?.content?.toIntOrNull()
                ?: throw DavException("config without iters")
            val wrapped = json["wrapped"]?.jsonPrimitive?.content
                ?: throw DavException("config without wrapped")
            val keys = RowStoreCrypto.derive(password, salt, iters, wrapped)
            if (keys.authUiHex != provisioningCode)
                Logger.getLogger(RowStoreAccount::class.java.name).warning(
                    "Derived AUTH_UI does not match the provisioning code — using the derived token (wrong code or rewrapped server?)."
                )
            return RowStoreAccount(api, keys)
        }
    }
}
