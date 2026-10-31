/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * JVM harness for RowStoreAccount + RowStoreUrls — runs the REAL account
 * operations (open: /config + derivation; listCalendars: manifest + §9b
 * batch + decrypt) against a MockEngine that speaks the row-store wire
 * protocol v4.3. Same pattern (and same KAT material) as
 * RowStoreCalDavCollectionTest.
 *
 * The crypto KAT literals are ported VERBATIM from the JavaScript reference
 * suite (calendar-web/test/crypto-parity.mjs) — cross-language parity pins.
 */
package at.bitfire.davdroid.resource.rowstore

import at.bitfire.dav4jvm.ktor.exception.DavException
import at.bitfire.dav4jvm.ktor.exception.NotFoundException
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64
import javax.crypto.spec.SecretKeySpec

class RowStoreAccountTest {

    // ---- KAT material: PoC dummy credentials (known insecure) ----
    private val katSalt = "e7c4efca4c020b3b5194f79f96a51d11"
    private val katWrapped = "gtOMiuuJlG5WJR41Tvn0uXGvXx8japyblEYhWungnA0haoeysqapBOdc/jv3dDF01l9BHvH9HcMOvp0A"
    private val katKDataHex = "6cdf2298ce2a2324b38e536db1cbf5097ca085cd2305c61372f53b7be5cba415"
    private val katAuthUiHex = "8b2d1be0bc3a9e7f9b551910b0642b992f98b2293efcabfc91e47763737bc13b"

    // ---- KAT material: cross-language vectors from test/crypto-parity.mjs ----
    private val parity = ParityKAT()

    private val server = Url("https://calendar-poc.example")

    private fun katRowKey() = SecretKeySpec(hex(katKDataHex), "AES")

    /** In-memory fake of the row-store server (protocol v4.3), incl. /config. */
    private class FakeRowStore(
        private val authUiHex: String,
        private val rowKey: javax.crypto.SecretKey,
        private val salt: String,
        private val iters: Int,
        private val wrapped: String
    ) {
        val rows = mutableMapOf<String, Pair<Long, RowStoreCrypto.Envelope>>()
        val requestLog = mutableListOf<Triple<HttpMethod, String, String>>()   // method, path, body

        /** When set, POST /rows:batch is answered with a silent drop (v4.2 server). */
        var batchRouteMissing = false

        fun put(id: String, ver: Long, payloadJson: String, key: javax.crypto.SecretKey = rowKey) {
            // wire format (§6): the payload is a JSON value — for both evt and
            // cmeta rows a JSON-encoded STRING (seed-prod.mjs parity)
            rows[id] = ver to RowStoreCrypto.encryptRow(key, id, ver, payloadJson)
        }

        /** Stores a cmeta row exactly like the web client does: the object
         *  text JSON-encoded as a string (double-encoded). */
        fun putCmeta(uuid: String, ver: Long, metaObjText: String, key: javax.crypto.SecretKey = rowKey) {
            put("cmeta:$uuid", ver, RowStoreCrypto.quoteJsonString(metaObjText), key)
        }

        private fun manifestJson(): String {
            val items = rows.keys.sorted().joinToString(",") { id ->
                """{"id":"$id","ver":${rows[id]!!.first}}"""
            }
            return """{"rows":[$items]}"""
        }

        val engine = MockEngine { request ->
            val auth = request.headers[HttpHeaders.Authorization]
            if (auth != "Bearer " + authUiHex)
                return@MockEngine respond("", HttpStatusCode.NotFound)          // §4 silent drop

            val path = request.url.encodedPath
            val body = (request.body as? TextContent)?.text
            requestLog.add(Triple(request.method, path, body ?: ""))

            when {
                request.method == HttpMethod.Get && path == "/config" ->
                    respond("""{"salt":"$salt","iters":$iters,"wrapped":"$wrapped","ver":1}""",
                        HttpStatusCode.OK, jsonHeaders())

                request.method == HttpMethod.Get && path == "/version" ->
                    respond("""{"proto":"4.3"}""", HttpStatusCode.OK, jsonHeaders())

                request.method == HttpMethod.Get && path == "/rows" ->
                    respond(manifestJson(), HttpStatusCode.OK, jsonHeaders())

                request.method == HttpMethod.Post && path == "/rows:batch" -> {
                    if (batchRouteMissing)
                        return@MockEngine respond("", HttpStatusCode.NotFound)  // v4.2: unknown route
                    val ids = Json.parseToJsonElement(body!!).jsonObject["ids"]!!.jsonArray
                        .map { it.jsonPrimitive.content }
                    val items = ids.joinToString(",") { id ->
                        val row = rows[id]
                        if (row == null)
                            """{"id":"$id","missing":true}"""
                        else
                            """{"id":"$id","ver":${row.first},"nonce":"${row.second.nonceB64}","ct":"${row.second.ctB64}"}"""
                    }
                    respond("""{"rows":[$items]}""", HttpStatusCode.OK, jsonHeaders())
                }

                request.method == HttpMethod.Get && path.startsWith("/rows/") -> {
                    // decode with decodeURIComponent semantics ('+' stays '+')
                    val id = RowStoreUrls.percentDecode(path.removePrefix("/rows/"))
                    val row = rows[id]
                        ?: return@MockEngine respond("""{"error":"not_found"}""", HttpStatusCode.NotFound, jsonHeaders())
                    respond("""{"id":"$id","ver":${row.first},"nonce":"${row.second.nonceB64}","ct":"${row.second.ctB64}"}""",
                        HttpStatusCode.OK, jsonHeaders())
                }

                else -> respond("", HttpStatusCode.NotFound)                     // unknown route
            }
        }

        private fun jsonHeaders() = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
    }

    private fun fake(
        authUiHex: String = katAuthUiHex,
        salt: String = katSalt,
        wrapped: String = katWrapped
    ) = FakeRowStore(authUiHex, katRowKey(), salt, 100000, wrapped)

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { i ->
        ((Character.digit(s[i * 2], 16) shl 4) + Character.digit(s[i * 2 + 1], 16)).toByte()
    }

    /** crypto-parity.mjs KAT literals (independent Python-derived reference). */
    private class ParityKAT {
        val password = "kat-password-0123456789"
        val saltHex = "00112233445566778899aabbccddeeff"
        val iters = 100000
        val wrappedHex = "0102030405060708090a0b0c8b4f77faa7bf7b268d19ce49870d319ab9f442734fdf7fdc0d0e7ecd7553f5f59afb719e64b837d6f9abd707335e3514"
        val kDataHex = "222fade7e1d29053be955a7da98e4d1e34066484150ba17b351cccba7e8c3bb8"
        val authUiHex = "083a2df48c4a464e203bb2e596fbaca722b6c56abe9de34d9381069cc0696c38"
        val aadId = "cal:20261030"
        val aadVer = 7L
        val aadHex = "63616c3a323032363130333000000007"
        val aadUnicodeId = "cal:\uD83C\uDF84"
        val aadUnicodeHex = "63616c3af09f8e8400000001"
        val rowId = "cal:20261030"
        val rowVer = 7L
        val rowNonceHex = "0a0b0c0d0e0f101112131415"
        val rowCtHex = "f27a79e21dd3ed636be2cdaeff19696db8c7299e3c2776ddb7f837f28390ad64cb91c2587f760a02a7ba541606cab554187547bbc649973c6937141f792a42a5559e8fa59d8c5dd23798487a215f1610fcb9faa20528fb74e65e0c82214d37694d80f7cfb7b0a7727587762014181967954d6f95c3170eaa0702129826d3e4e8af389914e8a06b9e7c3f"
        val rowPayloadJson = """{"events":[{"id":"w:11111111-2222-3333-4444-555555555555","date":"2026-11-01","hh":8,"mm":30,"title":"KAT","priority":1}]}"""

        fun wrappedB64() = Base64.getEncoder().encodeToString(hexBytes(wrappedHex))
        fun rowNonceB64() = Base64.getEncoder().encodeToString(hexBytes(rowNonceHex))
        fun rowCtB64() = Base64.getEncoder().encodeToString(hexBytes(rowCtHex))
        private fun hexBytes(s: String): ByteArray = ByteArray(s.length / 2) { i ->
            ((Character.digit(s[i * 2], 16) shl 4) + Character.digit(s[i * 2 + 1], 16)).toByte()
        }
    }

    // ---- cross-language crypto KATs (crypto-parity.mjs parity) ----

    @Test
    fun `crypto-parity KAT - derivation matches the JavaScript reference`() = runTest {
        val f = fake()
        val account = RowStoreAccount.open(HttpClient(f.engine), server, parity.authUiHex, parity.password)
        assertEquals(parity.kDataHex, account.keys.kData.encoded.joinToString("") { String.format("%02x", it) })
        assertEquals(parity.authUiHex, account.keys.authUiHex)
    }

    @Test
    fun `crypto-parity KAT - rowAad construction (ASCII and unicode ids)`() {
        assertEquals(parity.aadHex, RowStoreCrypto.rowAad(parity.aadId, parity.aadVer).joinToString("") { String.format("%02x", it) })
        assertEquals(parity.aadUnicodeHex, RowStoreCrypto.rowAad(parity.aadUnicodeId, 1).joinToString("") { String.format("%02x", it) })
    }

    @Test
    fun `crypto-parity KAT - row AEAD composition decrypts the JavaScript ciphertext`() {
        // decrypt the ct produced by the JS reference with the JS K_data:
        // proves AAD binding, nonce handling and key derivation agree byte-for-byte
        val kData = SecretKeySpec(hex(parity.kDataHex), "AES")
        val plain = RowStoreCrypto.decryptRow(kData, parity.rowId, parity.rowVer, parity.rowNonceB64(), parity.rowCtB64())
        assertEquals(parity.rowPayloadJson, plain)
    }

    // ---- RowStoreUrls ----

    @Test
    fun `collectionUrl and calUuidOf round-trip`() {
        val calUuid = "686247aa-e4c2-49cf-afa0-6437e41a7374"
        val url = RowStoreUrls.collectionUrl(server, calUuid)
        assertEquals("https://calendar-poc.example/clock/$calUuid/", url.toString())
        assertEquals(calUuid, RowStoreUrls.calUuidOf(url))
    }

    @Test
    fun `calUuidOf rejects non-row-store URLs`() {
        assertNull(RowStoreUrls.calUuidOf(Url("https://example.com/calendar/")))
        assertNull(RowStoreUrls.calUuidOf(Url("https://example.com/clock/")))
        assertNull(RowStoreUrls.calUuidOf(Url("https://example.com/clock/not-a-uuid/")))
        assertNull(RowStoreUrls.calUuidOf(Url("https://example.com/clock/686247AA-E4C2-49CF-AFA0-6437E41A7374/")))  // uppercase
        assertNull(RowStoreUrls.calUuidOf(Url("https://example.com/clock/686247aa-e4c2-49cf-afa0-6437e41a7374")))  // no trailing slash
        assertNull(RowStoreUrls.calUuidOf(Url("https://example.com/clock/686247aa-e4c2-49cf-afa0-6437e41a7374/events/")))  // deeper
    }

    @Test
    fun `parseCmetaRowId accepts only cmeta uuid rows`() {
        val uuid = "686247aa-e4c2-49cf-afa0-6437e41a7374"
        assertEquals(uuid, RowStoreUrls.parseCmetaRowId("cmeta:$uuid"))
        assertNull(RowStoreUrls.parseCmetaRowId("evt:$uuid:uid"))
        assertNull(RowStoreUrls.parseCmetaRowId("cmeta:not-a-uuid"))
        assertNull(RowStoreUrls.parseCmetaRowId("cmeta:"))
    }

    @Test
    fun `percent codec matches encodeURIComponent and decodeURIComponent`() {
        // JS: encodeURIComponent("a b+c/d?e#f&g=h%ü") === "a%20b%2Bc%2Fd%3Fe%23f%26g%3Dh%25%C3%BC"
        assertEquals("a%20b%2Bc%2Fd%3Fe%23f%26g%3Dh%25%C3%BC", RowStoreUrls.percentEncode("a b+c/d?e#f&g=h%ü"))
        // '+' must NOT decode to a space (decodeURIComponent parity)
        assertEquals("a+b c", RowStoreUrls.percentDecode("a+b%20c"))
        assertEquals("ü/é", RowStoreUrls.percentDecode("%C3%BC/%C3%A9"))
        // malformed escapes pass through unchanged (JS behavior: throws; we are
        // lenient because inputs are always OUR OWN encodings)
        assertEquals("100%", RowStoreUrls.percentDecode("100%"))
        assertEquals("", RowStoreUrls.percentEncode(""))
    }

    // ---- open ----

    @Test
    fun `open derives the KAT keys from the provisioning code and password`() = runTest {
        val f = fake()
        val account = RowStoreAccount.open(HttpClient(f.engine), server, katAuthUiHex, "password")
        assertEquals(katAuthUiHex, account.keys.authUiHex)
        assertEquals(
            katKDataHex,
            account.keys.kData.encoded.joinToString("") { String.format("%02x", it) }
        )
        assertEquals(server, account.server)
    }

    @Test
    fun `open with a wrong provisioning code fails as silent drop`() = runTest {
        val f = fake()
        val ex = assertThrows(RowStoreSilentDropException::class.java) {
            kotlinx.coroutines.runBlocking {
                RowStoreAccount.open(
                    HttpClient(f.engine), server,
                    "0000000000000000000000000000000000000000000000000000000000000000", "password"
                )
            }
        }
        assertTrue(ex.message!!.contains("silent drop"))
    }

    @Test
    fun `open with a wrong password fails (GCM unwrap)`() = runTest {
        val f = fake()
        assertThrows(Exception::class.java) {
            kotlinx.coroutines.runBlocking {
                RowStoreAccount.open(HttpClient(f.engine), server, katAuthUiHex, "wrong-password")
            }
        }
    }

    @Test
    fun `open validates config params (hostile server)`() = runTest {
        // absurd iteration count → must be rejected like the JS client does
        val f = fake(iters = 2_000_000_000)
        assertThrows(DavException::class.java) {
            kotlinx.coroutines.runBlocking {
                RowStoreAccount.open(HttpClient(f.engine), server, katAuthUiHex, "password")
            }
        }
        // malformed salt
        val f2 = fake(salt = "NOTHEX!")
        assertThrows(DavException::class.java) {
            kotlinx.coroutines.runBlocking {
                RowStoreAccount.open(HttpClient(f2.engine), server, katAuthUiHex, "password")
            }
        }
    }

    // ---- listCalendars ----

    @Test
    fun `listCalendars returns the calendars with names and colors`() = runTest {
        val f = fake()
        val cal1 = "686247aa-e4c2-49cf-afa0-6437e41a7374"
        val cal2 = "f7a8b9c0-1234-4def-9876-abcdefabcdef"
        f.putCmeta(cal1, 1, """{"v":1,"name":"Work","color":"#aabbcc"}""")
        f.putCmeta(cal2, 3, """{"v":1,"name":"Private","color":"#112233"}""")
        f.put("evt:$cal1:abcd", 2, RowStoreCrypto.quoteJsonString("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n"))

        val account = RowStoreAccount.open(HttpClient(f.engine), server, katAuthUiHex, "password")
        val listing = account.listCalendars()

        assertEquals(2, listing.calendars.size)
        assertTrue(listing.corruptRowIds.isEmpty())
        val byUuid = listing.calendars.associateBy { it.uuid }
        assertEquals("Work", byUuid[cal1]?.name)
        assertEquals("#AABBCC", byUuid[cal1]?.colorHex)
        assertEquals(0xFFAABBCC.toInt(), byUuid[cal1]?.colorArgb)
        assertEquals("Private", byUuid[cal2]?.name)
        // exactly one manifest + one batch request
        assertEquals(1, f.requestLog.count { it.first == HttpMethod.Get && it.second == "/rows" })
        assertEquals(1, f.requestLog.count { it.first == HttpMethod.Post && it.second == "/rows:batch" })
    }

    @Test
    fun `listCalendars on an empty store returns nothing and makes no batch request`() = runTest {
        val f = fake()
        val account = RowStoreAccount.open(HttpClient(f.engine), server, katAuthUiHex, "password")
        val listing = account.listCalendars()
        assertEquals(0, listing.calendars.size)
        assertTrue(listing.corruptRowIds.isEmpty())
        assertEquals(1, f.requestLog.count { it.first == HttpMethod.Get && it.second == "/rows" })
        assertEquals(0, f.requestLog.count { it.first == HttpMethod.Post && it.second == "/rows:batch" })
    }

    @Test
    fun `listCalendars reports corrupt cmeta rows instead of swallowing them`() = runTest {
        val f = fake()
        val good = "686247aa-e4c2-49cf-afa0-6437e41a7374"
        val corruptKey = "f7a8b9c0-1234-4def-9876-abcdefabcdef"
        val malformed = "01234567-89ab-4cde-8f01-234567890abc"
        f.putCmeta(good, 1, """{"v":1,"name":"Good","color":"#aabbcc"}""")
        // encrypted under a DIFFERENT key → decrypt fails → corrupt
        f.putCmeta(corruptKey, 1, """{"v":1,"name":"Bad","color":"#000000"}""",
            key = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES"))
        // payload decrypts, but is not a valid cmeta object → corrupt
        f.putCmeta(malformed, 1, """{"v":2,"name":"","color":"nope"}""")

        val account = RowStoreAccount.open(HttpClient(f.engine), server, katAuthUiHex, "password")
        val listing = account.listCalendars()
        assertEquals(1, listing.calendars.size)
        assertEquals("Good", listing.calendars[0].name)
        assertEquals(setOf("cmeta:$corruptKey", "cmeta:$malformed"), listing.corruptRowIds)
    }

    @Test
    fun `listCalendars falls back to per-row GETs on a v4.2 server (no /rows:batch)`() = runTest {
        val f = fake()
        f.batchRouteMissing = true
        val cal1 = "686247aa-e4c2-49cf-afa0-6437e41a7374"
        val cal2 = "f7a8b9c0-1234-4def-9876-abcdefabcdef"
        f.putCmeta(cal1, 1, """{"v":1,"name":"Work","color":"#aabbcc"}""")
        f.putCmeta(cal2, 3, """{"v":1,"name":"Private"}""")

        val account = RowStoreAccount.open(HttpClient(f.engine), server, katAuthUiHex, "password")
        val listing = account.listCalendars()

        assertEquals(2, listing.calendars.size)
        // the batch was attempted once, then two per-row GETs
        assertEquals(1, f.requestLog.count { it.first == HttpMethod.Post && it.second == "/rows:batch" })
        assertEquals(2, f.requestLog.count { it.first == HttpMethod.Get && it.second.startsWith("/rows/") })
    }

    @Test
    fun `listCalendars tolerates a missing color`() = runTest {
        val f = fake()
        val cal = "686247aa-e4c2-49cf-afa0-6437e41a7374"
        f.putCmeta(cal, 1, """{"v":1,"name":"NoColor"}""")
        val account = RowStoreAccount.open(HttpClient(f.engine), server, katAuthUiHex, "password")
        val listing = account.listCalendars()
        assertEquals(1, listing.calendars.size)
        assertNull(listing.calendars[0].colorHex)
        assertNull(listing.calendars[0].colorArgb)
    }
}
