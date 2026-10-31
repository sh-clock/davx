/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * JVM harness for RowStoreAccount + RowStoreUrls — runs the REAL account
 * operations (open: /config + derivation; listCalendars: manifest + §9b
 * batch + decrypt) against a MockEngine that speaks the row-store wire
 * protocol v4.3. Same pattern (and same KAT material) as
 * RowStoreCalDavCollectionTest.
 */
package at.bitfire.davdroid.resource.rowstore

import at.bitfire.dav4jvm.ktor.exception.DavException
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
import kotlinx.coroutines.flow.toList
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
import javax.crypto.spec.SecretKeySpec

class RowStoreAccountTest {

    // ---- KAT material (production PoC dummy credentials — known insecure) ----
    private val katSalt = "e7c4efca4c020b3b5194f79f96a51d11"
    private val katWrapped = "gtOMiuuJlG5WJR41Tvn0uXGvXx8japyblEYhWungnA0haoeysqapBOdc/jv3dDF01l9BHvH9HcMOvp0A"
    private val katKDataHex = "6cdf2298ce2a2324b38e536db1cbf5097ca085cd2305c61372f53b7be5cba415"
    private val katAuthUiHex = "8b2d1be0bc3a9e7f9b551910b0642b992f98b2293efcabfc91e47763737bc13b"

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
        val requestLog = mutableListOf<Pair<HttpMethod, String>>()

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
            requestLog.add(request.method to path)
            val body = (request.body as? TextContent)?.text

            when {
                request.method == HttpMethod.Get && path == "/config" ->
                    respond("""{"salt":"$salt","iters":$iters,"wrapped":"$wrapped","ver":1}""",
                        HttpStatusCode.OK, jsonHeaders())

                request.method == HttpMethod.Get && path == "/version" ->
                    respond("""{"proto":"4.3"}""", HttpStatusCode.OK, jsonHeaders())

                request.method == HttpMethod.Get && path == "/rows" ->
                    respond(manifestJson(), HttpStatusCode.OK, jsonHeaders())

                request.method == HttpMethod.Post && path == "/rows:batch" -> {
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

                else -> respond("", HttpStatusCode.NotFound)                     // unknown route
            }
        }

        private fun jsonHeaders() = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { i ->
        ((Character.digit(s[i * 2], 16) shl 4) + Character.digit(s[i * 2 + 1], 16)).toByte()
    }

    private fun fake(
        authUiHex: String = katAuthUiHex,
        salt: String = katSalt,
        wrapped: String = katWrapped
    ) = FakeRowStore(authUiHex, katRowKey(), salt, 100000, wrapped)

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
        val ex = assertThrows(DavException::class.java) {
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
        val calendars = account.listCalendars().toList()

        assertEquals(2, calendars.size)
        val byUuid = calendars.associateBy { it.uuid }
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
        assertEquals(0, account.listCalendars().toList().size)
        assertEquals(1, f.requestLog.count { it.first == HttpMethod.Get && it.second == "/rows" })
        assertEquals(0, f.requestLog.count { it.first == HttpMethod.Post && it.second == "/rows:batch" })
    }

    @Test
    fun `listCalendars skips corrupt cmeta rows but keeps the good ones`() = runTest {
        val f = fake()
        val good = "686247aa-e4c2-49cf-afa0-6437e41a7374"
        val corruptKey = "f7a8b9c0-1234-4def-9876-abcdefabcdef"
        val malformed = "01234567-89ab-4cde-8f01-234567890abc"
        f.putCmeta(good, 1, """{"v":1,"name":"Good","color":"#aabbcc"}""")
        // encrypted under a DIFFERENT key → decrypt fails → skipped
        f.putCmeta(corruptKey, 1, """{"v":1,"name":"Bad","color":"#000000"}""",
            key = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES"))
        // payload decrypts, but is not a valid cmeta object → skipped
        f.putCmeta(malformed, 1, """{"v":2,"name":"","color":"nope"}""")

        val account = RowStoreAccount.open(HttpClient(f.engine), server, katAuthUiHex, "password")
        val calendars = account.listCalendars().toList()
        assertEquals(1, calendars.size)
        assertEquals("Good", calendars[0].name)
    }

    @Test
    fun `listCalendars tolerates a missing color`() = runTest {
        val f = fake()
        val cal = "686247aa-e4c2-49cf-afa0-6437e41a7374"
        f.putCmeta(cal, 1, """{"v":1,"name":"NoColor"}""")
        val account = RowStoreAccount.open(HttpClient(f.engine), server, katAuthUiHex, "password")
        val calendars = account.listCalendars().toList()
        assertEquals(1, calendars.size)
        assertNull(calendars[0].colorHex)
        assertNull(calendars[0].colorArgb)
    }
}
