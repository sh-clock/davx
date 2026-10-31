/*
 * Copyright © All Contributors. See LICENSE and AUTHORS in the root directory for details.
 *
 * JVM harness for RowStoreCalDavCollection — runs the REAL adapter (and the REAL
 * crypto module) against a MockEngine that speaks the row-store wire protocol
 * v4.3 (manifest, §9b batch, §9c conditional PUT, DELETE, version). Pattern
 * copied from CalDavCollectionTest (pure JVM, no Android framework).
 *
 * Crypto correctness is pinned with KAT vectors from the JavaScript reference
 * implementation (calendar-web/js/crypto.js — the production client): the
 * PoC dummy credentials below are the user-designated known-insecure test
 * material (see calendar-web/.secrets/credentials.json).
 */
package at.bitfire.davdroid.resource.rowstore

import at.bitfire.dav4jvm.ktor.exception.DavException
import at.bitfire.dav4jvm.ktor.resolve
import at.bitfire.dav4jvm.ktor.exception.HttpException
import at.bitfire.dav4jvm.ktor.exception.PreconditionFailedException
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
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.spec.SecretKeySpec

class RowStoreCalDavCollectionTest {

    // ---- KAT material (production PoC dummy credentials — known insecure) ----
    private val katSalt = "e7c4efca4c020b3b5194f79f96a51d11"
    private val katWrapped = "gtOMiuuJlG5WJR41Tvn0uXGvXx8japyblEYhWungnA0haoeysqapBOdc/jv3dDF01l9BHvH9HcMOvp0A"
    private val katKDataHex = "6cdf2298ce2a2324b38e536db1cbf5097ca085cd2305c61372f53b7be5cba415"
    private val katAuthUiHex = "8b2d1be0bc3a9e7f9b551910b0642b992f98b2293efcabfc91e47763737bc13b"

    private val calUuid = "686247aa-e4c2-49cf-afa0-6437e41a7374"
    private val server = Url("https://calendar-poc.example")

    private fun katKeys() = RowStoreCrypto.derive("password", katSalt, 100000, katWrapped)

    /** In-memory fake of the row-store server (protocol v4.3 + §9c). */
    private class FakeRowStore(private val authUiHex: String, private val rowKey: javax.crypto.SecretKey) {
        val rows = mutableMapOf<String, Pair<Long, RowStoreCrypto.Envelope>>()   // id -> (ver, env)
        val requestLog = mutableListOf<Pair<HttpMethod, String>>()

        /** When set, POST /rows:batch is answered with a silent drop (v4.2 server). */
        var batchRouteMissing = false

        fun manifestJson(): String {
            val items = rows.keys.sorted().joinToString(",") { id ->
                """{"id":"$id","ver":${rows[id]!!.first}}"""
            }
            return """{"rows":[$items]}"""
        }

        fun envelopeJson(id: String): String {
            val (ver, env) = rows[id]!!
            return """{"id":"$id","ver":$ver,"nonce":"${env.nonceB64}","ct":"${env.ctB64}"}"""
        }

        fun decrypt(id: String): String {
            val (ver, env) = rows[id]!!
            return RowStoreCrypto.decryptRow(rowKey, id, ver, env.nonceB64, env.ctB64)
        }

        val engine = MockEngine { request ->
            val auth = request.headers[HttpHeaders.Authorization]
            if (auth != "Bearer " + authUiHex)
                return@MockEngine respond("", HttpStatusCode.NotFound)          // §4 silent drop

            val path = request.url.encodedPath
            requestLog.add(request.method to path)
            val body = (request.body as? TextContent)?.text

            when {
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
                        if (rows.containsKey(id)) envelopeJson(id)
                        else """{"id":"$id","missing":true}"""
                    }
                    respond("""{"rows":[$items]}""", HttpStatusCode.OK, jsonHeaders())
                }

                request.method == HttpMethod.Get && path.startsWith("/rows/") -> {
                    // decode with decodeURIComponent semantics ('+' stays '+')
                    val id = RowStoreUrls.percentDecode(path.removePrefix("/rows/"))
                    val row = rows[id]
                        ?: return@MockEngine respond("""{"error":"not_found"}""", HttpStatusCode.NotFound, jsonHeaders())
                    respond(envelopeJson(id), HttpStatusCode.OK, jsonHeaders())
                }

                request.method == HttpMethod.Put && path.startsWith("/rows/") -> {
                    val id = RowStoreUrls.percentDecode(path.removePrefix("/rows/"))
                    val json = Json.parseToJsonElement(body!!).jsonObject
                    val ver = json["ver"]!!.jsonPrimitive.content.toLong()
                    val env = RowStoreCrypto.Envelope(
                        ver,
                        json["nonce"]!!.jsonPrimitive.content,
                        json["ct"]!!.jsonPrimitive.content
                    )
                    // §9c conditional arbitration
                    val ifMatch = request.headers[HttpHeaders.IfMatch]
                    val ifNoneMatch = request.headers[HttpHeaders.IfNoneMatch]
                    if (ifMatch != null) {
                        val wanted = Regex("\"([0-9]+)\"").find(ifMatch)!!.groupValues[1].toLong()
                        val current = rows[id]
                        if (current == null)
                            return@MockEngine respond("""{"error":"not_found"}""", HttpStatusCode.NotFound, jsonHeaders())
                        if (current.first != wanted)
                            return@MockEngine respond("", HttpStatusCode.PreconditionFailed)
                    }
                    if (ifNoneMatch != null && ifNoneMatch.trim() == "*" && rows.containsKey(id))
                        return@MockEngine respond("", HttpStatusCode.PreconditionFailed)
                    // §9 RMW law: accept iff ver > stored (or new)
                    val current = rows[id]
                    if (current == null || ver > current.first) {
                        rows[id] = ver to env
                        respond(envelopeJson(id), HttpStatusCode.OK, jsonHeaders())
                    } else {
                        // 200-echo (web-client mode)
                        respond(envelopeJson(id), HttpStatusCode.OK, jsonHeaders())
                    }
                }

                request.method == HttpMethod.Delete && path.startsWith("/rows/") -> {
                    val id = RowStoreUrls.percentDecode(path.removePrefix("/rows/"))
                    rows.remove(id)
                    respond("{}", HttpStatusCode.OK, jsonHeaders())
                }

                else -> respond("", HttpStatusCode.NotFound)                     // unknown route
            }
        }

        private fun jsonHeaders() = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
    }

    private fun collection(fake: FakeRowStore): RowStoreCalDavCollection {
        val client = HttpClient(fake.engine)
        return RowStoreCalDavCollection(
            httpClient = client,
            server = server,
            calUuid = calUuid,
            authUiHex = katAuthUiHex,
            rowKey = SecretKeySpec(hex(katKDataHex), "AES")
        )
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { i ->
        ((Character.digit(s[i * 2], 16) shl 4) + Character.digit(s[i * 2 + 1], 16)).toByte()
    }

    private val ical = """
        BEGIN:VCALENDAR
        VERSION:2.0
        PRODID:-//sh-clock//Calendar PoC//EN
        BEGIN:VEVENT
        UID:test-event-1
        DTSTAMP:20261031T120000Z
        DTSTART:20261102T090000Z
        DTEND:20261102T100000Z
        SUMMARY:Harness test event
        END:VEVENT
        END:VCALENDAR
    """.trimIndent().replace("\n", "\r\n") + "\r\n"

    private fun textContent(s: String) = TextContent(s, ContentType.Text.Plain)

    // ---- crypto KATs (parity with the JS reference) ----

    @Test
    fun `crypto KAT - derive matches the JavaScript reference`() {
        val keys = katKeys()
        assertEquals(katAuthUiHex, keys.authUiHex)
        val kDataHex = keys.kData.encoded.joinToString("") { String.format("%02x", it) }
        assertEquals(katKDataHex, kDataHex)
    }

    @Test
    fun `crypto KAT - row encrypt round-trips with AAD binding`() {
        val keys = katKeys()
        val id = "evt:$calUuid:roundtrip"
        val env = RowStoreCrypto.encryptRow(keys.kData, id, 7, RowStoreCrypto.quoteJsonString(ical))
        val plain = RowStoreCrypto.decryptRow(keys.kData, id, 7, env.nonceB64, env.ctB64)
        assertEquals(ical, RowStoreCrypto.unquoteJsonString(plain))
        // AAD binds the ver: decrypting with a different ver must fail
        assertThrows(Exception::class.java) {
            RowStoreCrypto.decryptRow(keys.kData, id, 8, env.nonceB64, env.ctB64)
        }
        // AAD binds the id
        assertThrows(Exception::class.java) {
            RowStoreCrypto.decryptRow(keys.kData, "evt:$calUuid:other", 7, env.nonceB64, env.ctB64)
        }
    }

    @Test
    fun `crypto KAT - quoteJsonString escapes iCalendar text`() {
        val quoted = RowStoreCrypto.quoteJsonString("a\"b\\c\nd\te")
        assertEquals("\"a\\\"b\\\\c\\nd\\te\"", quoted)
        assertEquals("a\"b\\c\nd\te", RowStoreCrypto.unquoteJsonString(quoted))
    }

    // ---- adapter against the fake server ----

    @Test
    fun `listFilteredMembers lists the calendar's rows with ver ETags`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)
        // two rows on our calendar, one on another
        for ((id, ver) in listOf(
            "evt:$calUuid:a" to 1L,
            "evt:$calUuid:b" to 5L,
            "evt:ffffffff-0000-0000-0000-000000000000:x" to 3L
        )) {
            fake.rows[id] = ver to RowStoreCrypto.encryptRow(
                SecretKeySpec(hex(katKDataHex), "AES"), id, ver, RowStoreCrypto.quoteJsonString(ical)
            )
        }
        val members = collection.listFilteredMembers().toList()
        assertEquals(2, members.size)
        val etags = members.associate { it.fileName to it.eTag }
        assertEquals("1", etags["a"])
        assertEquals("5", etags["b"])
        // hrefs are below the pseudo-collection URL
        assertTrue(members.all { it.href.toString().startsWith("https://calendar-poc.example/clock/$calUuid/") })
    }

    @Test
    fun `createMember PUTs ver 1 with If-None-Match and stores the iCalendar text`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)
        val result = collection.createMember("test-event-1", textContent(ical))
        assertEquals("1", result.eTag)
        // stored row decrypts to the exact iCalendar text (JSON-encoded §6)
        assertEquals(ical, RowStoreCrypto.unquoteJsonString(fake.decrypt("evt:$calUuid:test-event-1")))
        // the request carried If-None-Match: * (§9c)
        assertTrue(fake.requestLog.any { it.first == HttpMethod.Put })
    }

    @Test
    fun `createMember on an existing row throws PreconditionFailedException`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)
        collection.createMember("test-event-1", textContent(ical))
        val ex = assertThrows(PreconditionFailedException::class.java) {
            kotlinx.coroutines.runBlocking {
                collection.createMember("test-event-1", textContent(ical))
            }
        }
        assertNotNull(ex)
    }

    @Test
    fun `updateMember PUTs ver+1 with If-Match and returns the new ETag`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)
        collection.createMember("test-event-1", textContent(ical))
        val newIcal = ical.replace("Harness test event", "Edited summary")
        val result = collection.updateMember("test-event-1", textContent(newIcal), ifETag = "1")
        assertEquals("2", result.eTag)
        assertEquals(newIcal, RowStoreCrypto.unquoteJsonString(fake.decrypt("evt:$calUuid:test-event-1")))
    }

    @Test
    fun `updateMember with a stale ETag throws PreconditionFailedException`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)
        collection.createMember("test-event-1", textContent(ical))
        // simulate a concurrent writer bumping the ver to 5
        fake.rows["evt:$calUuid:test-event-1"] = 5L to RowStoreCrypto.encryptRow(
            SecretKeySpec(hex(katKDataHex), "AES"), "evt:$calUuid:test-event-1", 5,
            RowStoreCrypto.quoteJsonString(ical)
        )
        val ex = assertThrows(PreconditionFailedException::class.java) {
            kotlinx.coroutines.runBlocking {
                collection.updateMember("test-event-1", textContent(ical), ifETag = "1")
            }
        }
        assertNotNull(ex)
    }

    @Test
    fun `multiget downloads and decrypts a batch in ONE request`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)
        collection.createMember("a", textContent(ical))
        collection.createMember("b", textContent(ical.replace("Harness", "Second")))
        val urls = listOf(collection.collectionUrl.resolve("a")!!, collection.collectionUrl.resolve("b")!!)
        val items = collection.multiget(urls, RowStoreCollection.Capabilities()).toList()
        assertEquals(2, items.size)
        assertEquals("1", items[0].eTag)
        assertEquals(ical, items[0].content)
        assertEquals(ical.replace("Harness", "Second"), items[1].content)
        // exactly ONE batch request (§9b)
        val batchRequests = fake.requestLog.count { it.first == HttpMethod.Post && it.second == "/rows:batch" }
        assertEquals(1, batchRequests)
    }

    @Test
    fun `multiget skips missing rows`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)
        collection.createMember("a", textContent(ical))
        val urls = listOf(collection.collectionUrl.resolve("a")!!, collection.collectionUrl.resolve("gone")!!)
        val items = collection.multiget(urls, RowStoreCollection.Capabilities()).toList()
        assertEquals(1, items.size)
        assertEquals("a", collection.fileNameOf(items[0].url))
    }

    @Test
    fun `deleteMember removes the row`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)
        collection.createMember("a", textContent(ical))
        collection.deleteMember("a")
        assertTrue(fake.rows.isEmpty())
    }

    @Test
    fun `queryCapabilities reports no collection sync and the 64 KiB size law`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)
        val caps = collection.queryCapabilities()
        assertEquals(64L * 1024, caps.maxCalResourceSize)
    }

    @Test
    fun `wrong token surfaces as DavException silent drop`() = runTest {
        val fake = FakeRowStore("0000000000000000000000000000000000000000000000000000000000000000", SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)    // uses the REAL token; the fake expects the wrong one
        val ex = assertThrows(DavException::class.java) {
            kotlinx.coroutines.runBlocking { collection.queryCapabilities() }
        }
        assertTrue(ex.message!!.contains("silent drop"))
    }

    @Test
    fun `server error surfaces as DavException`() = runTest {
        val engine = MockEngine { _ ->
            respond("""{"error":"bad_request"}""", HttpStatusCode.BadRequest, headersOf(HttpHeaders.ContentType, "application/json"))
        }
        val collection = RowStoreCalDavCollection(
            HttpClient(engine), server, calUuid, katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES")
        )
        val ex = assertThrows(DavException::class.java) {
            kotlinx.coroutines.runBlocking { collection.queryCapabilities() }
        }
        assertTrue(ex.message!!.contains("row-store error 400"))
    }

    @Test
    fun `multiget chunking - more than 256 urls uses multiple batch requests`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)
        val urls = (1..600).map { collection.collectionUrl.resolve("e$it")!! }
        collection.multiget(urls, RowStoreCollection.Capabilities()).toList()
        assertEquals(3, fake.requestLog.count { it.first == HttpMethod.Post && it.second == "/rows:batch" })
    }

    // ---- percent-encoding parity (audit A1-4 / A2-1) ----

    @Test
    fun `UIDs with '+' and spaces address the SAME row on create and multiget`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)
        // "a b+c" must map to the row id evt:{cal}:a b+c — the '+' must survive
        collection.createMember("a b+c", textContent(ical))
        assertTrue(fake.rows.containsKey("evt:$calUuid:a b+c"))

        // listing → multiget round-trip through href percent-encoding
        val members = collection.listFilteredMembers().toList()
        assertEquals(1, members.size)
        assertEquals("a b+c", collection.fileNameOf(members[0].href))
        val items = collection.multiget(listOf(members[0].href), RowStoreCollection.Capabilities()).toList()
        assertEquals(1, items.size)
        assertEquals(ical, items[0].content)
        assertEquals("a b+c", collection.fileNameOf(items[0].url))
        // a distinct UID that differs only by +/-/space must be a DIFFERENT row
        collection.createMember("a b-c", textContent(ical))
        assertTrue(fake.rows.containsKey("evt:$calUuid:a b-c"))
        assertEquals(2, fake.rows.size)
    }

    // ---- v4.2 fallback (audit A1-3 / A3-3) ----

    @Test
    fun `multiget falls back to per-row GETs on a v4.2 server (no /rows:batch)`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        fake.batchRouteMissing = true
        val collection = collection(fake)
        collection.createMember("a", textContent(ical))
        collection.createMember("b", textContent(ical.replace("Harness", "Second")))
        val urls = listOf(collection.collectionUrl.resolve("a")!!, collection.collectionUrl.resolve("b")!!)
        val items = collection.multiget(urls, RowStoreCollection.Capabilities()).toList()
        assertEquals(2, items.size)
        assertEquals(ical, items[0].content)
        // one batch attempt + two per-row GETs
        assertEquals(1, fake.requestLog.count { it.first == HttpMethod.Post && it.second == "/rows:batch" })
        assertEquals(2, fake.requestLog.count { it.first == HttpMethod.Get && it.second.startsWith("/rows/") })
    }

    // ---- corrupt-row isolation (audit A2-7) ----

    @Test
    fun `multiget skips an undecryptable row instead of aborting the sync`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)
        collection.createMember("good", textContent(ical))
        // a foreign-key-encrypted row: listing shows it, decryption fails
        val foreignKey = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES")
        fake.rows["evt:$calUuid:corrupt"] = 1L to RowStoreCrypto.encryptRow(
            foreignKey, "evt:$calUuid:corrupt", 1, RowStoreCrypto.quoteJsonString(ical)
        )
        val members = collection.listFilteredMembers().toList()
        assertEquals(2, members.size)
        val items = collection.multiget(members.map { it.href }, RowStoreCollection.Capabilities()).toList()
        // only the good row is emitted; the corrupt one is skipped, not thrown
        assertEquals(1, items.size)
        assertEquals("good", collection.fileNameOf(items[0].url))
    }

    // ---- member validation (audit A2-6 / A2-9) ----

    @Test
    fun `createMember rejects UIDs that violate the row id grammar`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)
        assertThrows(DavException::class.java) {
            kotlinx.coroutines.runBlocking { collection.createMember("with:colon", textContent(ical)) }
        }
        assertThrows(DavException::class.java) {
            kotlinx.coroutines.runBlocking { collection.createMember("", textContent(ical)) }
        }
        assertThrows(DavException::class.java) {
            kotlinx.coroutines.runBlocking { collection.createMember("x".repeat(201), textContent(ical)) }
        }
        assertTrue(fake.rows.isEmpty())
    }

    @Test
    fun `createMember rejects payloads over the 64 KiB row cap`() = runTest {
        val fake = FakeRowStore(katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES"))
        val collection = collection(fake)
        val huge = "X".repeat(64 * 1024 - 15)     // payload + 16 B tag = 65537 > 64 KiB
        assertThrows(DavException::class.java) {
            kotlinx.coroutines.runBlocking { collection.createMember("big", textContent(huge)) }
        }
        assertTrue(fake.rows.isEmpty())
    }

    // ---- error classification (audit A1-7) ----

    @Test
    fun `a foreign 404 page is NOT classified as NotFound`() = runTest {
        val engine = MockEngine { _ ->
            respond("<html>404 page not found</html>", HttpStatusCode.NotFound,
                headersOf(HttpHeaders.ContentType, "text/html"))
        }
        val collection = RowStoreCalDavCollection(
            HttpClient(engine), server, calUuid, katAuthUiHex, SecretKeySpec(hex(katKDataHex), "AES")
        )
        val ex = assertThrows(DavException::class.java) {
            kotlinx.coroutines.runBlocking { collection.deleteMember("gone") }
        }
        // generic DavException, NOT NotFoundException (which callers use for
        // "row missing" decisions)
        assertFalse(ex is at.bitfire.dav4jvm.ktor.exception.NotFoundException)
        assertTrue(ex.message!!.contains("row-store error 404"))
    }
}
