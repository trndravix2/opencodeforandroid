package com.dravix.ai

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.os.Build
import android.system.Os
import android.util.Log
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedWriter
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.net.URLEncoder
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Dravix runtime: extracts the bundled Alpine rootfs + OpenCode binary, starts
 * PRoot, and keeps the OpenCode HTTP server alive. Everything is bundled inside
 * the APK - no network download is required for setup.
 */
object DravixEngine {

    const val TAG = "DravixEngine"
    const val PORT = 4096
    private const val HOST = "127.0.0.1"
    private const val ROOTFS_MARKER = ".dravix-rootfs-v3"
    private const val DEBUG_STRACE = false

    private var appContext: Context? = null
    private val stateLock = Any()

    lateinit var rootfsDir: File
        private set
    lateinit var binDir: File
        private set
    lateinit var filesDir: File
        private set

    private var prootBin: File? = null
    private var opencodeBin: File? = null
    private var loaderBin: File? = null
    private var shimPath: File? = null

    private var shellProcess: Process? = null
    private var shellWriter: BufferedWriter? = null

    @Volatile
    private var serverProcess: Process? = null

    @Volatile
    var shellReady: Boolean = false
        private set

    @Volatile
    var serverReady: Boolean = false
        private set

    @Volatile
    var busy: Boolean = false
        private set

    @Volatile
    var version: String = ""
        private set

    @Volatile
    var lastStatus: String = "STARTING"
        private set

    @Volatile
    var serverPassword: String = ""
        private set

    @Volatile
    var serverUiUrl: String = "http://$HOST:$PORT"
        private set

    private var starting = false
    @Volatile
    private var serverStarting = false

    /** True while this engine instance should keep the server alive. */
    @Volatile
    private var superviseServer = false

    @Volatile
    private var serverSupervisor: Thread? = null

    @Volatile
    private var supervisorGeneration = 0

    @Volatile
    private var serverSupervisorGeneration = -1

    /** Last session opened in the UI, reused after a server crash/restart. */
    @Volatile
    private var lastSessionId: String? = null

    private val listeners = CopyOnWriteArrayList<(String) -> Unit>()
    private val history = ArrayDeque<String>()
    private val historyLock = Any()

    // ---------------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------------

    fun init(context: Context) {
        synchronized(stateLock) {
            if (appContext != null) return
            val ctx = context.applicationContext
            appContext = ctx
            filesDir = ctx.filesDir
            rootfsDir = File(filesDir, "rootfs")
            binDir = File(filesDir, "bin")
        }
    }

    fun addListener(listener: (String) -> Unit) {
        if (!listeners.contains(listener)) listeners.add(listener)
    }

    fun removeListener(listener: (String) -> Unit) {
        listeners.remove(listener)
    }

    fun historySnapshot(): List<String> = synchronized(historyLock) { history.toList() }

    fun statusJson(): String {
        val obj = JSONObject()
        obj.put("shell", shellReady)
        obj.put("server", serverReady)
        obj.put("status", lastStatus)
        obj.put("version", version)
        obj.put("port", PORT)
        obj.put("url", serverUiUrl)
        obj.put("password", serverPassword)
        return obj.toString()
    }

    fun historyJson(): String {
        val arr = JSONArray()
        synchronized(historyLock) { history.forEach { arr.put(it) } }
        return arr.toString()
    }

    /** Idempotent: extracts, starts the shell and the server if they are missing. */
    fun ensureStarted() {
        synchronized(stateLock) {
            if (starting || serverStarting) return
            starting = true
        }
        thread(isDaemon = true, name = "dravix-start") {
            try {
                startAll()
            } catch (t: Throwable) {
                Log.e(TAG, "startAll failed", t)
                log("Engine error: ${t.message}")
                setStatus("ERROR")
            } finally {
                synchronized(stateLock) { starting = false }
            }
        }
    }

    /** Full restart after a failure (asset error, dead shell, etc.). */
    fun retry() {
        synchronized(stateLock) {
            if (starting || busy || serverStarting) return
            starting = true
        }
        thread(isDaemon = true, name = "dravix-retry") {
            try {
                stopEverything()
                lastStatus = "STARTING"
                startAll()
            } catch (t: Throwable) {
                Log.e(TAG, "retry failed", t)
                log("Retry failed: ${t.message}")
                setStatus("ERROR")
            } finally {
                synchronized(stateLock) { starting = false }
            }
        }
    }

    fun restartServer() {
        synchronized(stateLock) {
            if (serverStarting || busy || starting) return
            serverStarting = true
        }
        thread(isDaemon = true, name = "dravix-restart-server") {
            try {
                setStatus("RESTARTING")
                stopServer()
                startServer()
                superviseServer = true
                ensureServerSupervisor()
            } catch (t: Throwable) {
                Log.e(TAG, "restartServer failed", t)
                log("Server restart failed: ${t.message}")
                setStatus("ERROR")
            } finally {
                serverStarting = false
            }
        }
    }

    fun verifyEnvironment() {
        thread(isDaemon = true, name = "dravix-verify") {
            try {
                if (!rootfsReady()) {
                    log("Rootfs not extracted yet. Running setup...")
                    ensureStarted()
                    return@thread
                }
                val output = runOneShot(prootArgs(listOf("/bin/sh", "-c", "opencode --version; echo ---; uname -a; echo ---; id")), 60_000)
                output.lineSequence().filter { it.isNotBlank() }.forEach { log(it) }
                val parsed = Regex("""v?\d+\.\d+\.\d+""").find(output)?.value
                if (parsed != null) version = parsed
            } catch (t: Throwable) {
                log("Verify failed: ${t.message}")
            }
        }
    }

    fun writeCommand(command: String) {
        val process = shellProcess
        val writer = shellWriter
        if (process == null || writer == null || !isAlive(process)) {
            log("Shell is not running. Restarting engine...")
            ensureStarted()
            return
        }
        logH("$ $command")
        try {
            synchronized(stateLock) {
                writer.write(command)
                writer.write("\n")
                writer.flush()
            }
        } catch (t: Throwable) {
            log("Command failed: ${t.message}")
        }
    }

    fun openUi(sessionId: String? = null, intentSink: (String) -> Unit) {
        thread(isDaemon = true, name = "dravix-ui") {
            if (!serverReady) {
                intentSink("")
                return@thread
            }
            // The password is printed a moment after the port opens.
            val deadline = System.currentTimeMillis() + 10_000
            while (serverPassword.isBlank() && System.currentTimeMillis() < deadline) {
                Thread.sleep(50)
            }
            if (serverPassword.isBlank()) {
                intentSink("")
                return@thread
            }
            val url = buildUiUrl(sessionId)
            serverUiUrl = url
            intentSink(url)
        }
    }

    /**
     * The bundled web UI accepts ?auth_token=<base64("opencode:<password>")>
     * and connects to this origin directly, skipping the pairing screen.
     * A blank session is created through the official API so the app opens
     * straight into a usable prompt instead of the empty project browser.
     *
     * On a server restart the previously opened session is reused, so the
     * conversation survives a crash.
     */
    private fun buildUiUrl(sessionId: String? = null): String {
        if (serverPassword.isBlank()) return "http://$HOST:$PORT"
        val token = android.util.Base64.encodeToString(
            "opencode:$serverPassword".toByteArray(Charsets.UTF_8),
            android.util.Base64.NO_WRAP
        )
        val auth = "auth_token=" + android.net.Uri.encode(token)
        val requested = sessionId?.takeIf { it.isNotBlank() } ?: lastSessionId
        val exists = requested?.let { sessionExists(it) }
        val id = when (exists) {
            true -> requested
            false -> createSession()
            null -> requested ?: createSession()
        }
        if (id != null) {
            lastSessionId = id
            return "http://$HOST:$PORT/server/${serverKey()}/session/$id?$auth"
        }
        return "http://$HOST:$PORT/?$auth"
    }

    private fun serverKey(): String = android.util.Base64.encodeToString(
        "http://$HOST:$PORT".toByteArray(Charsets.UTF_8),
        android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING
    )

    private fun basicAuth(): String = android.util.Base64.encodeToString(
        "opencode:$serverPassword".toByteArray(Charsets.UTF_8),
        android.util.Base64.NO_WRAP
    )

    /** true = exists, false = missing, null = could not determine. */
    private fun sessionExists(id: String): Boolean? {
        if (id.isBlank() || serverPassword.isBlank()) return false
        val encoded = try {
            URLEncoder.encode(id, "UTF-8")
        } catch (_: Throwable) {
            id
        }
        repeat(3) { attempt ->
            try {
                val conn = URL("http://$HOST:$PORT/api/session/$encoded")
                    .openConnection() as HttpURLConnection
                conn.requestMethod = "GET"
                conn.connectTimeout = 3_000
                conn.readTimeout = 5_000
                conn.setRequestProperty("Authorization", "Basic ${basicAuth()}")
                val code = conn.responseCode
                try {
                    conn.inputStream?.close()
                } catch (_: Throwable) {
                }
                try {
                    conn.errorStream?.close()
                } catch (_: Throwable) {
                }
                if (code in 200..299) return true
                if (code == 404) return false
                Log.w(TAG, "Session probe HTTP $code (attempt ${attempt + 1})")
            } catch (t: Throwable) {
                Log.w(TAG, "Session probe failed: ${t.message} (attempt ${attempt + 1})")
            }
            Thread.sleep(300)
        }
        return null
    }

    private fun createSession(): String? {
        val home = File(filesDir, "home").apply { mkdirs() }
        val body = JSONObject()
            .put("title", "New session")
            .put("location", JSONObject().put("directory", home.absolutePath))
            .toString()
        repeat(3) { attempt ->
            try {
                val conn = URL("http://$HOST:$PORT/api/session")
                    .openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.connectTimeout = 5_000
                conn.readTimeout = 15_000
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("Authorization", "Basic ${basicAuth()}")
                conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
                val code = conn.responseCode
                if (code !in 200..299) {
                    log("Session create failed: HTTP $code (attempt ${attempt + 1})")
                } else {
                    val text = conn.inputStream.bufferedReader().use { it.readText() }
                    val id = JSONObject(text).optJSONObject("data")?.optString("id")
                    if (!id.isNullOrBlank()) return id
                }
            } catch (t: Throwable) {
                Log.w(TAG, "Session create failed: ${t.message}")
            }
            Thread.sleep(300)
        }
        return null
    }

    fun stopEverything() {
        superviseServer = false
        supervisorGeneration++
        val supervisor = serverSupervisor
        serverSupervisor = null
        if (supervisor != null && supervisor != Thread.currentThread()) {
            try {
                supervisor.join(2_500)
            } catch (_: Throwable) {
            }
        }
        // An in-flight auto-restart must unwind before a full start begins.
        val startDeadline = System.currentTimeMillis() + 4_000
        while (serverStarting && System.currentTimeMillis() < startDeadline) {
            try {
                Thread.sleep(100)
            } catch (_: InterruptedException) {
                break
            }
        }
        stopServer()
        try {
            shellWriter?.close()
        } catch (_: Throwable) {
        }
        shellWriter = null
        shellProcess?.destroy()
        shellProcess = null
        shellReady = false
    }

    // ---------------------------------------------------------------------
    // Startup pipeline
    // ---------------------------------------------------------------------

    private fun startAll() {
        val ctx = appContext ?: return
        // Defense in depth: the engine refuses to start without a live lease,
        // even if every UI-side check is patched out.
        if (!GateStore.isAllowedToEnter(ctx)) {
            log("Access lease missing or expired. Engine start blocked.")
            setStatus("ERROR")
            return
        }
        busy = true
        try {
            setStatus("STARTING")
            log("Dravix engine starting...")
            log("ABI: ${abiTag()} (${Build.SUPPORTED_ABIS.joinToString()})")

            filesDir.mkdirs()
            File(filesDir, "tmp").mkdirs()

            ensureRootfs()
            ensureOpencode()
            ensureShim()
            resolveRuntime()
            configureEnvironment()
            verifyOpencodeBinary()

            superviseServer = true
            try {
                startServer()
            } catch (t: Throwable) {
                superviseServer = false
                throw t
            }
            if (superviseServer) ensureServerSupervisor()

            log("Dravix is ready. OpenCode ${version.ifBlank { "" }} on http://$HOST:$PORT".trim())
        } finally {
            busy = false
        }
    }

    private fun findProot() {
        val nativeDir = appContext!!.applicationInfo.nativeLibraryDir
        val candidate = File(nativeDir, "libproot.so")
        if (!candidate.exists() || candidate.length() < 100_000L) {
            throw IllegalStateException("PRoot binary missing at ${candidate.absolutePath}")
        }
        prootBin = candidate
        log("PRoot: ${candidate.absolutePath} (${candidate.length() / 1024} KB)")
    }

    private fun ensureRootfs() {
        if (rootfsReady()) {
            log("Rootfs verified: ${rootfsDir.absolutePath}")
            return
        }
        val assetName = "rootfs-${abiTag()}.bin"
        log("Extracting bundled Linux rootfs ($assetName)...")
        val startedAt = System.currentTimeMillis()
        rootfsDir.deleteRecursively()
        rootfsDir.mkdirs()
        var count = 0
        var bytes = 0L

        AssetVault.open(appContext!!, assetName).use { raw ->
            val buffered = BufferedInputStream(raw, 64 * 1024)
            buffered.mark(2)
            val magic = ByteArray(2)
            val n = buffered.read(magic)
            buffered.reset()
            val gzipped = n == 2 && magic[0] == 0x1f.toByte() && (magic[1].toInt() and 0xff) == 0x8b
            val source: InputStream = if (gzipped) GzipCompressorInputStream(buffered) else buffered
            TarArchiveInputStream(source).use { tar ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val entry = tar.nextEntry ?: break
                    var name = entry.name.replace('\\', '/')
                    while (name.startsWith("./")) name = name.substring(2)
                    name = name.trimStart('/')
                    if (name.isEmpty() || name == ".") continue
                    val out = File(rootfsDir, name)
                    if (!out.canonicalPath.startsWith(rootfsDir.canonicalPath + File.separator)) continue
                    when {
                        entry.isDirectory -> out.mkdirs()
                        entry.isSymbolicLink -> {
                            out.parentFile?.mkdirs()
                            out.delete()
                            try {
                                Os.symlink(entry.linkName, out.absolutePath)
                            } catch (t: Throwable) {
                                Log.w(TAG, "symlink failed: $name -> ${entry.linkName}: ${t.message}")
                            }
                        }
                        entry.isLink -> {
                            out.parentFile?.mkdirs()
                            out.delete()
                            val target = File(rootfsDir, entry.linkName.trimStart('/', '.', '/'))
                            try {
                                Os.link(target.absolutePath, out.absolutePath)
                            } catch (t: Throwable) {
                                Log.w(TAG, "hardlink failed: $name -> ${entry.linkName}: ${t.message}")
                            }
                        }
                        else -> {
                            out.parentFile?.mkdirs()
                            FileOutputStream(out).use { fos ->
                                var len: Int
                                while (true) {
                                    len = tar.read(buffer)
                                    if (len <= 0) break
                                    fos.write(buffer, 0, len)
                                    bytes += len
                                }
                            }
                            try {
                                Os.chmod(out.absolutePath, entry.mode and 0xFFF)
                            } catch (_: Throwable) {
                            }
                        }
                    }
                    count++
                    if (count % 400 == 0) log("Extracting... $count files")
                }
            }
        }

        // Alpine always needs a working /bin/sh (absolute symlink: File.exists()
        // follows it against the host root and would incorrectly return false).
        val busybox = File(rootfsDir, "bin/busybox")
        val sh = File(rootfsDir, "bin/sh")
        if (busybox.exists()) {
            busybox.setExecutable(true, false)
            if (!existsOrSymlink(sh)) {
                sh.parentFile?.mkdirs()
                try {
                    Os.symlink("/bin/busybox", sh.absolutePath)
                } catch (_: Throwable) {
                    busybox.copyTo(sh, overwrite = true)
                }
            }
        }
        if (!existsOrSymlink(sh)) throw IllegalStateException("/bin/sh missing after extraction")

        File(rootfsDir, ROOTFS_MARKER).writeText("3\n")
        AssetVault.writeWatermark(appContext!!, File(rootfsDir, "etc/dravix-watermark"))
        val seconds = (System.currentTimeMillis() - startedAt) / 1000
        log("Rootfs ready: $count files, ${bytes / (1024 * 1024)} MB in ${seconds}s")
    }

    private fun rootfsReady(): Boolean {
        val sh = File(rootfsDir, "bin/sh")
        val busybox = File(rootfsDir, "bin/busybox")
        val git = File(rootfsDir, "usr/bin/git")
        val marker = File(rootfsDir, ROOTFS_MARKER)
        return marker.exists() && existsOrSymlink(sh) && busybox.exists() &&
            busybox.length() > 100_000L && existsOrSymlink(git)
    }

    private fun existsOrSymlink(file: File): Boolean {
        if (file.exists()) return true
        return try {
            Os.readlink(file.absolutePath)
            true
        } catch (_: Throwable) {
            false
        }
    }

    private fun ensureOpencode() {
        val target = File(binDir, "opencode")
        val watermark = File(binDir, ".dravix-watermark")
        val minimum = 100L * 1024 * 1024
        if (target.exists() && target.length() > minimum && watermark.exists()) {
            target.setExecutable(true, false)
            opencodeBin = target
            log("OpenCode binary verified (${target.length() / (1024 * 1024)} MB)")
            return
        }
        val assetName = "opencode-${abiTag()}"
        binDir.mkdirs()
        log("Extracting bundled OpenCode binary ($assetName)...")
        val startedAt = System.currentTimeMillis()
        target.delete()
        var total = 0L
        var lastLog = 0L
        AssetVault.open(appContext!!, assetName).use { input ->
            FileOutputStream(target).use { fos ->
                val buffer = ByteArray(256 * 1024)
                while (true) {
                    val len = input.read(buffer)
                    if (len <= 0) break
                    fos.write(buffer, 0, len)
                    total += len
                    if (total - lastLog > 40L * 1024 * 1024) {
                        lastLog = total
                        log("Extracting OpenCode... ${total / (1024 * 1024)} MB")
                    }
                }
            }
        }
        if (total < minimum) {
            target.delete()
            throw IllegalStateException("Encrypted runtime failed to decrypt ($total bytes)")
        }
        target.setExecutable(true, false)
        AssetVault.writeWatermark(appContext!!, File(binDir, ".dravix-watermark"))
        opencodeBin = target
        val seconds = (System.currentTimeMillis() - startedAt) / 1000
        log("OpenCode binary ready: ${total / (1024 * 1024)} MB in ${seconds}s")
    }

    private fun configureEnvironment() {
        val etc = File(rootfsDir, "etc").apply { mkdirs() }
        val home = File(filesDir, "home").apply { mkdirs() }
        val tmp = File(filesDir, "tmp").apply { mkdirs() }
        val dns = detectDnsServers()
        val resolv = dns.joinToString("\n") { "nameserver $it" } + "\n"
        File(etc, "resolv.conf").writeText(resolv)
        File(home, "resolv.conf").writeText(resolv)
        File(home, "hosts").writeText("127.0.0.1 localhost\n::1 localhost\n")

        val configDir = File(home, ".config/opencode").apply { mkdirs() }
        val config = File(configDir, "opencode.json")
        if (!config.exists()) {
            config.writeText(
                """
                {
                  "${'$'}schema": "https://opencode.ai/config.json",
                  "theme": "opencode"
                }
                """.trimIndent()
            )
        }
        File(home, ".local/share/opencode").mkdirs()
        File(home, ".cache").mkdirs()
        tmp.mkdirs()
        patchResolverPaths()
        log("DNS: ${dns.joinToString()}")
    }

    private fun ensureShim() {
        val target = File(filesDir, "lib/libopencode-crhandler.so")
        val assetName = "libopencode-crhandler-${abiTag()}.so"
        target.parentFile?.mkdirs()
        try {
            // Always refresh: the shim is tiny and this guarantees a newly
            // installed APK never keeps a stale copy from a previous build.
            appContext!!.assets.open(assetName).use { input ->
                java.io.FileOutputStream(target).use { output -> input.copyTo(output) }
            }
            target.setReadable(true, false)
            shimPath = target
            log("Close-range shim ready (${target.length()} bytes)")
        } catch (t: Throwable) {
            throw IllegalStateException("close-range shim missing: ${t.message}", t)
        }
    }

    private fun resolveRuntime() {
        val loader = File(rootfsDir, "lib/ld-musl-${abiTag()}.so.1")
        if (!loader.exists()) throw IllegalStateException("musl loader missing: ${loader.absolutePath}")
        val bin = File(binDir, "opencode")
        if (!bin.exists() || bin.length() < 50L * 1024 * 1024) {
            throw IllegalStateException("opencode binary missing: ${bin.absolutePath}")
        }
        loaderBin = loader
        opencodeBin = bin
        log("Runtime: ${loader.name} + opencode ${bin.length() / (1024 * 1024)} MB")
    }

    private fun opencodeArgs(tail: List<String>): List<String> {
        val loader = loaderBin ?: throw IllegalStateException("musl loader missing")
        val bin = opencodeBin ?: throw IllegalStateException("opencode binary missing")
        val libPath = "${File(rootfsDir, "usr/lib").absolutePath}:${File(rootfsDir, "lib").absolutePath}"
        return listOf(loader.absolutePath, "--library-path", libPath, bin.absolutePath) + tail
    }

    private fun patchResolverPaths() {
        val loader = loaderBin ?: return
        if (!loader.exists()) return
        val pairs = listOf("/etc/resolv.conf" to "resolv.conf", "/etc/hosts" to "hosts")
        try {
            java.io.RandomAccessFile(loader, "rw").use { raf ->
                if (raf.length() > 4L * 1024 * 1024) return
                val data = ByteArray(raf.length().toInt())
                raf.seek(0)
                raf.readFully(data)
                var changed = false
                for ((from, to) in pairs) {
                    val fromBytes = from.toByteArray(Charsets.US_ASCII)
                    val toBytes = to.toByteArray(Charsets.US_ASCII)
                    var start = 0
                    while (true) {
                        val idx = indexOfBytes(data, fromBytes, start)
                        if (idx < 0) break
                        System.arraycopy(toBytes, 0, data, idx, toBytes.size)
                        for (i in toBytes.size until fromBytes.size) data[idx + i] = 0
                        changed = true
                        start = idx + fromBytes.size
                    }
                }
                if (changed) {
                    raf.seek(0)
                    raf.write(data)
                    log("Patched loader resolver paths")
                }
            }
        } catch (t: Throwable) {
            log("Resolver path patch failed: ${t.message}")
        }
    }

    private fun indexOfBytes(data: ByteArray, pattern: ByteArray, from: Int): Int {
        if (pattern.isEmpty() || data.size < pattern.size) return -1
        val last = data.size - pattern.size
        if (from > last) return -1
        outer@ for (i in from..last) {
            for (j in pattern.indices) {
                if (data[i + j] != pattern[j]) continue@outer
            }
            return i
        }
        return -1
    }

    private fun detectDnsServers(): List<String> {
        val servers = mutableListOf<String>()
        try {
            val cm = appContext!!.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork
            val lp = cm.getLinkProperties(network)
            lp?.dnsServers?.forEach { addr ->
                val host = addr.hostAddress
                if (!host.isNullOrBlank()) servers.add(host)
            }
        } catch (t: Throwable) {
            Log.w(TAG, "DNS detection failed: ${t.message}")
        }
        servers.add("1.1.1.1")
        servers.add("8.8.8.8")
        return servers.distinct().take(4)
    }

    private fun startShell() {
        val existing = shellProcess
        if (existing != null && isAlive(existing) && shellReady) {
            log("Shell already running")
            return
        }
        stopShell()

        val baseArgs = prootArgs(listOf("/bin/sh"))
        val strace = File("/system/bin/strace")
        val straceFile = File(filesDir, "proot_trace.txt")
        val command = if (DEBUG_STRACE && strace.exists()) {
            listOf(strace.absolutePath, "-s", "120", "-o", "/dev/stderr") + baseArgs
        } else {
            baseArgs
        }
        val pb = ProcessBuilder(command)
        applyEnvironment(pb)
        pb.redirectErrorStream(true)
        log("Shell command: ${pb.command().joinToString(" ")}")
        val process = pb.start()
        shellProcess = process
        shellWriter = BufferedWriter(OutputStreamWriter(process.outputStream, Charsets.UTF_8))

        val readyLatch = CountDownLatch(1)
        thread(isDaemon = true, name = "dravix-shell-reader") {
            try {
                process.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                    while (true) {
                        val line = reader.readLine() ?: break
                        if (line.contains("__DRAVIX_READY__")) {
                            if (readyLatch.count > 0) readyLatch.countDown()
                            continue
                        }
                        log("shell: $line")
                    }
                }
            } catch (t: Throwable) {
                Log.w(TAG, "shell reader: ${t.message}")
            }
            val code = try {
                process.exitValue()
            } catch (_: Throwable) {
                -1
            }
            val wasReady = shellReady
            shellReady = false
            if (wasReady) {
                log("Shell exited (code=$code). Restarting on next command.")
                setStatus("SHELL DEAD")
            } else {
                log("Shell process ended before ready (code=$code)")
            }
        }

        // Send the readiness probe immediately - the shell reads it from the pipe.
        try {
            synchronized(stateLock) {
                shellWriter?.write("echo __DRAVIX_READY__\n")
                shellWriter?.flush()
            }
        } catch (t: Throwable) {
            log("Could not write readiness probe: ${t.message}")
        }

        val deadline = System.currentTimeMillis() + 20_000
        while (System.currentTimeMillis() < deadline) {
            if (readyLatch.count == 0L) break
            if (!isAlive(process)) break
            Thread.sleep(100)
        }
        if (readyLatch.count > 0L) {
            val code = try {
                process.exitValue().toString()
            } catch (_: Throwable) {
                "still running"
            }
            throw IllegalStateException("Shell did not become ready (exit=$code). See shell output above.")
        }
        shellReady = true
        setStatus("SHELL READY")
        log("Linux shell is ready (PRoot, Alpine ${readAlpineVersion()})")
    }

    private fun readAlpineVersion(): String {
        return try {
            File(rootfsDir, "etc/alpine-release").readText().trim().ifBlank { "unknown" }
        } catch (_: Throwable) {
            "unknown"
        }
    }

    private fun stopShell() {
        try {
            shellWriter?.close()
        } catch (_: Throwable) {
        }
        shellWriter = null
        shellProcess?.destroy()
        shellProcess = null
        shellReady = false
    }

    private fun verifyOpencodeBinary() {
        log("Verifying OpenCode binary...")
        val output = runOneShot(opencodeArgs(listOf("--version")), 60_000)
        log("opencode --version output: ${output.trim().replace("\n", " | ").take(300)}")
        val lines = output.lineSequence().map { it.trim() }.filter { it.isNotBlank() }.toList()
        val line = lines.lastOrNull { it.contains("opencode", ignoreCase = true) } ?: lines.lastOrNull()
        if (line.isNullOrBlank()) {
            throw IllegalStateException("opencode --version returned nothing")
        }
        if (line.contains("Error", ignoreCase = true) || line.contains("not found", ignoreCase = true)) {
            throw IllegalStateException("opencode failed: $line")
        }
        version = line.substringAfterLast(" ").trim()
        log("OpenCode: $line")
    }

    private fun startServer() {
        if (isPortOpen()) {
            if (serverPassword.isBlank()) {
                throw IllegalStateException("Port $PORT is already in use but no server password is known")
            }
            serverReady = true
            setStatus("ONLINE")
            log("OpenCode server already listening on $HOST:$PORT")
            return
        }

        // A freshly started process prints a fresh password. Never reuse the old one.
        serverPassword = ""
        serverUiUrl = "http://$HOST:$PORT"
        log("Starting OpenCode server on $HOST:$PORT ...")
        val pb = ProcessBuilder(
            opencodeArgs(listOf("serve", "--port", "$PORT", "--hostname", HOST))
        )
        applyEnvironment(pb)
        pb.redirectErrorStream(true)
        val process = pb.start()
        serverProcess = process

        thread(isDaemon = true, name = "dravix-server-reader") {
            try {
                process.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                    while (true) {
                        val line = reader.readLine() ?: break
                        val pw = Regex("""server password\s+(\S+)""").find(line)
                        if (pw != null) {
                            synchronized(stateLock) {
                                if (serverProcess === process) {
                                    serverPassword = pw.groupValues[1]
                                    log("Server password: $serverPassword")
                                }
                            }
                        }
                        log("server: $line")
                    }
                }
            } catch (_: Throwable) {
            }
            synchronized(stateLock) {
                if (serverProcess === process) {
                    serverReady = false
                    serverPassword = ""
                }
            }
            if (lastStatus != "ERROR") log("OpenCode server output closed")
        }

        // Defines the process as dead even if the reader is blocked. The
        // supervisor owns restarting; this thread only updates state/logs.
        thread(isDaemon = true, name = "dravix-server-exit") {
            val code = try {
                process.waitFor()
            } catch (_: Throwable) {
                -1
            }
            var wasCurrent = false
            synchronized(stateLock) {
                if (serverProcess === process) {
                    wasCurrent = true
                    serverProcess = null
                    serverReady = false
                    serverPassword = ""
                    serverUiUrl = "http://$HOST:$PORT"
                }
            }
            if (wasCurrent) {
                Log.w(TAG, "OpenCode server exited (code=$code)")
                log("OpenCode server exited (code=$code)")
            }
        }

        var up = false
        val deadline = System.currentTimeMillis() + 90_000
        while (System.currentTimeMillis() < deadline) {
            if (!isAlive(process)) break
            if (isPortOpen()) {
                up = true
                break
            }
            Thread.sleep(500)
        }
        if (!up) {
            synchronized(stateLock) {
                if (serverProcess === process) {
                    serverProcess = null
                    serverReady = false
                    serverPassword = ""
                }
            }
            try {
                process.destroyForcibly()
            } catch (_: Throwable) {
            }
            throw IllegalStateException("OpenCode server did not open port $PORT")
        }

        // If the process died immediately after opening the port, do not
        // publish a false ONLINE. The supervisor will restart it.
        synchronized(stateLock) {
            if (serverProcess !== process || !isAlive(process)) {
                throw IllegalStateException("OpenCode server exited immediately")
            }
            serverReady = true
        }
        setStatus("ONLINE")
        log("OpenCode server is ready: http://$HOST:$PORT")
    }

    /**
     * Keeps the OpenCode process alive. It intentionally does not watch the
     * reader thread: process exit is the authoritative signal. On a crash the
     * password changes, so MainActivity is told to reload the same session
     * with a fresh auth token.
     */
    private fun ensureServerSupervisor() {
        if (!superviseServer) return
        synchronized(stateLock) {
            val existing = serverSupervisor
            if (existing != null && existing.isAlive && serverSupervisorGeneration == supervisorGeneration) return
            val generation = supervisorGeneration
            serverSupervisorGeneration = generation
            serverSupervisor = thread(isDaemon = true, name = "dravix-server-supervisor") {
                var failures = 0
                Log.i(TAG, "Server supervisor started")
                while (superviseServer && supervisorGeneration == generation) {
                    try {
                        Thread.sleep(1_500)
                    } catch (_: InterruptedException) {
                        break
                    }
                    if (!superviseServer || supervisorGeneration != generation) break

                    var start = false
                    synchronized(stateLock) {
                        if (!starting && !busy && !serverStarting) {
                            val p = serverProcess
                            if (p == null || !isAlive(p)) {
                                serverStarting = true
                                start = true
                            }
                        }
                    }
                    if (!start) continue

                    try {
                        setStatus("RESTARTING")
                        if (isPortOpen()) {
                            throw IllegalStateException("Port $PORT is still in use by an unknown process")
                        }
                        log("OpenCode server is down; restarting...")
                        startServer()
                        if (!superviseServer) {
                            stopServer()
                            break
                        }
                        failures = 0
                    } catch (t: Throwable) {
                        failures++
                        Log.w(TAG, "Server auto-restart failed (attempt $failures): ${t.message}")
                        log("Server auto-restart failed (attempt $failures): ${t.message}")
                        synchronized(stateLock) {
                            val p = serverProcess
                            if (p != null && !isAlive(p)) {
                                serverProcess = null
                                serverReady = false
                                serverPassword = ""
                            }
                        }
                        if (failures >= 3) setStatus("ERROR")
                        try {
                            Thread.sleep((1_000L * failures).coerceAtMost(10_000L))
                        } catch (_: InterruptedException) {
                            break
                        }
                    } finally {
                        serverStarting = false
                    }
                }
                Log.i(TAG, "Server supervisor stopped")
            }
        }
    }

    private fun stopServer() {
        serverReady = false
        val process = serverProcess
        serverProcess = null
        serverPassword = ""
        serverUiUrl = "http://$HOST:$PORT"
        try {
            process?.destroy()
        } catch (_: Throwable) {
        }
        if (process != null) {
            val deadline = System.currentTimeMillis() + 5_000
            while (isAlive(process) && System.currentTimeMillis() < deadline) {
                Thread.sleep(100)
            }
            if (isAlive(process)) {
                try {
                    process.destroyForcibly()
                } catch (_: Throwable) {
                }
            }
        }
        // Give the listener socket a moment to disappear before a restart.
        val portDeadline = System.currentTimeMillis() + 5_000
        while (isPortOpen() && System.currentTimeMillis() < portDeadline) {
            Thread.sleep(100)
        }
        if (shellReady) setStatus("SHELL READY")
    }

    // ---------------------------------------------------------------------
    // Process helpers
    // ---------------------------------------------------------------------

    private fun prootArgs(tail: List<String>): List<String> {
        val proot = prootBin ?: throw IllegalStateException("PRoot not initialized")
        val args = mutableListOf<String>()
        args.add(proot.absolutePath)
        args.addAll(
            listOf(
                "-v", "9",
                "-0",
                "-r", rootfsDir.absolutePath,
                "-b", "/dev",
                "-b", "/proc",
                "-b", "/sys",
                "-b", "${binDir.absolutePath}:/root/.opencode/bin",
                "-w", "/root"
            )
        )
        args.addAll(tail)
        return args
    }

    private fun applyEnvironment(pb: ProcessBuilder) {
        val home = File(filesDir, "home").apply { mkdirs() }
        val tmp = File(filesDir, "tmp").apply { mkdirs() }
        val env = pb.environment()
        val ca = File(rootfsDir, "etc/ssl/certs/ca-certificates.crt").absolutePath
        env["HOME"] = home.absolutePath
        env["TMPDIR"] = tmp.absolutePath
        env["XDG_DATA_HOME"] = File(home, ".local/share").absolutePath
        env["XDG_CONFIG_HOME"] = File(home, ".config").absolutePath
        env["XDG_CACHE_HOME"] = File(home, ".cache").absolutePath
        env["TERM"] = "xterm-256color"
        env["LANG"] = "C.UTF-8"
        env["PATH"] = "${binDir.absolutePath}:/system/bin:/system/xbin:/bin:/usr/bin"
        env["SSL_CERT_FILE"] = ca
        env["NODE_EXTRA_CA_CERTS"] = ca
        shimPath?.let { env["LD_PRELOAD"] = it.absolutePath }
        env.remove("PROOT_TMP_DIR")
        env.remove("PROOT_NO_SECCOMP")
        pb.directory(home)
    }

    private fun runOneShot(args: List<String>, timeoutMs: Long): String {
        val pb = ProcessBuilder(args)
        applyEnvironment(pb)
        pb.redirectErrorStream(true)
        val process = pb.start()
        val output = StringBuilder()
        val readerThread = thread(isDaemon = true) {
            try {
                process.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                    while (true) {
                        val line = reader.readLine() ?: break
                        synchronized(output) { output.append(line).append('\n') }
                    }
                }
            } catch (_: Throwable) {
            }
        }
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            try {
                process.exitValue()
                break
            } catch (_: IllegalThreadStateException) {
                Thread.sleep(200)
            }
        }
        val exited = !isAlive(process)
        val exitCode = if (exited) {
            try {
                process.exitValue()
            } catch (_: Throwable) {
                -1
            }
        } else {
            -1
        }
        if (!exited) process.destroy()
        readerThread.join(1500)
        Log.i(TAG, "runOneShot exit=$exitCode cmd=${args.joinToString(" ").take(180)}")
        return synchronized(output) { output.toString() }
    }

    private fun isAlive(process: Process): Boolean {
        return try {
            process.exitValue()
            false
        } catch (_: IllegalThreadStateException) {
            true
        } catch (_: Throwable) {
            false
        }
    }

    private fun isPortOpen(): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(HOST, PORT), 700)
                true
            }
        } catch (_: Throwable) {
            false
        }
    }

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    private fun setStatus(status: String) {
        lastStatus = status
        Log.i(TAG, "STATUS: $status")
        listeners.forEach { listener ->
            try {
                listener("__STATUS__$status")
            } catch (_: Throwable) {
            }
        }
    }

    private fun log(message: String) = logH(message)

    private fun logH(message: String) {
        Log.i(TAG, message)
        synchronized(historyLock) {
            history.addLast(message)
            while (history.size > 500) history.removeFirst()
        }
        listeners.forEach { listener ->
            try {
                listener(message)
            } catch (_: Throwable) {
            }
        }
    }

    fun abiTag(): String {
        val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"
        return if (abi.startsWith("x86")) "x86_64" else "aarch64"
    }
}
