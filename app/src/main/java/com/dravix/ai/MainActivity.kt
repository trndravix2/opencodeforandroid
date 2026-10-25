package com.dravix.ai

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.webkit.ConsoleMessage
import android.webkit.HttpAuthHandler
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject

/**
 * Single screen app: shows a small boot screen while the bundled OpenCode
 * runtime starts, then loads the OpenCode web UI full-screen.
 */
class MainActivity : AppCompatActivity() {

    lateinit var webView: WebView

    @Volatile
    private var uiRequested = false

    @Volatile
    private var lastSessionId: String? = null

    private var uiGeneration = 0
    private var serverRestartPending = false

    @Volatile
    private var leaseRefreshInFlight = false

    private val gateHandler = Handler(Looper.getMainLooper())
    private val leaseWatch = object : Runnable {
        override fun run() {
            if (isFinishing) return
            // Hard stop once the short-lived server lease has fully expired.
            if (!GateStore.hasValidLease(this@MainActivity)) {
                lockGate()
                return
            }
            refreshLease()
            gateHandler.postDelayed(this, 60_000L)
        }
    }

    private val engineListener: (String) -> Unit = { line ->
        if (line.startsWith("__STATUS__")) {
            val status = line.removePrefix("__STATUS__")
            sendJs("onEngineStatus", JSONObject.quote(status))
            when (status) {
                "ONLINE" -> runOnUiThread { loadOpenCode(force = serverRestartPending) }
                "RESTARTING" -> runOnUiThread { prepareServerRestart() }
            }
        } else {
            sendJs("onTerminalOutput", JSONObject.quote(line))
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Hard local gate: no token/entitlement means the engine never starts.
        if (!GateStore.isAllowedToEnter(this)) {
            openGateAndFinish()
            return
        }

        DravixEngine.init(this)

        webView = WebView(this)
        setContentView(webView)

        val settings: WebSettings = webView.settings
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.databaseEnabled = true
        settings.allowFileAccess = true
        settings.allowContentAccess = true
        settings.useWideViewPort = true
        settings.loadWithOverviewMode = true
        settings.cacheMode = WebSettings.LOAD_DEFAULT
        settings.mediaPlaybackRequiresUserGesture = false

        if (BuildConfig.DEBUG) {
            WebView.setWebContentsDebuggingEnabled(true)
        }

        webView.webViewClient = object : WebViewClient() {
            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)
                if (url == null) return
                if (url.startsWith("file:///android_asset/www/")) {
                    pushStateToWeb()
                    if (DravixEngine.serverReady) {
                        loadOpenCode()
                    }
                } else if (url.startsWith("http://127.0.0.1:4096")) {
                    extractSessionId(url)?.let { lastSessionId = it }
                    webView.clearHistory()
                }
            }

            override fun onReceivedHttpAuthRequest(
                view: WebView?,
                handler: HttpAuthHandler?,
                host: String?,
                realm: String?
            ) {
                val password = DravixEngine.serverPassword
                if (handler != null && host != null && host.contains("127.0.0.1") && password.isNotBlank()) {
                    handler.proceed("opencode", password)
                } else {
                    super.onReceivedHttpAuthRequest(view, handler, host, realm)
                }
            }

            override fun onReceivedError(
                view: WebView?,
                request: WebResourceRequest?,
                error: WebResourceError?
            ) {
                super.onReceivedError(view, request, error)
                if (request?.url?.toString()?.contains("127.0.0.1") == true) {
                    Log.w(DravixEngine.TAG, "WebView error: ${error?.description} for ${request.url}")
                    if (request.isForMainFrame) uiRequested = false
                }
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onConsoleMessage(message: ConsoleMessage?): Boolean {
                if (message != null) {
                    Log.i("DravixWeb", "${message.message()} (${message.lineNumber()})")
                }
                return true
            }
        }

        webView.addJavascriptInterface(DravixBridge(this), "DravixNative")

        DravixEngine.addListener(engineListener)
        startEngineService()

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001)
        }

        webView.loadUrl("file:///android_asset/www/index.html")
        gateHandler.post(leaseWatch)
    }

    override fun onResume() {
        super.onResume()
        if (::webView.isInitialized && !GateStore.isAllowedToEnter(this)) {
            lockGate()
        } else if (::webView.isInitialized) {
            refreshLease()
        }
    }

    private fun openGateAndFinish() {
        if (isFinishing) return
        val intent = Intent(this, GateActivity::class.java)
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        startActivity(intent)
        finish()
    }

    /**
     * Refreshes the 5 minute hardware-bound lease while the engine is running.
     * There is no offline grace: if the lease expires the engine is stopped.
     */
    private fun refreshLease() {
        if (leaseRefreshInFlight) return
        leaseRefreshInFlight = true
        Thread {
            try {
                val ok = LeaseManager.refresh(this)
                if (!ok) {
                    runOnUiThread { lockGate() }
                }
            } catch (e: GateApiException) {
                val state = e.state
                Log.w(DravixEngine.TAG, "Lease refresh failed: state=$state msg=${e.message}")
                if (LeaseManager.isFatalState(state)) {
                    runOnUiThread { lockGate() }
                }
                // Network errors: the stored lease remains valid for at most
                // 5 minutes; leaseWatch stops the engine when it expires.
            } catch (_: Throwable) {
                // Ignore; expiry is enforced by leaseWatch.
            } finally {
                leaseRefreshInFlight = false
            }
        }.start()
    }

    private fun lockGate() {
        if (isFinishing) return
        gateHandler.removeCallbacksAndMessages(null)
        try {
            webView.stopLoading()
        } catch (_: Throwable) {
        }
        Thread {
            try {
                DravixEngine.stopEverything()
            } catch (_: Throwable) {
            }
        }.start()
        stopService(Intent(this, DravixService::class.java))
        openGateAndFinish()
    }

    private fun startEngineService() {
        val intent = Intent(this, DravixService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                startForegroundService(intent)
            } catch (t: Throwable) {
                Log.w(DravixEngine.TAG, "startForegroundService failed: ${t.message}")
                startService(intent)
            }
        } else {
            startService(intent)
        }
    }

    fun loadOpenCode(force: Boolean = false) {
        if (!force && uiRequested) return
        val current = webView.url ?: ""
        if (!force && current.startsWith("http://127.0.0.1:4096")) return

        val generation = ++uiGeneration
        uiRequested = true
        sendJs("onEngineStatus", JSONObject.quote("ONLINE"))
        DravixEngine.openUi(lastSessionId) { url ->
            runOnUiThread {
                if (generation != uiGeneration) return@runOnUiThread
                if (url.isBlank()) {
                    uiRequested = false
                    sendJs("onEngineStatus", JSONObject.quote("ERROR"))
                } else {
                    serverRestartPending = false
                    webView.loadUrl(url)
                }
            }
        }
    }

    /**
     * The engine lost its server process and is restarting it. Keep the
     * current session id, invalidate any in-flight UI load, and show the
     * local splash until the fresh server is online. The WebView must not be
     * left running against a dead origin, otherwise every API call fails
     * with "Failed to fetch".
     */
    private fun prepareServerRestart() {
        val current = webView.url ?: ""
        extractSessionId(current)?.let { lastSessionId = it }
        serverRestartPending = true
        uiGeneration++
        uiRequested = false
        if (!current.startsWith("file:///android_asset/www/")) {
            try {
                webView.stopLoading()
            } catch (_: Throwable) {
            }
            webView.loadUrl("file:///android_asset/www/index.html")
        }
    }

    fun resetAndRetry() {
        val current = webView.url ?: ""
        extractSessionId(current)?.let { lastSessionId = it }
        serverRestartPending = true
        uiGeneration++
        uiRequested = false
        DravixEngine.retry()
    }

    private fun extractSessionId(url: String?): String? {
        if (url == null) return null
        return Regex("/session/([^/?#]+)").find(url)?.groupValues?.get(1)
    }

    fun pushStateToWeb() {
        sendJs("onNativeStatus", DravixEngine.statusJson())
        sendJs("onTerminalHistory", DravixEngine.historyJson())
    }

    private fun sendJs(function: String, jsonArg: String) {
        runOnUiThread {
            webView.evaluateJavascript("if(window.$function) window.$function($jsonArg);", null)
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        val current = webView.url ?: ""
        if (current.startsWith("file:///android_asset/")) {
            super.onBackPressed()
            return
        }
        if (webView.canGoBack()) {
            webView.goBack()
        } else {
            super.onBackPressed()
        }
    }

    override fun onDestroy() {
        gateHandler.removeCallbacksAndMessages(null)
        DravixEngine.removeListener(engineListener)
        super.onDestroy()
    }
}

class DravixBridge(private val activity: MainActivity) {

    @JavascriptInterface
    fun getStatus(): String = DravixEngine.statusJson()

    @JavascriptInterface
    fun getHistory(): String = DravixEngine.historyJson()

    @JavascriptInterface
    fun retry() {
        activity.runOnUiThread { activity.resetAndRetry() }
    }
}
