package com.dravix.ai

import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject

/**
 * Access gate. The OpenCode engine is only started after this activity has a
 * fresh server-issued token. Free users complete a GPLinks verification;
 * paid/comp users go straight through.
 */
class GateActivity : AppCompatActivity() {

    private lateinit var logo: TextView
    private lateinit var status: TextView
    private lateinit var progress: ProgressBar
    private lateinit var authPanel: LinearLayout
    private lateinit var registerPanel: LinearLayout
    private lateinit var choicePanel: LinearLayout
    private lateinit var verifyPanel: LinearLayout
    private lateinit var loginUsername: EditText
    private lateinit var loginPassword: EditText
    private lateinit var loginButton: Button
    private lateinit var telegramLoginButton: Button
    private lateinit var goRegister: TextView
    private lateinit var registerUsername: EditText
    private lateinit var registerPassword: EditText
    private lateinit var registerConfirm: EditText
    private lateinit var registerButton: Button
    private lateinit var backToLogin: TextView
    private lateinit var freeAccessButton: Button
    private lateinit var codeAccessButton: Button
    private lateinit var retryLeaseButton: Button
    private lateinit var choiceLogoutLink: TextView
    private lateinit var verifyTitle: TextView
    private lateinit var verifyDetail: TextView
    private lateinit var verifyButton: Button
    private lateinit var checkButton: Button
    private lateinit var redeemLink: TextView
    private lateinit var backToChoice: TextView
    private lateinit var hwidLink: TextView
    private lateinit var logoutLink: TextView
    private lateinit var gateError: TextView
    private lateinit var gateFooter: TextView

    private val handler = Handler(Looper.getMainLooper())
    private var busy = false
    private var awaitingVerification = false
    private var verifySession: String? = null
    private var shortUrl: String? = null
    private var pollStartedAt = 0L
    private var pollRunnable: Runnable? = null

    private var telegramSession: String? = null
    private var telegramPollStartedAt = 0L
    private var telegramPollRunnable: Runnable? = null
    private var telegramPollInFlight = false
    private var updateDialogShown = false

    private val hwid: String by lazy { GateStore.hwid(this) }
    private val installId: String by lazy { GateStore.installId(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        scrubLegacyStorage()
        setContentView(R.layout.activity_gate)

        bindViews()
        wireActions()

        gateFooter.text = "powered by @trndravix"
        loginPassword.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                doLogin()
                true
            } else false
        }

        checkAppConfig()
    }

    private fun bindViews() {
        logo = findViewById(R.id.gateLogo)
        status = findViewById(R.id.gateStatus)
        progress = findViewById(R.id.gateProgress)
        authPanel = findViewById(R.id.authPanel)
        registerPanel = findViewById(R.id.registerPanel)
        choicePanel = findViewById(R.id.choicePanel)
        verifyPanel = findViewById(R.id.verifyPanel)
        loginUsername = findViewById(R.id.loginUsername)
        loginPassword = findViewById(R.id.loginPassword)
        loginButton = findViewById(R.id.loginButton)
        telegramLoginButton = findViewById(R.id.telegramLoginButton)
        goRegister = findViewById(R.id.goRegister)
        registerUsername = findViewById(R.id.registerUsername)
        registerPassword = findViewById(R.id.registerPassword)
        registerConfirm = findViewById(R.id.registerConfirm)
        registerButton = findViewById(R.id.registerButton)
        backToLogin = findViewById(R.id.backToLogin)
        freeAccessButton = findViewById(R.id.freeAccessButton)
        codeAccessButton = findViewById(R.id.codeAccessButton)
        retryLeaseButton = findViewById(R.id.retryLeaseButton)
        choiceLogoutLink = findViewById(R.id.choiceLogoutLink)
        verifyTitle = findViewById(R.id.verifyTitle)
        verifyDetail = findViewById(R.id.verifyDetail)
        verifyButton = findViewById(R.id.verifyButton)
        checkButton = findViewById(R.id.checkButton)
        redeemLink = findViewById(R.id.redeemLink)
        backToChoice = findViewById(R.id.backToChoice)
        hwidLink = findViewById(R.id.hwidLink)
        logoutLink = findViewById(R.id.logoutLink)
        gateError = findViewById(R.id.gateError)
        gateFooter = findViewById(R.id.gateFooter)
    }

    private fun wireActions() {
        loginButton.setOnClickListener { doLogin() }
        telegramLoginButton.setOnClickListener { startTelegramLogin() }
        goRegister.setOnClickListener { showRegister() }
        backToLogin.setOnClickListener { showAuth() }
        registerButton.setOnClickListener { doRegister() }
        freeAccessButton.setOnClickListener { showVerify() }
        codeAccessButton.setOnClickListener { showRedeemDialog() }
        retryLeaseButton.setOnClickListener { attemptSavedSession() }
        choiceLogoutLink.setOnClickListener { logout() }
        verifyButton.setOnClickListener { startVerification() }
        checkButton.setOnClickListener { pollOnce() }
        redeemLink.setOnClickListener { showRedeemDialog() }
        backToChoice.setOnClickListener { showChoice() }
        hwidLink.setOnClickListener { showHwidResetDialog() }
        logoutLink.setOnClickListener { logout() }

        // The API base is compiled in and cannot be changed at runtime.
        gateFooter.setOnClickListener { }
        logo.setOnLongClickListener { true }
    }

    private fun logout() {
        stopTelegramPolling()
        GateStore.clearSession(this)
        awaitingVerification = false
        verifySession = null
        shortUrl = null
        telegramSession = null
        showAuth("Logged out.")
    }

    /** Removes the old plaintext preferences from pre-hardening builds. */
    private fun scrubLegacyStorage() {
        try {
            getSharedPreferences("dravix_gate_v1", MODE_PRIVATE).edit().clear().apply()
        } catch (_: Throwable) {
        }
        // Older hardened builds persisted the runtime AES key. It is now
        // memory-only, so delete any leftover copy.
        GateStore.purgeLegacyAssetKey(this)
    }

    // -----------------------------------------------------------------
    // App update / startup
    // -----------------------------------------------------------------

    private fun checkAppConfig() {
        Thread {
            try {
                val config = GateApi.post(this, "/gate/config", baseBody())
                runOnUiThread { maybeShowUpdate(config) { attemptSavedSession() } }
            } catch (_: Throwable) {
                runOnUiThread { attemptSavedSession() }
            }
        }.start()
    }

    private fun maybeShowUpdate(config: JSONObject, onContinue: () -> Unit) {
        if (config.optBoolean("maintenance_mode", false)) {
            updateDialogShown = true
            AlertDialog.Builder(this)
                .setTitle("Maintenance")
                .setMessage(
                    config.optString(
                        "maintenance_message",
                        "OpenCode is under maintenance. Please try again shortly."
                    )
                )
                .setCancelable(false)
                .setPositiveButton("Retry") { _, _ ->
                    updateDialogShown = false
                    checkAppConfig()
                }
                .setNegativeButton("Close") { _, _ -> finish() }
                .show()
            return
        }

        val latest = config.optInt("latest_version_code", 0)
        val min = config.optInt("min_version_code", 0)
        val url = config.optString("update_url", "").trim()
        val current = BuildConfig.VERSION_CODE
        val force = (min > 0 && current < min) ||
            (config.optBoolean("update_force", false) && latest > current)

        if (latest <= current || url.isBlank() || updateDialogShown) {
            onContinue()
            return
        }

        updateDialogShown = true
        val changelog = config.optString("update_changelog", "").trim()
        val versionName = config.optString("latest_version_name", latest.toString())
        val message = buildString {
            append("A newer OpenCode build is available (v")
            append(versionName)
            append(").")
            if (changelog.isNotBlank()) {
                append("\n\n")
                append(changelog)
            }
            if (force) append("\n\nThis update is required to continue.")
        }

        val builder = AlertDialog.Builder(this)
            .setTitle(if (force) "Update required" else "Update available")
            .setMessage(message)
            .setCancelable(false)
            .setPositiveButton("Update") { _, _ ->
                openBrowser(url)
                if (force) finish()
            }
        if (!force) {
            builder.setNegativeButton("Later") { _, _ -> onContinue() }
        }
        builder.show()
    }

    // -----------------------------------------------------------------
    // Startup / session
    // -----------------------------------------------------------------

    private fun attemptSavedSession() {
        val token = GateStore.token(this)
        if (token.isBlank()) {
            showAuth()
            return
        }
        if (!GateStore.hasFreshToken(this)) {
            GateStore.clearSession(this)
            showAuth("Your access period ended. Please verify again.")
            return
        }

        // Fail closed: no cached "allowed" flag and no offline grace. Every
        // cold start must obtain a fresh 5 minute lease bound to this device.
        setLoading(true, "Checking secure license...")
        Thread {
            try {
                val ok = LeaseManager.ensureLease(this)
                runOnUiThread {
                    setLoading(false, null)
                    if (ok && GateStore.hasValidLease(this)) {
                        enterApp()
                    } else {
                        showChoice()
                        showError("Your access is not active. Verify again or redeem a key.")
                    }
                }
            } catch (e: GateApiException) {
                runOnUiThread {
                    setLoading(false, null)
                    if (LeaseManager.isFatalState(e.state)) {
                        GateStore.clearSession(this)
                        showAuth(e.message ?: "Please log in again.")
                    } else {
                        showChoice(retryable = true)
                        showError(e.message ?: "Could not verify your license.")
                    }
                }
            }
        }.start()
    }

    private fun handleAccess(data: JSONObject) {
        GateStore.saveSession(this, data)
        if (!data.optBoolean("can_enter", false)) {
            showChoice()
            return
        }
        setLoading(true, "Activating secure license...")
        Thread {
            try {
                val ok = LeaseManager.ensureLease(this)
                runOnUiThread {
                    setLoading(false, null)
                    if (ok && GateStore.hasValidLease(this)) {
                        enterApp()
                    } else {
                        showChoice()
                        showError("Access could not be activated on this device.")
                    }
                }
            } catch (e: GateApiException) {
                runOnUiThread {
                    setLoading(false, null)
                    if (LeaseManager.isFatalState(e.state)) {
                        GateStore.clearSession(this)
                        showAuth(e.message ?: "Please log in again.")
                    } else {
                        showChoice(retryable = true)
                        showError(e.message ?: "Could not activate access.")
                    }
                }
            }
        }.start()
    }

    private fun enterApp() {
        handler.removeCallbacksAndMessages(null)
        val intent = Intent(this, MainActivity::class.java)
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        startActivity(intent)
        finish()
    }

    // -----------------------------------------------------------------
    // Telegram login
    // -----------------------------------------------------------------

    private fun startTelegramLogin() {
        if (busy) return
        hideError()
        setLoading(true, "Starting Telegram login...")
        Thread {
            try {
                val data = GateApi.post(this, "/gate/telegram_start", baseBody())
                val session = data.optString("session_token", "")
                val deepLink = data.optString("deep_link", "")
                val webLink = data.optString("web_link", "")
                runOnUiThread {
                    setLoading(false, "Open Telegram and tap Start")
                    if (session.isBlank() || deepLink.isBlank()) {
                        showError("The server did not return a Telegram login link.")
                        return@runOnUiThread
                    }
                    telegramSession = session
                    telegramPollStartedAt = System.currentTimeMillis()
                    openTelegram(deepLink, webLink)
                    startTelegramPolling()
                }
            } catch (e: GateApiException) {
                runOnUiThread {
                    setLoading(false, null)
                    showError(e.message ?: "Could not start Telegram login.")
                }
            }
        }.start()
    }

    private fun openTelegram(deepLink: String, webLink: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(deepLink)))
        } catch (_: ActivityNotFoundException) {
            try {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(webLink)))
            } catch (_: Throwable) {
                showError("Telegram is not installed. Install Telegram or use username/password.")
            }
        }
    }

    private fun startTelegramPolling() {
        stopTelegramPolling()
        val runnable = object : Runnable {
            override fun run() {
                if (telegramSession == null) return
                if (System.currentTimeMillis() - telegramPollStartedAt > 5 * 60 * 1000L) {
                    stopTelegramPolling()
                    telegramSession = null
                    showAuth("Telegram login timed out. Please try again.")
                    return
                }
                pollTelegramOnce()
                handler.postDelayed(this, 2500)
            }
        }
        telegramPollRunnable = runnable
        handler.postDelayed(runnable, 1800)
    }

    private fun stopTelegramPolling() {
        telegramPollRunnable?.let { handler.removeCallbacks(it) }
        telegramPollRunnable = null
        telegramPollInFlight = false
    }

    private fun pollTelegramOnce() {
        val session = telegramSession ?: return
        if (telegramPollInFlight) return
        telegramPollInFlight = true
        Thread {
            try {
                val body = baseBody().put("session_token", session)
                val data = GateApi.post(this, "/gate/telegram_poll", body)
                runOnUiThread {
                    telegramPollInFlight = false
                    stopTelegramPolling()
                    telegramSession = null
                    GateStore.saveSession(this, data)
                    if (data.optBoolean("telegram_new_account", false)) {
                        Toast.makeText(this, "OpenCode AI account created.", Toast.LENGTH_SHORT).show()
                    }
                    handleAccess(data)
                }
            } catch (e: GateApiException) {
                runOnUiThread {
                    telegramPollInFlight = false
                    when (e.state) {
                        "pending" -> {
                            status.text = "Waiting for Telegram confirmation..."
                        }
                        "expired", "session_not_found", "session_used", "hwid_mismatch",
                        "banned", "wrong_app", "account_inactive" -> {
                            stopTelegramPolling()
                            telegramSession = null
                            showAuth(e.message ?: "Telegram login failed. Please try again.")
                        }
                        else -> {
                            status.text = "Waiting for Telegram..."
                        }
                    }
                }
            }
        }.start()
    }

    // -----------------------------------------------------------------
    // Login / register
    // -----------------------------------------------------------------

    private fun doLogin() {
        if (busy) return
        val username = loginUsername.text.toString().trim()
        val password = loginPassword.text.toString()
        if (username.isEmpty() || password.isEmpty()) {
            showError("Username and password are required.")
            return
        }

        hideError()
        setLoading(true, "Signing inâ€¦")
        Thread {
            try {
                val body = baseBody()
                    .put("username", username)
                    .put("password", password)
                val data = GateApi.post(this, "/gate/login", body)
                runOnUiThread {
                    setLoading(false, null)
                    handleAccess(data)
                }
            } catch (e: GateApiException) {
                runOnUiThread {
                    setLoading(false, null)
                    if (e.state == "hwid_mismatch") {
                        offerHwidReset(username, password, e.message ?: "This account is locked to another device.")
                    } else {
                        showError(e.message ?: "Login failed.")
                    }
                }
            }
        }.start()
    }

    private fun doRegister() {
        if (busy) return
        val username = registerUsername.text.toString().trim()
        val password = registerPassword.text.toString()
        val confirm = registerConfirm.text.toString()

        if (username.length < 3) {
            showError("Username must be at least 3 characters.")
            return
        }
        if (password.length < 6) {
            showError("Password must be at least 6 characters.")
            return
        }
        if (password != confirm) {
            showError("Passwords do not match.")
            return
        }

        hideError()
        setLoading(true, "Creating accountâ€¦")
        Thread {
            try {
                val body = baseBody()
                    .put("username", username)
                    .put("password", password)
                val data = GateApi.post(this, "/gate/register", body)
                runOnUiThread {
                    setLoading(false, null)
                    GateStore.saveSession(this, data)
                    resetVerificationState()
                    showChoice()
                }
            } catch (e: GateApiException) {
                runOnUiThread {
                    setLoading(false, null)
                    if (e.state == "device_already_registered") {
                        showError(e.message ?: "This device already has an account. Log in instead.")
                    } else {
                        showError(e.message ?: "Registration failed.")
                    }
                }
            }
        }.start()
    }

    // -----------------------------------------------------------------
    // Free verification
    // -----------------------------------------------------------------

    private fun startVerification() {
        if (busy) return
        if (shortUrl != null && verifySession != null) {
            openBrowser(shortUrl!!)
            return
        }

        hideError()
        setLoading(true, "Creating verification linkâ€¦")
        Thread {
            try {
                val data = GateApi.post(this, "/gate/verify_start", bodyWithToken())
                runOnUiThread {
                    setLoading(false, null)
                    if (data.optBoolean("verified", false)) {
                        handleAccess(data)
                        return@runOnUiThread
                    }
                    val session = data.optString("session", "")
                    val url = data.optString("short_url", "")
                    if (session.isBlank() || url.isBlank()) {
                        showError("The server did not return a verification link.")
                        return@runOnUiThread
                    }
                    verifySession = session
                    shortUrl = url
                    awaitingVerification = true
                    checkButton.visibility = View.VISIBLE
                    verifyButton.text = "Open verification page"
                    status.text = "Complete the page in your browser"
                    verifyDetail.text = "After the ads page, return here. We will check automatically."
                    openBrowser(url)
                    startPolling()
                }
            } catch (e: GateApiException) {
                runOnUiThread {
                    setLoading(false, null)
                    showError(e.message ?: "Could not create the verification link.")
                }
            }
        }.start()
    }

    private fun startPolling() {
        pollRunnable?.let { handler.removeCallbacks(it) }
        pollStartedAt = System.currentTimeMillis()
        val runnable = object : Runnable {
            override fun run() {
                if (!awaitingVerification) return
                if (System.currentTimeMillis() - pollStartedAt > 10 * 60 * 1000L) {
                    awaitingVerification = false
                    status.text = "Verification timed out"
                    showError("The verification page timed out. Tap 'Open verification page' to try again.")
                    return
                }
                pollOnce()
                handler.postDelayed(this, 2500)
            }
        }
        pollRunnable = runnable
        handler.postDelayed(runnable, 2500)
    }

    private fun stopPolling() {
        pollRunnable?.let { handler.removeCallbacks(it) }
        pollRunnable = null
        awaitingVerification = false
    }

    private fun pollOnce() {
        val session = verifySession ?: return
        if (busy) return
        Thread {
            try {
                val body = bodyWithToken().put("session", session)
                val data = GateApi.post(this, "/gate/verify_poll", body)
                runOnUiThread {
                    if (data.optBoolean("verified", false)) {
                        stopPolling()
                        status.text = "Access verified"
                        handleAccess(data)
                    } else {
                        status.text = "Waiting for verificationâ€¦"
                        verifyDetail.text = "Complete the GPLinks page, then return to the app. Checking automatically."
                    }
                }
            } catch (e: GateApiException) {
                runOnUiThread {
                    if (e.state == "session_expired" || e.state == "session_not_found") {
                        stopPolling()
                        shortUrl = null
                        verifySession = null
                        checkButton.visibility = View.GONE
                        verifyButton.text = "Create a new verification link"
                        showError(e.message ?: "The verification session expired.")
                    } else if (e.state == "token_expired" || e.state == "banned" ||
                        e.state == "session_revoked" || e.state == "account_inactive" ||
                        e.state == "hwid_mismatch"
                    ) {
                        stopPolling()
                        GateStore.clearSession(this)
                        showAuth(e.message ?: "Please log in again.")
                    }
                    // Network errors while polling are retried silently.
                }
            }
        }.start()
    }

    private fun openBrowser(url: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (_: ActivityNotFoundException) {
            showError("No browser found. Install Chrome or another browser and try again.")
        }
    }

    override fun onResume() {
        super.onResume()
        if (awaitingVerification) pollOnce()
        if (telegramSession != null) pollTelegramOnce()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val uri = intent.data ?: return
        if (uri.scheme == "dravix" && uri.host == "verify") {
            if (uri.getQueryParameter("status") == "success") pollOnce()
        }
    }

    // -----------------------------------------------------------------
    // Paid keys / HWID reset / server settings
    // -----------------------------------------------------------------

    private fun showRedeemDialog() {
        if (GateStore.token(this).isBlank()) {
            showError("Please log in first.")
            return
        }
        val input = EditText(this).apply {
            hint = "DRAVIX-XXXX-XXXX"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS
            setSingleLine(true)
            setPadding(36, 24, 36, 24)
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle("Redeem activation key")
            .setMessage("Enter the key you received after payment.")
            .setView(input)
            .setPositiveButton("Redeem", null)
            .setNegativeButton("Cancel", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val code = input.text.toString().trim()
                if (code.isBlank()) {
                    input.error = "Enter a key"
                    return@setOnClickListener
                }
                dialog.dismiss()
                redeem(code)
            }
        }
        dialog.show()
    }

    private fun redeem(code: String) {
        if (busy) return
        setLoading(true, "Redeeming keyâ€¦")
        Thread {
            try {
                val body = bodyWithToken().put("code", code)
                val data = GateApi.post(this, "/gate/redeem", body)
                runOnUiThread {
                    setLoading(false, null)
                    Toast.makeText(this, "Key redeemed", Toast.LENGTH_SHORT).show()
                    handleAccess(data)
                }
            } catch (e: GateApiException) {
                runOnUiThread {
                    setLoading(false, null)
                    showError(e.message ?: "Could not redeem this key.")
                }
            }
        }.start()
    }

    private fun showHwidResetDialog() {
        val token = GateStore.token(this)
        if (token.isBlank()) {
            showError("Log in first, then request an HWID reset.")
            return
        }
        val reason = EditText(this).apply {
            hint = "Reason (optional) â€” e.g. new phone"
            setSingleLine(false)
            minLines = 2
            setPadding(36, 24, 36, 24)
        }
        AlertDialog.Builder(this)
            .setTitle("Request HWID reset")
            .setMessage("The administrator will review this request. Your current device will be unlinked after approval.")
            .setView(reason)
            .setPositiveButton("Submit request") { _, _ ->
                submitHwidRequest(null, null, reason.text.toString().trim())
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun offerHwidReset(username: String, password: String, detail: String) {
        AlertDialog.Builder(this)
            .setTitle("Device locked")
            .setMessage("$detail\n\nRequest an HWID reset from the administrator?")
            .setPositiveButton("Request reset") { _, _ ->
                submitHwidRequest(username, password, "Login from a new device")
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun submitHwidRequest(username: String?, password: String?, reason: String) {
        if (busy) return
        setLoading(true, "Submitting requestâ€¦")
        Thread {
            try {
                val body = baseBody().put("reason", reason)
                val token = GateStore.token(this)
                if (username != null && password != null) {
                    body.put("username", username)
                    body.put("password", password)
                } else if (token.isNotBlank()) {
                    body.put("token", token)
                }
                val data = GateApi.post(this, "/gate/hwid_request", body)
                runOnUiThread {
                    setLoading(false, "Request submitted. Waiting for admin approval.")
                    val state = data.optString("state", "pending")
                    if (state == "pending") {
                        Toast.makeText(this, "HWID reset request submitted.", Toast.LENGTH_LONG).show()
                    } else {
                        Toast.makeText(this, "Request submitted.", Toast.LENGTH_SHORT).show()
                    }
                }
            } catch (e: GateApiException) {
                runOnUiThread {
                    setLoading(false, "Welcome back")
                    showError(e.message ?: "Could not submit the HWID request.")
                }
            }
        }.start()
    }

    // -----------------------------------------------------------------
    // UI helpers
    // -----------------------------------------------------------------

    private fun showAuth(message: String? = null) {
        stopTelegramPolling()
        resetVerificationState()
        hideAllPanels()
        authPanel.visibility = View.VISIBLE
        status.text = "Welcome back"
        if (loginUsername.text.isNullOrBlank()) {
            loginUsername.setText(GateStore.username(this))
        }
        if (message != null) showError(message) else hideError()
        setLoading(false, null)
    }

    private fun showRegister() {
        stopTelegramPolling()
        resetVerificationState()
        hideAllPanels()
        registerPanel.visibility = View.VISIBLE
        status.text = "Create your account"
        registerUsername.requestFocus()
        hideError()
    }

    private fun showChoice(retryable: Boolean = false) {
        stopTelegramPolling()
        resetVerificationState()
        hideAllPanels()
        choicePanel.visibility = View.VISIBLE
        status.text = "Choose how to continue"
        retryLeaseButton.visibility =
            if (retryable && GateStore.token(this).isNotBlank()) View.VISIBLE else View.GONE
        hideError()
        setLoading(false, null)
    }

    private fun showVerify() {
        stopTelegramPolling()
        hideAllPanels()
        verifyPanel.visibility = View.VISIBLE
        status.text = "Free access verification"
        verifyTitle.text = "Unlock 24 hours of access"
        verifyDetail.text = "Complete one short verification page to use OpenCode for free. Paid and comp accounts skip this step."
        verifyButton.text = if (shortUrl != null) "Open verification page" else "Verify free access"
        checkButton.visibility = if (verifySession != null) View.VISIBLE else View.GONE
        hideError()
    }

    private fun resetVerificationState() {
        stopPolling()
        verifySession = null
        shortUrl = null
        checkButton.visibility = View.GONE
        verifyButton.text = "Verify free access"
    }

    private fun hideAllPanels() {
        authPanel.visibility = View.GONE
        registerPanel.visibility = View.GONE
        choicePanel.visibility = View.GONE
        verifyPanel.visibility = View.GONE
    }

    private fun setLoading(loading: Boolean, text: String?) {
        busy = loading
        progress.visibility = if (loading) View.VISIBLE else View.GONE
        if (text != null) status.text = text
        loginButton.isEnabled = !loading
        telegramLoginButton.isEnabled = !loading
        registerButton.isEnabled = !loading
        freeAccessButton.isEnabled = !loading
        codeAccessButton.isEnabled = !loading
        verifyButton.isEnabled = !loading
        checkButton.isEnabled = !loading
        goRegister.isEnabled = !loading
        backToLogin.isEnabled = !loading
        redeemLink.isEnabled = !loading
        backToChoice.isEnabled = !loading
        choiceLogoutLink.isEnabled = !loading
        hwidLink.isEnabled = !loading
        logoutLink.isEnabled = !loading
    }

    private fun showError(message: String) {
        gateError.text = message
        gateError.visibility = View.VISIBLE
    }

    private fun hideError() {
        gateError.visibility = View.GONE
    }

    private fun baseBody(): JSONObject = JSONObject()
        .put("hwid", hwid)
        .put("install_id", installId)
        .put("device_model", deviceName())

    private fun bodyWithToken(): JSONObject = baseBody()
        .put("token", GateStore.token(this))

    private fun deviceName(): String {
        val name = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
        return name.ifBlank { "Android device" }.take(120)
    }

    override fun onDestroy() {
        stopPolling()
        stopTelegramPolling()
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }
}
