package com.dravix.ai

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import androidx.core.app.NotificationCompat

/**
 * Foreground service that keeps the PRoot + OpenCode processes alive when the
 * app goes to the background or the screen turns off.
 */
class DravixService : Service() {

    companion object {
        const val CHANNEL_ID = "dravix_engine"
        const val NOTIFICATION_ID = 4096
    }

    private var wakeLock: PowerManager.WakeLock? = null
    private val handler = Handler(Looper.getMainLooper())

    @Volatile
    private var leaseCheckInFlight = false

    /**
     * The service is the last line of defense: even if the activity is gone,
     * an expired or revoked lease tears the engine down within a minute.
     */
    private val leaseWatch = object : Runnable {
        override fun run() {
            if (!GateStore.hasValidLease(this@DravixService)) {
                shutdownEngine()
                return
            }
            if (!leaseCheckInFlight) {
                leaseCheckInFlight = true
                Thread {
                    try {
                        if (!LeaseManager.refresh(this@DravixService)) {
                            handler.post { shutdownEngine() }
                        }
                    } catch (e: GateApiException) {
                        if (LeaseManager.isFatalState(e.state)) {
                            handler.post { shutdownEngine() }
                        }
                        // Network errors: expiry is enforced above.
                    } catch (_: Throwable) {
                        // Ignore; expiry is enforced above.
                    } finally {
                        leaseCheckInFlight = false
                    }
                }.start()
            }
            handler.postDelayed(this, 60_000L)
        }
    }

    private val engineListener: (String) -> Unit = { line ->
        if (line.startsWith("__STATUS__")) {
            updateNotification(statusText(line.removePrefix("__STATUS__")))
        }
    }

    override fun onCreate() {
        super.onCreate()
        createChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Starting Linux engine..."))

        if (!GateStore.isAllowedToEnter(this)) {
            stopSelf()
            return
        }

        val powerManager = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Dravix::Engine").apply {
            setReferenceCounted(false)
            acquire(12L * 60L * 60L * 1000L)
        }

        DravixEngine.init(this)
        DravixEngine.addListener(engineListener)
        DravixEngine.ensureStarted()
        handler.post(leaseWatch)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!GateStore.isAllowedToEnter(this)) {
            stopSelf()
            return START_NOT_STICKY
        }
        DravixEngine.ensureStarted()
        return START_STICKY
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        DravixEngine.removeListener(engineListener)
        try {
            wakeLock?.release()
        } catch (_: Throwable) {
        }
        wakeLock = null
        super.onDestroy()
    }

    private fun shutdownEngine() {
        handler.removeCallbacksAndMessages(null)
        Thread {
            try {
                DravixEngine.stopEverything()
            } catch (_: Throwable) {
            }
        }.start()
        stopSelf()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Dravix Engine",
                NotificationManager.IMPORTANCE_LOW
            )
            channel.description = "Keeps the local OpenCode server running"
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pending = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Dravix")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_zap)
            .setOngoing(true)
            .setContentIntent(pending)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun statusText(status: String): String = when (status) {
        "STARTING" -> "Starting Linux engine..."
        "SHELL READY" -> "Linux shell ready"
        "RESTARTING" -> "Restarting OpenCode server..."
        "ONLINE" -> "OpenCode online on 127.0.0.1:4096"
        "ERROR" -> "Engine error - open Dravix"
        "SHELL DEAD" -> "Shell stopped - restarting"
        else -> status
    }
}
