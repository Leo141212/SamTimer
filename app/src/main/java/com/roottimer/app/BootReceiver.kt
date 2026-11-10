package com.roottimer.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Boots the auto-root chain when RECEIVE_BOOT_COMPLETED fires and the user
 * enabled the toggle.  The chain is two chained WorkManager jobs:
 *
 *   ShizukuWaitWorker  - waits for Shizuku's binder (it starts on its own
 *                        boot receiver when the user set wireless debugging
 *                        to auto-start), up to 8 minutes.  The chain also
 *                        delays 3 minutes after boot first: the system is
 *                        still settling (load spikes eat the UAF race and
 *                        early runs fail far more often).
 *   AutoRootWorker     - binds the UserService and runs the exploit, with a
 *                        notification at each phase.  A failed run disables
 *                        the toggle so a bad build cannot boot-loop the
 *                        phone (DirtyFrag's failed-run interlock idea).
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val prefs = context.getSharedPreferences(Prefs.NAME, Context.MODE_PRIVATE)
        // Always record the boot-completed moment (within a few seconds of
        // sys.boot_completed): MainActivity holds manual runs inside the
        // 3-minute settle window based on this.
        prefs.edit()
            .putLong(Prefs.BOOT_AT_ELAPSED, SystemClock.elapsedRealtime())
            .apply()
        if (!prefs.getBoolean(Prefs.AUTO_ROOT, false)) return

        // A soft reboot (SystemServer restart) re-delivers BOOT_COMPLETED
        // while the kernel -- and the live kernelsu module -- is untouched.
        // Running the UAF chain again on a live system is wasted risk, so
        // bail out here and also drop any pending/retrying auto-root work a
        // previous boot left behind (the workers double-check, but stale
        // queued work must not fire at all).
        val alreadyRooted = try {
            File("/proc/modules").useLines { lines ->
                lines.any { it.startsWith("kernelsu ") }
            }
        } catch (_: Exception) {
            false
        }
        if (alreadyRooted) {
            AutoRootNotif.post(
                context, 1,
                context.getString(R.string.notif_already),
                context.getString(R.string.notif_already_text)
            )
            WorkManager.getInstance(context).cancelUniqueWork("auto_root")
            return
        }

        val wait = OneTimeWorkRequestBuilder<ShizukuWaitWorker>()
            .setInitialDelay(180, TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(context)
            .beginUniqueWork("auto_root", ExistingWorkPolicy.REPLACE, wait)
            .then(OneTimeWorkRequestBuilder<AutoRootWorker>().build())
            .enqueue()
    }
}
