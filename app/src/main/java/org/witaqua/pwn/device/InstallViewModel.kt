package org.witaqua.pwn.device

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File
import kotlin.time.Duration.Companion.milliseconds

enum class InstallPhase {
    Checking,
    Ready,
    Downloading,
    Exploiting,
    LoadingKernelSu,
    Installed,
    Failed,

    /**
     * Refused before it started, because this boot cannot win it. Terminal like
     * [Failed], but nothing was attempted, so it is not reported as a failure.
     */
    Skipped,
}

/** What is known about the payload release a finished run used. */
enum class PayloadState {
    /** Not checked -- no run has resolved a release yet, or the check failed. */
    Unknown,
    Current,
    Outdated,
    Fetching,
    Fetched,
}

data class InstallUiState(
    val phase: InstallPhase = InstallPhase.Checking,
    val message: String = "",
    val probeOutput: String = "",
    val log: String = "",
    /** The payload release this run read its artifacts from. */
    val payloadTag: String? = null,
    /** The release published right now, as of the last check. */
    val latestPayloadTag: String? = null,
    val payloadState: PayloadState = PayloadState.Unknown,
    /**
     * The KernelSU build this device's profile pairs with, so the overview can
     * name the manager version it needs rather than leaving the user to find
     * out from the manager that the two do not match. Null when no profile has
     * been resolved -- no network, or no entry for this device.
     */
    val kernelSu: KernelSuArtifact? = null,
    /**
     * The folder a debug run reads its payload from, when debug mode is on and
     * one is set. Non-null means the feed is being bypassed, which the screen
     * says out loud: a run from a local file has had none of the checks a
     * downloaded one has.
     */
    val localPayload: String? = null,
) {
    val busy: Boolean
        get() = phase in setOf(
            InstallPhase.Checking,
            InstallPhase.Downloading,
            InstallPhase.Exploiting,
            InstallPhase.LoadingKernelSu,
        )

}

data class TargetCatalogUiState(
    val loading: Boolean = false,
    val profiles: List<TargetProfile> = emptyList(),
    val error: String? = null,
)

/**
 * Thrown to end a run that this boot cannot win, before anything is attempted.
 * Carried by its own type so the outcome is recorded as skipped rather than
 * failed -- see [InstallRunResult.Skipped].
 */
private class RunSkipped(message: String) : Exception(message)

private data class CommandResult(val code: Int, val output: String)

class InstallViewModel(application: Application) : AndroidViewModel(application) {
    private val app = application
    private val repository = PayloadRepository(application)
    private val localSource = LocalPayloadSource(application)
    private val historyStore = InstallHistoryStore(application)
    private val mutableState = MutableStateFlow(InstallUiState())
    private val mutableHistory = MutableStateFlow(historyStore.closeInterruptedRuns())
    private val mutableTargetCatalog = MutableStateFlow(TargetCatalogUiState())
    private var discoveryJob: Job? = null
    private var installJob: Job? = null
    private var payloadCheckJob: Job? = null
    // Volatile because a delete arriving from the History page runs on a
    // different thread from the install job that keeps writing this entry.
    @Volatile
    private var activeHistoryEntry: InstallHistoryEntry? = null
    val state: StateFlow<InstallUiState> = mutableState.asStateFlow()
    val history: StateFlow<List<InstallHistoryEntry>> = mutableHistory.asStateFlow()
    val targetCatalog: StateFlow<TargetCatalogUiState> = mutableTargetCatalog.asStateFlow()

    init {
        refresh()
    }

    /**
     * The folder a debug run would read from, or null for the ordinary feed
     * path. Both halves have to hold: the switch, and a folder whose read
     * permission this app still has. Asked at the moment it is used rather than
     * cached, because either half can change between one run and the next.
     */
    private fun debugFolder(): LocalPayloadFolder? =
        if (AppPreferences.debugMode(app)) localSource.folder() else null

    fun refresh() {
        if (installJob?.isActive == true) return
        mutableHistory.value = historyStore.prune(HISTORY_LIMIT, activeHistoryEntry?.id)
        discoveryJob?.cancel()
        discoveryJob = viewModelScope.launch(Dispatchers.IO) {
            val probe = NativeProbe.run()
            val debug = debugFolder()
            val next = when {
                // Debug mode answers this screen without the network, because the
                // profile it would look for is the one deliberately not in the
                // feed. A folder that does not hold a payload is reported here
                // rather than at the start of a run.
                debug != null -> try {
                    val target = localSource.resolve()
                    val installed = detectInstalled()
                    InstallUiState(
                        phase = if (installed) InstallPhase.Installed else InstallPhase.Ready,
                        message = app.getString(
                            if (installed) R.string.status_ksu_active else R.string.status_not_installed,
                        ),
                        probeOutput = probe,
                        log = "$probe\n${app.getString(R.string.log_profile, target.profile.profileId)}" +
                            "\n${app.getString(R.string.log_local_source, debug.label)}",
                        latestPayloadTag = target.releaseTag,
                        kernelSu = target.profile.kernelSu,
                        localPayload = debug.label,
                    )
                } catch (error: Throwable) {
                    InstallUiState(
                        phase = InstallPhase.Failed,
                        message = app.getString(R.string.status_local_failed),
                        probeOutput = probe,
                        log = "$probe\n[-] ${error.message ?: error.javaClass.simpleName}",
                        localPayload = debug.label,
                    )
                }
                detectInstalled() -> InstallUiState(
                    phase = InstallPhase.Installed,
                    message = app.getString(R.string.status_ksu_active),
                    probeOutput = probe,
                    log = probe,
                    // Which manager to fetch is the one thing still to be done
                    // once KernelSU is loaded, and it comes from the feed. The
                    // branch is otherwise offline, so this is asked for rather
                    // than required: without an answer the overview says what
                    // it always said.
                    kernelSu = runCatching {
                        repository.resolveTarget(DeviceSnapshot.current()).profile.kernelSu
                    }.getOrNull(),
                )
                else -> try {
                    val target = repository.resolveTarget(DeviceSnapshot.current())
                    InstallUiState(
                        phase = InstallPhase.Ready,
                        message = app.getString(R.string.status_not_installed),
                        probeOutput = probe,
                        log = "$probe\n${app.getString(R.string.log_profile, target.profile.profileId)}",
                        latestPayloadTag = target.releaseTag,
                        kernelSu = target.profile.kernelSu,
                    )
                } catch (error: Throwable) {
                    InstallUiState(
                        phase = InstallPhase.Failed,
                        message = app.getString(R.string.status_support_failed),
                        probeOutput = probe,
                        log = "$probe\n[-] ${error.message ?: error.javaClass.simpleName}",
                    )
                }
            }
            // Assigned here rather than at each branch, and only if this job is
            // still the current one: install() cancels discovery, but cancelling
            // cannot interrupt the blocking network call this job parks in, so a
            // discovery started first can still return mid-install and would
            // otherwise drop a whole fresh state on top of the running install.
            if (isActive) mutableState.value = next
        }
    }

    fun loadTargetCatalog() {
        if (mutableTargetCatalog.value.loading) return
        viewModelScope.launch(Dispatchers.IO) {
            mutableTargetCatalog.value = TargetCatalogUiState(loading = true)
            mutableTargetCatalog.value = try {
                TargetCatalogUiState(
                    profiles = repository.loadTargets().sortedWith(
                        compareBy(
                            TargetProfile::kernelRelease,
                            TargetProfile::kernelBuildVersion,
                            TargetProfile::model,
                            TargetProfile::buildDisplay,
                        ),
                    ),
                )
            } catch (error: Throwable) {
                TargetCatalogUiState(error = error.message ?: error.javaClass.simpleName)
            }
        }
    }

    fun install(profileId: String? = null) {
        if (installJob?.isActive == true || mutableState.value.phase == InstallPhase.Installed) return
        discoveryJob?.cancel()
        payloadCheckJob?.cancel()
        installJob = viewModelScope.launch(Dispatchers.IO) {
            val debug = debugFolder()
            mutableState.value = InstallUiState(
                phase = InstallPhase.Checking,
                probeOutput = mutableState.value.probeOutput,
                // Carried across the reset: the run is about to resolve the
                // same profile again, and the manager it needs does not stop
                // being true while the install is in flight.
                kernelSu = mutableState.value.kernelSu,
                localPayload = debug?.label,
            )
            startHistory()
            try {
                // Before anything is fetched: a run cannot leak the kernel base while
                // the file it reads the answer out of is mounted over, and a reboot is
                // the only way to clear that. See leakChannelPinned().
                if (leakChannelPinned()) throw RunSkipped(app.getString(R.string.error_leak_channel_pinned))
                // Debug mode on with no usable folder is its own failure, not a
                // reason to fall back to the feed: the folder can stop being
                // readable after it was picked -- deleted, or its grant revoked
                // -- and a run that quietly went to the feed instead would
                // report whatever the feed says, which on a target that is not in
                // it reads as a network problem.
                if (AppPreferences.debugMode(app) && debug == null) {
                    error(app.getString(R.string.local_no_folder))
                }
                val target = if (debug != null) {
                    // Debug mode wins over a profile picked from the catalogue,
                    // because the folder is the only thing that can say what the
                    // local files are for. Said out loud rather than silently
                    // dropping the selection.
                    if (profileId != null) {
                        appendLog(app.getString(R.string.log_local_overrides, profileId))
                    }
                    setPhase(InstallPhase.Checking, app.getString(R.string.status_reading_local))
                    appendLog(app.getString(R.string.log_local_source, debug.label))
                    localSource.resolve()
                } else {
                    setPhase(InstallPhase.Checking, app.getString(R.string.status_checking_github))
                    if (profileId == null) {
                        repository.resolveTarget(DeviceSnapshot.current())
                    } else {
                        repository.resolveTarget(profileId)
                    }
                }
                mutableState.value = mutableState.value.copy(
                    payloadTag = target.releaseTag,
                    kernelSu = target.profile.kernelSu,
                )
                appendLog(app.getString(R.string.log_profile, target.profile.profileId))
                appendLog(app.getString(R.string.log_payload_release, target.releaseTag))

                setPhase(InstallPhase.Downloading, app.getString(R.string.status_downloading_payload))
                val payloads = if (debug != null) {
                    localSource.load(target) { appendLog("[*] $it") }
                } else {
                    repository.download(target) { appendLog("[*] $it") }
                }
                appendLog(
                    app.getString(
                        if (debug != null) R.string.log_local_ready else R.string.log_download_verified,
                    ),
                )

                setPhase(InstallPhase.Exploiting, app.getString(R.string.status_exploit_running))
                executeExploit(payloads.exploit)

                setPhase(InstallPhase.LoadingKernelSu, app.getString(R.string.status_ksu_loading))
                installKernelSu(payloads)

                setPhase(InstallPhase.Installed, app.getString(R.string.status_ksu_active))
                appendLog(app.getString(R.string.log_install_complete))
                finishHistory(InstallRunResult.Succeeded)
            } catch (skipped: RunSkipped) {
                // Not a failure: the run was refused before it touched anything, and
                // the reader should not go looking for a cause in the log.
                appendLog("[*] ${skipped.message}")
                setPhase(InstallPhase.Skipped, app.getString(R.string.status_install_skipped))
                finishHistory(InstallRunResult.Skipped)
            } catch (error: Throwable) {
                appendLog("[-] ${error.message ?: error.javaClass.simpleName}")
                setPhase(InstallPhase.Failed, app.getString(R.string.status_install_failed))
                finishHistory(InstallRunResult.Failed)
            }
            // After both outcomes, outside the try, and in a job of its own.
            // Outside the try because a check that cannot reach GitHub must not
            // turn a run that succeeded into a failed one. In its own job --
            // parented to viewModelScope, not to this coroutine -- because the
            // check makes a network call, and every button on the finished
            // screen, Retry and force fetch alike, guards on installJob still
            // being active and would look dead for as long as it ran.
            startPayloadCheck()
        }
    }

    /**
     * Asks what the payload repository publishes now and compares it with what
     * the run just used. Forced past any cache -- an answer repeated from one is
     * exactly the thing that would make a stale payload look current.
     */
    private fun startPayloadCheck() {
        val used = mutableState.value.payloadTag ?: return
        // A local payload has no release to be current or outdated against, and
        // asking GitHub what it publishes would answer a question this run did
        // not pose.
        if (mutableState.value.localPayload != null) return
        payloadCheckJob?.cancel()
        payloadCheckJob = viewModelScope.launch(Dispatchers.IO) {
            val latest = runCatching { repository.latestReleaseTag(forceRefresh = true) }.getOrNull()
            // Same reason discovery checks before assigning: cancelling cannot
            // interrupt the blocking call, and by the time it returns the user
            // may have started another run whose state this must not touch.
            if (!isActive || mutableState.value.payloadTag != used) return@launch
            if (latest == null) {
                appendLog(app.getString(R.string.log_payload_check_failed))
                return@launch
            }
            mutableState.value = mutableState.value.copy(
                latestPayloadTag = latest,
                payloadState = if (latest == used) PayloadState.Current else PayloadState.Outdated,
            )
            if (latest != used) appendLog(app.getString(R.string.log_payload_newer, latest))
        }
    }

    /**
     * Re-reads the release and pulls its artifacts down again, discarding what
     * is on the device. It stops there: the next run resolves the release for
     * itself, so this refreshes what is stored and what is displayed rather than
     * handing bytes to an install.
     */
    fun forceFetchPayload(profileId: String? = null) {
        if (installJob?.isActive == true) return
        if (mutableState.value.payloadState == PayloadState.Fetching) return
        viewModelScope.launch(Dispatchers.IO) {
            val previous = mutableState.value.payloadState
            val debug = debugFolder()
            mutableState.value = mutableState.value.copy(payloadState = PayloadState.Fetching)
            try {
                // In debug mode this re-reads the folder instead of the release,
                // which is what the button means there: pick up a payload that
                // was just rebuilt into it, without going through the picker
                // again.
                val target = if (debug != null) {
                    localSource.resolve()
                } else if (profileId == null) {
                    repository.resolveTarget(DeviceSnapshot.current(), forceRefresh = true)
                } else {
                    repository.resolveTarget(profileId, forceRefresh = true)
                }
                appendLog(app.getString(R.string.log_payload_fetching, target.releaseTag))
                if (debug != null) {
                    localSource.load(target) { appendLog("[*] $it") }
                } else {
                    repository.download(target) { appendLog("[*] $it") }
                }
                mutableState.value = mutableState.value.copy(
                    latestPayloadTag = target.releaseTag,
                    payloadState = PayloadState.Fetched,
                    localPayload = debug?.label,
                )
                appendLog(app.getString(R.string.log_payload_fetched, target.releaseTag))
            } catch (error: Throwable) {
                appendLog("[-] ${error.message ?: error.javaClass.simpleName}")
                // Back to what it was, not to Fetched: the newer release may not
                // carry a profile for this device at all, and the button has to
                // stay usable when it does not.
                mutableState.value = mutableState.value.copy(payloadState = previous)
            }
        }
    }

    fun deleteHistoryEntry(id: String) {
        viewModelScope.launch(Dispatchers.IO) {
            // Dropping the reference first is what makes the delete stick: a run
            // still in flight rewrites its own file on every log line, so leaving
            // it attached would put the entry straight back.
            if (activeHistoryEntry?.id == id) activeHistoryEntry = null
            historyStore.delete(id)
            mutableHistory.value = historyStore.load()
        }
    }

    fun clearHistory() {
        viewModelScope.launch(Dispatchers.IO) {
            activeHistoryEntry = null
            historyStore.clearAll()
            // The entry logs are copies of these files, which the payload writes and
            // which otherwise survive until a later run sweeps them. Clearing the
            // copies and leaving the originals is not a clear.
            RunScratch.sweep(exploitLogDirectory(), keep = null)
            mutableHistory.value = emptyList()
        }
    }

    private suspend fun executeExploit(payload: File) {
        // Fresh name per run, and the previous run's logs swept, for the same reason
        // the payload files are named that way -- see RunScratch. The logs have a
        // directory of their own so that sweeping it cannot reach anything else.
        val run = RunScratch.token()
        RunScratch.sweep(exploitLogDirectory(), run)
        val logFile = exploitLogFile(run)
        val helper = helperFile()
        require(helper.canExecute()) { app.getString(R.string.error_helper_unavailable) }
        val logPrefix = mutableState.value.log
        val bootToken = currentBootToken()
        val processBuilder = ProcessBuilder(
            helper.absolutePath,
            "--run-payload",
            payload.absolutePath,
            helper.absolutePath,
            logFile.absolutePath,
        ).redirectErrorStream(true)
        cachedP0Offset(bootToken)?.let { processBuilder.environment()[P0_OFFSET_ENV] = it }
        val process = processBuilder.start()

        try {
            val startedAt = SystemClock.elapsedRealtime()
            var lastProgressAt = startedAt
            var lastRawLog = ""
            while (process.isAlive) {
                val rawLog = logFile.readTextIfPresent()
                if (rawLog != lastRawLog) {
                    cacheP0Offset(bootToken, rawLog)
                    publishExploitLog(logPrefix, rawLog)
                    lastRawLog = rawLog
                    lastProgressAt = SystemClock.elapsedRealtime()
                }
                val now = SystemClock.elapsedRealtime()
                require(now - lastProgressAt < EXPLOIT_STALL_MILLIS) {
                    app.getString(R.string.error_exploit_stalled)
                }
                require(now - startedAt < EXPLOIT_TOTAL_MILLIS) {
                    app.getString(R.string.error_exploit_timeout)
                }
                delay(LOG_POLL_INTERVAL)
            }

            val exitCode = process.waitFor()
            val rawLog = logFile.readTextIfPresent()
            cacheP0Offset(bootToken, rawLog)
            publishExploitLog(logPrefix, rawLog)
            val earlyOutput = process.inputStream.bufferedReader().use { it.readText() }.trim()
            require(exitCode == 0) {
                app.getString(
                    R.string.error_payload_exit,
                    exitCode,
                    earlyOutput.takeIf(String::isNotBlank)?.let { " ($it)" } ?: "",
                )
            }
            require(rawLog.contains("exploit completed") && rawLog.contains("done=1 root=1")) {
                app.getString(R.string.error_success_marker)
            }
        } finally {
            if (process.isAlive) {
                process.destroy()
                delay(500.milliseconds)
                if (process.isAlive) process.destroyForcibly()
            }
        }
        appendLog(app.getString(R.string.log_bootstrap_root))
    }

    private fun publishExploitLog(prefix: String, rawLog: String) {
        mutableState.value = mutableState.value.copy(
            log = listOf(prefix, stripAnsi(rawLog))
                .filter(String::isNotBlank)
                .joinToString("\n"),
        )
        updateHistoryEntry()
    }

    private fun installKernelSu(payloads: VerifiedPayloads) {
        val source = shellQuote(payloads.kernelSu.absolutePath)
        val stageCommand =
            "/system/bin/cp $source /data/local/tmp/ksud && " +
                "/system/bin/cp $source /data/local/tmp/.ksud-stage && " +
                "/system/bin/chmod 755 /data/local/tmp/ksud /data/local/tmp/.ksud-stage"
        val stage = runHelper("-c", stageCommand)
        require(stage.code == 0) { app.getString(R.string.error_ksu_stage, stage.output) }
        appendLog(app.getString(R.string.log_ksu_staged))

        // ksud embeds one module per KMI and picks by the name it is given, so
        // these are properties of the target rather than of the helper. The
        // feed carries both; passing them is what lets a profile on a
        // different GKI branch load at all.
        val lateLoad = runHelper(
            "--late-load",
            payloads.profile.kernelSu.kmi,
            payloads.profile.kernelSu.managerPackage,
        )
        require(lateLoad.code == 0) {
            app.getString(R.string.error_ksu_verify, lateLoad.code, lateLoad.output)
        }
        if (lateLoad.output.isNotBlank()) appendLog(lateLoad.output)
        storeInstallReceipt()
        appendLog(app.getString(R.string.log_ksu_control_verified))
    }

    private fun detectInstalled(): Boolean {
        if (NativeProbe.isKernelSuActive()) return true
        val bootToken = currentBootToken() ?: return false
        val receipt = app.getSharedPreferences(INSTALL_RECEIPT, Application.MODE_PRIVATE)
        return receipt.getString(RECEIPT_BOOT_TOKEN, null) == bootToken &&
            receipt.getBoolean(RECEIPT_VERIFIED, false)
    }

    private fun storeInstallReceipt() {
        val bootToken = currentBootToken() ?: error(app.getString(R.string.error_boot_id))
        val stored = app.getSharedPreferences(INSTALL_RECEIPT, Application.MODE_PRIVATE)
            .edit()
            .putString(RECEIPT_BOOT_TOKEN, bootToken)
            .putBoolean(RECEIPT_VERIFIED, true)
            .commit()
        require(stored) { app.getString(R.string.error_receipt) }
    }

    private fun currentBootToken(): String? = runCatching {
        File("/proc/sys/kernel/random/boot_id")
            .readText(Charsets.US_ASCII)
            .trim()
            .takeIf(String::isNotBlank)
    }.getOrNull()

    private fun cachedP0Offset(bootToken: String?): String? {
        if (bootToken == null) return null
        val stored = app.getSharedPreferences(P0_CACHE, Application.MODE_PRIVATE)
        if (stored.getString(P0_CACHE_BOOT_TOKEN, null) != bootToken) return null
        return stored.getString(P0_CACHE_OFFSET, null)
    }

    private fun cacheP0Offset(bootToken: String?, log: String) {
        if (bootToken == null) return
        val match = P0_OFFSET_PATTERN.findAll(log).lastOrNull() ?: return
        val offset = match.groupValues[1].toLongOrNull(16) ?: return
        if (offset !in 0..P0_OFFSET_MAX || offset and P0_OFFSET_MASK != 0L) return
        val value = "0x${offset.toString(16)}"
        val stored = app.getSharedPreferences(P0_CACHE, Application.MODE_PRIVATE)
        if (stored.getString(P0_CACHE_BOOT_TOKEN, null) == bootToken &&
            stored.getString(P0_CACHE_OFFSET, null) == value
        ) return
        stored.edit()
            .putString(P0_CACHE_BOOT_TOKEN, bootToken)
            .putString(P0_CACHE_OFFSET, value)
            .apply()
    }

    /**
     * Whether a previous run has pinned `/proc/sys/kernel/random/boot_id`.
     *
     * The exploit leaks the kernel base by reading that file, and it has no other
     * channel at that point in the run -- establishing a kernel read is what the leak
     * is for. After a run takes root, `su_daemon`'s `pin_boot_id()` bind-mounts the
     * boot id the device actually started with over the same path, so that libcutils
     * can keep computing `/dev/ashmem<boot_id>` and applications keep launching.
     *
     * Both are needed and they want the same file. While the mount is there the leak
     * reads a real UUID, every attempt is rejected, and the run spends fifteen minutes
     * failing identically. A mount does not survive a reboot, and a pin only exists
     * because this boot has already been rooted once, so refusing here and saying so
     * is the whole of the fix.
     */
    private fun leakChannelPinned(): Boolean = runCatching {
        // Mount targets are the second field, so match the path with its separators.
        File("/proc/self/mounts").readText().contains(" /proc/sys/kernel/random/boot_id ")
    }.getOrDefault(false)

    private fun exploitLogDirectory() =
        File(app.filesDir, "exploit-logs").apply { mkdirs() }

    private fun exploitLogFile(run: String) = File(exploitLogDirectory(), "exploit-$run.log")

    private fun helperFile() = File(app.applicationInfo.nativeLibraryDir, "libcve43499root.so")

    private fun runHelper(vararg arguments: String): CommandResult {
        val process = ProcessBuilder(listOf(helperFile().absolutePath) + arguments)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().use { it.readText() }
        return CommandResult(process.waitFor(), stripAnsi(output.trim()))
    }

    private fun shellQuote(value: String) = "'${value.replace("'", "'\\''")}'"

    private fun setPhase(phase: InstallPhase, message: String) {
        mutableState.value = mutableState.value.copy(phase = phase, message = message)
        appendLog("[*] $message")
    }

    private fun appendLog(line: String) {
        val cleanLine = stripAnsi(line).trim()
        if (cleanLine.isBlank()) return
        mutableState.value = mutableState.value.copy(
            log = (mutableState.value.log + "\n" + cleanLine).trim(),
        )
        updateHistoryEntry()
    }

    private fun startHistory() {
        val entry = historyStore.create()
        activeHistoryEntry = entry
        publishHistory(entry)
    }

    private fun updateHistoryEntry() {
        val entry = activeHistoryEntry ?: return
        val updated = entry.copy(
            log = mutableState.value.log,
            payloadTag = mutableState.value.payloadTag,
        )
        activeHistoryEntry = updated
        historyStore.save(updated)
        publishHistory(updated)
    }

    private fun finishHistory(result: InstallRunResult) {
        val entry = activeHistoryEntry ?: return
        val completed = entry.copy(
            completedAtMillis = System.currentTimeMillis(),
            result = result,
            log = mutableState.value.log,
        )
        activeHistoryEntry = null
        historyStore.save(completed)
        // The cap is applied here as well as on refresh(), so that a session
        // that installs repeatedly without a restart still stays bounded.
        mutableHistory.value = historyStore.prune(HISTORY_LIMIT)
    }

    private fun publishHistory(entry: InstallHistoryEntry) {
        mutableHistory.value = (mutableHistory.value.filterNot { it.id == entry.id } + entry)
            .sortedByDescending(InstallHistoryEntry::startedAtMillis)
    }

    private fun File.readTextIfPresent(): String = if (exists()) readText() else ""

    companion object {
        private const val HISTORY_LIMIT = 20
        // Phase 0 (docs/PLAN-untrusted_app-fix.md): a slow untrusted_app slide
        // attempt needs longer before the watchdog treats it as stalled. The old
        // 90 s / 900 s killed mid-write and left boot_id/nf_logger corrupted.
        private const val EXPLOIT_STALL_MILLIS = 300_000L
        private const val EXPLOIT_TOTAL_MILLIS = 1_800_000L
        private const val INSTALL_RECEIPT = "install_receipt"
        private const val RECEIPT_BOOT_TOKEN = "kernel_boot_id"
        private const val RECEIPT_VERIFIED = "verified"
        private const val P0_CACHE = "p0_cache"
        private const val P0_CACHE_BOOT_TOKEN = "kernel_boot_id"
        private const val P0_CACHE_OFFSET = "offset"
        private const val P0_OFFSET_ENV = "SLIDE_P0_OFFSET"
        // Samsung's placement offset fits in 0x1f0000; a real arm64 KASLR slide does
        // not -- this device reports around 0x106c600000.
        private const val P0_OFFSET_MAX = 0x4000000000L
        private const val P0_OFFSET_MASK = 0xffffL
        private val LOG_POLL_INTERVAL = 250.milliseconds
        private val ANSI_ESCAPE = Regex("\u001B\\[[0-?]*[ -/]*[@-~]")
        private val P0_OFFSET_PATTERN = Regex(
            "slide-kaslr-ok[^\\n]*slide=([0-9a-fA-F]{16})",
        )

        private fun stripAnsi(value: String): String = ANSI_ESCAPE.replace(value, "").replace("\r", "")
    }
}
