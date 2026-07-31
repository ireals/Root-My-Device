package org.witaqua.pwn.device

import android.content.Context
import android.system.Os
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

data class VerifiedPayloads(
    val profile: TargetProfile,
    val releaseTag: String,
    val exploit: File,
    val kernelSu: File,
)

/**
 * A profile together with the payload release it was read out of. The two travel
 * together because the release is what dates a run: the profile alone cannot say
 * whether the artifacts behind it are still the ones being published.
 */
data class ResolvedTarget(
    val releaseTag: String,
    val profile: TargetProfile,
)

/**
 * The payload release the feed and every artifact are read from. The payload
 * repository builds its artifacts in CI and publishes them under a tag that is
 * unique to that run, so a resolved release is an immutable set: the assets
 * behind [downloadPrefix] never change once the release exists.
 */
private data class PayloadRelease(
    val tag: String,
    val downloadPrefix: String,
    val feedUrl: String,
)

class PayloadRepository(private val context: Context) {
    fun loadTargets(forceRefresh: Boolean = false): List<TargetProfile> =
        loadFeed(forceRefresh).second

    fun resolveTarget(snapshot: DeviceSnapshot, forceRefresh: Boolean = false): ResolvedTarget {
        val (tag, targets) = loadFeed(forceRefresh)
        val profile = targets.firstOrNull { it.matches(snapshot) }
            ?: error(context.getString(R.string.repo_no_profile))
        return ResolvedTarget(tag, profile)
    }

    fun resolveTarget(profileId: String, forceRefresh: Boolean = false): ResolvedTarget {
        val (tag, targets) = loadFeed(forceRefresh)
        val profile = targets.firstOrNull { it.profileId == profileId }
            ?: error(context.getString(R.string.repo_profile_missing, profileId))
        return ResolvedTarget(tag, profile)
    }

    /**
     * The tag of the release the payloads are published under right now, read
     * without the feed behind it. This is the cheap half of [loadFeed], for
     * asking whether a run that already happened used the current payload.
     */
    fun latestReleaseTag(forceRefresh: Boolean): String = resolveLatestRelease(forceRefresh).tag

    private fun loadFeed(forceRefresh: Boolean): Pair<String, List<TargetProfile>> {
        val release = resolveLatestRelease(forceRefresh)
        val manifestBytes = downloadBytes(release.feedUrl, MAX_MANIFEST_BYTES, forceRefresh)
        val targets = SupportManifest.parse(manifestBytes).targets.map { profile -> profile.copy(
            exploit = profile.exploit.copy(url = requireReleaseAsset(profile.exploit.url, release)),
            kernelSu = profile.kernelSu.copy(
                artifact = profile.kernelSu.artifact.copy(
                    url = requireReleaseAsset(profile.kernelSu.artifact.url, release),
                ),
            ),
        ) }
        return release.tag to targets
    }

    fun download(target: ResolvedTarget, onProgress: (String) -> Unit): VerifiedPayloads {
        val profile = target.profile
        val directory = File(context.filesDir, "payloads/${profile.profileId}").apply { mkdirs() }
        val run = RunScratch.token()
        RunScratch.sweep(directory, run)
        val exploit = downloadArtifact(
            profile.exploit,
            File(directory, "cve-2026-43499-app-$run.so"),
            context.getString(R.string.artifact_exploit),
            onProgress,
        )
        val kernelSu = downloadArtifact(
            profile.kernelSu.artifact,
            File(directory, "ksud-$run"),
            context.getString(R.string.artifact_kernelsu),
            onProgress,
        )
        Os.chmod(exploit.absolutePath, 0b100100100)
        Os.chmod(kernelSu.absolutePath, 0b100100100)
        return VerifiedPayloads(profile, target.releaseTag, exploit, kernelSu)
    }

    private fun downloadArtifact(
        artifact: RemoteArtifact,
        destination: File,
        label: String,
        onProgress: (String) -> Unit,
    ): File {
        onProgress(context.getString(R.string.repo_downloading, label))
        val connection = open(artifact.url)
        require(connection.contentLengthLong == -1L || connection.contentLengthLong == artifact.size) {
            context.getString(R.string.repo_size_mismatch, label)
        }
        var total = 0L
        connection.inputStream.use { input ->
            FileOutputStream(destination).use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= artifact.size) {
                        context.getString(R.string.repo_size_exceeded, label)
                    }
                    output.write(buffer, 0, count)
                }
                output.fd.sync()
            }
        }
        connection.disconnect()
        require(total == artifact.size) { context.getString(R.string.repo_incomplete, label) }
        onProgress(context.getString(R.string.repo_verified, label))
        return destination
    }

    private fun resolveLatestRelease(forceRefresh: Boolean): PayloadRelease {
        val response = downloadBytes(LATEST_RELEASE_API_URL, MAX_RELEASE_RESPONSE_BYTES, forceRefresh)
        val release = JSONObject(response.toString(Charsets.UTF_8))
        val tag = release.getString("tag_name")
        require(tag.matches(TAG_PATTERN)) { context.getString(R.string.repo_release_invalid) }
        val prefix = "$RELEASE_DOWNLOAD_REPOSITORY/$tag/"
        val assets = release.getJSONArray("assets")
        val feedUrl = (0 until assets.length())
            .map(assets::getJSONObject)
            .firstOrNull { it.getString("name") == FEED_ASSET_NAME }
            ?.getString("browser_download_url")
            ?: error(context.getString(R.string.repo_feed_missing, FEED_ASSET_NAME))
        // The asset URL comes back from the API, but it is still what every
        // subsequent download is anchored to, so hold it to the same rule the
        // feed's own URLs are held to below.
        require(feedUrl.startsWith(prefix)) { context.getString(R.string.repo_url_invalid) }
        return PayloadRelease(tag = tag, downloadPrefix = prefix, feedUrl = feedUrl)
    }

    /**
     * The feed is generated by the same CI run that uploaded the artifacts, so
     * its URLs already carry the release's tag. Verifying that rather than
     * rewriting it keeps a feed that names some other host from redirecting a
     * download away from the release it was published in.
     */
    private fun requireReleaseAsset(url: String, release: PayloadRelease): String {
        require(url.startsWith(release.downloadPrefix)) {
            context.getString(R.string.repo_url_invalid)
        }
        return url
    }

    private fun downloadBytes(url: String, maximum: Int, forceRefresh: Boolean = false): ByteArray {
        val connection = open(url, forceRefresh)
        val bytes = connection.inputStream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= maximum) {
                    context.getString(R.string.repo_response_too_large)
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        connection.disconnect()
        return bytes
    }

    private fun open(url: String, forceRefresh: Boolean = false): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 60_000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "RootMyDevice/${BuildConfig.VERSION_NAME}")
            // A forced fetch is asked for precisely when the answer that came
            // back last time is suspected of being a stale one, so it has to
            // reach past whatever between here and GitHub would answer from a
            // copy -- the platform's own response cache included.
            if (forceRefresh) {
                useCaches = false
                setRequestProperty("Cache-Control", "no-cache")
                setRequestProperty("Pragma", "no-cache")
            }
            connect()
            require(responseCode == HttpURLConnection.HTTP_OK) { "HTTP $responseCode" }
        }

    companion object {
        private const val PAYLOAD_REPOSITORY = "ireals/Root-My-Device-Payloads"
        private const val LATEST_RELEASE_API_URL =
            "https://api.github.com/repos/$PAYLOAD_REPOSITORY/releases/latest"
        private const val RELEASE_DOWNLOAD_REPOSITORY =
            "https://github.com/$PAYLOAD_REPOSITORY/releases/download"
        private const val FEED_ASSET_NAME = "targets-v2.json"
        private val TAG_PATTERN = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
        // A release lists every published artifact, so this response grows with
        // the number of profiles rather than being a fixed handful of fields.
        private const val MAX_RELEASE_RESPONSE_BYTES = 512 * 1024
        private const val MAX_MANIFEST_BYTES = 256 * 1024
    }
}
