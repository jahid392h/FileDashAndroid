package com.filedash.app

import android.content.Context
import android.util.Base64
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.TimeZone

/** Installs the web files and runs the bundled PHP built-in server (127.0.0.1) that the WebView talks to. */
object PhpRuntime {
    const val PORT = 47615

    private var process: Process? = null
    private var runningRoot: String? = null
    private var helper: HelperServer? = null
    private var helperToken = ""

    fun phpBinary(ctx: Context) = File(ctx.applicationInfo.nativeLibraryDir, "libphp.so")
    fun hasPhp(ctx: Context) = phpBinary(ctx).exists()

    /** secret that only this app's WebView knows (sent as cookie; the PHP router rejects everything else). */
    fun appToken(ctx: Context): String {
        val p = ctx.getSharedPreferences("fd", Context.MODE_PRIVATE)
        p.getString("token", null)?.let { return it }
        val b = ByteArray(24); SecureRandom().nextBytes(b)
        val t = b.joinToString("") { "%02x".format(it) }
        p.edit().putString("token", t).apply()
        return t
    }

    private fun copyAssets(ctx: Context, from: String, to: File) {
        val list = ctx.assets.list(from) ?: emptyArray()
        if (list.isEmpty()) {          // a file
            to.parentFile?.mkdirs()
            ctx.assets.open(from).use { i -> to.outputStream().use { o -> i.copyTo(o) } }
        } else {
            to.mkdirs()
            for (n in list) copyAssets(ctx, "$from/$n", File(to, n))
        }
    }

    private fun writeCaBundle(f: File) {
        if (f.exists() && f.length() > 1000) return
        val ks = KeyStore.getInstance("AndroidCAStore"); ks.load(null)
        val sb = StringBuilder()
        for (alias in ks.aliases()) {
            val c = ks.getCertificate(alias) as? X509Certificate ?: continue
            sb.append("-----BEGIN CERTIFICATE-----\n")
            sb.append(Base64.encodeToString(c.encoded, Base64.NO_WRAP).chunked(64).joinToString("\n"))
            sb.append("\n-----END CERTIFICATE-----\n")
        }
        f.writeText(sb.toString())
    }

    fun ping(): Boolean = try {
        val c = URL("http://127.0.0.1:$PORT/__ping").openConnection() as HttpURLConnection
        c.connectTimeout = 800; c.readTimeout = 1500
        val ok = c.responseCode == 200
        c.disconnect(); ok
    } catch (e: Exception) { false }

    fun isRunning(root: String): Boolean = process?.isAlive == true && runningRoot == root && ping()

    @Synchronized
    fun stop() { try { process?.destroy() } catch (e: Exception) {}; process = null; runningRoot = null }

    /** Blocks until the server answers (or throws). Call from a background thread. */
    @Synchronized
    fun start(ctx: Context, root: File) {
        if (isRunning(root.path)) return
        stop()
        val bin = phpBinary(ctx)
        if (!bin.exists()) throw IllegalStateException("PHP binary (libphp.so) is not inside this APK")
        bin.setExecutable(true)

        val files = ctx.filesDir
        val www = File(files, "www")
        copyAssets(ctx, "www", www)                         // index.php, assets-setup.php, router.php (keeps .filedash)
        val tmp = File(files, "tmp"); File(tmp, "sessions").mkdirs()
        val ca = File(files, "cacert.pem"); try { writeCaBundle(ca) } catch (e: Exception) {}

        if (helper == null) { helperToken = appToken(ctx).reversed(); helper = HelperServer(helperToken).also { it.start() } }

        val cmd = mutableListOf(
            bin.path, "-n", "-S", "127.0.0.1:$PORT", "-t", root.path,
            "-d", "display_errors=0", "-d", "log_errors=1", "-d", "error_log=${File(files, "php_errors.log").path}",
            "-d", "memory_limit=1024M", "-d", "max_execution_time=0", "-d", "max_input_time=-1",
            "-d", "upload_max_filesize=4G", "-d", "post_max_size=4G", "-d", "max_file_uploads=1000",
            "-d", "upload_tmp_dir=${tmp.path}", "-d", "sys_temp_dir=${tmp.path}", "-d", "session.save_path=${File(tmp, "sessions").path}",
            "-d", "date.timezone=${TimeZone.getDefault().id}", "-d", "allow_url_fopen=1", "-d", "default_charset=UTF-8",
            "-d", "curl.cainfo=${ca.path}", "-d", "openssl.cafile=${ca.path}",
            File(www, "router.php").path
        )
        val pb = ProcessBuilder(cmd).directory(root).redirectErrorStream(true)
        pb.redirectOutput(File(files, "php_server.log"))
        pb.environment().apply {
            put("HOME", files.path); put("TMPDIR", tmp.path)
            put("PHP_CLI_SERVER_WORKERS", "4")
            put("FD_APP_TOKEN", appToken(ctx)); put("FD_APP_ROOT", root.path)
            put("FD_HELPER_PORT", helper!!.port.toString()); put("FD_HELPER_TOKEN", helperToken)
            put("SSL_CERT_FILE", ca.path)
        }
        process = pb.start(); runningRoot = root.path

        val end = System.currentTimeMillis() + 20000
        while (System.currentTimeMillis() < end) {
            if (ping()) return
            if (process?.isAlive != true) break
            Thread.sleep(150)
        }
        val log = try { File(files, "php_server.log").readText().takeLast(600) } catch (e: Exception) { "" }
        stop()
        throw IllegalStateException("PHP server did not start. $log")
    }
}
