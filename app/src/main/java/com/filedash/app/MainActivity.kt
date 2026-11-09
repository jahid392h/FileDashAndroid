package com.filedash.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.view.Gravity
import android.view.ViewGroup
import android.webkit.*
import android.widget.*
import java.io.File
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

class MainActivity : Activity() {

    private lateinit var web: WebView
    private lateinit var splash: LinearLayout
    private lateinit var splashText: TextView
    private lateinit var splashBar: ProgressBar

    private var fileCb: ValueCallback<Array<Uri>>? = null
    private var root: File? = null
    private var waitingForStoragePermission = false
    private var loaded = false
    private var lastBack = 0L

    private val base get() = "http://127.0.0.1:${PhpRuntime.PORT}"

    // ------------------------------------------------------------------ UI
    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val frame = FrameLayout(this).apply { setBackgroundColor(Color.parseColor("#0A0E1A")) }
        web = WebView(this).apply {
            setBackgroundColor(Color.parseColor("#0A0E1A"))
            visibility = android.view.View.INVISIBLE
        }
        frame.addView(web, ViewGroup.LayoutParams(-1, -1))

        splashBar = ProgressBar(this)
        splashText = TextView(this).apply {
            text = "Starting FileDash…"; setTextColor(Color.parseColor("#E8EAF6")); textSize = 15f; gravity = Gravity.CENTER
            setPadding(48, 24, 48, 0)
        }
        splash = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER
            setBackgroundColor(Color.parseColor("#0A0E1A"))
            addView(splashBar); addView(splashText)
        }
        frame.addView(splash, ViewGroup.LayoutParams(-1, -1))
        setContentView(frame)

        setupWebView()
        ensureStorageThenStart()
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun setupWebView() {
        val s = web.settings
        s.javaScriptEnabled = true
        s.domStorageEnabled = true
        s.allowFileAccess = false
        s.allowContentAccess = true
        s.mediaPlaybackRequiresUserGesture = false
        s.useWideViewPort = true
        s.loadWithOverviewMode = false
        s.setSupportZoom(false)
        s.javaScriptCanOpenWindowsAutomatically = false
        CookieManager.getInstance().setAcceptCookie(true)
        web.addJavascriptInterface(Bridge(), "FDAndroid")

        web.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val u = request.url
                if (u.scheme == "blob" || u.scheme == "data" || u.scheme == "about" || u.scheme == "javascript") return false
                if (u.host == "127.0.0.1" && u.port == PhpRuntime.PORT) return false
                try { startActivity(Intent(Intent.ACTION_VIEW, u)) } catch (e: Exception) { toast("Cannot open link") }
                return true
            }

            override fun onPageFinished(view: WebView, url: String) {
                CookieManager.getInstance().flush()
                view.evaluateJavascript(BLOB_HOOK, null)
            }

            override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
                recreate(); return true
            }
        }

        web.webChromeClient = object : WebChromeClient() {
            override fun onShowFileChooser(w: WebView, cb: ValueCallback<Array<Uri>>, p: FileChooserParams): Boolean {
                fileCb?.onReceiveValue(null)
                fileCb = cb
                return try { startActivityForResult(p.createIntent(), REQ_FILE); true } catch (e: Exception) { fileCb = null; false }
            }

            override fun onJsAlert(v: WebView, url: String, msg: String, r: JsResult): Boolean {
                AlertDialog.Builder(this@MainActivity).setMessage(msg)
                    .setPositiveButton("OK") { _, _ -> r.confirm() }.setOnCancelListener { r.cancel() }.show()
                return true
            }

            override fun onJsConfirm(v: WebView, url: String, msg: String, r: JsResult): Boolean {
                AlertDialog.Builder(this@MainActivity).setMessage(msg)
                    .setPositiveButton("OK") { _, _ -> r.confirm() }
                    .setNegativeButton("Cancel") { _, _ -> r.cancel() }.setOnCancelListener { r.cancel() }.show()
                return true
            }

            override fun onJsPrompt(v: WebView, url: String, msg: String, def: String?, r: JsPromptResult): Boolean {
                val input = EditText(this@MainActivity).apply { setText(def ?: ""); setSingleLine() }
                AlertDialog.Builder(this@MainActivity).setMessage(msg).setView(input)
                    .setPositiveButton("OK") { _, _ -> r.confirm(input.text.toString()) }
                    .setNegativeButton("Cancel") { _, _ -> r.cancel() }.setOnCancelListener { r.cancel() }.show()
                return true
            }
        }

        web.setDownloadListener { url, ua, cd, mime, _ -> download(url, ua, cd, mime) }
    }

    // ------------------------------------------------------------------ storage permission → start server
    private fun ensureStorageThenStart() {
        if (Build.VERSION.SDK_INT >= 30) {
            if (Environment.isExternalStorageManager()) { begin(Environment.getExternalStorageDirectory()); return }
            AlertDialog.Builder(this)
                .setTitle("All files access")
                .setMessage("FileDash is a file manager. Allow “All files access” so it can browse, edit and manage the files on your phone.")
                .setCancelable(false)
                .setPositiveButton("Allow") { _, _ ->
                    waitingForStoragePermission = true
                    try {
                        startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName")))
                    } catch (e: Exception) { startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)) }
                }
                .setNegativeButton("Skip") { _, _ -> begin(getExternalFilesDir(null) ?: filesDir) }
                .show()
        } else {
            val need = arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE)
            if (need.all { checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED }) begin(Environment.getExternalStorageDirectory())
            else requestPermissions(need, REQ_PERM)
        }
    }

    override fun onRequestPermissionsResult(code: Int, perms: Array<out String>, res: IntArray) {
        if (code == REQ_PERM) begin(if (res.isNotEmpty() && res.all { it == PackageManager.PERMISSION_GRANTED }) Environment.getExternalStorageDirectory() else (getExternalFilesDir(null) ?: filesDir))
    }

    override fun onResume() {
        super.onResume()
        if (waitingForStoragePermission && Build.VERSION.SDK_INT >= 30) {
            if (Environment.isExternalStorageManager()) { waitingForStoragePermission = false; begin(Environment.getExternalStorageDirectory()) }
            return
        }
        // server may have been killed while the app was in the background → bring it back
        val r = root
        if (r != null && loaded) thread { if (!PhpRuntime.isRunning(r.path)) runOnUiThread { loaded = false; begin(r) } }
    }

    // ------------------------------------------------------------------ start PHP, then load the web UI
    private fun begin(r: File) {
        root = r
        splash.visibility = android.view.View.VISIBLE; splashBar.visibility = android.view.View.VISIBLE
        splashText.text = "Starting FileDash…"
        thread {
            try {
                PhpRuntime.start(applicationContext, r)
                runOnUiThread {
                    CookieManager.getInstance().setCookie(base, "fd_app=${PhpRuntime.appToken(this)}; Path=/; Max-Age=31536000")
                    CookieManager.getInstance().flush()
                    web.visibility = android.view.View.VISIBLE
                    splash.visibility = android.view.View.GONE
                    loaded = true
                    web.loadUrl("$base/")
                }
            } catch (e: Exception) {
                runOnUiThread {
                    splashBar.visibility = android.view.View.GONE
                    splashText.text = "Could not start FileDash\n\n${e.message}"
                }
            }
        }
    }

    // ------------------------------------------------------------------ uploads / downloads
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQ_FILE) {
            fileCb?.onReceiveValue(if (resultCode == RESULT_OK) WebChromeClient.FileChooserParams.parseResult(resultCode, data) else null)
            fileCb = null
        } else super.onActivityResult(requestCode, resultCode, data)
    }

    private fun downloadsDir(): File {
        val d = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        return try { d.mkdirs(); if (d.canWrite()) d else (getExternalFilesDir(null) ?: filesDir) } catch (e: Exception) { getExternalFilesDir(null) ?: filesDir }
    }

    private fun uniqueFile(dir: File, name: String): File {
        val clean = name.replace(Regex("[\\\\/:*?\"<>|]"), "_").ifBlank { "download" }
        var f = File(dir, clean)
        val dot = clean.lastIndexOf('.')
        val stem = if (dot > 0) clean.substring(0, dot) else clean
        val ext = if (dot > 0) clean.substring(dot) else ""
        var n = 1
        while (f.exists()) f = File(dir, "$stem ($n)$ext").also { n++ }
        return f
    }

    private fun saveStream(name: String, input: InputStream): File {
        val f = uniqueFile(downloadsDir(), name)
        f.outputStream().use { o -> input.copyTo(o) }
        return f
    }

    private fun download(url: String, ua: String?, cd: String?, mime: String?) {
        if (url.startsWith("blob:") || url.startsWith("data:")) return          // handled by BLOB_HOOK
        toast("Downloading…")
        thread {
            try {
                val c = URL(url).openConnection() as HttpURLConnection
                CookieManager.getInstance().getCookie(url)?.let { c.setRequestProperty("Cookie", it) }
                if (!ua.isNullOrBlank()) c.setRequestProperty("User-Agent", ua)
                c.connectTimeout = 15000; c.readTimeout = 60000
                val name = URLUtil.guessFileName(url, cd, mime)
                val f = c.inputStream.use { saveStream(name, it) }
                c.disconnect()
                toast("Saved: ${f.parentFile?.name}/${f.name}")
            } catch (e: Exception) { toast("Download failed: ${e.message}") }
        }
    }

    /** blob: downloads made by the page's JavaScript (e.g. exports) arrive here as base64. */
    inner class Bridge {
        @JavascriptInterface
        fun saveBase64(name: String, mime: String, b64: String) {
            thread {
                try {
                    val bytes = android.util.Base64.decode(b64, android.util.Base64.DEFAULT)
                    val f = saveStream(name, bytes.inputStream())
                    toast("Saved: ${f.parentFile?.name}/${f.name}")
                } catch (e: Exception) { toast("Save failed: ${e.message}") }
            }
        }
    }

    private fun toast(msg: String) = runOnUiThread { Toast.makeText(this, msg, Toast.LENGTH_SHORT).show() }

    // ------------------------------------------------------------------ lifecycle
    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (web.visibility == android.view.View.VISIBLE && web.canGoBack()) { web.goBack(); return }
        val now = System.currentTimeMillis()
        if (now - lastBack < 2000) super.onBackPressed() else { lastBack = now; toast("Press back again to exit") }
    }

    override fun onDestroy() {
        if (isFinishing) PhpRuntime.stop()
        web.destroy()
        super.onDestroy()
    }

    companion object {
        private const val REQ_FILE = 11
        private const val REQ_PERM = 12

        private const val BLOB_HOOK = """
(function(){ if (window.__fdHook) return; window.__fdHook = 1;
  document.addEventListener('click', function(e){
    var a = e.target && e.target.closest ? e.target.closest('a[download]') : null;
    if (!a || !a.href || a.href.indexOf('blob:') !== 0) return;
    e.preventDefault(); e.stopPropagation();
    var name = a.getAttribute('download') || 'download';
    fetch(a.href).then(function(r){ return r.blob(); }).then(function(b){
      var fr = new FileReader();
      fr.onload = function(){ FDAndroid.saveBase64(name, b.type || '', String(fr.result).split(',')[1] || ''); };
      fr.readAsDataURL(b);
    });
  }, true);
})();
"""
    }
}
