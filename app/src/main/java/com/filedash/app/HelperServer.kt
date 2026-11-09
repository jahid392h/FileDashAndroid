package com.filedash.app

import android.net.Uri
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.Inet4Address
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

/**
 * Tiny loopback helper for the bundled PHP: the static PHP binary has no /etc/resolv.conf, so host names are
 * resolved here with the Android resolver (GET /dns?t=TOKEN&h=host  ->  one IPv4 address per line).
 */
class HelperServer(private val token: String) {
    private val server = ServerSocket(0, 20, InetAddress.getByName("127.0.0.1"))
    val port: Int get() = server.localPort

    fun start() {
        thread(isDaemon = true, name = "fd-helper") {
            while (true) {
                val s = try { server.accept() } catch (e: Exception) { break }
                thread(isDaemon = true) { handle(s) }
            }
        }
    }

    private fun handle(s: Socket) {
        try {
            s.use {
                it.soTimeout = 5000
                val line = BufferedReader(InputStreamReader(it.getInputStream())).readLine() ?: return
                val target = line.split(" ").getOrNull(1) ?: return
                val q = Uri.parse("http://x$target")
                val ok = q.path == "/dns" && q.getQueryParameter("t") == token
                val host = q.getQueryParameter("h")
                var body = ""
                if (ok && !host.isNullOrBlank()) {
                    body = try {
                        InetAddress.getAllByName(host).filterIsInstance<Inet4Address>().joinToString("\n") { a -> a.hostAddress ?: "" }
                    } catch (e: Exception) { "" }
                }
                val bytes = body.toByteArray()
                val head = "HTTP/1.1 ${if (ok) 200 else 403} X\r\nContent-Type: text/plain\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n"
                it.getOutputStream().apply { write(head.toByteArray()); write(bytes); flush() }
            }
        } catch (e: Exception) { /* ignore */ }
    }
}
