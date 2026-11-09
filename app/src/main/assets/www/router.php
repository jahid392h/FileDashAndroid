<?php
/**
 * FileDash (Android) — router for PHP's built-in server.
 * Runs on every request. Keeps index.php / assets-setup.php byte-for-byte the web version
 * (only tools/patch_index.py touches them) and maps the Android folders:
 *   DOCUMENT_ROOT  = the storage folder FileDash manages (shared storage)
 *   <app>/www      = index.php, assets-setup.php, .filedash (account, logs)
 *   <app>/assets   = offline libraries (the "../assets" folder of the web version)
 */
$tok = (string)getenv('FD_APP_TOKEN');
$uri = rawurldecode((string)parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH));
if ($uri === '') $uri = '/';

if ($uri === '/__ping') { header('Content-Type: text/plain'); header('Cache-Control: no-store'); echo 'ok'; return true; }

// Only this app's WebView (holds the secret cookie) may talk to the server — other apps on the phone cannot.
if ($tok === '' || !hash_equals($tok, (string)($_COOKIE['fd_app'] ?? ''))) { http_response_code(403); header('Content-Type: text/plain'); echo 'Forbidden'; return true; }

if (!defined('FD_APP_ROOT')) define('FD_APP_ROOT', rtrim((string)(realpath((string)getenv('FD_APP_ROOT')) ?: (string)getenv('FD_APP_ROOT')), '/'));

/** DNS through the Android resolver (the bundled PHP has no /etc/resolv.conf). */
if (!function_exists('fdAndroidDns')) {
    function fdAndroidDns($host) {
        $host = (string)$host;
        if ($host === '') return [];
        if (filter_var($host, FILTER_VALIDATE_IP)) return [$host];
        $port = getenv('FD_HELPER_PORT');
        if (!$port) return @gethostbynamel($host) ?: [];
        $ctx = stream_context_create(['http' => ['timeout' => 8, 'ignore_errors' => true]]);
        $r = @file_get_contents('http://127.0.0.1:' . $port . '/dns?t=' . rawurlencode((string)getenv('FD_HELPER_TOKEN')) . '&h=' . rawurlencode($host), false, $ctx);
        return $r ? array_values(array_filter(array_map('trim', explode("\n", $r)))) : [];
    }
}

$www = __DIR__;

// "../assets/…" of the web version → <app>/assets
if (strpos($uri, '/assets/') === 0) {
    $base = realpath(dirname($www) . '/assets');
    $f = $base ? realpath($base . '/' . substr($uri, 8)) : false;
    if ($f && strpos($f, $base . '/') === 0 && is_file($f)) {
        static $mime = ['css' => 'text/css', 'js' => 'application/javascript', 'woff2' => 'font/woff2', 'woff' => 'font/woff', 'ttf' => 'font/ttf', 'svg' => 'image/svg+xml', 'json' => 'application/json', 'map' => 'application/json'];
        $ext = strtolower(pathinfo($f, PATHINFO_EXTENSION));
        header('Content-Type: ' . ($mime[$ext] ?? 'application/octet-stream'));
        header('Content-Length: ' . filesize($f)); header('Cache-Control: public, max-age=86400');
        readfile($f); return true;
    }
    http_response_code(404); echo 'Not found'; return true;
}

if ($uri === '/' || $uri === '/index.php' || $uri === '/assets-setup.php') {
    $script = $uri === '/assets-setup.php' ? 'assets-setup.php' : 'index.php';
    $_SERVER['SCRIPT_NAME'] = $_SERVER['PHP_SELF'] = '/' . $script;
    $_SERVER['SCRIPT_FILENAME'] = $www . '/' . $script;
    $_SERVER['SERVER_SOFTWARE'] = 'FileDash Android (PHP ' . PHP_VERSION . ')';
    require $www . '/' . $script;
    return true;
}

// any other file inside the managed storage is served as-is (previews, downloads) — same as the web version
$docroot = (string)$_SERVER['DOCUMENT_ROOT'];
if (is_file($docroot . $uri)) return false;
http_response_code(404); header('Content-Type: text/plain'); echo 'Not found';
return true;
