#!/usr/bin/env python3
"""
Builds the Android copy of the web files:  web/index.php + web/assets-setup.php  ->  app/src/main/assets/www/
The web files stay untouched; this only changes *where* things live on a phone:
  * __DIR__ meaning "the folder FileDash manages"  -> FD_APP_ROOT (shared storage)
  * DNS lookup / asset downloads                   -> go through the Android resolver (bundled PHP has no resolv.conf)
Run again whenever web/index.php changes.
"""
import re, shutil, sys, pathlib

root = pathlib.Path(__file__).resolve().parent.parent
out = root / 'app/src/main/assets/www'
out.mkdir(parents=True, exist_ok=True)

# ---------- index.php ----------
src = (root / 'web/index.php').read_text(encoding='utf-8')
lines = src.split('\n')
n_root = 0
for i, ln in enumerate(lines):
    if '__DIR__' not in ln: continue
    s = ln.lstrip()
    if s.startswith('*') or s.startswith('//') or s.startswith('/*'): continue          # comments
    if '.filedash' in ln or 'assets-setup.php' in ln or '/../assets/' in ln: continue    # app-private data stays in <app>/www
    lines[i] = ln.replace('__DIR__', 'FD_APP_ROOT'); n_root += 1
src = '\n'.join(lines)
n_dns = src.count('@gethostbynamel($host)')
src = src.replace('@gethostbynamel($host)', 'fdAndroidDns($host)')
(out / 'index.php').write_text(src, encoding='utf-8')

# ---------- assets-setup.php ----------
a = (root / 'web/assets-setup.php').read_text(encoding='utf-8')
i0 = a.index('/** download one URL')
i1 = a.index('function fdsCookie')
new_fetch = r'''/** download one URL → body string, or null with $err / $ssl set. (Android: DNS via the app, redirects followed by hand.) */
function fdsFetch($url, &$err, &$ssl, $insecure = false) {
    $err = ''; $ssl = false;
    if (!function_exists('curl_init')) { $err = 'cURL is missing in the bundled PHP'; return null; }
    for ($hop = 0; $hop < 6; $hop++) {
        $p = parse_url($url); $host = $p['host'] ?? ''; $sch = strtolower($p['scheme'] ?? 'https');
        $port = $p['port'] ?? ($sch === 'http' ? 80 : 443);
        $ips = function_exists('fdAndroidDns') ? fdAndroidDns($host) : (@gethostbynamel($host) ?: []);
        if (!$ips) { $err = 'could not resolve ' . $host . ' (no internet?)'; return null; }
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 12, CURLOPT_TIMEOUT => 90, CURLOPT_USERAGENT => 'FileDash-assets-setup',
            CURLOPT_RESOLVE => [$host . ':' . $port . ':' . $ips[0]],
            CURLOPT_SSL_VERIFYPEER => !$insecure, CURLOPT_SSL_VERIFYHOST => $insecure ? 0 : 2, CURLOPT_ENCODING => '']);
        $raw = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $hs = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $no = curl_errno($ch); $em = curl_error($ch); curl_close($ch);
        if ($raw === false) { $err = $em ?: 'download failed'; $ssl = in_array($no, [35, 51, 58, 60, 77, 83, 90], true); return null; }
        $head = substr($raw, 0, $hs); $body = substr($raw, $hs);
        if ($code >= 300 && $code < 400 && preg_match('/^location:\s*(\S+)/im', $head, $m)) {
            $l = $m[1];
            if (strpos($l, '//') === 0) $url = $sch . ':' . $l;
            elseif ($l !== '' && $l[0] === '/') $url = $sch . '://' . $host . ($p['port'] ?? false ? ':' . $p['port'] : '') . $l;
            else $url = $l;
            continue;
        }
        if ($code >= 400) { $err = 'server answered HTTP ' . $code; return null; }
        return $body;
    }
    $err = 'too many redirects'; return null;
}

'''
a = a[:i0] + new_fetch + a[i1:]
(out / 'assets-setup.php').write_text(a, encoding='utf-8')

shutil.copy(root / 'tools/router.php', out / 'router.php')
print(f'index.php: {n_root} root paths remapped, {n_dns} DNS call(s) patched; assets-setup.php + router.php written to {out}')
if n_dns < 1: sys.exit('DNS patch point not found in index.php — check fdDownload()')
