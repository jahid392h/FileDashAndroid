<?php
/**
 * FileDash — assets-setup.php  (standalone gate: offline files or online CDN?)
 *
 * What it does, every time a page is opened in the browser:
 *   1. All library files already exist in  ../assets/  → does nothing, FileDash loads (fully offline).
 *   2. Some are missing and the user already chose "keep online" → does nothing, FileDash uses the CDN copies.
 *   3. Otherwise it asks once:
 *        • "Make it work offline" → creates ../assets/ (one level above this file), downloads every missing
 *          library file from its CDN into it (with a progress bar), then loads FileDash.
 *        • "Keep using online"    → remembers the choice (cookie) and loads FileDash; the index then uses the
 *          online CDN whenever it cannot find the files in ../assets/.
 *
 * Use it in either way:
 *   A) As a gate – first line of index.php (right after "<?php"):   require __DIR__ . '/assets-setup.php';
 *   B) Directly – open  /assets-setup.php  in the browser; when done it sends you to index.php.
 *
 * Re-open the question any time:   index.php?fds=ask
 * Needs: PHP 7+, cURL or allow_url_fopen on the server, and write permission on the folder that will hold ../assets.
 * Only a fixed list of CDN files (below) can ever be downloaded – nothing is taken from the URL.
 */
if (PHP_SAPI === 'cli') return;

if (!function_exists('fdsManifest')) {

/** [path under ../assets/, CDN url] – must match the paths the pages load. */
function fdsManifest() {
    $fa = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/';
    $cm = 'https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/';
    $m  = [['tailwind.js', 'https://cdn.tailwindcss.com'], ['fa/css/all.min.css', $fa . 'css/all.min.css']];
    foreach (['fa-solid-900', 'fa-regular-400', 'fa-brands-400'] as $f) $m[] = ['fa/webfonts/' . $f . '.woff2', $fa . 'webfonts/' . $f . '.woff2'];
    $cmFiles = [
        'codemirror.min.css', 'codemirror.min.js',
        'theme/dracula.min.css', 'theme/eclipse.min.css', 'theme/material.min.css', 'theme/monokai.min.css', 'theme/solarized.min.css',
        'addon/dialog/dialog.min.css', 'addon/dialog/dialog.min.js',
        'addon/edit/closebrackets.min.js', 'addon/edit/matchbrackets.min.js',
        'addon/search/annotatescrollbar.min.js', 'addon/search/matchesonscrollbar.min.js', 'addon/search/search.min.js', 'addon/search/searchcursor.min.js',
        'addon/selection/active-line.min.js',
        'mode/clike/clike.min.js', 'mode/css/css.min.js', 'mode/htmlmixed/htmlmixed.min.js', 'mode/javascript/javascript.min.js',
        'mode/markdown/markdown.min.js', 'mode/php/php.min.js', 'mode/python/python.min.js', 'mode/sql/sql.min.js', 'mode/xml/xml.min.js',
    ];
    foreach ($cmFiles as $p) $m[] = ['cm/' . $p, $cm . $p];
    $m[] = ['cm/addon/search/matchesonscrollbar.css', $cm . 'addon/search/matchesonscrollbar.min.css']; // local name differs from the CDN's
    return $m;
}

function fdsDir() { return dirname(__DIR__) . '/assets'; }

/** indexes of manifest entries that are not on disk (or empty). */
function fdsMissing() {
    $out = [];
    foreach (fdsManifest() as $i => $it) { $f = fdsDir() . '/' . $it[0]; if (!is_file($f) || filesize($f) === 0) $out[] = $i; }
    return $out;
}

function fdsWritable() { $d = fdsDir(); return is_dir($d) ? is_writable($d) : is_writable(dirname($d)); }

function fdsJson($a, $code = 200) {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8'); header('Cache-Control: no-store');
    echo json_encode($a); exit;
}

/** download one URL → body string, or null with $err / $ssl set. (Android: DNS via the app, redirects followed by hand.) */
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

function fdsCookie($v) {
    if ($v === null) header('Set-Cookie: fd_assets=; Path=/; Max-Age=0; SameSite=Lax', false);
    else header('Set-Cookie: fd_assets=' . $v . '; Path=/; Max-Age=31536000; SameSite=Lax', false);
}

/** One simple page, three states: 'ask' (offline or online?), 'found' (everything in ../assets), 'partial' (folder found, some files missing). */
function fdsUi($mode, $c) {
    header('Content-Type: text/html; charset=utf-8'); header('Cache-Control: no-store');
    $c['mode'] = $mode;
    $cfg = json_encode($c, JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP);
    $html = <<<'HTML'
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex">
<title>FileDash · Assets</title>
<style>
:root{--bg:#0f1424;--card:#171e33;--bd:#2a3354;--tx:#e9edff;--mut:#97a1c7;--ac:#6366f1;--ok:#34d399;--warn:#fbbf24;--bad:#f87171}
@media (prefers-color-scheme:light){:root{--bg:#f3f5fb;--card:#fff;--bd:#dde2f1;--tx:#171c33;--mut:#646e94}}
*{box-sizing:border-box;margin:0}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--tx);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:18px}
.card{width:100%;max-width:460px;background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:22px}
h1{font-size:19px;margin-bottom:8px}
p{color:var(--mut);font-size:14px;line-height:1.6}p b{color:var(--tx)}
code{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;background:rgba(99,102,241,.14);padding:1px 5px;border-radius:5px;color:var(--tx)}
.list{margin-top:14px;border:1px solid var(--bd);border-radius:10px;padding:10px 12px;max-height:170px;overflow:auto;font-family:ui-monospace,Consolas,monospace;font-size:12px;line-height:1.8;color:var(--mut)}
.lh{margin-top:14px;font-size:12.5px;color:var(--mut);font-weight:600}.lh+.list{margin-top:6px}
.list div.bad{color:var(--bad)}.list div.ok{color:var(--ok)}
.btns{display:flex;flex-direction:column;gap:9px;margin-top:16px}
.btn{display:block;width:100%;text-align:center;font:inherit;font-size:14.5px;font-weight:600;color:#fff;text-decoration:none;background:var(--ac);border:1px solid var(--ac);border-radius:10px;padding:12px;cursor:pointer}
.btn.g{background:transparent;color:var(--tx);border-color:var(--bd)}.btn:hover{filter:brightness(1.1)}.btn[disabled]{opacity:.45;pointer-events:none}
.sub{font-size:12.5px;color:var(--mut);text-align:center;margin-top:12px}
.warn{margin-top:12px;font-size:12.5px;color:var(--bad);line-height:1.5}
.bar{height:6px;border-radius:9px;background:var(--bd);overflow:hidden;margin:14px 0 6px}.bar i{display:block;height:100%;width:0;background:var(--ac);transition:width .2s}
.row{display:flex;justify-content:space-between;font-size:12.5px;color:var(--mut)}
[hidden]{display:none!important}
</style></head><body>
<main class="card">
 <h1 id="ttl"></h1>
 <p id="lead"></p>
 <div id="miss" hidden><div class="lh" id="mt"></div><div class="list" id="mlist"></div></div>
 <div id="prog" hidden><div class="bar"><i id="fill"></i></div><div class="row"><span id="cur"></span><span id="pct">0%</span></div><div class="list" id="log"></div></div>
 <div class="btns" id="btns"></div>
 <div class="warn" id="nw" hidden>The server can't write the <code>../assets</code> folder. Make its parent folder writable, then reload.</div>
 <div class="sub" id="note" hidden>Asked only once. Open <code>?fds=ask</code> to see this again.</div>
</main>
<script>
const C = __CFG__;
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const missing = C.mode === 'ask' ? C.todo : (C.missing || []);
const names = a => a.map(x => '<div>' + esc(x.name) + '</div>').join('');
if (C.mode === 'ask') {
  $('ttl').textContent = 'Use FileDash offline?';
  $('lead').innerHTML = 'FileDash loads its libraries (icons, editor, styling) from online CDNs, so it needs <b>internet every time</b>. ' + (C.have > 0 ? 'Found <code>../assets</code> with <b>' + C.have + ' of ' + C.total + '</b> files.' : 'Download them once into <code>../assets</code> to run offline.');
  $('mt').textContent = 'Files to download (' + missing.length + ')'; $('mlist').innerHTML = names(missing); $('miss').hidden = false;
  $('btns').innerHTML = '<button class="btn" id="yes">Yes, download for offline use</button><a class="btn g" href="?fds=online">No, keep using online</a>';
  $('note').hidden = false;
  if (!C.writable) { $('yes').setAttribute('disabled', ''); $('nw').hidden = false; }
  $('yes').onclick = () => run(C.todo, false);
} else if (C.mode === 'found') {
  $('ttl').textContent = 'Assets folder found';
  $('lead').innerHTML = 'All <b>' + C.total + '</b> files are in <code>../assets</code>. FileDash runs offline.';
  $('btns').innerHTML = '<a class="btn" href="' + esc(C.next) + '">Continue</a>';
  setTimeout(() => location.replace(C.next), 1500);
} else {
  $('ttl').textContent = 'Assets folder found';
  $('lead').innerHTML = '<code>../assets</code> exists but <b>' + missing.length + ' of ' + C.total + '</b> files are missing. Those load from the online CDN.';
  $('mt').textContent = 'Missing files (' + missing.length + ')'; $('mlist').innerHTML = names(missing); $('miss').hidden = false;
  $('btns').innerHTML = '<a class="btn" href="' + esc(C.next) + '">Continue</a><a class="btn g" href="?fds=ask">Download missing files</a>';
}
async function run(list, insecure) {
  $('miss').hidden = true; $('note').hidden = true; $('prog').hidden = false; $('btns').innerHTML = ''; $('log').innerHTML = ''; $('lead').hidden = true; $('ttl').textContent = 'Downloading…';
  const fails = []; let done = 0, ssl = false;
  for (const it of list) {
    $('cur').textContent = it.name;
    const ln = document.createElement('div'); ln.textContent = '… ' + it.name; $('log').appendChild(ln); $('log').scrollTop = 1e6;
    try {
      const r = await fetch(C.self + '?fds=get&i=' + it.i + (insecure ? '&insecure=1' : ''), { headers: { 'X-Requested-With': 'fds' }, cache: 'no-store' });
      const j = await r.json();
      if (j.ok) { ln.className = 'ok'; ln.textContent = '✓ ' + it.name; }
      else { fails.push(it); ln.className = 'bad'; ln.textContent = '✗ ' + it.name + ' — ' + (j.err || 'failed'); if (j.ssl) ssl = true; }
    } catch (e) { fails.push(it); ln.className = 'bad'; ln.textContent = '✗ ' + it.name + ' — request failed'; }
    done++; const p = Math.round(done / list.length * 100); $('fill').style.width = p + '%'; $('pct').textContent = p + '%';
  }
  if (!fails.length) { $('ttl').textContent = 'Offline ready'; $('cur').textContent = 'All ' + list.length + ' files downloaded'; setTimeout(() => location.replace(C.self), 900); return; }
  $('ttl').textContent = fails.length + ' file' + (fails.length > 1 ? 's' : '') + ' failed'; $('cur').textContent = (list.length - fails.length) + ' of ' + list.length + ' downloaded';
  $('btns').innerHTML = '<button class="btn" id="rt">Retry failed</button>' + (ssl ? '<button class="btn g" id="rs">Retry without SSL check</button>' : '') + '<a class="btn g" href="?fds=online">Continue online</a>';
  $('rt').onclick = () => run(fails, false);
  if ($('rs')) $('rs').onclick = () => { if (confirm('Downloads will not verify the server certificate. Only do this on a network you trust.')) run(fails, true); };
}
</script></body></html>
HTML;
    echo str_replace('__CFG__', $cfg, $html);
    exit;
}

/** "assets folder found" – once per browser session (and whenever opened directly or with ?fds=ask). */
function fdsFoundPage($next, $total, $missNames) {
    header('Set-Cookie: fd_assets_ok=1; Path=/; SameSite=Lax', false);   // session cookie → not repeated on every page
    $miss = [];
    foreach ($missNames as $n) $miss[] = ['name' => $n];
    fdsUi($miss ? 'partial' : 'found', ['next' => $next, 'total' => $total, 'missing' => $miss]);
}

function fdsPage($self, $todo, $total, $writable) {
    fdsUi('ask', ['self' => $self, 'todo' => $todo, 'total' => $total, 'have' => $total - count($todo), 'writable' => $writable]);
}

} // function_exists guard

/* ---------------------------------------------------------------- router ---------------------------------------------------------------- */
$fdsSelf   = $_SERVER['SCRIPT_NAME'] ?? basename(__FILE__);
$fdsDirect = isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__);
$fdsAct    = isset($_GET['fds']) ? (string)$_GET['fds'] : '';
$fdsOnline = (isset($_COOKIE['fd_assets']) && $_COOKIE['fd_assets'] === 'online');
$fdsNav    = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && stripos($_SERVER['HTTP_ACCEPT'] ?? '', 'text/html') !== false;

if ($fdsAct === 'get') {                       // download ONE file of the fixed list
    if (($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') !== 'fds') fdsJson(['ok' => false, 'err' => 'forbidden'], 403);
    @set_time_limit(120);
    $man = fdsManifest(); $i = isset($_GET['i']) ? (int)$_GET['i'] : -1;
    if (!isset($man[$i])) fdsJson(['ok' => false, 'err' => 'unknown file']);
    list($rel, $url) = $man[$i]; $dest = fdsDir() . '/' . $rel;
    if (is_file($dest) && filesize($dest) > 0) fdsJson(['ok' => true, 'skip' => true]);
    $body = fdsFetch($url, $err, $ssl, !empty($_GET['insecure']));
    if ($body === null) fdsJson(['ok' => false, 'err' => $err, 'ssl' => $ssl]);
    $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
    if ($body === '' || (in_array($ext, ['js', 'css'], true) && substr(ltrim($body), 0, 1) === '<')) fdsJson(['ok' => false, 'err' => 'unexpected content (not a ' . $ext . ' file)']);
    $d = dirname($dest);
    if (!is_dir($d) && !@mkdir($d, 0755, true) && !is_dir($d)) fdsJson(['ok' => false, 'err' => 'cannot create folder (permission denied)']);
    $tmp = $dest . '.part';
    if (@file_put_contents($tmp, $body, LOCK_EX) === false || !@rename($tmp, $dest)) { @unlink($tmp); fdsJson(['ok' => false, 'err' => 'cannot write file (permission denied)']); }
    fdsJson(['ok' => true, 'size' => strlen($body)]);
}

if ($fdsAct === 'online') {                    // "keep using online" → remember, then carry on
    fdsCookie('online');
    header('Location: ' . $fdsSelf); exit;
}
$fdsAsk = ($fdsAct === 'ask');
if ($fdsAsk) fdsCookie(null);

$fdsMissing = fdsMissing();
$fdsHave    = !$fdsMissing;
$fdsPartial = !$fdsHave && $fdsOnline && !$fdsAsk && is_dir(fdsDir());   // folder exists but incomplete, user said "keep online"
if (($fdsHave && ($fdsAsk || $fdsDirect || ($fdsNav && empty($_COOKIE['fd_assets_ok'])))) || ($fdsPartial && ($fdsDirect || ($fdsNav && empty($_COOKIE['fd_assets_ok']))))) {
    // ../assets found → tell the user (once per session), then carry on
    $next = $fdsDirect ? 'index.php' : $fdsSelf . (!$fdsAsk && !empty($_SERVER['QUERY_STRING']) ? '?' . $_SERVER['QUERY_STRING'] : '');
    $fdsMan = fdsManifest(); $fdsNames = [];
    foreach ($fdsMissing as $i) $fdsNames[] = $fdsMan[$i][0];
    fdsFoundPage($next, count($fdsMan), $fdsNames);
}
if (!$fdsAsk && (!$fdsNav || $fdsHave || $fdsOnline)) {
    // nothing to ask → hand over
    if ($fdsDirect) { header('Location: index.php'); exit; }
    return;                                    // included from index.php → FileDash continues
}
$todo = [];
$man  = fdsManifest();
foreach ($fdsMissing as $i) $todo[] = ['i' => $i, 'name' => $man[$i][0]];
fdsPage($fdsSelf, $todo, count($man), fdsWritable());
