<?php
namespace {
require __DIR__ . '/assets-setup.php';
/** FileDash unified single-file build. */
if (!defined('FD_LOGIN_PAGE')) define('FD_LOGIN_PAGE', 1); // defer auth gate until router decides

/**
 * FileDash — auth.php
 * Shared auth layer used by ?fdpage=login, ?fdpage=logout, ?fdpage=settings and every protected page.
 * Protect a page by putting this right after "<?php":   require __DIR__ . '/auth.php';
 * Account lives in .filedash/auth.json (bcrypt hash). Forgot it? Delete that file → ?fdpage=login shows "Create account".
 */
if (!function_exists('fdaDir')) {

function fdaDir() { return __DIR__ . '/.filedash'; }

function fdaInit() {
    $d = fdaDir();
    if (!is_dir($d)) { @mkdir($d, 0755, true); @file_put_contents($d . '/index.html', ''); }
    if (is_dir($d) && !is_file($d . '/.htaccess'))
        @file_put_contents($d . '/.htaccess', "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
}

/* ===== asset loader — local first (../assets/…), CDN copy when the file is not there ===== */
if (!function_exists('fdAssetCdn')) {
/** CDN twin of an asset path relative to ../assets/ ('' = none known). */
function fdAssetCdn($rel) {
    static $over = ['cm/addon/search/matchesonscrollbar.css' => 'cm/addon/search/matchesonscrollbar.min.css'];
    if ($rel === 'tailwind.js') return 'https://cdn.tailwindcss.com';
    $rel = $over[$rel] ?? $rel;
    if (strpos($rel, 'fa/') === 0) return 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/' . substr($rel, 3);
    if (strpos($rel, 'cm/') === 0) return 'https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/' . substr($rel, 3);
    return '';
}
/** true when ../assets/<rel> exists on disk (Font Awesome also needs its webfonts folder). */
function fdAssetLocal($rel) {
    $base = __DIR__ . '/../assets/';
    if (!is_file($base . $rel)) return false;
    if (strpos($rel, 'fa/css/') === 0 && !is_dir($base . 'fa/webfonts')) return false;
    return true;
}
/** <link> tag: local copy if present → offline works; else CDN. A broken local file also falls back in the browser. */
function fdCss($rel) {
    $local = fdAssetLocal($rel); $cdn = fdAssetCdn($rel);
    $u = $local ? '../assets/' . $rel : $cdn; if ($u === '') return;
    echo '<link rel="stylesheet" href="' . $u . '"' . ($local && $cdn !== '' ? ' onerror="this.onerror=null;this.href=\'' . $cdn . '\'"' : '') . '>';
}
/** <script> tag with the same local → CDN logic (order of scripts is kept). */
function fdJs($rel) {
    $local = fdAssetLocal($rel); $cdn = fdAssetCdn($rel);
    $u = $local ? '../assets/' . $rel : $cdn; if ($u === '') return;
    echo '<script src="' . $u . '"' . ($local && $cdn !== '' ? ' onerror="this.onerror=null;document.write(\'<scr\'+\'ipt src=' . $cdn . '></scr\'+\'ipt>\')"' : '') . '></script>';
}
}

/** Reads fresh from disk every call (never cached). null = no account yet → first-run setup. */
function fdaAccount() {
    $f = fdaDir() . '/auth.json';
    if (!is_file($f)) return null;
    $j = json_decode((string)@file_get_contents($f), true);
    return (is_array($j) && !empty($j['user']) && !empty($j['hash'])) ? $j : null;
}
function fdaSaveAccount($a) { fdaInit(); return @file_put_contents(fdaDir() . '/auth.json', json_encode($a), LOCK_EX) !== false; }

function fdaLog($act, $detail = '') {
    fdaInit(); $f = fdaDir() . '/activity.log';
    @file_put_contents($f, json_encode(['t' => time(), 'a' => $act, 'd' => substr((string)$detail, 0, 300), 'ip' => $_SERVER['REMOTE_ADDR'] ?? '', 'ua' => substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 250)], JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
    if (@filesize($f) > 300000) { $l = @file($f); if ($l) @file_put_contents($f, implode('', array_slice($l, -600)), LOCK_EX); }
}

function fdaSession() {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    fdaInit();
    $sp = fdaDir() . '/sessions';                       // own session folder → "keep me signed in 30 days" really lasts
    if (!is_dir($sp)) @mkdir($sp, 0700, true);
    if (is_dir($sp) && is_writable($sp)) session_save_path($sp);
    @ini_set('session.gc_maxlifetime', '2592000');
    @ini_set('session.use_strict_mode', '1');
    @ini_set('session.use_only_cookies', '1');
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['SERVER_PORT'] ?? '') == 443);
    session_name('FDSESS');
    session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $https, 'httponly' => true, 'samesite' => 'Lax']);
    session_start();
}

function fdaCsrf() {
    fdaSession();
    if (empty($_SESSION['fd_csrf'])) $_SESSION['fd_csrf'] = bin2hex(random_bytes(16));
    return $_SESSION['fd_csrf'];
}

function fdaLoggedIn() {
    fdaSession();
    $acc = fdaAccount();
    if (!$acc || empty($_SESSION['fd_user'])) return false;
    if (strtolower((string)$_SESSION['fd_user']) !== strtolower($acc['user'])) return false;
    $max = !empty($_SESSION['fd_remember']) ? 2592000 : 21600;      // 30 days / 6 h idle
    return (time() - (int)($_SESSION['fd_seen'] ?? 0)) <= $max;
}

function fdaLogout() {
    fdaSession(); $_SESSION = [];
    $c = session_get_cookie_params();
    setcookie(session_name(), '', ['expires' => time() - 3600, 'path' => $c['path'], 'secure' => $c['secure'], 'httponly' => true, 'samesite' => 'Lax']);
    session_destroy();
}

/** Re-issue the 30-day cookie after session_regenerate_id() for "remembered" sessions. */
function fdaRememberCookie() {
    if (empty($_SESSION['fd_remember'])) return;
    $c = session_get_cookie_params();
    setcookie(session_name(), session_id(), ['expires' => time() + 2592000, 'path' => $c['path'], 'secure' => $c['secure'], 'httponly' => true, 'samesite' => 'Lax']);
}

function fdaGate() {
    fdaSession();
    $script = basename($_SERVER['SCRIPT_NAME'] ?? '');
    // public share links (index.php?s=TOKEN) must work without login
    if ($script === 'index.php' && isset($_GET['s']) && !isset($_GET['api'])) return;
    if (fdaLoggedIn()) { $_SESSION['fd_seen'] = time(); return; }

    $expired = !empty($_SESSION['fd_user']) && fdaAccount();
    unset($_SESSION['fd_user'], $_SESSION['fd_seen'], $_SESSION['fd_remember']);

    $mode = $_SERVER['HTTP_SEC_FETCH_MODE'] ?? '';
    $isPost = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
    $navigate = $mode === 'navigate' || ($mode === '' && !$isPost && !isset($_GET['api']) && !isset($_GET['raw']));
    if ($navigate) {
        $qs = (string)($_SERVER['QUERY_STRING'] ?? '');
        $next = ($isPost || $qs === '') ? '?fdpage=index' : '?' . $qs;
        header('Location: ?fdpage=login&next=' . rawurlencode($next) . ($expired ? '&expired=1' : '') . (!empty($_GET['embed']) ? '&embed=1' : '')); exit;
    }
    // fetch / XHR / <img src> → machine-readable answer instead of an HTML page
    http_response_code(401); header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'login' => true, 'error' => 'Session expired — please sign in again']); exit;
}

} // function_exists guard

if (!defined('FD_AUTH_GATED')) {
    define('FD_AUTH_GATED', 1);
    if (!defined('FD_LOGIN_PAGE')) fdaGate();       // ?fdpage=login / ?fdpage=logout define FD_LOGIN_PAGE to skip the gate
}

/**
 * Modern Neon File Manager - ?fdpage=trash (Recycle Bin System, v2)
 * Features: search, sort, filter, bulk restore/purge, stats, auto-clean old items,
 * CSRF protection, flash messages, custom confirm modal, fully responsive.
 */
/* ===== Trash library =====
 * index.php uses this file as a library:
 *
 *     trash_move($full_path);   // moves to .trash and remembers the original location
 */
function trash_meta_load(string $trash_dir): array
{
    $f = $trash_dir . '/.trash_meta.json';
    if (!is_file($f)) return [];
    $data = json_decode((string) @file_get_contents($f), true);
    return is_array($data) ? $data : [];
}

function trash_meta_save(string $trash_dir, array $meta): void
{
    @file_put_contents($trash_dir . '/.trash_meta.json', json_encode($meta, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);
}

function trash_move(string $abs_path): bool
{
    $trash_dir = FD_APP_ROOT . '/.trash';
    if (!is_dir($trash_dir) && !@mkdir($trash_dir, 0755, true)) return false;

    $real = realpath($abs_path);
    $trash_real = realpath($trash_dir);
    if ($real === false || $trash_real === false) return false;
    if ($real === $trash_real || strpos($real . DIRECTORY_SEPARATOR, $trash_real . DIRECTORY_SEPARATOR) === 0) return false;

    $name = basename($real);
    $target = $name;
    if (file_exists($trash_dir . '/' . $target) || is_link($trash_dir . '/' . $target)) {
        $info = pathinfo($name);
        $target = $info['filename'] . '_' . time() . '_' . random_int(10, 99)
            . (isset($info['extension']) ? '.' . $info['extension'] : '');
    }
    if (!@rename($real, $trash_dir . '/' . $target)) return false;

    $meta = trash_meta_load($trash_dir);
    $meta[$target] = ['orig' => str_replace('\\', '/', $real), 'time' => time()];
    trash_meta_save($trash_dir, $meta);
    return true;
}


}

namespace {
$__fdpage = strtolower((string)($_GET['fdpage'] ?? 'index'));
$__fdmap = ['index'=>'index.php','login'=>'login.php','logout'=>'logout.php','actions'=>'actions.php','trash'=>'trash.php','dashboard'=>'dashboard.php','settings'=>'settings.php','dbviewer'=>'dbviewer.php','editor'=>'editor.php'];
if (!isset($__fdmap[$__fdpage])) { http_response_code(404); exit('Not found'); }
$_SERVER['SCRIPT_NAME'] = '/' . $__fdmap[$__fdpage];
if ($__fdpage !== 'login' && $__fdpage !== 'logout') { fdaGate(); }

/* FD_MOBILE_EMBED_PATCH — embedded pages: no own background on mobile */
if (isset($_GET['embed']) && in_array($__fdpage, ['dashboard', 'trash', 'settings', 'dbviewer'], true) && ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
    ob_start(function ($html) {
        $css = '<style>@media (max-width:900px){'
             . 'html,body,body.bg-darkBg{background:transparent!important;background-image:none!important}'
             . 'body::before{display:none!important}'
             . 'main,main.wrap,.wrap{max-width:none!important;width:100%!important;margin:0!important;padding:8px 12px calc(96px + env(safe-area-inset-bottom))!important}'
             . '.top,.glass-panel.sticky{padding:4px 12px 0!important}'
             . 'html body header.glass-panel.sticky,html body header.glass-panel.sticky>div:first-child{background:transparent!important;border:0!important;box-shadow:none!important;backdrop-filter:none!important}'
             . 'html:not(.light){color-scheme:dark}html.light{color-scheme:light}'
             . 'html:not(.light) body header.glass-panel.sticky>div:first-child>a{background:#111827!important;border:1px solid rgba(255,255,255,.08)!important;color:#8f9bb8!important;width:40px!important;height:40px!important;padding:0!important;border-radius:12px!important;box-shadow:none!important}'
             . 'html:not(.light) body header.glass-panel.sticky>div:last-child>button{background:#111827!important;border:1px solid rgba(255,255,255,.08)!important;color:#e8eaf6!important;box-shadow:none!important}'
             . 'html:not(.light) body .pgcnt{background:#111827!important;border:1px solid rgba(255,255,255,.08)!important;color:#8f9bb8!important}'
             . 'html.light body header.glass-panel.sticky>div:first-child>a{background:#fff!important;border:1px solid rgba(20,26,60,.1)!important;color:#64708f!important;width:40px!important;height:40px!important;padding:0!important;border-radius:12px!important;box-shadow:none!important}'
             . 'html.light body header.glass-panel.sticky>div:last-child>button{background:#fff!important;border:1px solid rgba(20,26,60,.1)!important;color:#151a33!important;box-shadow:none!important}'
             . 'html.light body .pgcnt{background:#fff!important;border:1px solid rgba(20,26,60,.1)!important;color:#64708f!important}'
             . 'html body header.glass-panel.sticky>div:last-child>button:first-child i{color:#f59e0b!important}'
             . 'html body header.glass-panel.sticky>div:last-child>button:last-child i{color:#ef4444!important}'
             . 'html:not(.light) body.bg-darkBg,html.light body.bg-darkBg,html body.bg-darkBg{background:transparent!important;background-image:none!important}'
             . 'html:not(.light) body.bg-darkBg main section.glass-panel.overflow-hidden,html.light body.bg-darkBg main section.glass-panel.overflow-hidden{background:transparent!important;border:0!important;box-shadow:none!important;border-radius:0!important;overflow:visible!important;backdrop-filter:none!important}'
             . 'html:not(.light) body.bg-darkBg main section.glass-panel.overflow-hidden > .row-grid,html.light body.bg-darkBg main section.glass-panel.overflow-hidden > .row-grid{background:transparent!important;border:0!important;padding:2px 14px 8px!important}'
             . 'body.bg-darkBg #list{display:flex!important;flex-direction:column;gap:6px;border:0!important}'
             . 'html:not(.light) body.bg-darkBg #list>.item-row{background:#111827!important;border:1px solid rgba(255,255,255,.08)!important;border-radius:14px!important}'
             . 'html.light body.bg-darkBg #list>.item-row{background:#fff!important;border:1px solid rgba(20,26,60,.1)!important;border-radius:14px!important}'
             . '}</style>';
        $p = stripos($html, '</head>');
        return $p === false ? $html : substr_replace($html, $css, $p, 0);
    });
}
}

namespace FDLogin {
use \RecursiveIteratorIterator; use \RecursiveDirectoryIterator; use \FilesystemIterator; use \ZipArchive; use \DateTime; use \DateTimeZone; use \DirectoryIterator; use \SplFileInfo; use \Exception; use \Throwable; use \finfo;
/* hoisted function declarations (must be unconditional) */
function limFile() { return fdaDir() . '/attempts.json'; }

function limRead() { $j = json_decode((string)@file_get_contents(limFile()), true); return is_array($j) ? $j : []; }

function limWrite($a) { fdaInit(); foreach ($a as $k => $v) if (($v['lock'] ?? 0) < time() - 86400 && ($v['t'] ?? 0) < time() - 86400) unset($a[$k]); @file_put_contents(limFile(), json_encode($a), LOCK_EX); }

if ($__fdpage === 'login') {

/**
 * FileDash — ?fdpage=login
 * First visit = "Create admin account" screen. After that it is a normal sign-in.
 * Forgot the password? Delete .filedash/auth.json and open this page again.
 */
error_reporting(E_ALL); ini_set('display_errors', '0');
fdaSession();

$acc   = fdaAccount();
$setup = ($acc === null);
$err = ''; $info = '';
$ip  = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

$next = (string)($_GET['next'] ?? $_POST['next'] ?? '');
if (!preg_match('#^\?[^\s\\\\]*$#', $next) || $next === '?') $next = '?fdpage=index';

if (!$setup && fdaLoggedIn()) { header('Location: ' . $next); exit; }
if (isset($_GET['out'])) $info = 'You have been signed out.';
if (isset($_GET['expired'])) $info = 'Session expired. Please sign in again.';

/* ---- brute-force limiter (per IP) ---- */






$att = limRead(); $lockLeft = max(0, ($att[$ip]['lock'] ?? 0) - time());

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals(fdaCsrf(), (string)($_POST['csrf'] ?? ''))) {
        $err = 'Page expired — please try again.';
    } elseif ($setup) {
        $u = trim((string)($_POST['username'] ?? '')); $p = (string)($_POST['password'] ?? ''); $p2 = (string)($_POST['password2'] ?? '');
       // if (!preg_match('/^[A-Za-z0-9_.\-]{3,32}$/', $u)) $err = 'Username: 3–32 letters, numbers, . _ -';
       // elseif (strlen($p) < 8) $err = 'Password must be at least 8 characters.';
        if (!preg_match('/^[A-Za-z0-9_.\-]{1,32}$/', $u)) $err = 'Username: 1–32 letters, numbers, . _ -'; // unrestrict password
        elseif ($p === '') $err = 'Password cannot be empty.';
        elseif ($p !== $p2) $err = 'Passwords do not match.';
        else {
            fdaInit();
            file_put_contents(fdaDir() . '/auth.json', json_encode(['user' => $u, 'hash' => password_hash($p, PASSWORD_DEFAULT), 'created' => time()]), LOCK_EX);
            session_regenerate_id(true); $_SESSION['fd_user'] = $u; $_SESSION['fd_seen'] = time(); unset($_SESSION['fd_csrf']);
            fdaLog('login', 'Account created · signed in'); header('Location: ' . $next); exit;
        }
    } elseif ($lockLeft > 0) {
        $err = 'Too many attempts. Try again in ' . ceil($lockLeft / 60) . ' min.';
    } else {
        $u = (string)($_POST['username'] ?? ''); $p = (string)($_POST['password'] ?? '');
        $okU = hash_equals(strtolower($acc['user']), strtolower($u));
        $okP = password_verify($p, $acc['hash']);   // always verified → same timing for wrong user / wrong password
        if ($okU && $okP) {
            unset($att[$ip]); limWrite($att);
            $remember = !empty($_POST['remember']);
            session_regenerate_id(true);
            $_SESSION['fd_user'] = $acc['user']; $_SESSION['fd_seen'] = time(); $_SESSION['fd_remember'] = $remember; unset($_SESSION['fd_csrf']);
            if ($remember) { $c = session_get_cookie_params(); setcookie(session_name(), session_id(), ['expires' => time() + 2592000, 'path' => $c['path'], 'secure' => $c['secure'], 'httponly' => true, 'samesite' => 'Lax']); }
            if (password_needs_rehash($acc['hash'], PASSWORD_DEFAULT)) { $acc['hash'] = password_hash($p, PASSWORD_DEFAULT); @file_put_contents(fdaDir() . '/auth.json', json_encode($acc), LOCK_EX); }
            fdaLog('login', 'Signed in' . ($remember ? ' (remembered)' : '')); header('Location: ' . $next); exit;
        }
        $a = $att[$ip] ?? ['n' => 0, 't' => time()]; $a['n']++; $a['t'] = time();
        if ($a['n'] >= 5) { $a['lock'] = time() + 300 * min(6, $a['n'] - 4); }   // 5 min, then 10, 15 …
        $att[$ip] = $a; limWrite($att); fdaLog('login-fail', 'Wrong username or password');
        $left = 5 - $a['n'];
        $err = $a['n'] >= 5 ? 'Too many attempts. Try again in ' . ceil(($a['lock'] - time()) / 60) . ' min.' : 'Wrong username or password.' . ($left <= 2 ? " $left attempt(s) left." : '');
    }
    $acc = fdaAccount(); $setup = ($acc === null);
}
$csrf = fdaCsrf();
$h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<?php if (isset($_GET['embed'])): ?><script>try{if(window.top!==window.self)window.top.location.replace(location.href)}catch(e){}</script><?php endif; ?>
<meta name="theme-color" content="#6366f1">
<meta name="robots" content="noindex,nofollow">
<title><?= $setup ? 'Create account' : 'Sign in' ?> — FileDash</title>
<?php fdCss('fa/css/all.min.css'); ?>
<style>
:root{--ac:#6366f1;--ac2:#ec4899;--bg:#0a0e1a;--card:#111827;--card2:#172033;--tx:#e8eaf6;--mut:#8f9bb8;--bd:rgba(255,255,255,.08);--hov:rgba(129,140,248,.13);--sh:0 20px 50px rgba(0,0,0,.45);--ok:#10b981;--bad:#ef4444;color-scheme:dark}
html.light{--bg:#eef1fb;--card:#fff;--card2:#f4f6fd;--tx:#151a33;--mut:#64708f;--bd:rgba(20,26,60,.1);--hov:rgba(99,102,241,.09);--sh:0 20px 50px rgba(30,40,100,.15);color-scheme:light}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html{-webkit-text-size-adjust:100%}
body{font-family:Inter,system-ui,-apple-system,"Noto Sans Bengali",Segoe UI,sans-serif;background:var(--bg);color:var(--tx);font-size:14px;line-height:1.45;min-height:100vh;min-height:100dvh;display:grid;grid-template-columns:minmax(0,1fr);justify-items:center;align-content:center;padding:20px max(16px,env(safe-area-inset-right)) 20px max(16px,env(safe-area-inset-left));overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;z-index:-1;background:radial-gradient(620px 420px at 10% -5%,color-mix(in srgb,var(--ac) 26%,transparent),transparent),radial-gradient(520px 400px at 100% 100%,color-mix(in srgb,var(--ac2) 20%,transparent),transparent)}
button,input{font:inherit;color:inherit}button{cursor:pointer;border:0;background:none}
.wrap{width:100%;max-width:400px;animation:up .45s cubic-bezier(.2,.8,.2,1) both}
@keyframes up{from{opacity:0;transform:translateY(16px)}}
.card{padding:28px 24px 24px;border-radius:26px;background:color-mix(in srgb,var(--card) 92%,transparent);border:1px solid var(--bd);box-shadow:var(--sh);backdrop-filter:blur(14px);position:relative;overflow:hidden}
.card::after{content:"";position:absolute;right:-70px;top:-70px;width:200px;height:200px;border-radius:50%;background:radial-gradient(circle,color-mix(in srgb,var(--ac) 25%,transparent),transparent 70%);pointer-events:none}
.hd{display:flex;align-items:center;gap:14px;position:relative;z-index:1}
.ht{min-width:0}
.logo{width:48px;height:48px;border-radius:14px;flex:none;display:grid;place-items:center;font-size:20px;color:#fff;background:linear-gradient(135deg,var(--ac),var(--ac2));box-shadow:0 8px 20px color-mix(in srgb,var(--ac) 40%,transparent)}
h1{font-size:20px;text-align:left;line-height:1.2}.sub{text-align:left;color:var(--mut);margin:3px 0 0;font-size:13px}
.intro{position:relative;z-index:1;color:var(--mut);font-size:13px;line-height:1.55;margin:14px 0 22px}
form{position:relative;z-index:1;display:flex;flex-direction:column;gap:14px}
.f label{display:block;font-size:12.5px;font-weight:600;color:var(--mut);margin-bottom:6px}
.in{display:flex;align-items:center;gap:10px;height:48px;padding:0 14px;border-radius:14px;background:var(--card2);border:1px solid var(--bd);transition:.2s}
.in:focus-within{border-color:var(--ac);box-shadow:0 0 0 4px color-mix(in srgb,var(--ac) 18%,transparent)}
.in>i{color:var(--mut);width:16px;text-align:center;flex:none}
.in input{flex:1;min-width:0;height:100%;background:none;border:0;outline:0;font-size:16px}
.in input::placeholder{color:color-mix(in srgb,var(--mut) 70%,transparent)}
.eye{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;color:var(--mut);flex:none;margin-right:-6px}.eye:hover{background:var(--hov);color:var(--tx)}
.row{display:flex;align-items:center;justify-content:space-between;gap:10px;font-size:13px}
.chk{display:flex;align-items:center;gap:9px;color:var(--mut);cursor:pointer;user-select:none}
.chk input{appearance:none;width:19px;height:19px;border-radius:6px;border:2px solid var(--bd);background:var(--card2);display:grid;place-items:center;cursor:pointer;transition:.15s}
.chk input:checked{background:var(--ac);border-color:var(--ac)}.chk input:checked::after{content:"✓";color:#fff;font-size:12px;font-weight:700}
.btn{height:48px;border-radius:14px;font-weight:700;font-size:15px;color:#fff;background:linear-gradient(135deg,var(--ac),var(--ac2));box-shadow:0 10px 24px color-mix(in srgb,var(--ac) 40%,transparent);display:flex;align-items:center;justify-content:center;gap:9px;transition:.15s;margin-top:4px}
.btn:hover{transform:translateY(-1px)}.btn:active{transform:none}.btn[disabled]{opacity:.7;pointer-events:none}
.msg{display:flex;gap:10px;align-items:flex-start;padding:11px 13px;border-radius:13px;font-size:13px;position:relative;z-index:1;margin-bottom:14px}
.msg.err{background:color-mix(in srgb,var(--bad) 12%,var(--card2));border:1px solid color-mix(in srgb,var(--bad) 35%,transparent);color:var(--bad);animation:shake .4s}
.msg.ok{background:color-mix(in srgb,var(--ok) 12%,var(--card2));border:1px solid color-mix(in srgb,var(--ok) 35%,transparent);color:var(--ok)}
.msg i{margin-top:2px}.msg span{color:var(--tx)}
.msg.ok{overflow:hidden}
.msg.ok.fade{opacity:0;max-height:0!important;padding-top:0;padding-bottom:0;margin-bottom:0;border-width:0;transition:opacity .35s,max-height .45s,padding .45s,margin .45s,border-width .45s}
@keyframes shake{20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
.meter{height:5px;border-radius:9px;background:var(--bd);overflow:hidden;margin-top:8px}.meter i{display:block;height:100%;width:0;border-radius:9px;transition:.25s}
.hint{font-size:12px;color:var(--mut);margin-top:6px}
.foot{text-align:center;color:var(--mut);font-size:12px;margin-top:18px}
.theme{position:fixed;top:max(14px,env(safe-area-inset-top));right:max(14px,env(safe-area-inset-right));width:40px;height:40px;border-radius:12px;display:grid;place-items:center;background:var(--card);border:1px solid var(--bd);color:var(--mut)}.theme:hover{color:var(--tx)}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<button class="theme" id="themeBtn" type="button" aria-label="Theme"><i class="fa-solid fa-circle-half-stroke" style="color:#a78bfa"></i></button>
<main class="wrap">
  <div class="card">
    <div class="hd">
      <div class="logo"><i class="fa-solid <?= $setup ? 'fa-user-shield' : 'fa-folder-tree' ?>"></i></div>
      <div class="ht">
        <h1><?= $setup ? 'Create your account' : 'Welcome back' ?></h1>
        <p class="sub"><?= $setup ? 'First time here — set up the admin login for FileDash' : 'Sign in to FileDash' ?></p>
      </div>
    </div>
    <div style="height:22px"></div>

    <?php if ($err): ?><div class="msg err"><i class="fa-solid fa-circle-exclamation" style="color:#ef4444"></i><span><?= $h($err) ?></span></div>
    <?php elseif ($info): ?><div class="msg ok" id="flash"><i class="fa-solid fa-circle-check" style="color:#10b981"></i><span><?= $h($info) ?></span></div><?php endif; ?>

    <form method="post" autocomplete="on" id="lf">
      <input type="hidden" name="csrf" value="<?= $h($csrf) ?>">
      <input type="hidden" name="next" value="<?= $h($next) ?>">
      <div class="f"><label for="u">Username</label>
        <div class="in"><i class="fa-solid fa-user" style="color:#38bdf8"></i><input id="u" name="username" type="text" autocomplete="username" autocapitalize="off" autocorrect="off" spellcheck="false" required placeholder="admin" value="<?= $h($_POST['username'] ?? '') ?>"></div></div>
      <div class="f"><label for="p">Password</label>
        <div class="in"><i class="fa-solid fa-lock" style="color:#f59e0b"></i><input id="p" name="password" type="password" autocomplete="<?= $setup ? 'new-password' : 'current-password' ?>" required placeholder="<?= $setup ? 'At least 8 characters' : '••••••••' ?>"><button class="eye" type="button" data-eye="p" aria-label="Show password"><i class="fa-solid fa-eye" style="color:#8b5cf6"></i></button></div>
        <?php if ($setup): ?><div class="meter"><i id="mt"></i></div><div class="hint" id="mh">Use 8+ characters, mix letters &amp; numbers.</div><?php endif; ?></div>
      <?php if ($setup): ?>
      <div class="f"><label for="p2">Confirm password</label>
        <div class="in"><i class="fa-solid fa-lock" style="color:#f59e0b"></i><input id="p2" name="password2" type="password" autocomplete="new-password" required placeholder="Repeat password"><button class="eye" type="button" data-eye="p2" aria-label="Show password"><i class="fa-solid fa-eye" style="color:#8b5cf6"></i></button></div></div>
      <?php else: ?>
      <div class="row"><label class="chk"><input type="checkbox" name="remember" value="1">Keep me signed in for 30 days</label></div>
      <?php endif; ?>
      <button class="btn" type="submit" id="go"><i class="fa-solid <?= $setup ? 'fa-user-plus' : 'fa-right-to-bracket' ?>"></i><?= $setup ? 'Create account' : 'Sign in' ?></button>
    </form>
  </div>
  <div class="foot"><i class="fa-solid fa-shield-halved" style="color:#10b981"></i> Protected · FileDash</div>
</main>
<script>
(() => {
  const root = document.documentElement;
  const ls = { get: (k, d) => { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } }, set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} } };
  function applyTheme() { const t = ls.get('fd_theme', 'auto'); root.classList.toggle('light', !(t === 'dark' || (t === 'auto' && matchMedia('(prefers-color-scheme:dark)').matches))); }
  function hsl(h) { const n = parseInt(h.slice(1), 16), r = (n >> 16) / 255, g = (n >> 8 & 255) / 255, b = (n & 255) / 255, mx = Math.max(r, g, b), mn = Math.min(r, g, b); let H = 0, S = 0; const L = (mx + mn) / 2; if (mx !== mn) { const d = mx - mn; S = L > .5 ? d / (2 - mx - mn) : d / (mx + mn); H = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; H *= 60; } return [H, S * 100, L * 100]; }
  function applyAccent() { const a = ls.get('fd_accent', null); if (!a) return; const [h, s, l] = hsl(a); root.style.setProperty('--ac', a); root.style.setProperty('--ac2', `hsl(${(h + 45) % 360} ${Math.max(s, 55)}% ${Math.min(Math.max(l, 52), 62)}%)`); document.querySelector('meta[name=theme-color]').content = a; }
  document.getElementById('themeBtn').onclick = () => { const o = ['auto', 'light', 'dark'], n = o[(o.indexOf(ls.get('fd_theme', 'auto')) + 1) % 3]; ls.set('fd_theme', n); applyTheme(); };
  applyTheme(); applyAccent();

  document.querySelectorAll('[data-eye]').forEach(b => b.onclick = () => { const i = document.getElementById(b.dataset.eye), show = i.type === 'password'; i.type = show ? 'text' : 'password'; b.firstElementChild.className = 'fa-solid ' + (show ? 'fa-eye-slash' : 'fa-eye'); });

  const p = document.getElementById('p'), mt = document.getElementById('mt'), mh = document.getElementById('mh');
  if (mt) p.addEventListener('input', () => {
    const v = p.value; let s = 0; if (v.length >= 8) s++; if (v.length >= 12) s++; if (/[a-z]/.test(v) && /[A-Z]/.test(v)) s++; if (/\d/.test(v)) s++; if (/[^A-Za-z0-9]/.test(v)) s++;
    const L = [['Too weak', '#ef4444'], ['Weak', '#ef4444'], ['Okay', '#f59e0b'], ['Good', '#22c55e'], ['Strong', '#10b981'], ['Very strong', '#10b981']][v ? s : 0];
    mt.style.width = (v ? Math.max(12, s * 20) : 0) + '%'; mt.style.background = L[1]; mh.textContent = v ? L[0] : 'Use 8+ characters, mix letters & numbers.';
  });
  /* "signed out" / "session expired" notice vanishes after 5 s (and ?out / ?expired leave the URL) */
  const fl = document.getElementById('flash');
  if (fl) {
    try { const u = new URL(location.href); if (u.searchParams.has('out') || u.searchParams.has('expired')) { u.searchParams.delete('out'); u.searchParams.delete('expired'); history.replaceState(null, '', u); } } catch (e) {}
    setTimeout(() => { fl.style.maxHeight = fl.offsetHeight + 'px'; void fl.offsetHeight; fl.classList.add('fade'); setTimeout(() => fl.remove(), 600); }, 5000);
  }
  document.getElementById('lf').addEventListener('submit', () => { try { localStorage.removeItem('fd_view'); document.cookie = 'fd_view=;path=/;max-age=0;SameSite=Lax'; } catch (e) {}   /* every new sign-in / new account starts with the list view */ const g = document.getElementById('go'); setTimeout(() => { g.disabled = true; g.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>Please wait…'; }, 0); });
})();
</script>
</body>
</html>
<?php
} }

namespace FDLogout {
use \RecursiveIteratorIterator; use \RecursiveDirectoryIterator; use \FilesystemIterator; use \ZipArchive; use \DateTime; use \DateTimeZone; use \DirectoryIterator; use \SplFileInfo; use \Exception; use \Throwable; use \finfo;
if ($__fdpage === 'logout') {

/**
 * FileDash — ?fdpage=logout
 * Link it as:  ?fdpage=logout&t=<?= urlencode(fdaCsrf()) ?>   (signs out at once)
 * Opened without a valid token it shows a confirm button, so another site can't log you out silently.
 */
fdaSession();

if (!fdaLoggedIn()) { header('Location: ?fdpage=login'); exit; }

$tok = (string)($_POST['t'] ?? $_GET['t'] ?? '');
if ($tok !== '' && hash_equals(fdaCsrf(), $tok)) {
    fdaLog('logout', 'Signed out');
    fdaLogout();
    header('Location: ?fdpage=login&out=1'); exit;
}
$csrf = htmlspecialchars(fdaCsrf(), ENT_QUOTES, 'UTF-8');
?><!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Sign out — FileDash</title>
<style>
:root{--ac:#6366f1;--ac2:#ec4899;--bg:#0a0e1a;--card:#111827;--tx:#e8eaf6;--mut:#8f9bb8;--bd:rgba(255,255,255,.08);color-scheme:dark}
@media (prefers-color-scheme:light){:root{--bg:#eef1fb;--card:#fff;--tx:#151a33;--mut:#64708f;--bd:rgba(20,26,60,.1);color-scheme:light}}
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:grid;place-items:center;padding:16px;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--tx)}
.c{width:100%;max-width:360px;text-align:center;padding:28px 24px;border-radius:24px;background:var(--card);border:1px solid var(--bd)}
h1{font-size:19px;margin-bottom:6px}p{color:var(--mut);font-size:13px;margin-bottom:20px}
.b{display:block;width:100%;height:46px;border-radius:14px;font:700 15px inherit;color:#fff;border:0;cursor:pointer;background:linear-gradient(135deg,var(--ac),var(--ac2)); font-weight:bold}
a{display:flex;align-items:center;justify-content:center;width:100%;height:46px;margin-top:10px;border-radius:14px;color:var(--tx);font-size:14.5px;text-decoration:none;font-weight:700;background:rgba(127,140,180,.1);border:1px solid var(--bd);transition:background .15s,border-color .15s,transform .15s}
a:hover{background:rgba(127,140,180,.18);border-color:rgba(127,140,180,.28)}a:active{transform:scale(.98)}
</style></head><body>
<form class="c" method="post">
  <h1>Sign out?</h1><p>You will need to sign in again to open your files.</p>
  <input type="hidden" name="t" value="<?= $csrf ?>">
  <button class="b" type="submit">Sign out</button>
  <a href="index.php">Cancel</a>
</form></body></html>
<?php
} }

namespace FDActions {
use \RecursiveIteratorIterator; use \RecursiveDirectoryIterator; use \FilesystemIterator; use \ZipArchive; use \DateTime; use \DateTimeZone; use \DirectoryIterator; use \SplFileInfo; use \Exception; use \Throwable; use \finfo;
/* hoisted function declarations (must be unconditional) */
function resolveServerPath($path) {
    global $server_root;
    $path = trim($path);
    if (empty($path)) return $server_root;
    if (strpos($path, '/') === 0 || preg_match('/^[A-Z]:\\\\/i', $path)) {
        $real = realpath($path);
        if ($real !== false && file_exists($real)) return $real;
    }
    $real = realpath($server_root . '/' . $path);
    if ($real !== false) return $real;
    return $server_root;
}

function moveToTrash($source, $trash_dir) {
    if (!file_exists($source)) return false;

    $basename = basename($source);
    $destination = $trash_dir . '/' . $basename;

    // Handle duplicate names in trash
    if (file_exists($destination)) {
        $info = pathinfo($basename);
        $destination = $trash_dir . '/' . ($info['filename'] ?? $basename) . '_' . time() . (isset($info['extension']) ? '.' . $info['extension'] : '');
    }

    if (is_file($source)) {
        // Use copy + unlink for bulletproof file moving across filesystems
        if (@copy($source, $destination)) {
            @unlink($source);
            return true;
        }
    } elseif (is_dir($source)) {
        if (!is_dir($destination)) {
            @mkdir($destination, 0755, true);
        }
        $files = scandir($source);
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') continue;
            moveToTrash($source . '/' . $file, $destination);
        }
        @rmdir($source);
        return true;
    }
    return false;
}

if ($__fdpage === 'actions') {

/**
 * Modern Neon File Manager - ?fdpage=actions (Trash & Action Handler Fixed)
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

$server_root = realpath($_SERVER['DOCUMENT_ROOT'] ? $_SERVER['DOCUMENT_ROOT'] : FD_APP_ROOT);

// Helper to resolve paths securely



// Robust function to move files and folders to .trash



$current_path = resolveServerPath($_GET['path'] ?? $server_root);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // 1. Delete Action (Single File/Folder)
    if ($action === 'delete') {
        $item_path = $_POST['item_path'] ?? '';
        $trash_dir = $server_root . '/.trash';

        if (!is_dir($trash_dir)) {
            @mkdir($trash_dir, 0755, true);
        }

        if (!empty($item_path) && file_exists($item_path)) {
            moveToTrash($item_path, $trash_dir);
        }
    }

    // 2. Multi-Delete Action (Bulk Checkboxes)
    elseif ($action === 'multi_delete') {
        $files = $_POST['files'] ?? [];
        $trash_dir = $server_root . '/.trash';

        if (!is_dir($trash_dir)) {
            @mkdir($trash_dir, 0755, true);
        }

        foreach ($files as $file_path) {
            if (!empty($file_path) && file_exists($file_path)) {
                moveToTrash($file_path, $trash_dir);
            }
        }
    }

    // 3. Create Folder Action
    elseif ($action === 'create_folder') {
        $folder_name = trim($_POST['folder_name'] ?? '');
        if (!empty($folder_name)) {
            $new_folder = rtrim($current_path, '/') . '/' . $folder_name;
            if (!file_exists($new_folder)) {
                @mkdir($new_folder, 0755, true);
            }
        }
    }

    // 4. Create File Action
    elseif ($action === 'create_file') {
        $file_name = trim($_POST['file_name'] ?? '');
        if (!empty($file_name)) {
            $new_file = rtrim($current_path, '/') . '/' . $file_name;
            if (!file_exists($new_file)) {
                @file_put_contents($new_file, '');
            }
        }
    }

    // 5. Rename Action
    elseif ($action === 'rename') {
        $item_path = $_POST['item_path'] ?? '';
        $new_name = trim($_POST['new_name'] ?? '');
        if (!empty($item_path) && !empty($new_name) && file_exists($item_path)) {
            $dir = dirname($item_path);
            $target = rtrim($dir, '/') . '/' . $new_name;
            if (!file_exists($target)) {
                @rename($item_path, $target);
            }
        }
    }

    // 6. Upload Action
    elseif ($action === 'upload') {
        if (isset($_FILES['files'])) {
            $file_count = count($_FILES['files']['name']);
            for ($i = 0; $i < $file_count; $i++) {
                if ($_FILES['files']['error'][$i] === UPLOAD_ERR_OK) {
                    $tmp_name = $_FILES['files']['tmp_name'][$i];
                    $name = basename($_FILES['files']['name'][$i]);
                    @move_uploaded_file($tmp_name, rtrim($current_path, '/') . '/' . $name);
                }
            }
        }
    }

    // 7. Copy / Paste Action (Fixed for folders and files)
    elseif ($action === 'paste_copy') {
        $src = $_POST['item_path'] ?? '';
        $dest_dir = $_POST['dest_path'] ?? $current_path;
        
        if ($src && file_exists($src)) {
            $dest = rtrim($dest_dir, '/') . '/' . basename($src);
            
            // যদি এটি ফোল্ডার হয়, তবে রিকার্সিভভাবে কপি করুন
            if (is_dir($src)) {
                if (!is_dir($dest)) {
                    @mkdir($dest, 0755, true);
                }
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($src, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );
                foreach ($iterator as $item) {
                    $subDest = $dest . DIRECTORY_SEPARATOR . $iterator->getSubPathName();
                    if ($item->isDir()) {
                        if (!is_dir($subDest)) {
                            @mkdir($subDest, 0755, true);
                        }
                    } else {
                        $subDestDir = dirname($subDest);
                        if (!is_dir($subDestDir)) {
                            @mkdir($subDestDir, 0755, true);
                        }
                        @copy($item->getRealPath(), $subDest);
                    }
                }
            } else {
                // সাধারণ ফাইল হলে সরাসরি কপি হবে
                @copy($src, $dest);
            }
        }
    }

    // 8. Move / Paste Action
    elseif ($action === 'paste_move') {
        $src = $_POST['item_path'] ?? '';
        $dest_dir = $_POST['dest_path'] ?? $current_path;
        if ($src && file_exists($src)) {
            $dest = rtrim($dest_dir, '/') . '/' . basename($src);
            @rename($src, $dest);
        }
    }

    // 9. Multi-Download (ZIP) Action
    elseif ($action === 'multi_download') {
        $files = $_POST['files'] ?? [];
        if (!empty($files) && class_exists('ZipArchive')) {
            $zip = new ZipArchive();
            $zip_name = sys_get_temp_dir() . '/neon_files_' . time() . '.zip';
            
            if ($zip->open($zip_name, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
                foreach ($files as $f_path) {
                    if ($f_path && file_exists($f_path)) {
                        if (is_dir($f_path)) {
                            $iterator = new RecursiveIteratorIterator(
                                new RecursiveDirectoryIterator($f_path, RecursiveDirectoryIterator::SKIP_DOTS),
                                RecursiveIteratorIterator::SELF_FIRST
                            );
                            foreach ($iterator as $file) {
                                $sub_path = $file->getRealPath();
                                $relative_sub = substr($sub_path, strlen($f_path) + 1);
                                if ($file->isDir()) {
                                    $zip->addEmptyDir(basename($f_path) . '/' . $relative_sub);
                                } else if ($file->isFile()) {
                                    $zip->addFile($sub_path, basename($f_path) . '/' . $relative_sub);
                                }
                            }
                        } else {
                            $zip->addFile($f_path, basename($f_path));
                        }
                    }
                }
                $zip->close();

                header('Content-Type: application/zip');
                header('Content-Disposition: attachment; filename="download_' . date('Y-m-d') . '.zip"');
                header('Content-Length: ' . filesize($zip_name));
                readfile($zip_name);
                @unlink($zip_name);
                exit;
            }
        }
    }
}

// Redirect back to file manager index keeping the current path active
header('Location: index.php?path=' . urlencode($current_path));
exit;
} }

namespace FDTrashPage {
use \RecursiveIteratorIterator; use \RecursiveDirectoryIterator; use \FilesystemIterator; use \ZipArchive; use \DateTime; use \DateTimeZone; use \DirectoryIterator; use \SplFileInfo; use \Exception; use \Throwable; use \finfo;
/* hoisted function declarations (must be unconditional) */
function trash_meta_load(string $trash_dir): array
{
    $f = $trash_dir . '/.trash_meta.json';
    if (!is_file($f)) return [];
    $data = json_decode((string) @file_get_contents($f), true);
    return is_array($data) ? $data : [];
}

function trash_meta_save(string $trash_dir, array $meta): void
{
    @file_put_contents($trash_dir . '/.trash_meta.json', json_encode($meta, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);
}

function trash_move(string $abs_path): bool
{
    $trash_dir = FD_APP_ROOT . '/.trash';
    if (!is_dir($trash_dir) && !@mkdir($trash_dir, 0755, true)) return false;

    $real = realpath($abs_path);
    $trash_real = realpath($trash_dir);
    if ($real === false || $trash_real === false) return false;
    if ($real === $trash_real || strpos($real . DIRECTORY_SEPARATOR, $trash_real . DIRECTORY_SEPARATOR) === 0) return false;

    $name = basename($real);
    $target = $name;
    if (file_exists($trash_dir . '/' . $target) || is_link($trash_dir . '/' . $target)) {
        $info = pathinfo($name);
        $target = $info['filename'] . '_' . time() . '_' . random_int(10, 99)
            . (isset($info['extension']) ? '.' . $info['extension'] : '');
    }
    if (!@rename($real, $trash_dir . '/' . $target)) return false;

    $meta = trash_meta_load($trash_dir);
    $meta[$target] = ['orig' => str_replace('\\', '/', $real), 'time' => time()];
    trash_meta_save($trash_dir, $meta);
    return true;
}

function rm_recursive(string $path): bool
{
    if (is_link($path) || is_file($path)) {
        return @unlink($path);
    }
    if (!is_dir($path)) {
        return false;
    }
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $f) {
        if ($f->isLink() || $f->isFile()) {
            @unlink($f->getPathname());
        } else {
            @rmdir($f->getPathname());
        }
    }
    return @rmdir($path);
}

function dir_stats(string $path): array
{
    $size = 0;
    $count = 0;
    $dirs = 0;
    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($it as $f) {
            if ($f->isDir() && !$f->isLink()) {
                $dirs++;
            } elseif ($f->isFile()) {
                $size += $f->getSize();
                $count++;
            }
        }
    } catch (Exception $e) {
    }
    return [$size, $count, $dirs];
}

function human_size(int $bytes): string
{
    if ($bytes <= 0) return '0 B';
    $u = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = min((int) floor(log($bytes, 1024)), count($u) - 1);
    return round($bytes / pow(1024, $i), $i ? 1 : 0) . ' ' . $u[$i];
}

function time_ago(int $ts): string
{
    $d = time() - $ts;
    if ($d < 60) return 'just now';
    if ($d < 3600) return floor($d / 60) . ' min ago';
    if ($d < 86400) return floor($d / 3600) . ' hr ago';
    if ($d < 86400 * 30) return floor($d / 86400) . ' days ago';
    return date('d M Y', $ts);
}

function file_icon(string $name): array
{
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    $map = [
        'image'   => [['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico'], 'fa-file-image', 'text-pink-400', 'Image'],
        'video'   => [['mp4', 'mkv', 'avi', 'mov', 'webm'], 'fa-file-video', 'text-purple-400', 'Video'],
        'audio'   => [['mp3', 'wav', 'ogg', 'flac', 'm4a'], 'fa-file-audio', 'text-fuchsia-400', 'Audio'],
        'archive' => [['zip', 'rar', '7z', 'tar', 'gz'], 'fa-file-zipper', 'text-orange-400', 'Archive'],
        'code'    => [['php', 'js', 'css', 'html', 'json', 'py', 'sql', 'xml', 'sh', 'ts'], 'fa-file-code', 'text-emerald-400', 'Code'],
        'doc'     => [['pdf', 'doc', 'docx', 'txt', 'md', 'xls', 'xlsx', 'ppt', 'pptx', 'csv'], 'fa-file-lines', 'text-sky-400', 'Document'],
    ];
    foreach ($map as $key => [$exts, $icon, $color, $label]) {
        if (in_array($ext, $exts, true)) {
            return [$key, $icon, $color, $label];
        }
    }
    return ['other', 'fa-file', 'text-indigo-400', 'File'];
}

function flash(string $type, string $msg): void
{
    $_SESSION['trash_flash'] = ['type' => $type, 'msg' => $msg];
}

function restore_target(array $meta, string $name, string $trash_dir, string $root_path): string
{
    $orig = (string) ($meta[$name]['orig'] ?? '');
    $ok = $orig !== ''
        && preg_match('#^(/|[A-Za-z]:/)#', $orig)
        && !preg_match('#(^|/)\.\.(/|$)#', $orig)
        && strpos($orig . '/', str_replace('\\', '/', $trash_dir) . '/') !== 0;
    return $ok ? $orig : $root_path . '/' . $name;
}

if ($__fdpage === 'trash') {

/**
 * Modern Neon File Manager - ?fdpage=trash (Recycle Bin System, v2)
 * Features: search, sort, filter, bulk restore/purge, stats, auto-clean old items,
 * CSRF protection, flash messages, custom confirm modal, fully responsive.
 */
/* ===== Trash library =====
 * index.php uses this file as a library:
 *
 *     trash_move($full_path);   // moves to .trash and remembers the original location
 */











error_reporting(E_ALL);
ini_set('display_errors', 1);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}
if (empty($_SESSION['trash_csrf'])) {
    $_SESSION['trash_csrf'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['trash_csrf'];

$root_path = FD_APP_ROOT;
$trash_dir = $root_path . '/.trash';

if (!is_dir($trash_dir)) {
    mkdir($trash_dir, 0755, true);
}

/* ---------- Helpers ---------- */


















/** Where an item will be restored to (original path if known and safe, else root folder). */



/* ---------- Actions ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($csrf, (string) ($_POST['csrf'] ?? ''))) {
        http_response_code(403);
        exit('Invalid CSRF token.');
    }

    $action = $_POST['action'] ?? '';
    $names = $_POST['items'] ?? [];
    if (!is_array($names)) $names = [$names];
    $names = array_values(array_unique(array_filter(array_map('basename', array_map('strval', $names)), function ($n) {
        return $n !== '' && $n !== '.' && $n !== '..' && $n !== '.trash_meta.json';
    })));

    $done = 0;
    $failed = 0;

    if ($action === 'restore') {
        $meta = trash_meta_load($trash_dir);
        foreach ($names as $name) {
            $src = $trash_dir . '/' . $name;
            if (!file_exists($src) && !is_link($src)) { $failed++; continue; }

            // Restore to the original location (fallback: root folder)
            $dest = restore_target($meta, $name, $trash_dir, $root_path);
            $dest_dir = dirname($dest);
            if (!is_dir($dest_dir)) {
                @mkdir($dest_dir, 0755, true);
            }
            if (file_exists($dest) || is_link($dest)) {
                $info = pathinfo($dest);
                $dest = $info['dirname'] . '/' . $info['filename'] . '_' . time() . '_' . random_int(10, 99)
                    . (isset($info['extension']) ? '.' . $info['extension'] : '');
            }
            @rename($src, $dest) ? $done++ : $failed++;
        }
        flash($failed ? 'warn' : 'ok', "$done item(s) restored" . ($failed ? ", $failed failed." : '.'));
    } elseif ($action === 'purge') {
        foreach ($names as $name) {
            $p = $trash_dir . '/' . $name;
            if (!file_exists($p) && !is_link($p)) { $failed++; continue; }
            rm_recursive($p) ? $done++ : $failed++;
        }
        flash($failed ? 'warn' : 'ok', "$done item(s) permanently deleted" . ($failed ? ", $failed failed." : '.'));
    } elseif ($action === 'purge_old') {
        $days = max(1, min(3650, (int) ($_POST['days'] ?? 30)));
        $limit = time() - $days * 86400;
        $meta = trash_meta_load($trash_dir);
        foreach (scandir($trash_dir) as $item) {
            if ($item === '.' || $item === '..' || $item === '.trash_meta.json') continue;
            $p = $trash_dir . '/' . $item;
            // age = time spent in the trash (falls back to file mtime for older items)
            $when = (int) ($meta[$item]['time'] ?? (@filemtime($p) ?: time()));
            if ($when < $limit) {
                rm_recursive($p) ? $done++ : $failed++;
            }
        }
        flash('ok', "$done item(s) older than $days days deleted" . ($failed ? ", $failed failed." : '.'));
    } elseif ($action === 'empty_trash') {
        foreach (scandir($trash_dir) as $item) {
            if ($item === '.' || $item === '..' || $item === '.trash_meta.json') continue;
            rm_recursive($trash_dir . '/' . $item) ? $done++ : $failed++;
        }
        flash($failed ? 'warn' : 'ok', "Trash emptied ($done item(s) removed" . ($failed ? ", $failed failed" : '') . ').');
    }

    // Drop metadata for items that no longer exist in the trash
    $meta = trash_meta_load($trash_dir);
    foreach (array_keys($meta) as $k) {
        if (!file_exists($trash_dir . '/' . $k) && !is_link($trash_dir . '/' . $k)) {
            unset($meta[$k]);
        }
    }
    trash_meta_save($trash_dir, $meta);

    header('Location: ?fdpage=trash' . (isset($_GET['embed']) ? '&embed=1' : ''));
    exit;
}

/* ---------- Load items ---------- */
$items = [];
$total_size = 0;
$meta = trash_meta_load($trash_dir);
foreach (scandir($trash_dir) as $item) {
    if ($item === '.' || $item === '..' || $item === '.trash_meta.json') continue;
    $p = $trash_dir . '/' . $item;
    $is_dir = is_dir($p) && !is_link($p);
    if ($is_dir) {
        [$size, $children, $subdirs] = dir_stats($p);
    } else {
        $size = (int) @filesize($p);
        $children = 0;
        $subdirs = 0;
    }
    $modified = (int) (@filemtime($p) ?: time());
    $deleted = (int) ($meta[$item]['time'] ?? $modified);   // real deletion time (older items: mtime)
    $mtime = $deleted;
    [$type, $icon, $color, $label] = $is_dir ? ['folder', 'fa-folder', 'text-amber-400', 'Folder'] : file_icon($item);
    $orig = (string) ($meta[$item]['orig'] ?? '');
    $orig_dir = $orig !== '' ? dirname($orig) : null; // null = unknown -> restores to root

    // ---- properties shown in the details sheet ----
    $ext = $is_dir ? '' : strtolower(pathinfo($item, PATHINFO_EXTENSION));
    $dest_path = restore_target($meta, $item, $trash_dir, $root_path);
    $dim = null;
    if (in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'], true) && $size < 50 * 1024 * 1024) {
        $gi = @getimagesize($p);
        if ($gi) $dim = $gi[0] . ' × ' . $gi[1] . ' px';
    }
    $mime = $is_dir ? 'Directory' : (function_exists('mime_content_type') ? (@mime_content_type($p) ?: 'unknown') : 'unknown');
    $props = [
        'name' => $item, 'icon' => $icon, 'color' => $color, 'kind' => $label, 'ext' => $ext, 'mime' => $mime,
        'size_h' => human_size($size), 'size_b' => number_format($size),
        'is_dir' => $is_dir, 'files' => $children, 'folders' => $subdirs, 'dim' => $dim,
        'tracked' => $orig !== '', 'orig' => $orig !== '' ? $orig : null,
        'restore_to' => $dest_path,
        'dest_exists' => is_dir(dirname($dest_path)),
        'conflict' => file_exists($dest_path) || is_link($dest_path),
        'deleted' => date('d M Y, H:i', $deleted), 'ago' => time_ago($deleted),
        'days' => (int) floor((time() - $deleted) / 86400),
        'modified' => date('d M Y, H:i', $modified),
        'perms' => substr(sprintf('%o', @fileperms($p) ?: 0), -4),
    ];

    $items[] = [
        'props' => $props,
        'orig_dir' => $orig_dir,
        'name' => $item, 'is_dir' => $is_dir, 'size' => $size, 'children' => $children,
        'mtime' => $mtime, 'type' => $type, 'icon' => $icon, 'color' => $color, 'label' => $label,
    ];
    $total_size += $size;
}
usort($items, fn($a, $b) => $b['mtime'] <=> $a['mtime']);

$folder_count = count(array_filter($items, fn($i) => $i['is_dir']));
$file_count = count($items) - $folder_count;
$flash = $_SESSION['trash_flash'] ?? null;
unset($_SESSION['trash_flash']);
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <script>(function(){function apply(){var t="auto";try{var v=localStorage.getItem("fd_theme");if(v!==null)t=JSON.parse(v)}catch(e){}var d=t==="dark"||(t==="auto"&&matchMedia("(prefers-color-scheme:dark)").matches);document.documentElement.classList.toggle("dark",d);document.documentElement.classList.toggle("light",!d)}apply();addEventListener("storage",function(e){if(e.key==="fd_theme")apply()});})();</script>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recycle Bin - Neon File Manager</title>
    <?php fdJs('tailwind.js'); ?>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: { extend: { colors: { darkBg: '#0b0f19', panelBg: '#111827' } } }
        }
    </script>
    <?php fdCss('fa/css/all.min.css'); ?>
    <style>
        html.light body{background:#eef1fb!important;color:#151a33!important}
        html.light .glass-panel{background:rgba(255,255,255,.9)!important;border-color:rgba(20,26,60,.1)!important}
        html.light .stats-wrap,html.light .stat-card{background:rgba(255,255,255,.94)!important;border-color:rgba(20,26,60,.1)!important;color:#151a33!important}
        html.light .stat-card .text-slate-400{color:#64708b!important}
        html.light body [class*="text-slate-"]{color:#334155!important}
        html.light body [class*="bg-slate-"]{background-color:#fff!important;border-color:rgba(20,26,60,.12)!important}

        /* ===== Dark mode = same palette as Dashboard / Activity log (bg #0a0e1a · card #111827 · soft white borders) ===== */
        html:not(.light) body{background:#0a0e1a!important;background-image:none!important;color:#e8eaf6;font-family:Inter,system-ui,-apple-system,"Noto Sans Bengali","Segoe UI",sans-serif}
        html:not(.light) body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background:radial-gradient(600px 400px at 8% -5%,rgba(99,102,241,.22),transparent),radial-gradient(500px 380px at 100% 100%,rgba(236,72,153,.16),transparent)}
        html:not(.light) .glass-panel:not(.sticky),html:not(.light) .stats-wrap,html:not(.light) .stat-card{background:#111827!important;border:1px solid rgba(255,255,255,.08)!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important;box-shadow:0 12px 34px rgba(0,0,0,.4)!important}
        html:not(.light) .stats-wrap .stat-card{background:transparent!important;border:0!important;box-shadow:none!important}
        html:not(.light) .stat-card + .stat-card::before{background:rgba(255,255,255,.1)}
        @media (min-width:640px){html:not(.light) .stats-wrap{background:none!important;border:0!important;box-shadow:none!important}html:not(.light) .stats-wrap .stat-card{background:#111827!important;border:1px solid rgba(255,255,255,.08)!important;box-shadow:0 12px 34px rgba(0,0,0,.4)!important}}
        html:not(.light) body [class*="text-slate-100"],html:not(.light) body [class*="text-slate-200"],html:not(.light) body [class*="text-slate-300"]{color:#e8eaf6}
        html:not(.light) body [class*="text-slate-400"],html:not(.light) body [class*="text-slate-500"]{color:#8f9bb8}
        html:not(.light) body [class*="border-slate-"]:not([class*="border-indigo"]){border-color:rgba(255,255,255,.08)}
        html:not(.light) body input[class*="bg-slate-900"],html:not(.light) body select[class*="bg-slate-900"]{background:#172033;border-color:rgba(255,255,255,.08)}
        html:not(.light) body .row-grid[class*="bg-slate-900"]{background:rgba(255,255,255,.03)}
        html:not(.light) body .item-row{background:transparent}
        html:not(.light) button.w-8.h-8:not(:hover){background:#172033}
        html:not(.light) .chk{border-color:#8f9bb8}
        html:not(.light) ::-webkit-scrollbar-thumb{background:#2a3550}

        body {
            background-image:
                radial-gradient(ellipse at 15% 0%, rgba(244, 63, 94, 0.10), transparent 45%),
                radial-gradient(ellipse at 90% 10%, rgba(99, 102, 241, 0.12), transparent 40%);
            background-attachment: fixed;
        }
        .glass-panel {
            background: rgba(17, 24, 39, 0.75);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.06);
        }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }

        .row-grid { display: grid; grid-template-columns: 2rem minmax(0, 1fr); gap: .75rem; align-items: center; }
        @media (min-width: 640px)  { .row-grid { grid-template-columns: 2rem minmax(0, 1fr) 6.5rem auto; } }
        @media (min-width: 768px)  { .row-grid { grid-template-columns: 2rem minmax(0, 1fr) 6.5rem 9rem auto; } }

        .chk { appearance: none; width: 1.1rem; height: 1.1rem; border-radius: .35rem; border: 1.5px solid #475569;
               background: transparent; cursor: pointer; display: grid; place-content: center; transition: all .15s; }
        .chk:checked { background: #6366f1; border-color: #6366f1; box-shadow: 0 0 10px rgba(99,102,241,.6); }
        .chk:checked::after { content: "\f00c"; font-family: "Font Awesome 6 Free", "FontAwesome"; font-weight: 900; font-size: .6rem; color: #fff; }

        .item-row { animation: rise .35s ease both; }
        @keyframes rise { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
        .modal-enter { animation: pop .18s ease both; }
        @keyframes pop { from { opacity: 0; transform: scale(.94); } to { opacity: 1; transform: none; } }
        .toast-in { animation: toast .4s ease both;}
        @keyframes toast { from { opacity: 0; translate: 0 -12px; } to { opacity: 1; translate: 0 0; }}
        /* Stats: mobile = ONE panel with '|' dividers; desktop (>=640px) = 4 separate cards, unchanged */
        .stats-wrap {
            background: rgba(17, 24, 39, 0.75);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 1rem;
            box-shadow: 0 10px 15px -3px rgba(0,0,0,.1), 0 4px 6px -4px rgba(0,0,0,.1);
        }
        .stat-card { position: relative; }
        .stat-card + .stat-card::before {
            content: ""; position: absolute; left: 0; top: 22%; bottom: 22%;
            width: 1px; background: rgba(148, 163, 184, 0.35);
        }
        @media (min-width: 640px) {
            .stats-wrap { background: none; backdrop-filter: none; -webkit-backdrop-filter: none; border: 0; border-radius: 0; box-shadow: none; }
            .stat-card {
                background: rgba(17, 24, 39, 0.75);
                backdrop-filter: blur(16px);
                -webkit-backdrop-filter: blur(16px);
                border: 1px solid rgba(255, 255, 255, 0.06);
                border-radius: 1rem;
            }
            .stat-card + .stat-card::before { display: none; }
        }
        .sheet-enter { animation: sheetUp .22s ease both; }
        @keyframes sheetUp { from { transform: translateY(100%); } to { transform: none; } }
        @media (min-width: 640px) { .sheet-enter { animation: pop .18s ease both; } }
        .item-row { -webkit-tap-highlight-color: transparent; }
        @media (pointer: coarse) { .item-row { -webkit-touch-callout: none; -webkit-user-select: none; user-select: none; } }
        @media(max-width:639px){
          header.glass-panel.sticky{padding:10px 12px!important;gap:8px!important;justify-content:space-between!important}
          header.glass-panel.sticky>div:first-child{display:flex!important;align-items:center!important;gap:9px!important;min-width:0}
          header.glass-panel.sticky>div:first-child>div p{display:none!important}
          header.glass-panel.sticky>div:last-child{gap:6px!important}
          header.glass-panel.sticky button{width:36px;height:36px;padding:0!important;justify-content:center}
          header.glass-panel.sticky button span{display:none!important}
          main{padding:12px!important}
        }
    <?php if (isset($_GET['embed'])): ?>
/* embedded in FileDash: same page header as Shared links / Activity log (back · title · count · icon actions) */
html,body{background:transparent!important;min-height:100%;overflow-x:hidden}
.glass-panel.sticky{position:static!important;border:0!important;box-shadow:none!important;background:transparent!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important;padding:4px 14px 0!important;gap:12px!important}
.glass-panel.sticky>div:first-child{display:flex!important;align-items:center!important;gap:12px!important;min-width:0;flex:1}
.glass-panel.sticky>div:first-child>a{width:40px!important;height:40px!important;border-radius:12px!important}
.glass-panel.sticky h1{font-size:18px!important;line-height:1.2}
.glass-panel.sticky>div:first-child p{display:block!important;font-size:11.5px!important}
.glass-panel.sticky>div:last-child{gap:6px!important}
.glass-panel.sticky>div:last-child button{height:34px;padding:0 13px!important;gap:7px;justify-content:center;border-radius:10px!important;font-size:13px;font-weight:600;white-space:nowrap}
@media(max-width:639px){.glass-panel.sticky>div:last-child button{width:34px;padding:0!important}.glass-panel.sticky>div:last-child button span{display:none!important}}
.pgcnt{padding:3px 11px;border-radius:99px;background:rgba(148,163,184,.12);border:1px solid rgba(148,163,184,.25);color:#94a3b8;font-size:12.5px;font-weight:600}
main{max-width:none!important;width:100%!important;margin:0!important;padding:14px!important}
<?php endif; ?>
</style>
</head>
<body class="bg-darkBg text-slate-100 min-h-screen flex flex-col font-sans">

    <!-- Top Navigation -->
    <header class="glass-panel sticky top-0 z-40 px-3 sm:px-6 py-3 flex items-center justify-between gap-3 border-b border-slate-800 shadow-xl">
        <div class="flex items-center space-x-3 min-w-0">
            <a href="index.php" class="bg-slate-800 hover:bg-slate-700 p-2 w-9 h-9 flex items-center justify-center rounded-xl text-slate-300 transition shrink-0" title="Back">
                <i class="fa-solid fa-arrow-left text-xs" style="color:#818cf8"></i>
            </a>
            <div class="min-w-0">
                <h1 class="text-sm sm:text-base font-bold text-slate-100 flex items-center space-x-2">
                    <i class="fa-solid fa-trash-can text-rose-400"></i>
                    <span>Trash</span>
                    <?php if (isset($_GET['embed'])): ?><span class="pgcnt"><?php echo count($items); ?></span><?php endif; ?>
                </h1>
                <p class="text-[10px] text-slate-400 hidden sm:block">Deleted files and folders are stored here</p>
            </div>
        </div>

        <div class="flex items-center gap-2 shrink-0">
            <button type="button" onclick="cleanOld()" class="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-2 rounded-xl text-xs font-semibold transition flex items-center gap-1.5 disabled:opacity-40" <?php echo $items ? '' : 'disabled'; ?> title="Delete items older than N days">
                <i class="fa-solid fa-broom" style="color:#f59e0b"></i><span class="hidden sm:inline">Clean old</span>
            </button>
            <button type="button" onclick="emptyAll()" class="bg-rose-600/80 hover:bg-rose-600 text-white px-3 py-2 rounded-xl text-xs font-semibold shadow transition flex items-center gap-1.5 disabled:opacity-40" <?php echo $items ? '' : 'disabled'; ?>>
                <i class="fa-solid fa-ban" style="color:#ef4444"></i><span class="hidden sm:inline">Empty Trash</span>
            </button>
        </div>
    </header>

    <?php if ($flash): ?>
    <div id="toast" class="toast-in fixed top-16 sm:top-20 left-1/2 -translate-x-1/2 z-50 w-[92%] max-w-md">
        <div class="glass-panel rounded-xl px-4 py-3 shadow-2xl flex items-center gap-3 text-sm
            <?php echo $flash['type'] === 'ok' ? 'border-emerald-500/40' : 'border-amber-500/40'; ?>">
            <i class="fa-solid <?php echo $flash['type'] === 'ok' ? 'fa-circle-check text-emerald-400' : 'fa-triangle-exclamation text-amber-400'; ?>"></i>
            <span class="flex-1"><?php echo htmlspecialchars($flash['msg']); ?></span>
            <button onclick="document.getElementById('toast').remove()" class="text-slate-400 hover:text-white"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button>
        </div>
    </div>
    <script>setTimeout(function () { var t = document.getElementById('toast'); if (t) t.remove(); }, 4500);</script>
    <?php endif; ?>

    <main class="flex-1 max-w-7xl w-full mx-auto p-3 sm:p-6 flex flex-col gap-4 pb-28">

        <!-- Stats -->
        <section class="stats-wrap grid grid-cols-4 sm:gap-3">
            <?php
            $stats = [
                ['Total Items', count($items), 'fa-layer-group', 'text-indigo-400', 'bg-indigo-500/10'],
                ['Files', $file_count, 'fa-file', 'text-sky-400', 'bg-sky-500/10'],
                ['Folders', $folder_count, 'fa-folder', 'text-amber-400', 'bg-amber-500/10'],
                ['Space Used', human_size($total_size), 'fa-hard-drive', 'text-rose-400', 'bg-rose-500/10'],
            ];
            foreach ($stats as [$label, $val, $ic, $col, $bg]): ?>
            <div class="stat-card sm:shadow-lg py-3 px-1 sm:p-4 flex flex-col sm:flex-row items-center text-center sm:text-left gap-1.5 sm:gap-3 min-w-0">
                <div class="w-8 h-8 sm:w-10 sm:h-10 rounded-lg sm:rounded-xl <?php echo $bg; ?> flex items-center justify-center shrink-0">
                    <i class="fa-solid <?php echo $ic . ' ' . $col; ?> text-xs sm:text-base"></i>
                </div>
                <div class="min-w-0 w-full">
                    <div class="text-base sm:text-xl font-bold leading-tight truncate"><?php echo $val; ?></div>
                    <div class="text-[10px] sm:text-[11px] uppercase tracking-wide sm:tracking-wider text-slate-400 truncate"><?php echo $label; ?></div>
                </div>
            </div>
            <?php endforeach; ?>
        </section>

        <!-- Toolbar -->
        <section class="glass-panel rounded-2xl p-2 sm:p-3 flex flex-row items-center gap-1.5 sm:gap-2.5 shadow-lg">
            <div class="relative flex-1 min-w-0">
                <i class="fa-solid fa-magnifying-glass absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 text-xs"></i>
                <input id="search" type="text" placeholder="Search..." autocomplete="off"
                    class="w-full bg-slate-900/70 border border-slate-700/80 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 outline-none rounded-xl pl-8 sm:pl-9 pr-2 sm:pr-3 py-2 sm:py-2.5 text-xs sm:text-sm placeholder-slate-500 transition">
            </div>
            <div class="flex gap-1.5 sm:gap-2 shrink-0">
                <select id="filter" class="w-[5rem] sm:w-auto bg-slate-900/70 border border-slate-700/80 rounded-xl px-1.5 sm:px-3 py-2 sm:py-2.5 text-[11px] sm:text-sm outline-none focus:border-indigo-500">
                    <option value="all">All types</option>
                    <option value="folder">Folders</option>
                    <option value="image">Images</option>
                    <option value="video">Videos</option>
                    <option value="audio">Audio</option>
                    <option value="doc">Documents</option>
                    <option value="code">Code</option>
                    <option value="archive">Archives</option>
                    <option value="other">Other</option>
                </select>
                <select id="sort" class="w-[4.4rem] sm:w-auto bg-slate-900/70 border border-slate-700/80 rounded-xl px-1.5 sm:px-3 py-2 sm:py-2.5 text-[11px] sm:text-sm outline-none focus:border-indigo-500">
                    <option value="date-desc">Newest first</option>
                    <option value="date-asc">Oldest first</option>
                    <option value="name-asc">Name A–Z</option>
                    <option value="name-desc">Name Z–A</option>
                    <option value="size-desc">Largest first</option>
                    <option value="size-asc">Smallest first</option>
                </select>
            </div>
        </section>

        <!-- List -->
        <section class="glass-panel rounded-2xl shadow-xl overflow-hidden border border-slate-700/80">
            <!-- Header row -->
            <div class="row-grid px-3 sm:px-4 py-3 border-b border-slate-800 bg-slate-900/40 text-slate-400 text-[11px] uppercase tracking-wider font-semibold">
                <input type="checkbox" id="selectAll" class="chk" title="Select all">
                <span>Name</span>
                <span class="hidden sm:block">Size</span>
                <span class="hidden md:block">Deleted</span>
                <span class="hidden sm:block text-right w-28">Actions</span>
            </div>

            <div id="list" class="divide-y divide-slate-800/40">
                <?php foreach ($items as $i => $it): ?>
                <div class="item-row row-grid px-3 sm:px-4 py-3 hover:bg-slate-800/40 transition"
                     style="animation-delay: <?php echo min($i, 15) * 25; ?>ms"
                     data-name="<?php echo htmlspecialchars(mb_strtolower($it['name']), ENT_QUOTES); ?>"
                     data-type="<?php echo $it['type']; ?>"
                     data-size="<?php echo $it['size']; ?>"
                     data-date="<?php echo $it['mtime']; ?>"
                     data-props="<?php echo htmlspecialchars(json_encode($it['props'], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), ENT_QUOTES); ?>">
                    <input type="checkbox" class="chk row-chk" value="<?php echo htmlspecialchars($it['name'], ENT_QUOTES); ?>">

                    <div class="flex items-center gap-3 min-w-0">
                        <div class="w-9 h-9 rounded-xl bg-slate-800/80 flex items-center justify-center shrink-0">
                            <i class="fa-solid <?php echo $it['icon'] . ' ' . $it['color']; ?>"></i>
                        </div>
                        <div class="min-w-0">
                            <div class="font-medium text-slate-200 truncate text-sm" title="<?php echo htmlspecialchars($it['name']); ?>">
                                <?php echo htmlspecialchars($it['name']); ?>
                            </div>
                            <div class="text-[11px] text-sky-400/80 truncate flex items-center gap-1" title="Original location">
                                <i class="fa-solid fa-location-dot text-[9px] shrink-0" style="color:#38bdf8"></i>
                                <span class="truncate"><?php echo $it['orig_dir'] === null ? '/ (root)' : htmlspecialchars($it['orig_dir']); ?></span>
                            </div>
                            <div class="text-[11px] text-slate-500 truncate">
                                <?php echo $it['label']; ?>
                                <?php if ($it['is_dir']): ?> · <?php echo $it['children']; ?> file(s)<?php endif; ?>
                                <span class="sm:hidden"> · <?php echo human_size($it['size']); ?></span>
                                <span class="md:hidden"> · <?php echo time_ago($it['mtime']); ?></span>
                            </div>
                        </div>
                    </div>

                    <div class="hidden sm:block text-xs text-slate-400 whitespace-nowrap"><?php echo human_size($it['size']); ?></div>
                    <div class="hidden md:block text-xs text-slate-400 whitespace-nowrap" title="<?php echo date('d M Y H:i', $it['mtime']); ?>">
                        <?php echo time_ago($it['mtime']); ?>
                    </div>

                    <div class="hidden sm:flex items-center justify-end gap-1.5 w-28">
                        <button type="button" title="Properties" onclick="showProps(this)"
                            class="w-8 h-8 bg-slate-800 hover:bg-sky-600 text-slate-300 hover:text-white rounded-lg transition">
                            <i class="fa-solid fa-circle-info text-xs" style="color:#38bdf8"></i>
                        </button>
                        <button type="button" title="Restore" onclick='act("restore", [<?php echo json_encode($it['name'], JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_TAG | JSON_HEX_AMP); ?>])'
                            class="w-8 h-8 bg-slate-800 hover:bg-emerald-600 text-slate-300 hover:text-white rounded-lg transition">
                            <i class="fa-solid fa-rotate-left text-xs" style="color:#34d399"></i>
                        </button>
                        <button type="button" title="Delete forever" onclick='act("purge", [<?php echo json_encode($it['name'], JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_TAG | JSON_HEX_AMP); ?>])'
                            class="w-8 h-8 bg-slate-800 hover:bg-rose-600 text-slate-300 hover:text-white rounded-lg transition">
                            <i class="fa-solid fa-trash text-xs" style="color:#fb7185"></i>
                        </button>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>

            <?php if ($items): ?>
            <p class="sm:hidden text-center text-[11px] text-slate-500 py-2.5 border-t border-slate-800/60">
                <i class="fa-solid fa-hand-pointer mr-1" style="color:#fbbf24"></i>Tap for details · Long-press for actions
            </p>
            <?php endif; ?>

            <!-- Empty states -->
            <div id="emptyState" class="<?php echo $items ? 'hidden' : ''; ?> text-center py-16 text-slate-500 text-sm">
                <i class="fa-solid fa-trash-can-arrow-up text-4xl mb-3 text-slate-600 block"></i>
                Recycle bin is empty.
            </div>
            <div id="noMatch" class="hidden text-center py-14 text-slate-500 text-sm">
                <i class="fa-solid fa-magnifying-glass text-3xl mb-3 text-slate-600 block"></i>
                No items match your search.
            </div>
        </section>
    </main>

    <!-- Floating bulk action bar -->
    <div id="bulkBar" class="fixed bottom-4 left-1/2 -translate-x-1/2 z-40 w-[94%] max-w-xl translate-y-32 opacity-0 pointer-events-none transition-all duration-300">
        <div class="glass-panel rounded-2xl shadow-2xl px-3 sm:px-4 py-2.5 flex items-center gap-2 border-indigo-500/30">
            <div class="flex items-center gap-2 flex-1 min-w-0">
                <span id="selCount" class="bg-indigo-600 text-white text-xs font-bold rounded-lg px-2 py-1">0</span>
                <span class="text-xs text-slate-300 truncate">selected</span>
            </div>
            <button type="button" onclick="bulk('restore')" class="bg-emerald-600/90 hover:bg-emerald-600 text-white px-3 py-2 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition">
                <i class="fa-solid fa-rotate-left" style="color:#34d399"></i><span>Restore</span>
            </button>
            <button type="button" onclick="bulk('purge')" class="bg-rose-600/90 hover:bg-rose-600 text-white px-3 py-2 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition">
                <i class="fa-solid fa-trash" style="color:#fb7185"></i><span>Delete</span>
            </button>
            <button type="button" onclick="clearSel()" class="bg-slate-800 hover:bg-slate-700 text-slate-300 w-9 h-9 rounded-xl transition" title="Clear selection">
                <i class="fa-solid fa-xmark text-xs" style="color:#fb7185"></i>
            </button>
        </div>
    </div>

    <!-- Properties / actions sheet (bottom sheet on mobile, centered on desktop) -->
    <div id="sheet" class="hidden fixed inset-0 z-50 bg-black/70 backdrop-blur-sm items-end sm:items-center justify-center sm:p-4">
        <div class="sheet-enter glass-panel w-full sm:max-w-md rounded-t-3xl sm:rounded-2xl shadow-2xl max-h-[88vh] flex flex-col">
            <div class="sm:hidden mx-auto mt-2 h-1 w-10 rounded-full bg-slate-600"></div>
            <div class="flex items-center gap-3 p-4 border-b border-slate-800">
                <div class="w-11 h-11 rounded-xl bg-slate-800 flex items-center justify-center shrink-0">
                    <i id="sIcon" class="fa-solid text-lg"></i>
                </div>
                <div class="min-w-0 flex-1">
                    <div id="sName" class="font-semibold text-slate-100 truncate"></div>
                    <div id="sSub" class="text-xs text-slate-400 truncate"></div>
                </div>
                <button type="button" onclick="closeSheet()" class="w-9 h-9 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 transition shrink-0" title="Close">
                    <i class="fa-solid fa-xmark text-xs" style="color:#fb7185"></i>
                </button>
            </div>
            <div id="sBody" class="overflow-y-auto p-2"></div>
            <div id="sFoot" class="p-3 border-t border-slate-800 flex gap-2"></div>
        </div>
    </div>

    <!-- Confirm modal -->
    <div id="modal" class="hidden fixed inset-0 z-50 bg-black/70 backdrop-blur-sm items-center justify-center p-4">
        <div class="modal-enter glass-panel rounded-2xl w-full max-w-sm p-5 shadow-2xl">
            <div class="flex items-start gap-3">
                <div id="mIconWrap" class="w-11 h-11 rounded-xl flex items-center justify-center shrink-0">
                    <i id="mIcon" class="fa-solid text-lg"></i>
                </div>
                <div class="min-w-0">
                    <h3 id="mTitle" class="font-bold text-slate-100"></h3>
                    <p id="mText" class="text-sm text-slate-400 mt-1 break-words"></p>
                </div>
            </div>
            <div id="mExtra" class="hidden mt-4">
                <label class="text-xs text-slate-400">Delete items older than (days)</label>
                <input id="mDays" type="number" min="1" value="30" class="mt-1 w-full bg-slate-900/70 border border-slate-700 rounded-xl px-3 py-2 text-sm outline-none focus:border-indigo-500">
            </div>
            <div class="flex justify-end gap-2 mt-5">
                <button type="button" onclick="closeModal()" class="px-4 py-2 rounded-xl text-sm bg-slate-800 hover:bg-slate-700 text-slate-300 transition">Cancel</button>
                <button type="button" id="mConfirm" class="px-4 py-2 rounded-xl text-sm font-semibold text-white transition">Confirm</button>
            </div>
        </div>
    </div>

    <!-- Hidden post form -->
    <form id="postForm" action="?fdpage=trash<?= isset($_GET['embed']) ? '&embed=1' : '' ?>" method="POST" class="hidden">
        <input type="hidden" name="csrf" value="<?php echo $csrf; ?>">
        <input type="hidden" name="action" id="fAction">
        <input type="hidden" name="days" id="fDays">
        <div id="fItems"></div>
    </form>

    <script>
    (function () {
        var list = document.getElementById('list');
        var rows = Array.prototype.slice.call(list.querySelectorAll('.item-row'));
        var search = document.getElementById('search');
        var filter = document.getElementById('filter');
        var sort = document.getElementById('sort');
        var selectAll = document.getElementById('selectAll');
        var bar = document.getElementById('bulkBar');
        var noMatch = document.getElementById('noMatch');

        function visibleRows() { return rows.filter(function (r) { return !r.hidden; }); }

        function apply() {
            var q = search.value.trim().toLowerCase();
            var f = filter.value;
            rows.forEach(function (r) {
                var okName = !q || r.dataset.name.indexOf(q) !== -1;
                var okType = f === 'all' || r.dataset.type === f;
                r.hidden = !(okName && okType);
                r.style.display = r.hidden ? 'none' : '';
            });

            var s = sort.value.split('-');
            var key = s[0], dir = s[1] === 'asc' ? 1 : -1;
            rows.sort(function (a, b) {
                var va, vb;
                if (key === 'name') { va = a.dataset.name; vb = b.dataset.name; return va < vb ? -dir : va > vb ? dir : 0; }
                va = parseFloat(a.dataset[key]); vb = parseFloat(b.dataset[key]);
                return (va - vb) * dir;
            }).forEach(function (r) { list.appendChild(r); });

            noMatch.classList.toggle('hidden', rows.length === 0 || visibleRows().length > 0);
            refreshSel();
        }

        function selected() {
            return rows.filter(function (r) { return r.querySelector('.row-chk').checked; })
                       .map(function (r) { return r.querySelector('.row-chk').value; });
        }

        function refreshSel() {
            var sel = selected();
            document.getElementById('selCount').textContent = sel.length;
            bar.classList.toggle('translate-y-32', sel.length === 0);
            bar.classList.toggle('opacity-0', sel.length === 0);
            bar.classList.toggle('pointer-events-none', sel.length === 0);
            var vis = visibleRows();
            var visChecked = vis.filter(function (r) { return r.querySelector('.row-chk').checked; }).length;
            selectAll.checked = vis.length > 0 && visChecked === vis.length;
        }

        list.addEventListener('change', function (e) { if (e.target.classList.contains('row-chk')) refreshSel(); });
        selectAll.addEventListener('change', function () {
            visibleRows().forEach(function (r) { r.querySelector('.row-chk').checked = selectAll.checked; });
            refreshSel();
        });
        search.addEventListener('input', apply);
        filter.addEventListener('change', apply);
        sort.addEventListener('change', apply);

        window.clearSel = function () {
            rows.forEach(function (r) { r.querySelector('.row-chk').checked = false; });
            refreshSel();
        };

        /* ----- modal ----- */
        var modal = document.getElementById('modal');
        var mConfirm = document.getElementById('mConfirm');
        var pending = null;

        function openModal(o) {
            document.getElementById('mTitle').textContent = o.title;
            document.getElementById('mText').textContent = o.text;
            var wrap = document.getElementById('mIconWrap');
            wrap.className = 'w-11 h-11 rounded-xl flex items-center justify-center shrink-0 ' + o.bg;
            document.getElementById('mIcon').className = 'fa-solid text-lg ' + o.icon + ' ' + o.color;
            document.getElementById('mExtra').classList.toggle('hidden', !o.extra);
            mConfirm.textContent = o.btn;
            mConfirm.className = 'px-4 py-2 rounded-xl text-sm font-semibold text-white transition ' + o.btnClass;
            pending = o.run;
            modal.classList.remove('hidden');
            modal.classList.add('flex');
        }
        window.closeModal = function () { modal.classList.add('hidden'); modal.classList.remove('flex'); pending = null; };
        mConfirm.addEventListener('click', function () { if (pending) pending(); });
        modal.addEventListener('click', function (e) { if (e.target === modal) closeModal(); });
        document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { closeModal(); closeSheet(); } });

        function submit(action, names, days) {
            document.getElementById('fAction').value = action;
            document.getElementById('fDays').value = days || '';
            var box = document.getElementById('fItems');
            box.innerHTML = '';
            (names || []).forEach(function (n) {
                var i = document.createElement('input');
                i.type = 'hidden'; i.name = 'items[]'; i.value = n;
                box.appendChild(i);
            });
            document.getElementById('postForm').submit();
        }

        window.act = function (action, names) {
            var many = names.length > 1;
            var label = many ? names.length + ' items' : '"' + names[0] + '"';
            if (action === 'restore') {
                openModal({
                    title: 'Restore ' + (many ? 'items' : 'item') + '?',
                    text: label + ' will be moved back to the folder it was deleted from. If the name already exists there, a timestamp is added.',
                    icon: 'fa-rotate-left', color: 'text-emerald-400', bg: 'bg-emerald-500/10',
                    btn: 'Restore', btnClass: 'bg-emerald-600 hover:bg-emerald-500',
                    run: function () { submit('restore', names); }
                });
            } else {
                openModal({
                    title: 'Delete forever?',
                    text: label + ' will be permanently deleted. This cannot be undone.',
                    icon: 'fa-triangle-exclamation', color: 'text-rose-400', bg: 'bg-rose-500/10',
                    btn: 'Delete', btnClass: 'bg-rose-600 hover:bg-rose-500',
                    run: function () { submit('purge', names); }
                });
            }
        };
        window.bulk = function (action) { var s = selected(); if (s.length) act(action, s); };

        window.emptyAll = function () {
            openModal({
                title: 'Empty the trash?',
                text: 'Every item in the recycle bin will be permanently deleted.',
                icon: 'fa-ban', color: 'text-rose-400', bg: 'bg-rose-500/10',
                btn: 'Empty Trash', btnClass: 'bg-rose-600 hover:bg-rose-500',
                run: function () { submit('empty_trash', []); }
            });
        };
        window.cleanOld = function () {
            openModal({
                title: 'Clean old items',
                text: 'Permanently delete everything that has been in the trash longer than the number of days below.',
                icon: 'fa-broom', color: 'text-amber-400', bg: 'bg-amber-500/10', extra: true,
                btn: 'Clean up', btnClass: 'bg-amber-600 hover:bg-amber-500',
                run: function () { submit('purge_old', [], document.getElementById('mDays').value); }
            });
        };

        /* ----- properties sheet + long-press actions ----- */
        var sheet = document.getElementById('sheet');
        var sBody = document.getElementById('sBody');
        var sFoot = document.getElementById('sFoot');
        var openedAt = 0, lpTimer = null, lpFired = false, sx = 0, sy = 0;

        function el(tag, cls, text) {
            var n = document.createElement(tag);
            if (cls) n.className = cls;
            if (text != null) n.textContent = text;
            return n;
        }
        function rowOf(t) { return t && t.closest ? t.closest('.item-row') : null; }
        function dataOf(r) { try { return JSON.parse(r.dataset.props || '{}'); } catch (e) { return {}; } }
        function isMobile() { return window.matchMedia('(max-width: 639px)').matches; }
        function sheetOpen() { return !sheet.classList.contains('hidden'); }

        function showSheet(d) {
            document.getElementById('sName').textContent = d.name || '';
            document.getElementById('sSub').textContent = (d.kind || '') + ' · ' + (d.size_h || '');
            document.getElementById('sIcon').className = 'fa-solid text-lg ' + (d.icon || 'fa-file') + ' ' + (d.color || '');
            sBody.innerHTML = '';
            sheet.classList.remove('hidden');
            sheet.classList.add('flex');
            openedAt = Date.now();
        }
        window.closeSheet = function () { sheet.classList.add('hidden'); sheet.classList.remove('flex'); };

        // ignore the "ghost click" that follows a long-press, and close on backdrop tap
        sheet.addEventListener('click', function (e) {
            if (Date.now() - openedAt < 450) { e.stopPropagation(); e.preventDefault(); return; }
            if (e.target === sheet) closeSheet();
        }, true);

        function copyText(text, btn) {
            try {
                navigator.clipboard.writeText(text).then(function () {
                    btn.innerHTML = '<i class="fa-solid fa-check text-xs text-emerald-400"></i>';
                    setTimeout(function () { btn.innerHTML = '<i class="fa-solid fa-copy text-xs" style="color:#818cf8"></i>'; }, 1200);
                });
            } catch (e) { }
        }

        function propRow(label, value, opts) {
            opts = opts || {};
            var r = el('div', 'flex gap-3 px-3 py-2.5 border-b border-slate-800/50');
            r.appendChild(el('div', 'w-28 shrink-0 text-xs text-slate-400 pt-0.5', label));
            r.appendChild(el('div', 'min-w-0 flex-1 text-sm break-all ' + (opts.cls || 'text-slate-200'), value));
            if (opts.copy) {
                var b = el('button', 'shrink-0 w-7 h-7 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300');
                b.type = 'button';
                b.title = 'Copy';
                b.innerHTML = '<i class="fa-solid fa-copy text-xs" style="color:#818cf8"></i>';
                b.onclick = function () { copyText(opts.copy, b); };
                r.appendChild(b);
            }
            return r;
        }

        function openProps(r) {
            var d = dataOf(r);
            showSheet(d);
            sFoot.classList.remove('hidden');
            sFoot.innerHTML = '';

            sBody.appendChild(propRow('Type', (d.kind || '') + (d.ext ? ' (.' + d.ext + ')' : '')));
            sBody.appendChild(propRow('MIME type', d.mime || 'unknown'));
            sBody.appendChild(propRow('Size', d.size_h + ' (' + d.size_b + ' bytes)'));
            if (d.is_dir) sBody.appendChild(propRow('Contains', d.files + ' file(s), ' + d.folders + ' folder(s)'));
            if (d.dim) sBody.appendChild(propRow('Dimensions', d.dim));
            sBody.appendChild(propRow('Original location', d.orig || 'Unknown (older item)',
                { copy: d.orig || null, cls: d.orig ? 'text-sky-300' : 'text-slate-500' }));

            var rt = propRow('Restore to', d.restore_to, { copy: d.restore_to });
            var notes = [];
            if (!d.tracked) notes.push('original location unknown, goes to the root folder');
            if (!d.dest_exists) notes.push('folder is missing and will be re-created');
            if (d.conflict) notes.push('same name exists there, a timestamp will be added');
            if (notes.length) rt.children[1].appendChild(el('div', 'text-[11px] text-amber-400 mt-1', '⚠ ' + notes.join(' · ')));
            sBody.appendChild(rt);

            sBody.appendChild(propRow('Deleted', d.deleted + ' (' + d.ago + ')'));
            sBody.appendChild(propRow('In trash for', d.days < 1 ? 'Less than a day' : d.days + ' day(s)'));
            sBody.appendChild(propRow('Last modified', d.modified));
            sBody.appendChild(propRow('Permissions', d.perms));

            var rb = el('button', 'flex-1 px-4 py-2.5 rounded-xl text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-500 transition');
            rb.type = 'button';
            rb.innerHTML = '<i class="fa-solid fa-rotate-left mr-1.5" style="color:#34d399"></i>Restore';
            rb.onclick = function () { closeSheet(); act('restore', [d.name]); };
            var cb = el('button', 'px-5 py-2.5 rounded-xl text-sm bg-slate-800 hover:bg-slate-700 text-slate-300 transition', 'Close');
            cb.type = 'button';
            cb.onclick = closeSheet;
            sFoot.appendChild(rb);
            sFoot.appendChild(cb);
        }
        window.showProps = function (btn) { var r = rowOf(btn); if (r) openProps(r); };

        function actionBtn(icon, color, title, sub, fn) {
            var b = el('button', 'w-full flex items-center gap-3 px-3 py-3 rounded-xl hover:bg-slate-800/70 active:bg-slate-800 text-left transition');
            b.type = 'button';
            var ic = el('div', 'w-10 h-10 rounded-xl bg-slate-800 flex items-center justify-center shrink-0');
            ic.innerHTML = '<i class="fa-solid ' + icon + ' ' + color + '"></i>';
            var tx = el('div', 'min-w-0');
            tx.appendChild(el('div', 'text-sm font-semibold text-slate-100', title));
            tx.appendChild(el('div', 'text-xs text-slate-400', sub));
            b.appendChild(ic);
            b.appendChild(tx);
            b.onclick = fn;
            return b;
        }

        function openActions(r) {
            if (sheetOpen()) return;
            var d = dataOf(r), chk = r.querySelector('.row-chk');
            showSheet(d);
            sFoot.classList.add('hidden');
            sBody.appendChild(actionBtn('fa-rotate-left', 'text-emerald-400', 'Restore',
                'Move back to ' + (d.tracked ? 'its original folder' : 'the root folder'),
                function () { closeSheet(); act('restore', [d.name]); }));
            sBody.appendChild(actionBtn('fa-circle-info', 'text-sky-400', 'Properties',
                'Size, location, dates and more', function () { openProps(r); }));
            sBody.appendChild(actionBtn(chk.checked ? 'fa-square-minus' : 'fa-square-check', 'text-indigo-400',
                chk.checked ? 'Unselect' : 'Select', 'Pick several items for bulk actions',
                function () { chk.checked = !chk.checked; refreshSel(); closeSheet(); }));
            sBody.appendChild(actionBtn('fa-trash', 'text-rose-400', 'Delete forever',
                'Permanently remove, cannot be undone', function () { closeSheet(); act('purge', [d.name]); }));
        }

        // long-press (touch) -> actions
        list.addEventListener('touchstart', function (e) {
            var r = rowOf(e.target);
            lpFired = false;
            clearTimeout(lpTimer);
            if (!r || e.target.closest('.chk, button')) return;
            var t = e.touches[0];
            sx = t.clientX; sy = t.clientY;
            lpTimer = setTimeout(function () {
                lpFired = true;
                try { if (navigator.vibrate) navigator.vibrate(15); } catch (_) { }
                openActions(r);
            }, 480);
        }, { passive: true });
        list.addEventListener('touchmove', function (e) {
            var t = e.touches[0];
            if (Math.abs(t.clientX - sx) > 8 || Math.abs(t.clientY - sy) > 8) clearTimeout(lpTimer);
        }, { passive: true });
        ['touchend', 'touchcancel'].forEach(function (n) {
            list.addEventListener(n, function () { clearTimeout(lpTimer); }, { passive: true });
        });

        // right-click (desktop) / native long-press menu (Android) -> same actions
        list.addEventListener('contextmenu', function (e) {
            var r = rowOf(e.target);
            if (!r) return;
            e.preventDefault();
            lpFired = true;
            openActions(r);
        });

        // mobile tap: toggle selection if already selecting, otherwise show properties
        list.addEventListener('click', function (e) {
            if (lpFired) { lpFired = false; e.preventDefault(); return; }
            if (!isMobile()) return;
            if (e.target.closest('.chk, button')) return;
            var r = rowOf(e.target);
            if (!r) return;
            if (selected().length) {
                var c = r.querySelector('.row-chk');
                c.checked = !c.checked;
                refreshSel();
            } else {
                openProps(r);
            }
        });

        apply();
    })();
    </script>
<?php if (isset($_GET['embed'])): ?><script>
document.addEventListener('click',function(e){var a=e.target.closest('a[href]');if(!a||a.target==='_blank'||a.hasAttribute('download'))return;var u=new URL(a.href,location.href);if(u.origin!==location.origin)return;
if(u.pathname.split('/').pop()==='index.php'&&!u.search&&!u.hash){e.preventDefault();try{window.parent.postMessage('fd-close-page',location.origin)}catch(x){window.top.location.href=u.pathname}return;}
if(u.pathname===location.pathname&&u.search===location.search&&u.hash)return;
var p=u.searchParams.get('fdpage')||'index';
if(['trash','dashboard','settings'].indexOf(p)>-1){if(!u.searchParams.has('embed')){u.searchParams.set('embed','1');a.href=u.pathname+u.search+u.hash;}return;}
e.preventDefault();window.top.location.href=u.pathname+u.search+u.hash;});
document.addEventListener('submit',function(e){var f=e.target;var u=new URL(f.action||location.href,location.href);if(!u.searchParams.has('embed')){u.searchParams.set('embed','1');if((f.method||'get').toLowerCase()==='post'){f.action=u.pathname+u.search;}else if(!f.querySelector('input[name=embed]')){var i=document.createElement('input');i.type='hidden';i.name='embed';i.value='1';f.appendChild(i);}}});
</script><?php endif; ?></body>
</html>
<?php
} }

namespace FDDashboard {
use \RecursiveIteratorIterator; use \RecursiveDirectoryIterator; use \FilesystemIterator; use \ZipArchive; use \DateTime; use \DateTimeZone; use \DirectoryIterator; use \SplFileInfo; use \Exception; use \Throwable; use \finfo;
/* hoisted function declarations (must be unconditional) */
function formatBytes($b, $p = 2) {
    $u = ['B', 'KB', 'MB', 'GB', 'TB']; $b = max((float)$b, 0);
    $pow = $b > 0 ? (int)floor(log($b) / log(1024)) : 0; $pow = min($pow, count($u) - 1);
    return round($b / pow(1024, $pow), $p) . ' ' . $u[$pow];
}

function ago($t) {
    $d = time() - $t; if ($d < 60) return 'just now'; if ($d < 3600) return floor($d / 60) . ' min ago';
    if ($d < 86400) return floor($d / 3600) . ' h ago'; if ($d < 2592000) return floor($d / 86400) . ' d ago';
    return date('d M Y', $t);
}

function fileHref($abs, $ext) {
    $prv = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'mp4', 'webm', 'm4v', 'mp3', 'wav', 'ogg', 'm4a', 'pdf'];
    $bin = ['zip', 'rar', 'tar', 'gz', 'tgz', 'bz2', '7z', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'pdf', 'exe', 'mp4', 'mp3', 'iso', 'lock', 'bin', 'mkv', 'avi', 'mov', 'flv', 'wmv', 'm4v', 'webm', 'ogg', 'wav', 'm4a', 'aac', 'flac', 'ico', 'bmp',
            'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt'];
    if (in_array($ext, $prv, true)) return ['index.php?raw=' . urlencode($abs), true];
    if (!in_array($ext, $bin, true)) return ['?fdpage=editor&file=' . urlencode($abs), false];
    return ['index.php?download=' . urlencode($abs), false];
}

function folderHref($root, $dir) { return 'index.php?path=' . urlencode($dir === '' ? $root : $root . '/' . $dir); }

if ($__fdpage === 'dashboard') {

/**
 * FileDash — ?fdpage=dashboard (Storage Analytics & Server Health)
 * Same neon design system as index.php (theme + accent colour are shared via localStorage).
 * Single self-contained file. FontAwesome CDN only.
 */

error_reporting(E_ALL);
ini_set('display_errors', '0');

$root      = FD_APP_ROOT;
$trash_dir = $root . '/.trash';
$started   = microtime(true);
$deadline  = $started + 8;          // scan time budget (seconds)
$partial   = false;

/* ---------- helpers ---------- */




$e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
/* where a click on a file goes — same rules as index.php (inline preview / editor / download) */





$catExt = [
    'image'   => 'jpg jpeg png gif webp bmp svg ico avif',
    'video'   => 'mp4 mkv avi mov webm flv wmv m4v',
    'audio'   => 'mp3 wav ogg flac m4a aac',
    'doc'     => 'pdf doc docx xls xlsx ppt pptx odt txt rtf csv md',
    'archive' => 'zip rar 7z tar gz tgz bz2',
    'code'    => 'php js ts html htm css scss json xml yml yaml py java c cpp h go rb rs sh sql ini conf log env vue',
];
$extMap = [];
foreach ($catExt as $c => $s) foreach (explode(' ', $s) as $x) $extMap[$x] = $c;
$cats = [ // key => [label, colour, icon]
    'image'   => ['Images',   '#ec4899', 'fa-file-image'],
    'video'   => ['Video',    '#8b5cf6', 'fa-file-video'],
    'audio'   => ['Audio',    '#06b6d4', 'fa-file-audio'],
    'doc'     => ['Documents', '#3b82f6', 'fa-file-lines'],
    'archive' => ['Archives', '#f97316', 'fa-file-zipper'],
    'code'    => ['Code',     '#10b981', 'fa-file-code'],
    'other'   => ['Other',    '#94a3b8', 'fa-file'],
];

/* ---------- category view (?cat=image|video|audio|doc|archive|code|other|all) ---------- */
$catView = $_GET['cat'] ?? null;
if ($catView !== null && $catView !== 'all' && !isset($cats[$catView])) $catView = null;
$sortBy = in_array($_GET['sort'] ?? '', ['new', 'old', 'size', 'small', 'name'], true) ? $_GET['sort'] : 'new';
$catFiles = [];

/* ---------- one recursive scan ---------- */
$files = 0; $dirs = 0; $bytes = 0; $trash_bytes = 0; $trash_files = 0;
$bycat = []; foreach ($cats as $k => $_) $bycat[$k] = ['n' => 0, 'b' => 0];
$byext = []; $topdirs = []; $root_bytes = 0; $largest = []; $recent = [];
try {
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST, RecursiveIteratorIterator::CATCH_GET_CHILD);
    foreach ($it as $f) {
        if (microtime(true) > $deadline) { $partial = true; break; }
        if ($f->isLink()) continue;
        $rel = str_replace('\\', '/', substr($f->getPathname(), strlen($root) + 1));
        $inTrash = ($rel === '.trash' || strpos($rel, '.trash/') === 0);
        if ($f->isDir()) { if (!$inTrash) $dirs++; continue; }
        $sz = (int)$f->getSize();
        if ($inTrash) { $trash_bytes += $sz; $trash_files++; continue; }
        $files++; $bytes += $sz; $mt = (int)$f->getMTime();
        $ext = strtolower($f->getExtension()); $cat = $extMap[$ext] ?? 'other';
        $bycat[$cat]['n']++; $bycat[$cat]['b'] += $sz;
        $k = $ext === '' ? '(none)' : '.' . $ext; $byext[$k] = ($byext[$k] ?? ['n' => 0, 'b' => 0]); $byext[$k]['n']++; $byext[$k]['b'] += $sz;
        $pos = strpos($rel, '/');
        if ($pos === false) $root_bytes += $sz; else { $d = substr($rel, 0, $pos); $topdirs[$d] = ($topdirs[$d] ?? 0) + $sz; }
        $row = ['rel' => $rel, 'name' => $f->getFilename(), 'dir' => $pos === false ? '' : dirname($rel), 'size' => $sz, 'mt' => $mt, 'cat' => $cat];
        if ($catView !== null && ($catView === 'all' || $catView === $cat) && count($catFiles) < 20000) $catFiles[] = $row + ['ext' => $ext];
        $largest[] = $row; $recent[] = $row;
        if (count($largest) > 60) { usort($largest, fn($a, $b) => $b['size'] <=> $a['size']); $largest = array_slice($largest, 0, 10); }
        if (count($recent) > 60)  { usort($recent, fn($a, $b) => $b['mt'] <=> $a['mt']); $recent = array_slice($recent, 0, 10); }
    }
} catch (Exception $ex) { $partial = true; }
usort($largest, fn($a, $b) => $b['size'] <=> $a['size']); $largest = array_slice($largest, 0, 10);
usort($recent,  fn($a, $b) => $b['mt'] <=> $a['mt']);     $recent  = array_slice($recent, 0, 10);
arsort($topdirs); if ($root_bytes > 0) $topdirs['(root files)'] = $root_bytes; arsort($topdirs); $topdirs = array_slice($topdirs, 0, 8, true);
uasort($byext, fn($a, $b) => $b['b'] <=> $a['b']); $byext = array_slice($byext, 0, 8, true);
$trash_items = is_dir($trash_dir) ? max(0, count(scandir($trash_dir)) - 2) : 0;
$catTotal = 0; $catShown = [];
if ($catView !== null) {
    $cmp = [
        'new'   => fn($a, $b) => $b['mt'] <=> $a['mt'],
        'old'   => fn($a, $b) => $a['mt'] <=> $b['mt'],
        'size'  => fn($a, $b) => $b['size'] <=> $a['size'],
        'small' => fn($a, $b) => $a['size'] <=> $b['size'],
        'name'  => fn($a, $b) => strcasecmp($a['name'], $b['name']),
    ];
    usort($catFiles, $cmp[$sortBy]);
    $catTotal = count($catFiles);
    $catShown = array_slice($catFiles, 0, 600);
}
$scan_ms = round((microtime(true) - $started) * 1000);

/* ---------- disk / server ---------- */
$total = @disk_total_space($root) ?: 0; $free = @disk_free_space($root) ?: 0; $used = max(0, $total - $free);
$pct = $total > 0 ? round($used / $total * 100, 1) : 0;
$app_pct = $total > 0 ? max(0.1, round(($bytes + $trash_bytes) / $total * 100, 2)) : 0;
$load = function_exists('sys_getloadavg') ? @sys_getloadavg() : false;
$exts = ['zip' => 'ZipArchive (ZIP download)', 'gd' => 'GD (images)', 'mbstring' => 'mbstring', 'fileinfo' => 'fileinfo', 'curl' => 'cURL', 'pdo_mysql' => 'PDO MySQL', 'mysqli' => 'MySQLi', 'json' => 'JSON'];
$env = [
    ['fa-server', 'Server software', $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'],
    ['fa-plug', 'Interface (SAPI)', php_sapi_name()],
    ['fa-brands fa-php', 'PHP version', PHP_VERSION],
    ['fa-desktop', 'Operating system', PHP_OS_FAMILY . ' · ' . php_uname('m')],
    ['fa-cloud-arrow-up', 'Max upload size', ini_get('upload_max_filesize')],
    ['fa-paper-plane', 'Max POST size', ini_get('post_max_size')],
    ['fa-memory', 'Memory limit', ini_get('memory_limit')],
    ['fa-stopwatch', 'Max execution time', ini_get('max_execution_time') . ' s'],
    ['fa-earth-asia', 'Timezone', date_default_timezone_get()],
    ['fa-clock', 'Server time', date('d M Y, H:i:s')],
    ['fa-gauge-high', 'PHP memory (peak)', formatBytes(memory_get_peak_usage(true))],
    ['fa-folder-tree', 'App folder', $root],
];
if ($load) array_splice($env, 11, 0, [['fa-wave-square', 'Load average', implode(' / ', array_map(fn($x) => number_format($x, 2), $load))]]);

/* ---------- insights ---------- */
$tips = [];
if ($pct >= 90) $tips[] = ['bad', 'fa-triangle-exclamation', "Disk is {$pct}% full — free up space soon."];
elseif ($pct >= 75) $tips[] = ['warn', 'fa-circle-exclamation', "Disk is {$pct}% used — keep an eye on it."];
else $tips[] = ['ok', 'fa-circle-check', 'Disk space looks healthy.'];
if ($trash_bytes > 0) $tips[] = ['warn', 'fa-trash-can', 'Trash holds ' . formatBytes($trash_bytes) . ' — empty it to reclaim space.'];
if ($largest && $bytes > 0 && $largest[0]['size'] / $bytes > .4) $tips[] = ['warn', 'fa-weight-hanging', '“' . $largest[0]['name'] . '” alone is ' . round($largest[0]['size'] / $bytes * 100) . '% of your files.'];
if ($bycat['archive']['b'] > 0 && $bytes > 0 && $bycat['archive']['b'] / $bytes > .25) $tips[] = ['warn', 'fa-file-zipper', 'Archives use ' . round($bycat['archive']['b'] / $bytes * 100) . '% of space — old backups?'];
foreach (['zip'] as $x) if (!extension_loaded($x)) $tips[] = ['bad', 'fa-puzzle-piece', "PHP extension “{$x}” is missing — ZIP download will not work."];
if ($partial) $tips[] = ['warn', 'fa-hourglass-half', 'Scan stopped after 8 s — numbers are partial (very large folder).'];

$circ = 2 * M_PI * 52;
$maxCatBytes = max(1, $bytes);
$maxTop = $topdirs ? max($topdirs) : 1;
$maxExt = $byext ? max(array_column($byext, 'b')) : 1;
$isAll = $catView === 'all';
$cmeta = $catView === null ? null : ($isAll ? ['All files', 'var(--ac)', 'fa-layer-group'] : $cats[$catView]);
$cN = $catView === null ? 0 : ($isAll ? $files : $bycat[$catView]['n']);
$cB = $catView === null ? 0 : ($isAll ? $bytes : $bycat[$catView]['b']);
$qs = fn($c) => '?fdpage=dashboard&cat=' . $c . ($sortBy !== 'new' ? '&sort=' . $sortBy : '');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#6366f1">
<title><?= $catView !== null ? $e($cmeta[0]) . ' · ' : '' ?>Dashboard — FileDash</title>
<?php fdCss('fa/css/all.min.css'); ?>
<style>
:root{--ac:#6366f1;--ac2:#ec4899;--bg:#0a0e1a;--bg2:#080b15;--card:#111827;--card2:#172033;--tx:#e8eaf6;--mut:#8f9bb8;--bd:rgba(255,255,255,.08);--hov:rgba(129,140,248,.13);--sh:0 12px 34px rgba(0,0,0,.4);--ok:#10b981;--bad:#ef4444;--warn:#f59e0b;color-scheme:dark}
html.light{--bg:#eef1fb;--bg2:#fff;--card:#fff;--card2:#f4f6fd;--tx:#151a33;--mut:#64708f;--bd:rgba(20,26,60,.1);--hov:rgba(99,102,241,.09);--sh:0 12px 34px rgba(30,40,100,.12);color-scheme:light}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{font-family:Inter,system-ui,-apple-system,"Noto Sans Bengali",Segoe UI,sans-serif;background:var(--bg);color:var(--tx);font-size:14px;line-height:1.45;overflow-x:hidden;min-height:100vh}
body::before{content:"";position:fixed;inset:0;z-index:-1;background:radial-gradient(600px 400px at 8% -5%,color-mix(in srgb,var(--ac) 22%,transparent),transparent),radial-gradient(500px 380px at 100% 100%,color-mix(in srgb,var(--ac2) 16%,transparent),transparent)}
a{color:inherit;text-decoration:none}button{font:inherit;color:inherit;cursor:pointer;border:0;background:none}
.top{position:sticky;top:0;z-index:40;display:flex;align-items:center;gap:10px;padding:12px max(24px,env(safe-area-inset-right)) 12px max(24px,env(safe-area-inset-left));background:color-mix(in srgb,var(--bg) 78%,transparent);backdrop-filter:blur(16px);border-bottom:1px solid var(--bd)}
.ib{width:40px;height:40px;border-radius:12px;display:inline-grid;place-items:center;background:var(--card);border:1px solid var(--bd);color:var(--mut);transition:.15s;flex:none}.ib:hover{color:var(--tx);background:var(--hov);transform:translateY(-1px)}
.ttl{flex:1;min-width:0}.ttl b{display:flex;align-items:center;gap:9px;font-size:16px;line-height:1.2}.ttl b i{color:var(--ac)}.ttl small{color:var(--mut);font-size:11.5px;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.btn{height:38px;padding:0 15px;border-radius:11px;font-weight:600;font-size:13px;background:var(--card);border:1px solid var(--bd);display:inline-flex;align-items:center;gap:8px;white-space:nowrap;transition:.15s}.btn:hover{background:var(--hov);transform:translateY(-1px)}
.btn.pri{color:#fff;border-color:transparent;background:linear-gradient(135deg,var(--ac),var(--ac2));box-shadow:0 8px 20px color-mix(in srgb,var(--ac) 35%,transparent)}
.wrap{max-width:1200px;margin:0 auto;padding:20px max(24px,env(safe-area-inset-left)) 50px;display:flex;flex-direction:column;gap:16px}
/* hero */
.hero{display:grid;grid-template-columns:auto 1fr;gap:22px;align-items:center;padding:22px;border-radius:22px;background:var(--card);border:1px solid var(--bd);box-shadow:var(--sh);position:relative;overflow:hidden}
.hero::after{content:"";position:absolute;right:-60px;top:-60px;width:220px;height:220px;border-radius:50%;background:radial-gradient(circle,color-mix(in srgb,var(--ac) 28%,transparent),transparent 70%);pointer-events:none}
.donut{position:relative;width:150px;height:150px}.donut svg{width:100%;height:100%;transform:rotate(-90deg)}
.donut .tr{fill:none;stroke:var(--bd);stroke-width:12}.donut .pg{fill:none;stroke:url(#gr);stroke-width:12;stroke-linecap:round;stroke-dasharray:<?= $circ ?>;stroke-dashoffset:<?= $circ * (1 - min(100, $pct) / 100) ?>;animation:ring 1.1s cubic-bezier(.4,0,.2,1)}
@keyframes ring{from{stroke-dashoffset:<?= $circ ?>}}
.donut .mid{position:absolute;inset:0;display:grid;place-content:center;text-align:center}.donut .mid b{font-size:26px;line-height:1}.donut .mid small{color:var(--mut);font-size:11.5px;margin-top:3px}
.hl{display:flex;flex-direction:column;gap:12px;min-width:0;position:relative;z-index:1}
.hl h2{font-size:17px;display:flex;align-items:center;gap:9px}.hl h2 i{color:var(--ac)}
.hl .sub{color:var(--mut);font-size:12.5px}
.dbar{height:12px;border-radius:99px;background:var(--bd);overflow:hidden;display:flex}
.dbar i{display:block;height:100%;transform-origin:left;animation:grow .9s cubic-bezier(.4,0,.2,1) both}
.leg{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:12.5px;color:var(--mut)}.leg span{display:inline-flex;align-items:center;gap:7px}.leg em{width:9px;height:9px;border-radius:50%;display:inline-block;background:var(--c)}.leg b{color:var(--tx);font-weight:600}
@keyframes grow{from{transform:scaleX(0)}}
/* stat cards */
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.cd{padding:15px 16px;border-radius:16px;background:var(--card);border:1px solid var(--bd);display:flex;align-items:center;gap:13px;box-shadow:var(--sh);min-width:0;transition:.18s}.cd:hover{transform:translateY(-2px);border-color:color-mix(in srgb,var(--c) 45%,var(--bd))}
.cd .ci{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;font-size:17px;color:var(--c);background:color-mix(in srgb,var(--c) 16%,transparent);flex:none}
.cd div{min-width:0}.cd b{font-size:19px;display:block;line-height:1.15;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.cd small{color:var(--mut);font-size:12px}
/* panels */
.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.pn{padding:18px;border-radius:20px;background:var(--card);border:1px solid var(--bd);box-shadow:var(--sh);min-width:0;display:flex;flex-direction:column;gap:14px}
.pn h3{font-size:14.5px;display:flex;align-items:center;gap:9px}.pn h3 i{color:var(--ac)}.pn h3 span{margin-left:auto;font-size:11.5px;color:var(--mut);font-weight:500}
.row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 12px;align-items:center}
.row .n{display:flex;align-items:center;gap:9px;min-width:0;font-weight:600}.row .n span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .n i{width:18px;text-align:center;color:var(--c,var(--mut));flex:none}
.row .v{color:var(--mut);font-size:12.5px;white-space:nowrap}.row .v b{color:var(--tx);font-weight:600}
.row .bar{grid-column:1/-1;height:7px;border-radius:9px;background:var(--bd);overflow:hidden}.row .bar i{display:block;height:100%;border-radius:9px;background:var(--c,var(--ac));transform-origin:left;animation:grow .9s cubic-bezier(.4,0,.2,1) both}
.stack{display:flex;flex-direction:column;gap:13px}
.fl{display:flex;flex-direction:column;gap:6px}
.fi{display:grid;grid-template-columns:38px minmax(0,1fr) auto;gap:11px;align-items:center;padding:8px 10px;border-radius:13px;background:var(--card2);border:1px solid var(--bd);transition:.15s}.fi:hover{border-color:color-mix(in srgb,var(--ac) 45%,var(--bd))}
.fi .ico{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;font-size:16px;color:var(--c);background:color-mix(in srgb,var(--c) 16%,transparent)}
.fi .t{min-width:0}.fi .t b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600}.fi .t small{display:block;color:var(--mut);font-size:11.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fi .s{text-align:right;font-weight:700;font-size:13px;white-space:nowrap}.fi .s small{display:block;color:var(--mut);font-weight:500;font-size:11.5px}
.tips{display:flex;flex-direction:column;gap:8px}
.tip{display:flex;gap:11px;align-items:center;padding:10px 13px;border-radius:13px;background:color-mix(in srgb,var(--c) 11%,var(--card2));border:1px solid color-mix(in srgb,var(--c) 30%,transparent)}.tip i{color:var(--c);width:18px;text-align:center}
.tip.ok{--c:var(--ok)}.tip.warn{--c:var(--warn)}.tip.bad{--c:var(--bad)}
.env{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}
.ev{display:flex;align-items:center;gap:11px;padding:10px 12px;border-radius:13px;background:var(--card2);border:1px solid var(--bd);min-width:0}
.ev i{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;font-size:13px;color:var(--ac);background:color-mix(in srgb,var(--ac) 14%,transparent);flex:none}
.ev div{min-width:0}.ev small{display:block;color:var(--mut);font-size:11.5px}.ev b{display:block;font:600 12.5px ui-monospace,Consolas,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.exts{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.ex{display:flex;align-items:center;gap:8px;padding:8px 10px;border-radius:11px;background:var(--card2);border:1px solid var(--bd);font-size:12.5px;min-width:0}
.ex i{font-size:11px;flex:none}.ex span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ex.y i{color:var(--ok)}.ex.n i{color:var(--bad)}.ex.n{opacity:.8}
.empty{color:var(--mut);text-align:center;padding:18px 0}
.foot{text-align:center;color:var(--mut);font-size:12px}
.pn,.cd,.hero{animation:in .4s both}@keyframes in{from{opacity:0;transform:translateY(10px)}}
/* clickable cards / rows */
a.cd{cursor:pointer;color:inherit}
.cd .go{margin-left:auto;color:var(--mut);font-size:11px;opacity:.55;flex:none;transition:.15s}.cd:hover .go{opacity:1;transform:translateX(2px);color:var(--c)}
a.row.lnk{padding:8px 10px;margin:-8px -10px;border-radius:12px;transition:.15s;cursor:pointer}a.row.lnk:hover{background:var(--hov)}
.row .v .go{font-size:10px;margin-left:8px;opacity:.55}
.pn h3 span a{display:inline-flex;align-items:center;gap:6px}.pn h3 span a:hover{color:var(--tx)}
/* category page (phone-style storage view) */
.chead{display:flex;align-items:center;gap:14px;padding:18px;border-radius:20px;background:var(--card);border:1px solid var(--bd);box-shadow:var(--sh)}
.chead .big{width:54px;height:54px;border-radius:16px;display:grid;place-items:center;font-size:22px;color:var(--c);background:color-mix(in srgb,var(--c) 16%,transparent);flex:none}
.chead b{font-size:18px;display:block;line-height:1.2}.chead small{color:var(--mut);font-size:12.5px}
.chead .pc{margin-left:auto;text-align:right;font-weight:700;font-size:18px;white-space:nowrap}.chead .pc small{display:block;font-weight:500}
.chips{display:flex;gap:8px;overflow-x:auto;scroll-snap-type:x proximity;padding:2px 0 6px;scrollbar-width:none}.chips::-webkit-scrollbar{display:none}
.chip{flex:none;scroll-snap-align:start;display:inline-flex;align-items:center;gap:8px;height:38px;padding:0 14px;border-radius:99px;background:var(--card);border:1px solid var(--bd);font-weight:600;font-size:13px;white-space:nowrap;transition:.15s}
.chip i{color:var(--c,var(--mut))}.chip small{color:var(--mut);font-weight:500;font-size:11.5px}.chip:hover{background:var(--hov)}
.chip.on{color:#fff;border-color:transparent;background:var(--c,var(--ac))}.chip.on i,.chip.on small{color:#fff}
.tool{display:flex;gap:8px}.tool .srch{flex:1;min-width:0;position:relative}.tool .srch i{position:absolute;left:13px;top:50%;transform:translateY(-50%);color:var(--mut);font-size:12px}
.tool input,.tool select{height:40px;border-radius:12px;background:var(--card);border:1px solid var(--bd);color:var(--tx);font:inherit;outline:0}
.tool input{width:100%;padding:0 12px 0 34px}.tool select{padding:0 10px;max-width:46%}.tool input:focus,.tool select:focus{border-color:var(--ac)}
.gal{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:6px}
.th{position:relative;aspect-ratio:1;border-radius:12px;overflow:hidden;background:var(--card2);border:1px solid var(--bd)}
.th .tl{position:absolute;inset:0;display:block}.th img{width:100%;height:100%;object-fit:cover;display:block;transition:.2s}.th:hover img{transform:scale(1.05)}
.th .ph{position:absolute;inset:0;display:none;place-items:center;font-size:26px;color:var(--c)}.th.bad img{display:none}.th.bad .ph{display:grid}
.th .cap{position:absolute;left:0;right:0;bottom:0;padding:16px 7px 5px;background:linear-gradient(transparent,rgba(0,0,0,.72));color:#fff;font-size:11px;line-height:1.25;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
.th .fo{position:absolute;top:5px;right:5px;width:28px;height:28px;border-radius:9px;display:grid;place-items:center;background:rgba(0,0,0,.55);color:#fff;font-size:12px;opacity:0;transition:.15s;z-index:2}
.th:hover .fo,.th .fo:focus{opacity:1}@media (hover:none){.th .fo{opacity:1}}
.fm{display:flex;align-items:center;gap:8px}.fm .fi{flex:1;min-width:0}.fm .ico{overflow:hidden;position:relative}.fm .ico img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;display:block}
.fm .fo{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;background:var(--card2);border:1px solid var(--bd);color:var(--mut);flex:none;transition:.15s}.fm .fo:hover{color:var(--tx);background:var(--hov)}
.more{text-align:center;color:var(--mut);font-size:12.5px;padding:6px 0}
@media (max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}.cols{grid-template-columns:1fr}.exts{grid-template-columns:repeat(2,1fr)}}
@media (max-width:600px){
 .top{padding:10px 12px}.wrap{padding:12px 12px 40px;gap:12px}.hide-m{display:none}
 .hero{grid-template-columns:1fr;justify-items:center;text-align:center;padding:18px}.hl{width:100%;align-items:stretch}.hl h2{justify-content:center}.leg{justify-content:center}
 .cards{gap:8px}.cd{padding:10px;gap:9px}.cd .ci{width:34px;height:34px}.cd b{font-size:15px}
 .env{grid-template-columns:1fr}.pn{padding:14px}
}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
<?php if (isset($_GET['embed'])): ?>
/* embedded in FileDash: same page header as Shared links / Activity log */
html,body{background:transparent!important;min-height:100%;overflow-x:hidden}
.top{display:flex!important;position:static!important;background:transparent!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important;border:0!important;padding:4px 14px 0!important;gap:12px}
.top .ttl b{font-size:18px;gap:10px}.top .ttl small{font-size:11.5px}
.top .hide-m{display:inline-flex!important}.top #themeBtn{display:none!important}
.top .btn.hide-m{height:34px;min-height:34px;max-height:34px;padding:0 13px!important;gap:8px;justify-content:center;font-size:13px;line-height:1;border-radius:10px;background:var(--card2);color:var(--tx)}
.top .btn.hide-m i{font-size:14px}
.top .ib[title="Refresh"]{width:34px;height:34px;border-radius:10px;background:var(--card2)}
@media(max-width:639px){.top .btn.hide-m{width:34px;padding:0!important;gap:0;font-size:0}}
.wrap{max-width:none!important;width:100%!important;margin:0!important;padding:14px!important}
@media(max-width:600px){
 .top{padding:2px 10px 0!important;gap:9px}
 .top .ttl small{display:none}
 .wrap{padding:12px!important;gap:12px!important}
 /* Restore the original roomy dashboard mobile composition */
 .hero{grid-template-columns:1fr;justify-items:center;text-align:center;padding:18px;gap:22px}
 .hero .donut{width:150px;height:150px}.hero .donut svg{width:100%;height:100%}.hero .hl{width:100%;align-items:stretch}.hero .hl h2{justify-content:center;font-size:17px}.hero .sub{font-size:12.5px}.hero .leg{justify-content:center;gap:6px 18px;font-size:12.5px}
 .cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.cd{padding:10px;gap:9px;border-radius:14px;min-height:0}.cd .ci{width:34px;height:34px}.cd b{font-size:15px}.cd small{font-size:11px}.cd .go{margin-left:auto}
 .pn{padding:14px;border-radius:16px;gap:14px}.pn h3{font-size:14px}.tip{padding:10px 13px;font-size:12.5px}.cols{gap:12px}.env{grid-template-columns:1fr}.exts{grid-template-columns:repeat(2,minmax(0,1fr))}
}
<?php endif; ?>
</style>
</head>
<body>

<header class="top">
  <a class="ib" href="<?= $catView !== null ? '?fdpage=dashboard' : 'index.php' ?>" aria-label="<?= $catView !== null ? 'Back to dashboard' : 'Back to files' ?>"><i class="fa-solid fa-arrow-left" style="color:#818cf8"></i></a>
  <?php if ($catView !== null): ?>
  <div class="ttl"><b><i class="fa-solid <?= $cmeta[2] ?>" style="color:<?= $cmeta[1] ?>"></i><?= $e($cmeta[0]) ?></b><small>Storage by file type · scanned in <?= $scan_ms ?> ms</small></div>
  <?php else: ?>
  <div class="ttl"><b><i class="fa-solid fa-chart-pie" style="color:#34d399"></i>Dashboard</b><small>Storage analytics &amp; server health · scanned in <?= $scan_ms ?> ms</small></div>
  <?php endif; ?>
  <a class="btn hide-m" href="?fdpage=trash"><i class="fa-solid fa-trash" style="color:var(--bad)"></i>Trash</a>
  <a class="ib" href="?fdpage=dashboard" title="Refresh"><i class="fa-solid fa-rotate" style="color:#22d3ee"></i></a>
  <button class="ib" id="themeBtn" title="Theme"><i class="fa-solid fa-circle-half-stroke" style="color:#a78bfa"></i></button>
</header>

<?php if ($catView !== null): ?>
<main class="wrap">
  <section class="chead" style="--c:<?= $cmeta[1] ?>">
    <div class="big"><i class="fa-solid <?= $cmeta[2] ?>"></i></div>
    <div><b><?= $e($cmeta[0]) ?></b><small><?= number_format($cN) ?> file(s) · <?= $e(formatBytes($cB)) ?></small></div>
    <div class="pc"><?= $bytes ? round($cB / $bytes * 100) : 0 ?>%<small>of all files</small></div>
  </section>

  <nav class="chips" aria-label="File types">
    <a class="chip<?= $isAll ? ' on' : '' ?>" style="--c:var(--ac)" href="<?= $e($qs('all')) ?>"><i class="fa-solid fa-layer-group" style="color:#6366f1"></i>All <small><?= number_format($files) ?></small></a>
    <?php foreach ($cats as $k => $c): ?>
    <a class="chip<?= $catView === $k ? ' on' : '' ?>" style="--c:<?= $c[1] ?>" href="<?= $e($qs($k)) ?>"><i class="fa-solid <?= $c[2] ?>"></i><?= $e($c[0]) ?> <small><?= number_format($bycat[$k]['n']) ?></small></a>
    <?php endforeach; ?>
  </nav>

  <form class="tool" method="get">
    <input type="hidden" name="fdpage" value="dashboard">
    <input type="hidden" name="cat" value="<?= $e($catView) ?>">
    <label class="srch"><i class="fa-solid fa-magnifying-glass" style="color:#38bdf8"></i><input id="q" type="search" placeholder="Search <?= $e(strtolower($cmeta[0])) ?>…" autocomplete="off"></label>
    <select name="sort" onchange="this.form.submit()" aria-label="Sort">
      <?php foreach (['new' => 'Newest', 'old' => 'Oldest', 'size' => 'Largest', 'small' => 'Smallest', 'name' => 'Name A–Z'] as $sk => $sl): ?>
      <option value="<?= $sk ?>"<?= $sortBy === $sk ? ' selected' : '' ?>><?= $sl ?></option>
      <?php endforeach; ?>
    </select>
  </form>

  <?php if (!$catShown): ?>
  <section class="pn"><div class="empty">No files in this category.</div></section>
  <?php elseif ($catView === 'image'): ?>
  <div class="gal" id="items">
    <?php foreach ($catShown as $f):
      $abs = $root . '/' . $f['rel']; $thumb = in_array($f['ext'], ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'], true);
      [$href, $blank] = fileHref($abs, $f['ext']); ?>
    <div class="th<?= $thumb ? '' : ' bad' ?>" style="--c:<?= $cats['image'][1] ?>" data-n="<?= $e(mb_strtolower($f['name'])) ?>">
      <a class="tl" href="<?= $e($href) ?>"<?= $blank ? ' target="_blank" rel="noopener"' : '' ?> title="<?= $e($f['rel']) ?>">
        <?php if ($thumb): ?><img loading="lazy" src="index.php?raw=<?= rawurlencode($abs) ?>" alt="" onerror="this.parentNode.parentNode.classList.add('bad')"><?php endif; ?>
        <span class="ph"><i class="fa-solid fa-file-image" style="color:#ec4899"></i></span>
        <span class="cap"><?= $e($f['name']) ?> · <?= $e(formatBytes($f['size'], 0)) ?></span>
      </a>
      <a class="fo" href="<?= $e(folderHref($root, $f['dir'])) ?>" title="Open folder"><i class="fa-solid fa-folder-open" style="color:#f59e0b"></i></a>
    </div>
    <?php endforeach; ?>
  </div>
  <?php else: ?>
  <div class="fl" id="items">
    <?php foreach ($catShown as $f):
      $c = $cats[$f['cat']]; $abs = $root . '/' . $f['rel'];
      $thumb = $f['cat'] === 'image' && in_array($f['ext'], ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'], true);
      [$href, $blank] = fileHref($abs, $f['ext']); ?>
    <div class="fm" data-n="<?= $e(mb_strtolower($f['name'])) ?>">
      <a class="fi" style="--c:<?= $c[1] ?>" href="<?= $e($href) ?>"<?= $blank ? ' target="_blank" rel="noopener"' : '' ?>>
        <span class="ico"><i class="fa-solid <?= $c[2] ?>"></i><?php if ($thumb): ?><img loading="lazy" src="index.php?raw=<?= rawurlencode($abs) ?>" alt="" onerror="this.style.display='none'"><?php endif; ?></span>
        <span class="t"><b><?= $e($f['name']) ?></b><small><?= $e($f['dir'] === '' ? '/' : '/' . $f['dir']) ?></small></span>
        <span class="s"><?= $e(formatBytes($f['size'])) ?><small><?= $e(date('d M Y', $f['mt'])) ?></small></span>
      </a>
      <a class="fo" href="<?= $e(folderHref($root, $f['dir'])) ?>" title="Open folder"><i class="fa-solid fa-folder-open" style="color:#f59e0b"></i></a>
    </div>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>
  <div class="empty" id="nomatch" hidden>No file matches your search.</div>
  <?php if ($catTotal > count($catShown)): ?><div class="more">Showing the first <?= count($catShown) ?> of <?= number_format($catTotal) ?> — use search or sorting to narrow down.</div><?php endif; ?>
  <?php if ($partial): ?><div class="more">Scan stopped after 8 s — the list may be incomplete.</div><?php endif; ?>
  <div class="foot">Generated <?= date('d M Y, H:i:s') ?> · FileDash</div>
</main>
<?php else: ?>
<main class="wrap">

  <!-- disk hero -->
  <section class="hero">
    <div class="donut">
      <svg viewBox="0 0 120 120"><defs><linearGradient id="gr" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="var(--ac)"/><stop offset="1" stop-color="var(--ac2)"/></linearGradient></defs>
        <circle class="tr" cx="60" cy="60" r="52"/><circle class="pg" cx="60" cy="60" r="52"/></svg>
      <div class="mid"><b><?= $pct ?>%</b><small>disk used</small></div>
    </div>
    <div class="hl">
      <h2><i class="fa-solid fa-database" style="color:#a78bfa"></i>Disk usage</h2>
      <div class="sub"><?= $e(formatBytes($used)) ?> used of <?= $e(formatBytes($total)) ?> · <b style="color:var(--tx)"><?= $e(formatBytes($free)) ?></b> free</div>
      <div class="dbar" title="This app's files vs rest of disk">
        <i style="width:<?= min(100, $app_pct) ?>%;background:var(--ac2)"></i>
        <i style="width:<?= max(0, min(100, $pct) - min(100, $app_pct)) ?>%;background:linear-gradient(90deg,var(--ac),color-mix(in srgb,var(--ac) 60%,var(--ac2)))"></i>
      </div>
      <div class="leg">
        <span><em style="--c:var(--ac2)"></em>This app <b><?= $e(formatBytes($bytes + $trash_bytes)) ?></b></span>
        <span><em style="--c:var(--ac)"></em>Other data <b><?= $e(formatBytes(max(0, $used - $bytes - $trash_bytes))) ?></b></span>
        <span><em style="--c:var(--bd)"></em>Free <b><?= $e(formatBytes($free)) ?></b></span>
      </div>
    </div>
  </section>

  <!-- stats -->
  <section class="cards">
    <a class="cd" style="--c:#f59e0b" href="<?= $e(folderHref($root, '')) ?>" title="Open folders in file manager"><div class="ci"><i class="fa-solid fa-folder"></i></div><div><b><?= number_format($dirs) ?></b><small>Total folders</small></div><i class="fa-solid fa-chevron-right go"></i></a>
    <a class="cd" style="--c:#6366f1" href="?fdpage=dashboard&cat=all" title="See all files"><div class="ci"><i class="fa-solid fa-file"></i></div><div><b><?= number_format($files) ?></b><small>Total files</small></div><i class="fa-solid fa-chevron-right go"></i></a>
    <a class="cd" style="--c:#10b981" href="?fdpage=dashboard&cat=all&amp;sort=size" title="Biggest files first"><div class="ci"><i class="fa-solid fa-weight-hanging"></i></div><div><b><?= $e(formatBytes($bytes)) ?></b><small>Files size</small></div><i class="fa-solid fa-chevron-right go"></i></a>
    <a class="cd" style="--c:#ef4444" href="?fdpage=trash" title="Open Trash"><div class="ci"><i class="fa-solid fa-trash-can"></i></div><div><b><?= $e(formatBytes($trash_bytes)) ?></b><small>Trash:<?= $trash_items ?> item(s)</small></div><i class="fa-solid fa-chevron-right go"></i></a>
  </section>

  <!-- insights -->
  <section class="pn">
    <h3><i class="fa-solid fa-lightbulb" style="color:#fbbf24"></i>Insights</h3>
    <div class="tips"><?php foreach ($tips as $t): ?><div class="tip <?= $t[0] ?>"><i class="fa-solid <?= $t[1] ?>"></i><span><?= $e($t[2]) ?></span></div><?php endforeach; ?></div>
  </section>

  <div class="cols">
    <!-- by type -->
    <section class="pn">
      <h3><i class="fa-solid fa-shapes" style="color:#a78bfa"></i>Storage by file type<span><a href="?fdpage=dashboard&cat=all"><?= number_format($files) ?> files<i class="fa-solid fa-chevron-right" style="font-size:9px"></i></a></span></h3>
      <?php if ($files): ?>
      <div class="dbar"><?php foreach ($cats as $k => $c): if ($bycat[$k]['b'] > 0): ?><i style="width:<?= $bycat[$k]['b'] / $maxCatBytes * 100 ?>%;background:<?= $c[1] ?>" title="<?= $e($c[0]) ?>"></i><?php endif; endforeach; ?></div>
      <div class="stack">
        <?php foreach ($cats as $k => $c): $d = $bycat[$k]; ?>
        <a class="row lnk" style="--c:<?= $c[1] ?>" href="?fdpage=dashboard&cat=<?= $k ?>" title="Show all <?= $e(strtolower($c[0])) ?>">
          <div class="n"><i class="fa-solid <?= $c[2] ?>"></i><span><?= $e($c[0]) ?></span></div>
          <div class="v"><b><?= $e(formatBytes($d['b'])) ?></b> · <?= number_format($d['n']) ?> file(s)<i class="fa-solid fa-chevron-right go"></i></div>
          <div class="bar"><i style="width:<?= $d['b'] ? max(1.5, $d['b'] / $maxCatBytes * 100) : 0 ?>%"></i></div>
        </a>
        <?php endforeach; ?>
      </div>
      <?php else: ?><div class="empty">No files yet.</div><?php endif; ?>
    </section>

    <!-- top folders -->
    <section class="pn">
      <h3><i class="fa-solid fa-folder-tree" style="color:#f59e0b"></i>Biggest folders<span>top <?= count($topdirs) ?></span></h3>
      <?php if ($topdirs): ?><div class="stack">
        <?php foreach ($topdirs as $d => $sz): $isRoot = $d === '(root files)'; ?>
        <a class="row lnk" style="--c:#f59e0b" href="<?= $e(folderHref($root, $isRoot ? '' : $d)) ?>" title="Open in file manager">
          <div class="n"><i class="fa-solid <?= $isRoot ? 'fa-file' : 'fa-folder' ?>"></i><span><?= $e($d) ?></span></div>
          <div class="v"><b><?= $e(formatBytes($sz)) ?></b> · <?= $bytes ? round($sz / $bytes * 100) : 0 ?>%<i class="fa-solid fa-chevron-right go"></i></div>
          <div class="bar"><i style="width:<?= max(1.5, $sz / $maxTop * 100) ?>%"></i></div>
        </a>
        <?php endforeach; ?>
      </div><?php else: ?><div class="empty">No sub-folders with files.</div><?php endif; ?>
    </section>
  </div>

  <div class="cols">
    <section class="pn">
      <h3><i class="fa-solid fa-arrow-up-wide-short" style="color:#10b981"></i>Largest files<span>top <?= count($largest) ?></span></h3>
      <div class="fl">
      <?php foreach ($largest as $f): $c = $cats[$f['cat']]; ?>
        <a class="fi" style="--c:<?= $c[1] ?>" href="index.php?path=<?= urlencode($f['dir'] === '' ? $root : $root . '/' . $f['dir']) ?>" title="Open folder">
          <span class="ico"><i class="fa-solid <?= $c[2] ?>"></i></span>
          <span class="t"><b><?= $e($f['name']) ?></b><small><?= $e($f['dir'] === '' ? '/' : '/' . $f['dir']) ?></small></span>
          <span class="s"><?= $e(formatBytes($f['size'])) ?><small><?= $bytes ? round($f['size'] / $bytes * 100, 1) : 0 ?>%</small></span>
        </a>
      <?php endforeach; if (!$largest): ?><div class="empty">Nothing to show.</div><?php endif; ?>
      </div>
    </section>

    <section class="pn">
      <h3><i class="fa-solid fa-clock-rotate-left" style="color:#38bdf8"></i>Recently modified<span>latest <?= count($recent) ?></span></h3>
      <div class="fl">
      <?php foreach ($recent as $f): $c = $cats[$f['cat']]; ?>
        <a class="fi" style="--c:<?= $c[1] ?>" href="index.php?path=<?= urlencode($f['dir'] === '' ? $root : $root . '/' . $f['dir']) ?>" title="Open folder">
          <span class="ico"><i class="fa-solid <?= $c[2] ?>"></i></span>
          <span class="t"><b><?= $e($f['name']) ?></b><small><?= $e($f['dir'] === '' ? '/' : '/' . $f['dir']) ?></small></span>
          <span class="s"><?= $e(ago($f['mt'])) ?><small><?= $e(formatBytes($f['size'])) ?></small></span>
        </a>
      <?php endforeach; if (!$recent): ?><div class="empty">Nothing to show.</div><?php endif; ?>
      </div>
    </section>
  </div>

  <!-- extensions -->
  <?php if ($byext): ?>
  <section class="pn">
    <h3><i class="fa-solid fa-hashtag" style="color:#6366f1"></i>Top extensions by size</h3>
    <div class="stack">
      <?php foreach ($byext as $x => $d): ?>
      <div class="row" style="--c:var(--ac)">
        <div class="n"><i class="fa-solid fa-file-code" style="color:#f59e0b"></i><span><?= $e($x) ?></span></div>
        <div class="v"><b><?= $e(formatBytes($d['b'])) ?></b> · <?= number_format($d['n']) ?> file(s)</div>
        <div class="bar"><i style="width:<?= max(1.5, $d['b'] / $maxExt * 100) ?>%"></i></div>
      </div>
      <?php endforeach; ?>
    </div>
  </section>
  <?php endif; ?>

  <!-- server -->
  <section class="pn">
    <h3><i class="fa-solid fa-microchip" style="color:#a78bfa"></i>Server environment</h3>
    <div class="env">
      <?php foreach ($env as $r): ?><div class="ev"><i class="fa-solid <?= $r[0] ?>"></i><div><small><?= $e($r[1]) ?></small><b title="<?= $e($r[2]) ?>"><?= $e($r[2]) ?></b></div></div><?php endforeach; ?>
    </div>
    <h3 style="margin-top:4px"><i class="fa-solid fa-puzzle-piece" style="color:#f59e0b"></i>PHP extensions</h3>
    <div class="exts">
      <?php foreach ($exts as $k => $l): $on = extension_loaded($k); ?><div class="ex <?= $on ? 'y' : 'n' ?>"><i class="fa-solid <?= $on ? 'fa-circle-check' : 'fa-circle-xmark' ?>"></i><span><?= $e($l) ?></span></div><?php endforeach; ?>
    </div>
  </section>

  <div class="foot">Generated <?= date('d M Y, H:i:s') ?> · FileDash</div>
</main>
<?php endif; ?>

<script>
(() => {
  const root = document.documentElement;
  const ls = { get: (k, d) => { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } }, set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} } };
  function applyTheme() { const t = ls.get('fd_theme', 'auto'); const dark = t === 'dark' || (t === 'auto' && matchMedia('(prefers-color-scheme:dark)').matches); root.classList.toggle('light', !dark); }
  addEventListener('storage', e => { if (e.key === 'fd_theme') applyTheme(); if (e.key === 'fd_accent') applyAccent(); });
  function hsl(h) { const n = parseInt(h.slice(1), 16), r = (n >> 16) / 255, g = (n >> 8 & 255) / 255, b = (n & 255) / 255, mx = Math.max(r, g, b), mn = Math.min(r, g, b); let H = 0, S = 0; const L = (mx + mn) / 2; if (mx !== mn) { const d = mx - mn; S = L > .5 ? d / (2 - mx - mn) : d / (mx + mn); H = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; H *= 60; } return [H, S * 100, L * 100]; }
  function applyAccent() { const a = ls.get('fd_accent', null); if (!a) return; const [h, s, l] = hsl(a); root.style.setProperty('--ac', a); root.style.setProperty('--ac2', `hsl(${(h + 45) % 360} ${Math.max(s, 55)}% ${Math.min(Math.max(l, 52), 62)}%)`); document.querySelector('meta[name=theme-color]').content = a; }
  document.getElementById('themeBtn').onclick = () => { const o = ['auto', 'light', 'dark'], n = o[(o.indexOf(ls.get('fd_theme', 'auto')) + 1) % 3]; ls.set('fd_theme', n); applyTheme(); };
  applyTheme(); applyAccent();
  // live search inside a category page
  const q = document.getElementById('q');
  if (q) {
    const items = [...document.querySelectorAll('#items > [data-n]')], none = document.getElementById('nomatch');
    q.addEventListener('input', () => {
      const v = q.value.trim().toLowerCase(); let n = 0;
      items.forEach(i => { const ok = !v || i.dataset.n.includes(v); i.style.display = ok ? '' : 'none'; if (ok) n++; });
      none.hidden = n > 0 || !items.length;
    });
    q.form.addEventListener('submit', e => { if (document.activeElement === q) e.preventDefault(); });
  }
})();
</script>
<?php if (isset($_GET['embed'])): ?><script>
document.addEventListener('click',function(e){var a=e.target.closest('a[href]');if(!a||a.target==='_blank'||a.hasAttribute('download'))return;var u=new URL(a.href,location.href);if(u.origin!==location.origin)return;
if(u.pathname.split('/').pop()==='index.php'&&!u.search&&!u.hash){e.preventDefault();try{window.parent.postMessage('fd-close-page',location.origin)}catch(x){window.top.location.href=u.pathname}return;}
if(u.pathname===location.pathname&&u.search===location.search&&u.hash)return;
var p=u.searchParams.get('fdpage')||'index';
if(['trash','dashboard','settings'].indexOf(p)>-1){if(!u.searchParams.has('embed')){u.searchParams.set('embed','1');a.href=u.pathname+u.search+u.hash;}return;}
e.preventDefault();window.top.location.href=u.pathname+u.search+u.hash;});
document.addEventListener('submit',function(e){var f=e.target;var u=new URL(f.action||location.href,location.href);if(!u.searchParams.has('embed')){u.searchParams.set('embed','1');if((f.method||'get').toLowerCase()==='post'){f.action=u.pathname+u.search;}else if(!f.querySelector('input[name=embed]')){var i=document.createElement('input');i.type='hidden';i.name='embed';i.value='1';f.appendChild(i);}}});
</script><?php endif; ?></body>
</html>

<?php
} }

namespace FDSettings {
use \RecursiveIteratorIterator; use \RecursiveDirectoryIterator; use \FilesystemIterator; use \ZipArchive; use \DateTime; use \DateTimeZone; use \DirectoryIterator; use \SplFileInfo; use \Exception; use \Throwable; use \finfo;
/* hoisted function declarations (must be unconditional) */
function fmtB($b) { $u = ['B', 'KB', 'MB', 'GB', 'TB']; $b = max((float)$b, 0); $i = $b > 0 ? min(4, (int)floor(log($b, 1024))) : 0; return round($b / pow(1024, $i), $i ? 1 : 0) . ' ' . $u[$i]; }

function jread($f, $d = []) { $j = is_file($f) ? json_decode((string)@file_get_contents($f), true) : null; return is_array($j) ? $j : $d; }

function dirBytes($d) { $n = 0; if (!is_dir($d)) return 0; foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS)) as $f) { if (strpos($f->getPathname(), DIRECTORY_SEPARATOR . 'sessions' . DIRECTORY_SEPARATOR) !== false) continue; if ($f->isFile()) $n += $f->getSize(); } return $n; }

function actLines($dir) { $f = $dir . '/activity.log'; if (!is_file($f)) return []; $o = []; foreach (array_reverse((array)@file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) as $l) { $r = json_decode($l, true); if (is_array($r) && isset($r['t'], $r['a'])) $o[] = $r; } return $o; }

function fdUA($ua) {
    $ua = (string)$ua; if ($ua === '') return null;
    $os = 'Unknown OS'; $dev = 'Desktop'; $model = '';
    if (preg_match('/Android ([\d.]+)/', $ua, $m)) { $os = 'Android ' . $m[1]; $dev = stripos($ua, 'Mobile') !== false ? 'Phone' : 'Tablet'; if (preg_match('/Android [\d.]+; ([^;)]+)/', $ua, $mm)) $model = trim($mm[1]); }
    elseif (preg_match('/iPhone|iPad|iPod/', $ua, $m)) { $os = 'iOS' . (preg_match('/OS (\d+)/', $ua, $v) ? ' ' . $v[1] : ''); $dev = $m[0] === 'iPad' ? 'Tablet' : 'Phone'; $model = $m[0]; }
    elseif (preg_match('/Windows NT ([\d.]+)/', $ua, $m)) $os = ['10.0' => 'Windows 10/11', '6.3' => 'Windows 8.1', '6.1' => 'Windows 7'][$m[1]] ?? 'Windows';
    elseif (stripos($ua, 'Mac OS X') !== false) $os = 'macOS';
    elseif (stripos($ua, 'CrOS') !== false) $os = 'ChromeOS';
    elseif (stripos($ua, 'Linux') !== false) $os = 'Linux';
    $br = 'Unknown browser';
    foreach (['Edg' => 'Edge', 'OPR' => 'Opera', 'SamsungBrowser' => 'Samsung Internet', 'Firefox' => 'Firefox', 'FxiOS' => 'Firefox', 'CriOS' => 'Chrome', 'Chrome' => 'Chrome', 'Version' => 'Safari'] as $k => $n)
        if (preg_match('/' . $k . '\/(\d+)/', $ua, $m)) { $br = $n . ' ' . $m[1]; break; }
    return ['dev' => $dev, 'model' => $model, 'os' => $os, 'br' => $br];
}
    
function saveAcc($acc, $dir) { return function_exists('fdaSaveAccount') ? fdaSaveAccount($acc) : (@file_put_contents($dir . '/auth.json', json_encode($acc), LOCK_EX) !== false); }

if ($__fdpage === 'settings') {

/**
 * FileDash — ?fdpage=settings
 * Account · Appearance · Preferences · Security · Data · About
 * Works with your existing auth.php (uses fdaAccount / fdaCsrf / fdaLog and, if present, fdaSaveAccount / fdaRememberCookie).
 */

error_reporting(E_ALL); ini_set('display_errors', '0');

$acc  = fdaAccount();
$dir  = function_exists('fdaDir') ? fdaDir() : __DIR__ . '/.filedash';
$h    = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
$csrf = fdaCsrf();

/* ---------- small helpers ---------- */











/* ---------- JSON export (favorites + activity + link summary) ---------- */
if (isset($_GET['export'])) {
    $links = []; foreach (jread($dir . '/links.json') as $l) $links[] = ['name' => $l['name'] ?? '', 'expires' => $l['exp'] ?? 0, 'views' => $l['views'] ?? 0, 'created' => $l['created'] ?? 0];
    header('Content-Type: application/json; charset=utf-8'); header('Content-Disposition: attachment; filename="filedash-backup-' . date('Ymd-His') . '.json"');
    echo json_encode(['exported' => date('c'), 'user' => $acc['user'], 'favorites' => jread($dir . '/favorites.json'), 'downloads' => jread($dir . '/downloads.json'), 'links' => $links, 'activity' => actLines($dir)], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

/* ---------- POST actions (PRG: redirect back to the same tab) ---------- */
$flash = $_SESSION['fd_sflash'] ?? null; unset($_SESSION['fd_sflash']);
$err = ''; $tab = 'account';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $do = (string)($_POST['do'] ?? ''); $tab = preg_replace('/[^a-z]/', '', (string)($_POST['tab'] ?? 'account')) ?: 'account'; $ok = '';
    $lockLeft = max(0, (int)($_SESSION['fd_slock'] ?? 0) - time());
    if (!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) { $err = 'Page expired — reload and try again.'; }
    elseif ($do === 'account') {
        $cur = (string)($_POST['cur'] ?? ''); $nu = trim((string)($_POST['new_user'] ?? '')); $np = (string)($_POST['new_pass'] ?? ''); $np2 = (string)($_POST['new_pass2'] ?? ''); if ($nu === '') $nu = $acc['user'];
        if ($lockLeft > 0) $err = 'Too many wrong attempts. Try again in ' . ceil($lockLeft / 60) . ' min.';
        elseif (!password_verify($cur, $acc['hash'])) {
            $_SESSION['fd_sfail'] = (int)($_SESSION['fd_sfail'] ?? 0) + 1; if ($_SESSION['fd_sfail'] >= 5) { $_SESSION['fd_slock'] = time() + 300; $_SESSION['fd_sfail'] = 0; }
            fdaLog('login-fail', 'Wrong current password in Settings'); usleep(400000); $err = 'Current password is wrong.';
        }
        //elseif (!preg_match('/^[A-Za-z0-9_.\-]{3,32}$/', $nu)) $err = 'Username: 3–32 letters, numbers, . _ -';
        elseif (!preg_match('/^[A-Za-z0-9_.\-]{1,32}$/', $nu)) $err = 'Username: 1–32 letters, numbers, . _ -'; // unrestrict password
        elseif ($np !== $np2) $err = 'New passwords do not match.';
        elseif ($np === '' && $nu === $acc['user']) $err = 'Nothing to change — enter a new username or a new password.';
        else {
            $old = $acc['user']; $acc['user'] = $nu; if ($np !== '') $acc['hash'] = password_hash($np, PASSWORD_DEFAULT); $acc['changed'] = time();
            if (!saveAcc($acc, $dir)) $err = 'Could not save. Make sure the .filedash folder is writable.';
            else {
                $_SESSION['fd_sfail'] = 0; session_regenerate_id(true); $_SESSION['fd_user'] = $nu; $_SESSION['fd_seen'] = time(); unset($_SESSION['fd_csrf']);
                if (function_exists('fdaRememberCookie')) fdaRememberCookie();
                $what = ($nu !== $old ? 'username' : '') . ($nu !== $old && $np !== '' ? ' + ' : '') . ($np !== '' ? 'password' : ''); fdaLog('account', 'Changed ' . $what . ($nu !== $old ? " ($old → $nu)" : '')); $ok = ucfirst($what) . ' updated.';
            }
        }
    }
    elseif ($do === 'clear_log')   { @unlink($dir . '/activity.log'); $ok = 'Activity log cleared.'; }
    elseif ($do === 'clear_dl')    { @unlink($dir . '/downloads.json'); fdaLog('web', 'Web download history cleared'); $ok = 'Web download history cleared.'; }
    elseif ($do === 'revoke_links'){ $n = count(jread($dir . '/links.json')); @unlink($dir . '/links.json'); fdaLog('share', "All share links revoked ($n)"); $ok = "$n share link(s) revoked."; }
    elseif ($do === 'clear_favs')  { @unlink($dir . '/favorites.json'); fdaLog('star', 'Favorites cleared'); $ok = 'Favorites cleared.'; }
    else $err = 'Unknown action.';
    if ($err === '') { $_SESSION['fd_sflash'] = $ok; header('Location: ?fdpage=settings' . (isset($_GET['embed']) ? '&embed=1' : '') . '#' . $tab); exit; }
    $flash = null;   // show the error on the same tab below
}

/* ---------- data for the page ---------- */
$acts   = actLines($dir);
$logins = array_slice(array_values(array_filter($acts, fn($r) => in_array($r['a'], ['login', 'login-fail', 'logout', 'account'], true))), 0, 12);
$fails24 = count(array_filter($acts, fn($r) => $r['a'] === 'login-fail' && $r['t'] > time() - 86400));
$favs   = jread($dir . '/favorites.json'); $links = jread($dir . '/links.json'); $dls = jread($dir . '/downloads.json');
$activeLinks = count(array_filter($links, fn($l) => empty($l['exp']) || $l['exp'] > time()));
$stored = dirBytes($dir); $logBytes = is_file($dir . '/activity.log') ? filesize($dir . '/activity.log') : 0;
$total = @disk_total_space(FD_APP_ROOT) ?: 0; $free = @disk_free_space(FD_APP_ROOT) ?: 0;
$ini = strtoupper(function_exists('mb_substr') ? mb_substr($acc['user'], 0, 1) : substr($acc['user'], 0, 1));
$remember = !empty($_SESSION['fd_remember']);
$curTab = $err !== '' ? $tab : 'account';
$lmap = ['login' => ['fa-right-to-bracket', '#10b981', 'Signed in'], 'login-fail' => ['fa-shield-halved', '#ef4444', 'Failed sign-in'], 'logout' => ['fa-right-from-bracket', '#94a3b8', 'Signed out'], 'account' => ['fa-user-gear', '#8b5cf6', 'Account changed']];
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#6366f1">
<title>Settings — FileDash</title>
<?php fdCss('fa/css/all.min.css'); ?>
<style>
:root{--ac:#6366f1;--ac2:#ec4899;--bg:#0a0e1a;--bg2:#080b15;--card:#111827;--card2:#172033;--tx:#e8eaf6;--mut:#8f9bb8;--bd:rgba(255,255,255,.08);--hov:rgba(129,140,248,.13);--sh:0 12px 34px rgba(0,0,0,.4);--ok:#10b981;--bad:#ef4444;--warn:#f59e0b;color-scheme:dark}
html.light{--bg:#eef1fb;--bg2:#fff;--card:#fff;--card2:#f4f6fd;--tx:#151a33;--mut:#64708f;--bd:rgba(20,26,60,.1);--hov:rgba(99,102,241,.09);--sh:0 12px 34px rgba(30,40,100,.12);color-scheme:light}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{font-family:Inter,system-ui,-apple-system,"Noto Sans Bengali",Segoe UI,sans-serif;background:var(--bg);color:var(--tx);font-size:14px;line-height:1.45;min-height:100vh;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;z-index:-1;background:radial-gradient(600px 400px at 8% -5%,color-mix(in srgb,var(--ac) 22%,transparent),transparent),radial-gradient(500px 380px at 100% 100%,color-mix(in srgb,var(--ac2) 16%,transparent),transparent)}
a{color:inherit;text-decoration:none}button,input,select{font:inherit;color:inherit}button{cursor:pointer;border:0;background:none}[hidden]{display:none!important}
body.lock{overflow:hidden}
/* header */
.top{position:sticky;top:0;z-index:40;display:flex;align-items:center;gap:10px;padding:12px max(18px,env(safe-area-inset-right)) 12px max(18px,env(safe-area-inset-left));background:color-mix(in srgb,var(--bg) 78%,transparent);backdrop-filter:blur(16px);border-bottom:1px solid var(--bd)}
.ib{width:40px;height:40px;border-radius:12px;display:inline-grid;place-items:center;background:var(--card);border:1px solid var(--bd);color:var(--mut);transition:.15s;flex:none}.ib:hover{color:var(--tx);background:var(--hov);transform:translateY(-1px)}
.ttl{flex:1;min-width:0}.ttl b{display:flex;align-items:center;gap:9px;font-size:16px;line-height:1.2}.ttl b i{color:var(--ac)}.ttl small{display:block;color:var(--mut);font-size:11.5px}
.wrap{max-width:780px;margin:0 auto;padding:18px max(16px,env(safe-area-inset-left)) 60px;display:flex;flex-direction:column;gap:14px}
/* hero */
.hero{display:flex;align-items:center;gap:16px;padding:20px;border-radius:22px;background:var(--card);border:1px solid var(--bd);box-shadow:var(--sh);position:relative;overflow:hidden}
.hero::after{content:"";position:absolute;right:-60px;top:-70px;width:220px;height:220px;border-radius:50%;background:radial-gradient(circle,color-mix(in srgb,var(--ac) 26%,transparent),transparent 70%);pointer-events:none}
.av{width:64px;height:64px;border-radius:50%;display:grid;place-items:center;font-size:26px;font-weight:700;color:#fff;flex:none;background:linear-gradient(135deg,var(--ac2),var(--ac));box-shadow:0 10px 26px color-mix(in srgb,var(--ac) 40%,transparent)}
.hero h1{font-size:20px;line-height:1.2;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.hero .who{min-width:0;position:relative;z-index:1}
.badge{display:inline-flex;align-items:center;gap:6px;margin-top:6px;padding:3px 10px;border-radius:99px;font-size:12px;font-weight:600;color:var(--ac);background:color-mix(in srgb,var(--ac) 14%,transparent)}
.meta{display:flex;flex-wrap:wrap;gap:6px 14px;margin-top:9px;color:var(--mut);font-size:12.5px}.meta span{display:inline-flex;align-items:center;gap:6px}
/* tabs */
.tabs{display:flex;gap:6px;overflow-x:auto;scrollbar-width:none;padding:4px;border-radius:16px;background:var(--card);border:1px solid var(--bd);position:sticky;top:66px;z-index:30}.tabs::-webkit-scrollbar{display:none}
.tab{flex:1 0 auto;display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:9px 14px;border-radius:12px;font-weight:600;font-size:13px;color:var(--mut);white-space:nowrap;transition:.15s}
.tab:hover{color:var(--tx);background:var(--hov)}.tab.on{color:#fff;background:linear-gradient(135deg,var(--ac),var(--ac2));box-shadow:0 8px 20px color-mix(in srgb,var(--ac) 35%,transparent)}
/* cards */
.panel{display:flex;flex-direction:column;gap:14px;animation:in .3s both}@keyframes in{from{opacity:0;transform:translateY(8px)}}
.card{padding:20px;border-radius:20px;background:var(--card);border:1px solid var(--bd);box-shadow:var(--sh);display:flex;flex-direction:column;gap:14px}
.card h2{font-size:15px;display:flex;align-items:center;gap:10px}.card h2 i{color:var(--ac)}.card h2 small{margin-left:auto;color:var(--mut);font-weight:500;font-size:12px}
.sub{color:var(--mut);font-size:12.5px;margin-top:-8px}
.fld label{display:block;font-size:12.5px;font-weight:600;color:var(--mut);margin-bottom:6px}
.in{display:flex;align-items:center;gap:10px;height:46px;padding:0 14px;border-radius:13px;background:var(--card2);border:1px solid var(--bd);transition:.2s}
.in:focus-within{border-color:var(--ac);box-shadow:0 0 0 4px color-mix(in srgb,var(--ac) 18%,transparent)}
.in>i{color:var(--mut);width:16px;text-align:center;flex:none}.in input{flex:1;min-width:0;height:100%;background:none;border:0;outline:0;font-size:16px}
.eye{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;color:var(--mut);margin-right:-6px;flex:none}.eye:hover{background:var(--hov);color:var(--tx)}
.hint{font-size:12px;color:var(--mut);margin-top:6px}.hint.ok{color:var(--ok)}.hint.bad{color:var(--bad)}
hr{border:0;border-top:1px solid var(--bd)}
.btn{height:42px;padding:0 18px;border-radius:12px;font-weight:600;font-size:13.5px;background:var(--card2);border:1px solid var(--bd);display:inline-flex;align-items:center;justify-content:center;gap:9px;white-space:nowrap;transition:.15s}.btn:hover{background:var(--hov);transform:translateY(-1px)}
.btn.pri{color:#fff;border-color:transparent;background:linear-gradient(135deg,var(--ac),var(--ac2));box-shadow:0 10px 24px color-mix(in srgb,var(--ac) 38%,transparent)}
.btn.dng{color:var(--bad)}.btn.dng:hover{background:var(--bad);color:#fff;border-color:transparent}
.btn.blk{width:100%;height:46px}
.msg{display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border-radius:14px;font-size:13px;border:1px solid}
.msg.ok{background:color-mix(in srgb,var(--ok) 12%,var(--card2));border-color:color-mix(in srgb,var(--ok) 35%,transparent)}.msg.ok i{color:var(--ok)}
.msg.er{background:color-mix(in srgb,var(--bad) 12%,var(--card2));border-color:color-mix(in srgb,var(--bad) 35%,transparent);animation:shake .4s}.msg.er i{color:var(--bad)}
@keyframes shake{20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
/* segmented, swatches */
.seg{display:flex;padding:4px;gap:4px;border-radius:14px;background:var(--card2);border:1px solid var(--bd)}
.seg button{flex:1;display:inline-flex;align-items:center;justify-content:center;gap:8px;height:38px;border-radius:10px;color:var(--mut);font-weight:600;font-size:13px;transition:.15s}.seg button:hover{color:var(--tx)}
.seg button.on{color:#fff;background:linear-gradient(135deg,var(--ac),var(--ac2));box-shadow:0 6px 16px color-mix(in srgb,var(--ac) 32%,transparent)}
.sw{display:flex;flex-wrap:wrap;gap:12px}.sw button{width:38px;height:38px;border-radius:50%;border:3px solid transparent;box-shadow:0 0 0 1px var(--bd);transition:.15s;display:grid;place-items:center;color:#fff;font-size:13px}.sw button:hover{transform:scale(1.1)}
.sw button.on{border-color:var(--card);box-shadow:0 0 0 2px var(--ac)}
.pick{display:flex;align-items:center;gap:12px;color:var(--mut)}.pick input{width:44px;height:38px;border:0;background:none;padding:0;cursor:pointer}
.prev{display:flex;align-items:center;gap:12px;padding:14px;border-radius:16px;background:var(--card2);border:1px solid var(--bd)}
.prev .pi{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,var(--ac),var(--ac2))}.prev b{display:block}.prev small{color:var(--mut)}
.prev .pb{margin-left:auto;padding:7px 14px;border-radius:10px;color:#fff;font-weight:600;font-size:12.5px;background:linear-gradient(135deg,var(--ac),var(--ac2))}
/* lists */
.list{display:flex;flex-direction:column;gap:8px}
.row{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:14px;background:var(--card2);border:1px solid var(--bd);min-width:0}
.row .ri{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;flex:none;color:var(--c,var(--ac));background:color-mix(in srgb,var(--c,var(--ac)) 16%,transparent)}
.row .rt{flex:1;min-width:0}.row .rt b{display:block;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.row .rt small{display:block;color:var(--mut);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .rr{color:var(--mut);font-size:12px;white-space:nowrap}
.row .x{width:32px;height:32px;border-radius:10px;display:grid;place-items:center;color:var(--mut);flex:none}.row .x:hover{color:#fff;background:var(--bad)}
.empty{padding:22px 0;text-align:center;color:var(--mut)}.empty i{display:block;font-size:30px;opacity:.5;margin-bottom:8px}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.tile{padding:12px;border-radius:14px;background:var(--card2);border:1px solid var(--bd);min-width:0}.tile i{color:var(--c,var(--ac));font-size:15px}.tile b{display:block;font-size:18px;line-height:1.2;margin-top:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.tile small{color:var(--mut);font-size:11.5px}
.act{display:flex;align-items:center;gap:12px;padding:12px 14px;border-radius:14px;background:var(--card2);border:1px solid var(--bd)}
.act>div{flex:1;min-width:0}.act b{display:block;font-weight:600}.act small{color:var(--mut);font-size:12px}.act .btn{height:36px;padding:0 14px;font-size:13px}
.kv{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.kv>div{display:flex;align-items:center;gap:11px;padding:10px 12px;border-radius:13px;background:var(--card2);border:1px solid var(--bd);min-width:0}
.kv i{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;font-size:13px;color:var(--ac);background:color-mix(in srgb,var(--ac) 14%,transparent);flex:none}
.kv small{display:block;color:var(--mut);font-size:11.5px}.kv b{display:block;font:600 12.5px ui-monospace,Consolas,monospace;overflow:visible;white-space:normal;overflow-wrap:anywhere;word-break:break-word;line-height:1.4}
.kv>div>span{min-width:0;flex:1}.kv>div{align-items:flex-start}.kv>div>i{margin-top:1px}
.wrap>*,.panel,.card,.act>div,.row{min-width:0;max-width:100%}
/* confirm sheet + toast */
.cf{position:fixed;inset:0;z-index:300;display:grid;place-items:center;padding:16px;background:rgba(3,6,20,.65);backdrop-filter:blur(6px);animation:fade .18s}@keyframes fade{from{opacity:0}}
.cfc{width:100%;max-width:400px;padding:22px;border-radius:22px;background:var(--card);border:1px solid var(--bd);box-shadow:var(--sh);animation:up .22s}@keyframes up{from{opacity:0;transform:translateY(14px)}}
.cfc h3{display:flex;align-items:center;gap:10px;font-size:16px;margin-bottom:8px}.cfc h3 i{color:var(--warn)}.cfc p{color:var(--mut)}.cfb{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}
.toast{position:fixed;left:50%;bottom:calc(20px + env(safe-area-inset-bottom));transform:translateX(-50%);z-index:400;padding:12px 18px;border-radius:14px;background:var(--card);border:1px solid var(--bd);border-left:4px solid var(--ok);box-shadow:var(--sh);display:flex;gap:10px;align-items:center;max-width:90vw;animation:sl .3s}
.toast.out{opacity:0;transition:.3s}@keyframes sl{from{opacity:0;transform:translate(-50%,16px)}}
@media (max-width:640px){
 .top{padding:10px 12px}.wrap{padding:12px 12px 50px;gap:12px}.hero{padding:16px;gap:14px}.av{width:56px;height:56px;font-size:23px}
 .tabs{top:60px}.tab{padding:9px 12px}.card{padding:16px}.tiles{grid-template-columns:repeat(2,1fr)}.kv{grid-template-columns:1fr}
 .act{flex-wrap:wrap}.act .btn{width:100%}
 .cf{align-items:end;padding:0}.cfc{max-width:none;border-radius:24px 24px 0 0;padding-bottom:calc(22px + env(safe-area-inset-bottom))}
}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
.row[data-info]{user-select:none;-webkit-user-select:none;-webkit-touch-callout:none;cursor:pointer}
@media(max-width:640px){
 #accForm{gap:11px}
 #accForm .fld label{font-size:12px;margin-bottom:4px}
 #accForm .in{height:38px;padding:0 11px;border-radius:11px;gap:8px}
 #accForm .in input{font-size:14px}
 #accForm .eye{width:28px;height:28px;margin-right:-4px}
 #accForm .hint{font-size:11.5px;margin-top:4px}
 #accForm .btn.blk{height:42px}
}
//.row.holding{transform:scale(.985);box-shadow:0 0 0 2px var(--c)}
.si{position:fixed;z-index:200;width:min(320px,calc(100vw - 24px));background:var(--card);border:1px solid var(--bd);border-radius:14px;box-shadow:0 24px 60px rgba(0,0,0,.45);padding:14px;animation:siIn .16s ease both}
.si[hidden]{display:none}
@keyframes siIn{from{opacity:0;transform:translateY(6px) scale(.97)}to{opacity:1;transform:none}}
.si h4{display:flex;align-items:center;gap:8px;font-size:14px;margin-bottom:10px;padding-right:30px;position:relative}.si .si-close{position:absolute;right:0;top:-5px;width:28px;height:28px;display:grid;place-items:center;border:1px solid var(--bd);border-radius:8px;background:var(--card2);color:var(--mut);cursor:pointer;font-size:14px}.si .si-close:hover{background:var(--bad);border-color:var(--bad);color:#fff}
.si .k{display:flex;justify-content:space-between;gap:14px;padding:6px 0;border-top:1px solid var(--bd);font-size:12.5px}
.si .k span{color:var(--mut)}.si .k b{font-weight:600;text-align:right;word-break:break-word}
<?php if (isset($_GET['embed'])): ?>
body{min-height:100%;overflow-x:hidden}html,body{background:transparent!important}
.top{display:flex!important;position:static!important;background:transparent!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important;border:0!important;padding:4px 14px 0!important;gap:12px}
.top .ttl{flex:1;min-width:0}.top .ttl b{font-size:18px;gap:10px}.top .ttl small{font-size:11.5px}
.top #themeBtn,.top a[title="Sign out"]{display:none!important}
.wrap{max-width:none!important;width:100%!important;margin:0!important;padding:14px!important}
@media(max-width:600px){.top{padding:2px 10px 0!important;gap:9px}.top .ttl small{display:none}}
@media(max-width:640px){
 .wrap{padding:10px!important;gap:10px!important}.hero{padding:13px;border-radius:15px;gap:12px}.av{width:46px;height:46px;font-size:19px}.hero h1{font-size:17px}.meta{gap:5px 9px;font-size:11px}
 .tabs{top:6px;padding:3px;border-radius:12px;gap:4px}.tab{padding:8px 10px;font-size:12px;gap:6px}
 .panel{gap:10px}.card{padding:13px;border-radius:14px;gap:11px}.act{padding:10px;border-radius:12px;gap:9px}.act b{font-size:13px}.act small{font-size:11px}.act .btn{width:auto;min-width:74px;padding:0 10px}
 .kv>div{padding:9px 10px}.tiles{gap:7px}.tile{padding:10px}
}
<?php endif; ?>
</style>
</head>
<body>

<header class="top">
  <a class="ib" href="index.php" aria-label="Back to files"><i class="fa-solid fa-arrow-left" style="color:#818cf8"></i></a>
  <div class="ttl"><b><i class="fa-solid fa-sliders" style="color:#a78bfa"></i>Settings</b><small>Account, appearance &amp; data</small></div>
  <button class="ib" id="themeBtn" type="button" title="Theme"><i class="fa-solid fa-circle-half-stroke" style="color:#a78bfa"></i></button>
  <a class="ib" href="?fdpage=logout&t=<?= $h(urlencode($csrf)) ?>" title="Sign out"><i class="fa-solid fa-right-from-bracket" style="color:#ef4444"></i></a>
</header>

<main class="wrap">

  <section class="hero">
    <div class="av"><?= $h($ini) ?></div>
    <div class="who">
      <h1><?= $h($acc['user']) ?></h1>
      <span class="badge"><i class="fa-solid fa-shield-halved" style="color:#10b981"></i>Admin</span>
      <div class="meta">
        <?php if (!empty($acc['created'])): ?><span><i class="fa-regular fa-calendar" style="color:#f59e0b"></i>Since <span data-date="<?= (int)$acc['created'] ?>"></span></span><?php endif; ?>
        <?php if (!empty($acc['changed'])): ?><span><i class="fa-solid fa-key" style="color:#eab308"></i>Password changed <span data-ago="<?= (int)$acc['changed'] ?>"></span></span><?php endif; ?>
        <span><i class="fa-solid fa-laptop" style="color:#38bdf8"></i><?= $remember ? 'Remembered · 30 days' : 'This session only' ?></span>
      </div>
    </div>
  </section>

  <nav class="tabs" id="tabs" role="tablist">
    <button class="tab" data-tab="account"><i class="fa-solid fa-user"></i>Account</button>
    <button class="tab" data-tab="appearance"><i class="fa-solid fa-palette"></i>Appearance</button>
    <button class="tab" data-tab="prefs"><i class="fa-solid fa-sliders"></i>Preferences</button>
    <button class="tab" data-tab="security"><i class="fa-solid fa-fingerprint"></i>Security</button>
    <button class="tab" data-tab="data"><i class="fa-solid fa-database"></i>Data</button>
    <button class="tab" data-tab="about"><i class="fa-solid fa-circle-info"></i>About</button>
  </nav>

  <?php if ($err): ?><div class="msg er"><i class="fa-solid fa-circle-exclamation" style="color:#ef4444"></i><span><?= $h($err) ?></span></div><?php endif; ?>

  <!-- ============ ACCOUNT ============ -->
  <section class="panel" data-panel="account" hidden>
    <form class="card" method="post" autocomplete="off" id="accForm">
      <input type="hidden" name="csrf" value="<?= $h($csrf) ?>"><input type="hidden" name="do" value="account"><input type="hidden" name="tab" value="account">
      <h2><i class="fa-solid fa-user-pen" style="color:#8b5cf6"></i>Username &amp; password</h2>
      <div class="fld"><label for="nu">Username</label>
        <div class="in"><i class="fa-solid fa-user" style="color:#38bdf8"></i><input id="nu" name="new_user" type="text" value="<?= $h($acc['user']) ?>" autocomplete="username" autocapitalize="off" spellcheck="false"></div>
        <div class="hint">3–32 characters: letters, numbers, . _ -</div></div>
      <div class="fld"><label for="np">New password</label>
        <div class="in"><i class="fa-solid fa-lock" style="color:#f59e0b"></i><input id="np" name="new_pass" type="password" autocomplete="new-password" placeholder="Leave empty to keep current"><button class="eye" type="button" data-eye="np" aria-label="Show"><i class="fa-solid fa-eye" style="color:#8b5cf6"></i></button></div></div>
      <div class="fld"><label for="np2">Confirm new password</label>
        <div class="in"><i class="fa-solid fa-lock" style="color:#f59e0b"></i><input id="np2" name="new_pass2" type="password" autocomplete="new-password"><button class="eye" type="button" data-eye="np2" aria-label="Show"><i class="fa-solid fa-eye" style="color:#8b5cf6"></i></button></div>
        <div class="hint" id="pwHint" hidden></div></div>
      <hr>
      <div class="fld"><label for="cur">Current password <span style="color:var(--bad)">*</span></label>
        <div class="in"><i class="fa-solid fa-key" style="color:#eab308"></i><input id="cur" name="cur" type="password" autocomplete="current-password" required><button class="eye" type="button" data-eye="cur" aria-label="Show"><i class="fa-solid fa-eye" style="color:#8b5cf6"></i></button></div>
        <div class="hint">Needed to confirm it's really you.</div></div>
      <button class="btn pri blk" type="submit"><i class="fa-solid fa-floppy-disk"></i>Save changes</button>
    </form>
  </section>

  <!-- ============ APPEARANCE ============ -->
  <section class="panel" data-panel="appearance" hidden>
    <div class="card">
      <h2><i class="fa-solid fa-circle-half-stroke" style="color:#a78bfa"></i>Theme</h2>
      <div class="seg" id="themeSeg">
        <button data-t="auto"><i class="fa-solid fa-wand-magic-sparkles"></i>Auto</button>
        <button data-t="light"><i class="fa-solid fa-sun"></i>Light</button>
        <button data-t="dark"><i class="fa-solid fa-moon"></i>Dark</button>
      </div>
      <div class="hint" style="margin:0">Auto follows your phone / computer setting.</div>
    </div>
    <div class="card">
      <h2><i class="fa-solid fa-palette" style="color:#ec4899"></i>Accent colour</h2>
      <div class="sw" id="sw"></div>
      <label class="pick"><input type="color" id="accPick" value="#6366f1"><span>Pick any colour</span></label>
      <div class="prev"><span class="pi"><i class="fa-solid fa-folder-tree"></i></span><div><b>FileDash</b><small>Live preview</small></div><span class="pb">Button</span></div>
      <button class="btn" type="button" id="accReset"><i class="fa-solid fa-rotate-left" style="color:#34d399"></i>Reset to default</button>
    </div>
  </section>

  <!-- ============ PREFERENCES ============ -->
  <section class="panel" data-panel="prefs" hidden>
    <div class="card">
      <h2><i class="fa-solid fa-table-cells-large" style="color:#38bdf8"></i>Default file view</h2>
      <div class="seg" id="viewSeg">
        <button data-v="list"><i class="fa-solid fa-list"></i>List</button>
        <button data-v="grid"><i class="fa-solid fa-grip"></i>Grid</button>
        <button data-v="gallery"><i class="fa-solid fa-image"></i>Gallery</button>
      </div>
      <div class="hint" style="margin:0">Used on this device when you open the file manager.</div>
    </div>
    <div class="card">
      <h2><i class="fa-solid fa-thumbtack" style="color:#f43f5e"></i>Pinned folders<small id="pinN"></small></h2>
      <div class="list" id="pinList"></div>
    </div>
    <div class="card">
      <h2><i class="fa-solid fa-broom" style="color:#f59e0b"></i>This device</h2>
      <div class="act"><div><b>Recent folders</b><small id="recN"></small></div><button class="btn" type="button" data-ls="fd_recent">Clear</button></div>
      <div class="act"><div><b>Copy / cut clipboard</b><small id="clipN"></small></div><button class="btn" type="button" data-ls="fd_clip">Clear</button></div>
    </div>
  </section>

  <!-- ============ SECURITY ============ -->
  <section class="panel" data-panel="security" hidden>
    <div class="card">
      <h2><i class="fa-solid fa-laptop" style="color:var(--ac)"></i>Current session</h2>
      <div class="kv">
        <div><i class="fa-solid fa-user" style="color:var(--ac)"></i><span><small>Signed in as</small><b><?= $h($acc['user']) ?></b></span></div>
        <div><i class="fa-solid fa-location-dot" style="color:var(--ac)"></i><span><small>Your IP</small><b><?= $h($_SERVER['REMOTE_ADDR'] ?? '—') ?></b></span></div>
        <div><i class="fa-solid fa-clock" style="color:var(--ac)"></i><span><small>Stay signed in</small><b><?= $remember ? '30 days' : 'Until browser closes' ?></b></span></div>
        <div><i class="fa-solid fa-triangle-exclamation" style="color:#f59e0b"></i><span><small>Failed sign-ins (24 h)</small><b style="<?= $fails24 ? 'color:var(--bad)' : '' ?>"><?= $fails24 ?></b></span></div>
      </div>
      <a class="btn dng blk" href="?fdpage=logout&t=<?= $h(urlencode($csrf)) ?>"><i class="fa-solid fa-right-from-bracket" style="color:#ef4444"></i>Sign out</a>
    </div>
    <div class="card">
      <h2><i class="fa-solid fa-clock-rotate-left" style="color:#38bdf8"></i>Recent sign-ins<small>last <?= count($logins) ?></small></h2>
      <div class="list">
  <?php foreach ($logins as $r): [$ic, $col, $lab] = $lmap[$r['a']]; $u = fdUA($r['ua'] ?? ''); $info = ['lab' => $lab, 't' => (int)$r['t'], 'ip' => $r['ip'] ?? '', 'note' => $r['d'] ?? '', 'dev' => $u['dev'] ?? '', 'model' => $u['model'] ?? '', 'os' => $u['os'] ?? '', 'br' => $u['br'] ?? '', 'ok' => $r['a'] !== 'login-fail']; ?>
  <div class="row" data-info="<?= $h(json_encode($info, JSON_UNESCAPED_UNICODE)) ?>" style="--c:<?= $col ?>"><span class="ri"><i class="fa-solid <?= $ic ?>"></i></span><span class="rt"><b><?= $h($lab) ?></b><small><?= $h(($r['ip'] ?? '') ?: '—') ?><?= !empty($r['d']) ? ' · ' . $h($r['d']) : '' ?></small></span><span class="rr" data-when="<?= (int)$r['t'] ?>"></span></div>
  <?php endforeach; if (!$logins): ?><div class="empty"><i class="fa-solid fa-fingerprint" style="color:#8b5cf6"></i>No sign-in history yet</div><?php endif; ?>
</div>
    </div>
  </section>

  <!-- ============ DATA ============ -->
  <section class="panel" data-panel="data" hidden>
    <div class="card">
      <h2><i class="fa-solid fa-hard-drive" style="color:#ec4899"></i>Stored by FileDash<small><?= $h(fmtB($stored)) ?></small></h2>
      <div class="tiles">
        <div class="tile" style="--c:#f59e0b"><i class="fa-solid fa-star" style="color:#f59e0b"></i><b><?= count($favs) ?></b><small>Favorites</small></div>
        <div class="tile" style="--c:#ec4899"><i class="fa-solid fa-link" style="color:#ec4899"></i><b><?= $activeLinks ?></b><small>Active links</small></div>
        <div class="tile" style="--c:#06b6d4"><i class="fa-solid fa-globe" style="color:#06b6d4"></i><b><?= count($dls) ?></b><small>Web downloads</small></div>
        <div class="tile" style="--c:#6366f1"><i class="fa-solid fa-scroll" style="color:#a78bfa"></i><b><?= count($acts) ?></b><small>Log entries · <?= $h(fmtB($logBytes)) ?></small></div>
      </div>
    </div>
    <div class="card">
      <h2><i class="fa-solid fa-download" style="color:#10b981"></i>Backup</h2>
      <div class="act"><div><b>Export data (JSON)</b><small>Favorites, activity log, downloads &amp; link summary</small></div><a class="btn pri" href="?export=1"><i class="fa-solid fa-file-arrow-down"></i>Export</a></div>
    </div>
    <div class="card">
      <h2><i class="fa-solid fa-broom" style="color:#f59e0b"></i>Clean up</h2>
      <?php foreach ([['clear_log', 'Clear activity log', count($acts) . ' entries', 'fa-scroll', 'Delete the whole activity log? This cannot be undone.'],
                      ['clear_dl', 'Clear web download history', count($dls) . ' entries', 'fa-globe', 'Clear the list of web downloads? (Downloaded files are kept.)'],
                      ['revoke_links', 'Revoke all share links', count($links) . ' links', 'fa-link-slash', 'Revoke every share link? People using them will lose access.'],
                      ['clear_favs', 'Clear favorites', count($favs) . ' items', 'fa-star', 'Remove all favorites? (The files themselves are not touched.)']] as [$do, $t, $s, $ic, $q]): ?>
      <form class="act" method="post" data-confirm="<?= $h($q) ?>" data-title="<?= $h($t) ?>">
        <input type="hidden" name="csrf" value="<?= $h($csrf) ?>"><input type="hidden" name="do" value="<?= $do ?>"><input type="hidden" name="tab" value="data">
        <div><b><i class="fa-solid <?= $ic ?>" style="color:var(--mut);width:20px"></i><?= $h($t) ?></b><small><?= $h($s) ?></small></div>
        <button class="btn dng" type="submit">Clear</button>
      </form>
      <?php endforeach; ?>
    </div>
  </section>

  <!-- ============ ABOUT ============ -->
  <section class="panel" data-panel="about" hidden>
    <div class="card">
      <h2><i class="fa-solid fa-server" style="color:#38bdf8"></i>Server</h2>
      <div class="kv">
        <div><i class="fa-brands fa-php" style="color:#818cf8"></i><span><small>PHP</small><b><?= $h(PHP_VERSION) ?></b></span></div>
        <div><i class="fa-solid fa-server" style="color:#38bdf8"></i><span><small>Software</small><b title="<?= $h($_SERVER['SERVER_SOFTWARE'] ?? '') ?>"><?= $h($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown') ?></b></span></div>
        <div><i class="fa-solid fa-cloud-arrow-up" style="color:#6366f1"></i><span><small>Max upload</small><b><?= $h(ini_get('upload_max_filesize')) ?></b></span></div>
        <div><i class="fa-solid fa-paper-plane" style="color:#38bdf8"></i><span><small>Max POST</small><b><?= $h(ini_get('post_max_size')) ?></b></span></div>
        <div><i class="fa-solid fa-memory" style="color:#a78bfa"></i><span><small>Memory limit</small><b><?= $h(ini_get('memory_limit')) ?></b></span></div>
        <div><i class="fa-solid fa-earth-asia" style="color:#14b8a6"></i><span><small>Timezone</small><b><?= $h(date_default_timezone_get()) ?></b></span></div>
        <div><i class="fa-solid fa-hard-drive" style="color:#ec4899"></i><span><small>Disk free</small><b><?= $h(fmtB($free)) ?> / <?= $h(fmtB($total)) ?></b></span></div>
        <div><i class="fa-solid fa-folder-tree" style="color:#f59e0b"></i><span><small>App folder</small><b title="<?= $h(FD_APP_ROOT) ?>"><?= $h(FD_APP_ROOT) ?></b></span></div>
      </div>
    </div>
    <div class="card">
      <h2><i class="fa-solid fa-circle-info" style="color:#38bdf8"></i>FileDash</h2>
      <div class="act"><div><b>FileDash v2</b><small>Neon smart file manager</small></div><a class="btn" href="?fdpage=dashboard"><i class="fa-solid fa-chart-pie" style="color:#34d399"></i>Dashboard</a></div>
    </div>
  </section>
</main>

<div class="cf" id="cf" hidden><div class="cfc"><h3><i class="fa-solid fa-triangle-exclamation" style="color:#f59e0b"></i><span id="cfT">Confirm</span></h3><p id="cfM"></p><div class="cfb"><button class="btn" type="button" id="cfN">Cancel</button><button class="btn dng" type="button" id="cfY">Confirm</button></div></div></div>
<?php if ($flash): ?><div class="toast" id="flash"><i class="fa-solid fa-circle-check" style="color:var(--ok)"></i><span><?= $h($flash) ?></span></div><?php endif; ?>

<script>
(() => {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const ls = { get: (k, d) => { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } }, set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }, del: k => { try { localStorage.removeItem(k); } catch (e) {} } };
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const root = document.documentElement;

  /* ---- theme + accent (shared with the file manager) ---- */
  const applyTheme = () => { const t = ls.get('fd_theme', 'auto'); root.classList.toggle('light', !(t === 'dark' || (t === 'auto' && matchMedia('(prefers-color-scheme:dark)').matches))); $$('#themeSeg button').forEach(b => b.classList.toggle('on', b.dataset.t === t)); };
  addEventListener('storage', e => { if (e.key === 'fd_theme') applyTheme(); if (e.key === 'fd_accent') applyAccent(); });
  function hsl(h) { const n = parseInt(h.slice(1), 16), r = (n >> 16) / 255, g = (n >> 8 & 255) / 255, b = (n & 255) / 255, mx = Math.max(r, g, b), mn = Math.min(r, g, b); let H = 0, S = 0; const L = (mx + mn) / 2; if (mx !== mn) { const d = mx - mn; S = L > .5 ? d / (2 - mx - mn) : d / (mx + mn); H = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; H *= 60; } return [H, S * 100, L * 100]; }
  const COLS = ['#6366f1', '#8b5cf6', '#ec4899', '#ef4444', '#f97316', '#eab308', '#22c55e', '#14b8a6', '#06b6d4', '#3b82f6'];
  function applyAccent() {
    const a = ls.get('fd_accent', null);
    if (!a) { root.style.removeProperty('--ac'); root.style.removeProperty('--ac2'); } else { const [h, s, l] = hsl(a); root.style.setProperty('--ac', a); root.style.setProperty('--ac2', `hsl(${(h + 45) % 360} ${Math.max(s, 55)}% ${Math.min(Math.max(l, 52), 62)}%)`); document.querySelector('meta[name=theme-color]').content = a; }
    $$('#sw button').forEach(b => b.classList.toggle('on', b.dataset.c === (a || COLS[0])));
  }
  $('#themeBtn').onclick = () => { const o = ['auto', 'light', 'dark']; ls.set('fd_theme', o[(o.indexOf(ls.get('fd_theme', 'auto')) + 1) % 3]); applyTheme(); };
  $('#themeSeg').onclick = e => { const b = e.target.closest('button'); if (b) { ls.set('fd_theme', b.dataset.t); applyTheme(); } };
  $('#sw').innerHTML = COLS.map(c => `<button type="button" data-c="${c}" style="background:${c}" aria-label="${c}"></button>`).join('');
  $('#sw').onclick = e => { const b = e.target.closest('button'); if (b) { ls.set('fd_accent', b.dataset.c); $('#accPick').value = b.dataset.c; applyAccent(); } };
  $('#accPick').oninput = e => { ls.set('fd_accent', e.target.value); applyAccent(); };
  $('#accReset').onclick = () => { ls.del('fd_accent'); $('#accPick').value = '#6366f1'; applyAccent(); toast('Accent reset'); };
  applyTheme(); applyAccent(); { const a = ls.get('fd_accent', null); if (a) $('#accPick').value = a; }
 /* click/tap a sign-in card → details */
{
  const si = document.getElementById('si') || document.body.appendChild(Object.assign(document.createElement('div'), { id: 'si', className: 'si', hidden: true }));

  const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const k = (a, b) => b ? `<div class="k"><span>${a}</span><b>${esc(b)}</b></div>` : '';

  const hide = () => { si.hidden = true; };
  si.addEventListener('click', e => { if (e.target.closest('.si-close')) hide(); });

  const show = (row, x, y) => {
    let d;
    try { d = JSON.parse(row.dataset.info); } catch (e) { return; }

    const dev = [d.model, d.dev].filter(Boolean).join(' · ');

    si.innerHTML = `<h4><i class="fa-solid ${d.ok ? 'fa-circle-check' : 'fa-circle-xmark'}" style="color:${d.ok ? '#34d399' : '#fb7185'}"></i>${esc(d.lab)}<button type="button" class="si-close" aria-label="Close" title="Close"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></h4>`
      + k('When', new Date(d.t * 1000).toLocaleString())
      + k('What happened', d.note)
      + k('Device', dev)
      + k('System', d.os)
      + k('Browser', d.br)
      + k('IP address', d.ip)
      + (d.br ? '' : '<div class="k"><span>Browser info</span><b>Not recorded (old entry)</b></div>');

    si.hidden = false;

    const w = si.offsetWidth, h = si.offsetHeight;

    if (innerWidth <= 900) { /* mobile: level with the tapped card, always above the bottom dock */
      const c = row.getBoundingClientRect(); let B = innerHeight;
      try { const f = window.frameElement, n = f && parent.document.querySelector('.bnav'); if (n && parent.getComputedStyle(n).display !== 'none') B = Math.min(B, n.getBoundingClientRect().top - f.getBoundingClientRect().top); } catch (e) {}
      B -= 12; const T = 12, hh = Math.min(h, B - T);
      si.style.maxHeight = (B - T) + 'px'; si.style.overflowY = 'auto';
      si.style.left = Math.max(12, Math.min(c.left + c.width / 2 - w / 2, innerWidth - w - 12)) + 'px';
      si.style.top = Math.max(T, Math.min(c.top, B - hh)) + 'px'; return;
    }
    si.style.left = Math.max(12, Math.min(x - w / 2, innerWidth - w - 12)) + 'px';
    si.style.top = Math.max(12, Math.min(y + 14, innerHeight - h - 12)) + 'px';
  };

  document.addEventListener('click', e => {
    const row = e.target.closest('.row[data-info]');

    if (row) {
      show(row, e.clientX, e.clientY);
    } else if (!e.target.closest('#si')) {
      hide();
    }
  });

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') hide();
  });
}

  /* ---- tabs (hash-based so the back button works) ---- */
  const TABS = $$('.tab').map(t => t.dataset.tab), first = <?= json_encode($curTab) ?>;
  function showTab(n) {
    if (!TABS.includes(n)) n = first;
    $$('.tab').forEach(t => t.classList.toggle('on', t.dataset.tab === n)); $$('.panel').forEach(p => p.hidden = p.dataset.panel !== n);
    $('.tab.on').scrollIntoView({ inline: 'center', block: 'nearest' });
    if (n === 'prefs') drawPrefs();
  }
  $('#tabs').onclick = e => { const t = e.target.closest('.tab'); if (t) { history.replaceState(null, '', '#' + t.dataset.tab); showTab(t.dataset.tab); scrollTo({ top: 0, behavior: 'smooth' }); } };
  addEventListener('hashchange', () => showTab(location.hash.slice(1)));
  showTab(<?= $err !== '' ? json_encode($tab) : "location.hash.slice(1)" ?>);

  /* ---- preferences (stored on this device, read by the file manager) ---- */
  const base = p => String(p).replace(/[\\/]+$/, '').split(/[\\/]/).pop() || p;
  function drawPrefs() {
    $$('#viewSeg button').forEach(b => b.classList.toggle('on', b.dataset.v === ls.get('fd_view', innerWidth <= 900 ? 'grid' : 'list')));
    const pins = ls.get('fd_pins', []);
    $('#pinN').textContent = pins.length ? pins.length + ' pinned' : '';
    $('#pinList').innerHTML = pins.map((p, i) => `<div class="row"><span class="ri" style="--c:#f59e0b"><i class="fa-solid fa-folder"></i></span><span class="rt"><b>${esc(base(p))}</b><small>${esc(p)}</small></span><button class="x" type="button" data-unpin="${i}" aria-label="Unpin"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></div>`).join('') || '<div class="empty"><i class="fa-solid fa-thumbtack" style="color:#f43f5e"></i>No pinned folders.<br><small>Open ⋯ on a folder → Pin to sidebar</small></div>';
    $('#recN').textContent = ls.get('fd_recent', []).length + ' folder(s) remembered';
    const c = ls.get('fd_clip', null); $('#clipN').textContent = c && c.paths && c.paths.length ? c.paths.length + ' item(s) waiting to ' + (c.type === 'move' ? 'move' : 'paste') : 'Empty';
  }
  $('#viewSeg').onclick = e => { const b = e.target.closest('button'); if (b) { ls.set('fd_view', b.dataset.v); drawPrefs(); toast('Default view: ' + b.dataset.v); } };
  $('#pinList').onclick = e => { const b = e.target.closest('[data-unpin]'); if (b) { const a = ls.get('fd_pins', []); a.splice(+b.dataset.unpin, 1); ls.set('fd_pins', a); drawPrefs(); } };
  $$('[data-ls]').forEach(b => b.onclick = () => { ls.del(b.dataset.ls); drawPrefs(); toast('Cleared'); });

  /* ---- password helpers ---- */
  $$('[data-eye]').forEach(b => b.onclick = () => { const i = document.getElementById(b.dataset.eye), s = i.type === 'password'; i.type = s ? 'text' : 'password'; b.firstElementChild.className = 'fa-solid ' + (s ? 'fa-eye-slash' : 'fa-eye'); });
  const np = $('#np'), np2 = $('#np2'), hint = $('#pwHint');
  const chk = () => { if (!np.value && !np2.value) { hint.hidden = true; return; } hint.hidden = false; const m = np.value === np2.value; hint.className = 'hint ' + (m ? 'ok' : 'bad'); hint.textContent = m ? '✓ Passwords match' : 'Passwords do not match yet'; };
  np.addEventListener('input', chk); np2.addEventListener('input', chk);

  /* ---- confirm sheet for destructive forms ---- */
  const cf = $('#cf'); let pending = null;
  const closeCf = () => { cf.hidden = true; document.body.classList.remove('lock'); pending = null; };
  $$('form[data-confirm]').forEach(f => f.addEventListener('submit', e => { e.preventDefault(); pending = f; $('#cfT').textContent = f.dataset.title; $('#cfM').textContent = f.dataset.confirm; cf.hidden = false; document.body.classList.add('lock'); }));
  $('#cfN').onclick = closeCf; cf.onclick = e => { if (e.target === cf) closeCf(); }; $('#cfY').onclick = () => { const f = pending; closeCf(); f && f.submit(); };
  addEventListener('keydown', e => { if (e.key === 'Escape') closeCf(); });

  /* ---- times (shown in your local timezone) ---- */
  const ago = t => { const s = Math.max(0, Date.now() / 1e3 - t); return s < 60 ? 'just now' : s < 3600 ? Math.floor(s / 60) + ' min ago' : s < 86400 ? Math.floor(s / 3600) + ' h ago' : s < 2592000 ? Math.floor(s / 86400) + ' d ago' : new Date(t * 1e3).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }); };
  $$('[data-ago]').forEach(el => el.textContent = ago(+el.dataset.ago));
  $$('[data-date]').forEach(el => el.textContent = new Date(+el.dataset.date * 1e3).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }));
  $$('[data-when]').forEach(el => { const t = +el.dataset.when; el.textContent = new Date(t * 1e3).toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }); });

  /* ---- toast ---- */
  function toast(m) { const d = document.createElement('div'); d.className = 'toast'; d.innerHTML = '<i class="fa-solid fa-circle-check" style="color:var(--ok)"></i><span></span>'; d.lastChild.textContent = m; document.body.append(d); setTimeout(() => { d.classList.add('out'); setTimeout(() => d.remove(), 300); }, 2200); }
  const fl = $('#flash'); if (fl) setTimeout(() => { fl.classList.add('out'); setTimeout(() => fl.remove(), 300); }, 3200);
})();
</script>
<?php if (isset($_GET['embed'])): ?><script>
document.addEventListener('click',function(e){var a=e.target.closest('a[href]');if(!a||a.target==='_blank'||a.hasAttribute('download'))return;var u=new URL(a.href,location.href);if(u.origin!==location.origin)return;
if(u.pathname.split('/').pop()==='index.php'&&!u.search&&!u.hash){e.preventDefault();try{window.parent.postMessage('fd-close-page',location.origin)}catch(x){window.top.location.href=u.pathname}return;}
if(u.pathname===location.pathname&&u.search===location.search&&u.hash)return;
var p=u.searchParams.get('fdpage')||'index';
if(['trash','dashboard','settings'].indexOf(p)>-1){if(!u.searchParams.has('embed')){u.searchParams.set('embed','1');a.href=u.pathname+u.search+u.hash;}return;}
e.preventDefault();window.top.location.href=u.pathname+u.search+u.hash;});
document.addEventListener('submit',function(e){var f=e.target;var u=new URL(f.action||location.href,location.href);if(!u.searchParams.has('embed')){u.searchParams.set('embed','1');if((f.method||'get').toLowerCase()==='post'){f.action=u.pathname+u.search;}else if(!f.querySelector('input[name=embed]')){var i=document.createElement('input');i.type='hidden';i.name='embed';i.value='1';f.appendChild(i);}}});
</script><?php endif; ?></body>
</html>

<?php
} }

namespace FDDb {
use \PDO; use \Throwable; use \Exception;

function cell($v) {
    if ($v === null) return null; $v = (string)$v;
    if (!preg_match('//u', $v)) return '[binary ' . strlen($v) . ' bytes]';
    return strlen($v) > 1500 ? substr($v, 0, 1500) . '…' : $v;
}
function ident($n) { return '`' . str_replace('`', '``', (string)$n) . '`'; }
function readonlySql($sql) { return (bool)preg_match('/^\s*(?:\/\*.*?\*\/\s*|--[^\n]*\n\s*|#[^\n]*\n\s*)*(?:select|show|describe|desc|explain|with)\b/is', $sql); }

final class Conn {
    public $pdo = null; public $my = null;
    function __construct($c, $db = null) {
        if (extension_loaded('pdo_mysql')) {
            $o = [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 6, PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => false];
            if (defined('PDO::MYSQL_ATTR_MULTI_STATEMENTS')) $o[PDO::MYSQL_ATTR_MULTI_STATEMENTS] = false;
            $this->pdo = new PDO('mysql:host=' . $c['host'] . ';port=' . (int)$c['port'] . ';charset=utf8mb4' . ($db !== null && $db !== '' ? ';dbname=' . $db : ''), $c['user'], $c['pass'], $o);
        } elseif (class_exists('mysqli')) {
            mysqli_report(MYSQLI_REPORT_OFF);
            $this->my = @new \mysqli($c['host'], $c['user'], $c['pass'], ($db !== null && $db !== '') ? $db : null, (int)$c['port']);
            if ($this->my->connect_errno) throw new Exception($this->my->connect_error);
            $this->my->set_charset('utf8mb4');
        } else throw new Exception('PHP has neither the pdo_mysql nor the mysqli extension enabled');
    }
    function q($v) { return $this->pdo ? $this->pdo->quote((string)$v) : "'" . $this->my->real_escape_string((string)$v) . "'"; }
    function run($sql, $limit = 0) {
        $cols = []; $rows = []; $more = false; $aff = null;
        if ($this->pdo) {
            $st = $this->pdo->query($sql);
            if ($st->columnCount() > 0) {
                for ($i = 0, $n = $st->columnCount(); $i < $n; $i++) { $m = $st->getColumnMeta($i); $cols[] = $m['name'] ?? ('col' . $i); }
                while (($r = $st->fetch(PDO::FETCH_NUM)) !== false) { if ($limit && count($rows) >= $limit) { $more = true; break; } $rows[] = array_map(fn($v) => cell($v), $r); }
                if (!$more) $st->closeCursor();
            } else { $aff = $st->rowCount(); $st->closeCursor(); }
        } else {
            $res = $this->my->query($sql);
            if ($res === false) throw new Exception($this->my->error);
            if ($res === true) $aff = $this->my->affected_rows;
            else {
                foreach ($res->fetch_fields() as $f) $cols[] = $f->name;
                while (($r = $res->fetch_row()) !== null) { if ($limit && count($rows) >= $limit) { $more = true; break; } $rows[] = array_map(fn($v) => cell($v), $r); }
                $res->free();
            }
        }
        return ['cols' => $cols, 'rows' => $rows, 'aff' => $aff, 'more' => $more];
    }
}

function fdbOne($cn, $sql) {
    if ($cn->pdo) { $st = $cn->pdo->query($sql); $r = $st->fetch(PDO::FETCH_ASSOC); $st->closeCursor(); return $r ?: null; }
    $res = $cn->my->query($sql); if (!$res) throw new Exception($cn->my->error);
    $r = $res->fetch_assoc(); $res->free(); return $r ?: null;
}
function fdbStream($cn, $sql, $cb) {
    if ($cn->pdo) {
        $st = $cn->pdo->query($sql); $cols = [];
        for ($i = 0, $n = $st->columnCount(); $i < $n; $i++) { $m = $st->getColumnMeta($i); $cols[] = $m['name'] ?? ('col' . $i); }
        $cb('cols', $cols);
        while (($r = $st->fetch(PDO::FETCH_NUM)) !== false) $cb('row', $r);
        $st->closeCursor();
    } else {
        $res = $cn->my->query($sql, MYSQLI_USE_RESULT); if (!$res) throw new Exception($cn->my->error);
        $cols = []; foreach ($res->fetch_fields() as $f) $cols[] = $f->name; $cb('cols', $cols);
        while (($r = $res->fetch_row()) !== null) $cb('row', $r);
        $res->free();
    }
}
function fdbFields($cn, $full) { return array_column($cn->run('SHOW COLUMNS FROM ' . $full)['rows'], 0); }
function fdbWhere($cn, $fields, $q, $qcol) {
    if ($q === '' || !$fields) return '';
    $like = $cn->q('%' . addcslashes($q, '\\%_') . '%');
    if ($qcol !== '' && in_array($qcol, $fields, true)) return ' WHERE ' . ident($qcol) . ' LIKE ' . $like;
    return ' WHERE CONCAT_WS(\' \', ' . implode(', ', array_map(fn($f) => ident($f), $fields)) . ') LIKE ' . $like;
}
function fdbPk($cn, $full) {
    $r = $cn->run('SHOW KEYS FROM ' . $full . ' WHERE Key_name = \'PRIMARY\'');
    $ci = array_search('Column_name', $r['cols']); $si = array_search('Seq_in_index', $r['cols']);
    if ($ci === false) return [];
    $rows = $r['rows']; if ($si !== false) usort($rows, fn($a, $b) => (int)$a[$si] <=> (int)$b[$si]);
    return array_map(fn($x) => $x[$ci], $rows);
}
function fdbPkWhere($cn, $pkCols, $pkVals) {
    if (!$pkCols) throw new Exception('This table has no primary key — editing is disabled');
    $p = [];
    foreach ($pkCols as $c) { if (!array_key_exists($c, $pkVals) || $pkVals[$c] === null) throw new Exception('Missing key value for ' . $c); $p[] = ident($c) . ' = ' . $cn->q((string)$pkVals[$c]); }
    return implode(' AND ', $p);
}
function fdbJson($k) { $j = json_decode((string)($_POST[$k] ?? ''), true); return is_array($j) ? $j : []; }
function fdbVal($cn, $d) { if (!is_array($d)) throw new Exception('Bad value'); return !empty($d['n']) ? 'NULL' : $cn->q((string)($d['v'] ?? '')); }

if ($__fdpage === 'dbviewer') {

error_reporting(E_ALL); ini_set('display_errors', '0');
$csrf = fdaCsrf();
$h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
$S = $_SESSION['fd_db'] ?? null;

/* ---------- AJAX actions (POST, CSRF-protected) ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $out = function ($a) { header('Content-Type: application/json; charset=utf-8'); header('Cache-Control: no-store'); echo json_encode($a, JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR); exit; };
    if (!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) $out(['ok' => false, 'error' => 'Page expired — reload and try again.']);
    $act = (string)($_POST['act'] ?? ''); $t0 = microtime(true);
    $dbn = trim((string)($_POST['db'] ?? ''));
    try {
        if ($act === 'connect') {
            $c = ['host' => trim((string)($_POST['host'] ?? 'localhost')), 'port' => (int)($_POST['port'] ?? 3306) ?: 3306, 'user' => (string)($_POST['user'] ?? ''), 'pass' => (string)($_POST['pass'] ?? ''), 'db' => $dbn];
            if ($c['host'] === '' || !preg_match('/^[A-Za-z0-9._:\-\[\]]+$/', $c['host'])) $out(['ok' => false, 'error' => 'Invalid host']);
            if ($c['port'] < 1 || $c['port'] > 65535) $out(['ok' => false, 'error' => 'Invalid port']);
            $cn = new Conn($c, $dbn); $v = $cn->run('SELECT VERSION()')['rows'][0][0] ?? '';
            $_SESSION['fd_db'] = $c; if (function_exists('fdaLog')) fdaLog('db', 'Connected to MySQL ' . $c['host'] . ' as ' . $c['user']);
            $out(['ok' => true, 'version' => $v, 'host' => $c['host'], 'user' => $c['user'], 'db' => $dbn]);
        }
        if ($act === 'disconnect') { unset($_SESSION['fd_db']); $out(['ok' => true]); }
        if (!$S) $out(['ok' => false, 'error' => 'Not connected', 'auth' => true]);
        if ($act === 'dbs') {
            $cn = new Conn($S); $names = array_column($cn->run('SHOW DATABASES')['rows'], 0);
            $ver = $cn->run('SELECT VERSION()')['rows'][0][0] ?? '';
            $sys = ['information_schema', 'performance_schema', 'mysql', 'sys'];
            usort($names, fn($a, $b) => (in_array($a, $sys, true) <=> in_array($b, $sys, true)) ?: strcasecmp($a, $b));
            $out(['ok' => true, 'dbs' => $names, 'sys' => $sys, 'current' => $S['db'] ?? '', 'version' => $ver, 'host' => $S['host'], 'user' => $S['user']]);
        }
        if ($dbn === '') $out(['ok' => false, 'error' => 'Choose a database first']);
        $cn = new Conn($S, $dbn);
        if ($act === 'tables') {
            $r = $cn->run('SELECT TABLE_NAME, TABLE_TYPE, ENGINE, TABLE_ROWS, DATA_LENGTH + INDEX_LENGTH FROM information_schema.TABLES WHERE TABLE_SCHEMA = ' . $cn->q($dbn) . ' ORDER BY TABLE_NAME');
            $out(['ok' => true, 'tables' => array_map(fn($x) => ['n' => $x[0], 'v' => stripos((string)$x[1], 'VIEW') !== false, 'e' => $x[2], 'r' => $x[3] === null ? null : (int)$x[3], 's' => (int)$x[4]], $r['rows'])]);
        }
        $tb = (string)($_POST['table'] ?? '');
        if (in_array($act, ['browse', 'structure', 'meta', 'row_get', 'row_update', 'row_insert', 'row_delete', 'export'], true)) {
            if ($tb === '') $out(['ok' => false, 'error' => 'Choose a table']);
            $full = ident($dbn) . '.' . ident($tb);

            if ($act === 'structure') {
                $cols = $cn->run('SHOW FULL COLUMNS FROM ' . $full); $idx = $cn->run('SHOW INDEX FROM ' . $full);
                try { $cr = $cn->run('SHOW CREATE TABLE ' . $full)['rows'][0][1] ?? ''; } catch (Throwable $e) { $cr = ''; }
                $out(['ok' => true, 'cols' => $cols['cols'], 'rows' => $cols['rows'], 'icols' => $idx['cols'], 'irows' => $idx['rows'], 'create' => $cr]);
            }
            if ($act === 'meta') {
                $r = $cn->run('SHOW FULL COLUMNS FROM ' . $full); $ix = array_flip($r['cols']);
                $g = fn($row, $k) => isset($ix[$k]) ? $row[$ix[$k]] : null;
                $cols = array_map(fn($row) => ['n' => $g($row, 'Field'), 't' => (string)$g($row, 'Type'), 'nul' => $g($row, 'Null') === 'YES', 'k' => (string)$g($row, 'Key'), 'd' => $g($row, 'Default'), 'e' => (string)$g($row, 'Extra')], $r['rows']);
                $out(['ok' => true, 'cols' => $cols, 'pk' => fdbPk($cn, $full)]);
            }
            if ($act === 'browse') {
                $fields = fdbFields($cn, $full); $pk = fdbPk($cn, $full);
                $per = in_array((int)($_POST['per'] ?? 50), [25, 50, 100, 200], true) ? (int)$_POST['per'] : 50; $page = max(1, (int)($_POST['page'] ?? 1));
                $sort = (string)($_POST['sort'] ?? ''); $dir = (($_POST['dir'] ?? '') === 'desc') ? 'DESC' : 'ASC';
                $q = trim((string)($_POST['q'] ?? '')); $where = fdbWhere($cn, $fields, $q, (string)($_POST['qcol'] ?? ''));
                $order = in_array($sort, $fields, true) ? ' ORDER BY ' . ident($sort) . ' ' . $dir : '';
                $total = (int)($cn->run('SELECT COUNT(*) FROM ' . $full . $where)['rows'][0][0] ?? 0);
                $pages = max(1, (int)ceil($total / $per)); $page = min($page, $pages);
                $r = $cn->run('SELECT * FROM ' . $full . $where . $order . ' LIMIT ' . $per . ' OFFSET ' . (($page - 1) * $per));
                $out(['ok' => true, 'cols' => $r['cols'], 'rows' => $r['rows'], 'pk' => $pk, 'total' => $total, 'page' => $page, 'pages' => $pages, 'per' => $per, 'ms' => round((microtime(true) - $t0) * 1000)]);
            }
            if ($act === 'export') {
                $fmt = (($_POST['fmt'] ?? '') === 'json') ? 'json' : 'csv';
                $fields = fdbFields($cn, $full); $sort = (string)($_POST['sort'] ?? ''); $dir = (($_POST['dir'] ?? '') === 'desc') ? 'DESC' : 'ASC';
                $where = fdbWhere($cn, $fields, trim((string)($_POST['q'] ?? '')), (string)($_POST['qcol'] ?? ''));
                $order = in_array($sort, $fields, true) ? ' ORDER BY ' . ident($sort) . ' ' . $dir : '';
                $fname = preg_replace('/[^A-Za-z0-9_.-]+/', '_', $tb) . '_' . date('Ymd_His') . '.' . $fmt;
                if (function_exists('fdaLog')) fdaLog('db', 'Export ' . $dbn . '.' . $tb . ' as ' . strtoupper($fmt));
                session_write_close(); @set_time_limit(0);
                $first = true; $cols = [];
                fdbStream($cn, 'SELECT * FROM ' . $full . $where . $order . ' LIMIT 200000', function ($kind, $d) use (&$first, &$cols, $fmt, $fname) {
                    if ($kind === 'cols') {
                        $cols = $d; while (ob_get_level()) @ob_end_clean();
                        header('Content-Type: ' . ($fmt === 'json' ? 'application/json' : 'text/csv') . '; charset=utf-8');
                        header('Content-Disposition: attachment; filename="' . $fname . '"'); header('X-Content-Type-Options: nosniff'); header('Cache-Control: no-store');
                        $csvSafe = fn($v) => (is_string($v) && $v !== '' && strpos("=+-@\t\r", $v[0]) !== false && !is_numeric($v)) ? "'" . $v : $v;   /* stop Excel running =formulas */
                        if ($fmt === 'csv') { echo "\xEF\xBB\xBF"; $o = fopen('php://output', 'w'); fputcsv($o, array_map($csvSafe, $d)); fclose($o); } else echo "[\n";
                        return;
                    }
                    $row = array_map(fn($v) => ($v !== null && !preg_match('//u', (string)$v)) ? '[binary ' . strlen((string)$v) . ' bytes]' : $v, $d);
                    if ($fmt === 'csv') { $o = fopen('php://output', 'w'); fputcsv($o, array_map(fn($v) => $v === null ? '' : (is_string($v) && $v !== '' && strpos("=+-@\t\r", $v[0]) !== false && !is_numeric($v) ? "'" . $v : $v), $row)); fclose($o); }
                    else { echo ($first ? '' : ",\n") . json_encode(array_combine($cols, $row), JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE); }
                    $first = false;
                });
                if ($fmt === 'json') echo "\n]\n";
                exit;
            }

            /* ----- row operations (need a primary key) ----- */
            $pkc = fdbPk($cn, $full);
            if ($act === 'row_get') {
                $row = fdbOne($cn, 'SELECT * FROM ' . $full . ' WHERE ' . fdbPkWhere($cn, $pkc, fdbJson('pk')) . ' LIMIT 1');
                if (!$row) $out(['ok' => false, 'error' => 'Row not found (it may have been changed or deleted)']);
                $o = [];
                foreach ($row as $k => $v) $o[$k] = $v === null ? ['n' => 1] : (!preg_match('//u', (string)$v) ? ['b' => 1] : ['v' => (string)$v]);
                $out(['ok' => true, 'row' => $o]);
            }
            if ($act === 'row_update') {
                $where = fdbPkWhere($cn, $pkc, fdbJson('pk')); $fields = fdbFields($cn, $full); $set = [];
                foreach (fdbJson('data') as $c => $d) { if (!in_array($c, $fields, true)) throw new Exception('Unknown column ' . $c); $set[] = ident($c) . ' = ' . fdbVal($cn, $d); }
                if (!$set) $out(['ok' => false, 'error' => 'Nothing to change']);
                $r = $cn->run('UPDATE ' . $full . ' SET ' . implode(', ', $set) . ' WHERE ' . $where . ' LIMIT 1');
                if (function_exists('fdaLog')) fdaLog('db', 'UPDATE row in ' . $dbn . '.' . $tb);
                $out(['ok' => true, 'aff' => $r['aff']]);
            }
            if ($act === 'row_insert') {
                $fields = fdbFields($cn, $full); $cl = []; $vl = [];
                foreach (fdbJson('data') as $c => $d) { if (!in_array($c, $fields, true)) throw new Exception('Unknown column ' . $c); $cl[] = ident($c); $vl[] = fdbVal($cn, $d); }
                $r = $cn->run('INSERT INTO ' . $full . ($cl ? ' (' . implode(', ', $cl) . ') VALUES (' . implode(', ', $vl) . ')' : ' () VALUES ()'));
                if (function_exists('fdaLog')) fdaLog('db', 'INSERT row into ' . $dbn . '.' . $tb);
                $out(['ok' => true, 'aff' => $r['aff']]);
            }
            if ($act === 'row_delete') {
                $r = $cn->run('DELETE FROM ' . $full . ' WHERE ' . fdbPkWhere($cn, $pkc, fdbJson('pk')) . ' LIMIT 1');
                if (!$r['aff']) $out(['ok' => false, 'error' => 'Row not found — nothing was deleted']);
                if (function_exists('fdaLog')) fdaLog('db', 'DELETE row from ' . $dbn . '.' . $tb);
                $out(['ok' => true]);
            }
        }
        if ($act === 'query') {
            $sql = trim((string)($_POST['sql'] ?? '')); $sql = rtrim($sql, "; \t\r\n");
            $lim = in_array((int)($_POST['lim'] ?? 500), [100, 500, 1000, 5000], true) ? (int)$_POST['lim'] : 500;
            if ($sql === '') $out(['ok' => false, 'error' => 'Type a query first']);
            if (!readonlySql($sql) && ($_POST['confirm'] ?? '') !== '1') $out(['ok' => false, 'needs_confirm' => true, 'error' => 'This statement changes data — confirm to run it.']);
            if (!readonlySql($sql) && function_exists('fdaLog')) fdaLog('db', 'SQL on ' . $dbn . ': ' . preg_replace('/\s+/', ' ', preg_replace('/\'(?:[^\'\\\\]|\\\\.|\'\')*\'|"(?:[^"\\\\]|\\\\.)*"/s', "'?'", $sql)));
            $r = $cn->run($sql, $lim);
            $out(['ok' => true, 'cols' => $r['cols'], 'rows' => $r['rows'], 'aff' => $r['aff'], 'more' => $r['more'], 'lim' => $lim, 'ms' => round((microtime(true) - $t0) * 1000)]);
        }
        $out(['ok' => false, 'error' => 'Unknown action']);
    } catch (Throwable $e) { $out(['ok' => false, 'error' => preg_replace('/^SQLSTATE\[[^\]]*\]:?\s*(\[[^\]]*\]\s*)?/', '', $e->getMessage())]); }
}

$embed = isset($_GET['embed']);
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#6366f1">
<title>Database — FileDash</title>
<?php fdCss('fa/css/all.min.css'); ?>
<style>
:root{--ac:#6366f1;--ac2:#ec4899;--bg:#0a0e1a;--bg2:#080b15;--card:#111827;--card2:#172033;--tx:#e8eaf6;--mut:#8f9bb8;--bd:rgba(255,255,255,.08);--hov:rgba(129,140,248,.13);--sh:0 12px 34px rgba(0,0,0,.4);--ok:#10b981;--bad:#ef4444;--warn:#f59e0b;color-scheme:dark}
html.light{--bg:#eef1fb;--bg2:#fff;--card:#fff;--card2:#f4f6fd;--tx:#151a33;--mut:#64708f;--bd:rgba(20,26,60,.1);--hov:rgba(99,102,241,.09);--sh:0 12px 34px rgba(30,40,100,.12);color-scheme:light}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html{-webkit-text-size-adjust:100%}
body{font-family:Inter,system-ui,-apple-system,"Noto Sans Bengali",Segoe UI,sans-serif;background:var(--bg);color:var(--tx);font-size:14px;line-height:1.45;min-height:100vh;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;z-index:-1;background:radial-gradient(600px 400px at 8% -5%,color-mix(in srgb,var(--ac) 22%,transparent),transparent),radial-gradient(500px 380px at 100% 100%,color-mix(in srgb,var(--ac2) 16%,transparent),transparent)}
a{color:inherit;text-decoration:none}button,input,select,textarea{font:inherit;color:inherit}button{cursor:pointer;border:0;background:none}[hidden]{display:none!important}
.top{position:sticky;top:0;z-index:40;display:flex;align-items:center;gap:10px;padding:12px max(18px,env(safe-area-inset-right)) 12px max(18px,env(safe-area-inset-left));background:color-mix(in srgb,var(--bg) 78%,transparent);backdrop-filter:blur(16px);border-bottom:1px solid var(--bd)}
.ib{width:40px;height:40px;border-radius:12px;display:inline-grid;place-items:center;background:var(--card);border:1px solid var(--bd);color:var(--mut);transition:.15s;flex:none}.ib:hover{color:var(--tx);background:var(--hov)}.ib.sm{width:34px;height:34px;border-radius:10px}
.ttl{flex:1;min-width:0}.ttl b{display:flex;align-items:center;gap:9px;font-size:16px;line-height:1.2}.ttl b i{color:var(--ac)}.ttl small{display:block;color:var(--mut);font-size:11.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.wrap{max-width:1500px;margin:0 auto;padding:18px max(18px,env(safe-area-inset-left))}
.card{background:var(--card);border:1px solid var(--bd);border-radius:18px;padding:18px;box-shadow:var(--sh)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;height:38px;padding:0 16px;border-radius:11px;background:var(--card2);border:1px solid var(--bd);font-weight:600;font-size:13px;transition:.15s;white-space:nowrap;flex:none}.btn:hover{background:var(--hov)}
.btn.pri{background:linear-gradient(135deg,var(--ac),var(--ac2));border-color:transparent;color:#fff}.btn.pri:hover{filter:brightness(1.08)}.btn.dng{color:var(--bad)}.btn.dng:hover{background:var(--bad);color:#fff;border-color:transparent}.btn.sm{height:34px;padding:0 12px;font-size:12.5px}.btn:disabled{opacity:.45;cursor:default;pointer-events:none}
.inp{width:100%;height:40px;padding:0 12px;border-radius:11px;background:var(--card2);border:1px solid var(--bd);outline:none;min-width:0}.inp:focus{border-color:var(--ac);box-shadow:0 0 0 3px color-mix(in srgb,var(--ac) 22%,transparent)}
label.f{display:flex;flex-direction:column;gap:5px;font-size:12px;color:var(--mut);font-weight:600}
.conn{max-width:560px;margin:5vh auto 0}.conn h2{display:flex;align-items:center;gap:10px;font-size:18px;margin-bottom:4px}.conn h2 i{color:var(--ac)}.conn p.s{color:var(--mut);font-size:12.5px;margin-bottom:16px}
.grid2{display:grid;grid-template-columns:1fr 110px;gap:12px}.stack{display:grid;gap:12px}
.pw{position:relative}.pw .inp{padding-right:44px}.pw button{position:absolute;right:4px;top:4px;width:32px;height:32px;border-radius:9px;color:var(--mut)}
.chk{display:flex;align-items:center;gap:9px;color:var(--mut);font-size:13px;cursor:pointer;user-select:none}.chk input{width:17px;height:17px;accent-color:var(--ac)}
.err{color:#fda4af;background:color-mix(in srgb,var(--bad) 14%,transparent);border:1px solid color-mix(in srgb,var(--bad) 38%,transparent);border-radius:11px;padding:9px 12px;font-size:12.5px;word-break:break-word}
.app{display:grid;grid-template-columns:270px minmax(0,1fr);gap:16px;align-items:start}
.side{position:sticky;top:76px;display:grid;gap:10px;max-height:calc(100vh - 96px);align-content:start}.side .card{padding:12px;display:flex;flex-direction:column;gap:8px;min-height:0}
.side .sh{display:none}
.cinfo{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:11px;background:var(--card2);border:1px solid var(--bd);font-size:12px;color:var(--mut);min-width:0}.cinfo i{color:var(--ok);font-size:9px}.cinfo span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tlist{overflow:auto;max-height:calc(100vh - 330px);display:grid;gap:2px;align-content:start}
.ti{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:10px;cursor:pointer;font-size:13px;min-width:0}.ti:hover{background:var(--hov)}.ti.on{background:color-mix(in srgb,var(--ac) 20%,transparent);font-weight:700}
.ti i{color:var(--ac);width:14px;text-align:center;flex:none}.ti span{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ti small{color:var(--mut);font-size:11px;flex:none}
.sbd{position:fixed;inset:0;z-index:240;background:rgba(0,0,0,.55);backdrop-filter:blur(3px)}
.ctxbar{display:none;gap:8px;margin-bottom:12px}.ctxbar .btn{flex:1;justify-content:space-between;min-width:0}.ctxbar .btn span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tabs{display:flex;gap:6px;margin-bottom:12px;overflow-x:auto;scrollbar-width:none}.tabs::-webkit-scrollbar{display:none}
.tab{flex:none;padding:8px 14px;border-radius:11px;font-weight:600;font-size:13px;color:var(--mut);border:1px solid transparent;white-space:nowrap}.tab:hover{color:var(--tx)}.tab.on{color:var(--tx);background:var(--card);border-color:var(--bd)}
.bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px}.bar .inp{width:auto;flex:1;min-width:140px;max-width:300px;height:36px}.bar select.inp{flex:none;width:auto;min-width:72px;max-width:170px}.grow{flex:1}.mut{color:var(--mut);font-size:12.5px}
.bl{display:contents}.tname{font-size:15px;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.badge{font-size:11px;padding:2px 8px;border-radius:99px;background:color-mix(in srgb,var(--ac) 16%,transparent);color:var(--ac);font-weight:600}.badge.w{background:color-mix(in srgb,var(--warn) 18%,transparent);color:var(--warn)}
.pg input{width:58px;text-align:center;padding:0 4px}
.dd{position:relative}.ddm{position:absolute;right:0;top:calc(100% + 6px);z-index:30;min-width:150px;background:var(--card);border:1px solid var(--bd);border-radius:12px;box-shadow:var(--sh);padding:5px}
.ddm button{display:flex;align-items:center;gap:9px;width:100%;padding:9px 11px;border-radius:8px;text-align:left;font-weight:600;font-size:13px}.ddm button:hover{background:var(--hov)}
.tw{overflow:auto;border:1px solid var(--bd);border-radius:14px;max-height:calc(100vh - 270px);background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:12.5px}th,td{padding:7px 11px;border-bottom:1px solid var(--bd);text-align:left;white-space:nowrap;max-width:300px;overflow:hidden;text-overflow:ellipsis;vertical-align:top}
th{position:sticky;top:0;background:var(--card2);z-index:1;font-weight:700;cursor:pointer;user-select:none}th:hover{color:var(--ac)}th .ar{color:var(--ac);margin-left:5px;font-size:10px}
td{font-family:ui-monospace,Consolas,monospace}tbody tr[data-i]{cursor:pointer}tr:hover td{background:var(--hov)}td i.nl,.v.nl,.rl em i{color:var(--mut);font-style:italic;font-size:11px;font-family:inherit}td.n{color:#7dd3fc}
.plain th{cursor:default}.plain th:hover{color:inherit}.plain tbody tr{cursor:default}
.no{text-align:center;color:var(--mut);padding:40px 10px}
.rcs{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px}
.rc{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:12px;cursor:pointer;min-width:0;transition:.15s}.rc:hover,.rc:active{border-color:var(--ac);background:var(--hov)}
.rc .rt{display:flex;align-items:baseline;gap:8px;margin-bottom:6px;min-width:0}.rc .rt b{font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.rk{font-size:11px;color:var(--ac);font-weight:700;flex:none}
.rl{display:flex;justify-content:space-between;gap:12px;font-size:12.5px;padding:3px 0;border-top:1px solid var(--bd);min-width:0}.rl span{color:var(--mut);flex:none;max-width:42%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.rl em{font-style:normal;font-family:ui-monospace,Consolas,monospace;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.rm{font-size:11.5px;color:var(--mut);padding-top:5px;border-top:1px solid var(--bd)}
textarea.sql{width:100%;min-height:150px;padding:12px;border-radius:13px;background:var(--card2);border:1px solid var(--bd);outline:none;font:13px/1.55 ui-monospace,Consolas,monospace;resize:vertical;tab-size:4}textarea.sql:focus{border-color:var(--ac)}
pre.cr{background:var(--card2);border:1px solid var(--bd);border-radius:13px;padding:13px;overflow:auto;font:12.5px/1.55 ui-monospace,Consolas,monospace;margin-top:12px;white-space:pre}
h4.sec{margin:16px 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--ac)}h4.sec:first-child{margin-top:0}
.qch{display:flex;gap:6px;overflow-x:auto;scrollbar-width:none;margin-bottom:10px}.qch::-webkit-scrollbar{display:none}
.qch button,.hist button{flex:none;padding:5px 12px;border-radius:99px;background:var(--card2);border:1px solid var(--bd);font-size:12px;font-weight:600;color:var(--mut);white-space:nowrap}.qch button:hover,.hist button:hover{color:var(--tx);border-color:var(--ac)}
.hist{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}.hist button{max-width:260px;overflow:hidden;text-overflow:ellipsis;font:11.5px ui-monospace,Consolas,monospace}
.ok{color:var(--ok);font-weight:600}
.ovs{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px}.ov{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:12px;text-align:center}.ov b{display:block;font-size:20px}.ov small{color:var(--mut)}
.ol{display:grid;gap:8px}.oi{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:11px 13px;cursor:pointer;min-width:0}.oi:hover{border-color:var(--ac)}.oi .r1{display:flex;align-items:center;gap:10px;min-width:0}.oi .r1 b{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.oi .r1 small{color:var(--mut);white-space:nowrap}.oi .r2{display:flex;justify-content:space-between;color:var(--mut);font-size:12px;margin:3px 0 6px}
.oi .pb{height:5px;border-radius:9px;background:var(--bd);overflow:hidden}.oi .pb i{display:block;height:100%;background:linear-gradient(90deg,var(--ac),var(--ac2))}
.sum{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.toast{position:fixed;left:50%;bottom:calc(20px + env(safe-area-inset-bottom));transform:translateX(-50%);z-index:600;padding:11px 18px;border-radius:13px;background:var(--card);border:1px solid var(--bd);border-left:4px solid var(--ok);box-shadow:var(--sh);max-width:92vw}.toast.e{border-left-color:var(--bad)}
.sheet{position:fixed;inset:0;z-index:300;display:grid;place-items:center;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);padding:16px}
.sc{width:min(580px,100%);max-height:90vh;max-height:90dvh;display:flex;flex-direction:column;background:var(--card);border:1px solid var(--bd);border-radius:20px;box-shadow:var(--sh);overflow:hidden;animation:up .2s}
@keyframes up{from{opacity:0;transform:translateY(16px)}}
.sc .sh2{display:flex;align-items:center;gap:8px;padding:12px 14px;border-bottom:1px solid var(--bd)}.sc .sh2 b{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:14.5px}
.sc .sb{overflow:auto;padding:10px 14px;flex:1;overscroll-behavior:contain}.sc .sf{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;padding:12px 14px;border-top:1px solid var(--bd)}
.sc .sf .btn.sp{margin-right:auto}
.kv{display:grid;grid-template-columns:minmax(80px,32%) 1fr 32px;gap:8px;align-items:start;padding:9px 0;border-bottom:1px solid var(--bd)}.kv:last-child{border:0}
.kv .k{color:var(--ac);font-size:12px;font-weight:700;word-break:break-word}.kv .k .pk{font-size:10px;color:var(--warn)}.kv .v{font:12.5px ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-word;max-height:220px;overflow:auto}.kv .cp{width:30px;height:30px;border-radius:9px;color:var(--mut)}.kv .cp:hover{background:var(--hov);color:var(--tx)}
.ff{padding:9px 0;border-bottom:1px solid var(--bd)}.ff:last-child{border:0}.fl{display:flex;justify-content:space-between;gap:8px;align-items:baseline;font-size:12.5px;font-weight:700;color:var(--ac);margin-bottom:5px}.fl small{color:var(--mut);font-weight:500;font-size:11px;text-align:right}
.ff textarea.inp{height:auto;padding:9px 12px;font-family:ui-monospace,Consolas,monospace;font-size:13px;resize:vertical}
.fo{display:flex;gap:14px;margin-top:6px;flex-wrap:wrap}.mini{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--mut);cursor:pointer}.mini input{accent-color:var(--ac);width:15px;height:15px}
.cfc pre{margin:10px 0 0;max-height:140px;overflow:auto;background:var(--card2);border-radius:10px;padding:10px;font:12px ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-word}
.cfc .sb p{color:var(--mut)}
@media(max-width:860px){
 .wrap{padding:12px}.top{padding:10px 12px}.conn{margin-top:2vh}
 .app{grid-template-columns:1fr}.ctxbar{display:flex}
 .side{position:fixed;left:0;right:0;bottom:0;top:auto;z-index:250;max-height:82dvh;max-height:82vh;border-radius:22px 22px 0 0;background:var(--card);border:1px solid var(--bd);padding:10px 12px calc(12px + env(safe-area-inset-bottom));transform:translateY(110%);transition:transform .25s cubic-bezier(.4,0,.2,1);box-shadow:var(--sh);overflow:auto}
 .side.open{transform:none}.side .card{border:0;box-shadow:none;padding:0;background:none}.side .sh{display:flex;align-items:center;justify-content:space-between;padding:2px 2px 6px}.side .sh b{font-size:15px}
 .tlist{max-height:46dvh;max-height:46vh}
 .tw{max-height:none}
 .btn{height:42px}.btn.sm{height:38px}.inp{height:44px;font-size:16px}.bar .inp{height:40px}textarea.sql{font-size:13px;min-height:120px}
 .bl{display:flex;gap:8px;width:100%;align-items:center}.bar{gap:8px}.bar .inp{max-width:none;min-width:0}.bar select.inp{max-width:46%}
 .bl1 .tname{flex:1;max-width:none}.bl3 .btn{flex:1}.bl3 .dd{flex:1}.bl3 .dd .btn{width:100%}.bl3 .btn .lb{display:inline}
 .bl4{flex-wrap:wrap}.bl4 .grow{display:none}.bl4 #bInfo{width:100%;order:9}
 .ovs{gap:8px}.ov{padding:9px}.ov b{font-size:17px}
 .sc{width:100%;max-width:none;border-radius:22px 22px 0 0;max-height:92dvh;max-height:92vh}.sheet{align-items:end;padding:0}
 .sc .sf{padding-bottom:calc(12px + env(safe-area-inset-bottom))}.sc .sf .btn{flex:1}.sc .sf .btn.sp{margin-right:0}
 .kv{grid-template-columns:1fr 32px}.kv .k{grid-column:1/2}.kv .cp{grid-row:1;grid-column:2}.kv .v{grid-column:1/3}
 .rcs{grid-template-columns:1fr}
}
@media(min-width:861px){.bl3 .lb{display:inline}}
@media(max-width:860px){
 #vConn.conn{margin:1vh auto 0;padding:14px;border-radius:16px}
 #vConn h2{font-size:15px;gap:8px;margin-bottom:2px}
 #vConn p.s{font-size:11.5px;margin-bottom:12px}
 #vConn .stack{gap:9px}
 #vConn .grid2{gap:9px;grid-template-columns:1fr 84px}
 #vConn label.f{font-size:11px;gap:4px}
 #vConn .inp{height:36px;font-size:14px;padding:0 10px;border-radius:10px}
 #vConn .pw .inp{padding-right:38px}
 #vConn .pw button{width:28px;height:28px;top:3px;right:3px}
 #vConn .chk{font-size:12px;gap:8px}#vConn .chk input{width:15px;height:15px}
 #vConn .btn{height:38px;font-size:13px}
 #vConn .err{font-size:12px;padding:8px 10px}
 .bl4{flex-wrap:wrap;gap:6px;justify-content:space-between;align-items:center}
 .bl4 #bper{flex:none;width:auto;max-width:none;min-width:0;height:34px;font-size:13px;padding:0 6px}
 .bl4 .pg{margin-left:auto;gap:4px!important;flex:none}
 .bl4 .pg .btn.sm{width:32px;height:34px;padding:0}
 .bl4 .pg input{width:44px;height:34px;font-size:13px;padding:0 2px}
 /* mobile: smaller search placeholder + column picker; colourful, slightly bigger headings & values */
 #bq::placeholder{font-size:14px}#bqc{font-size:13.5px}#tFilter::placeholder{font-size:13px}
 table{font-size:13.5px}
 th{font-size:13.5px;letter-spacing:.01em;background:color-mix(in srgb,var(--ac) 9%,var(--card2))}
 th:nth-child(6n+1){color:#818cf8}th:nth-child(6n+2){color:#38bdf8}th:nth-child(6n+3){color:#34d399}th:nth-child(6n+4){color:#fbbf24}th:nth-child(6n+5){color:#f472b6}th:nth-child(6n+6){color:#a78bfa}
 html.light th:nth-child(6n+1){color:#4f46e5}html.light th:nth-child(6n+2){color:#0284c7}html.light th:nth-child(6n+3){color:#059669}html.light th:nth-child(6n+4){color:#b45309}html.light th:nth-child(6n+5){color:#db2777}html.light th:nth-child(6n+6){color:#7c3aed}
 .plain th:nth-child(n){cursor:default}
 .rc .rt b{font-size:15.5px}.rk{font-size:12px}
 .rl{font-size:13.5px}.rl em{font-size:13.5px}.rl span{font-size:13px;font-weight:700}
 .rl:nth-child(5n+2) span{color:#38bdf8}.rl:nth-child(5n+3) span{color:#34d399}.rl:nth-child(5n+4) span{color:#fbbf24}.rl:nth-child(5n+5) span{color:#f472b6}.rl:nth-child(5n+6) span{color:#a78bfa}
 html.light .rl:nth-child(5n+2) span{color:#0284c7}html.light .rl:nth-child(5n+3) span{color:#059669}html.light .rl:nth-child(5n+4) span{color:#b45309}html.light .rl:nth-child(5n+5) span{color:#db2777}html.light .rl:nth-child(5n+6) span{color:#7c3aed}
}
<?php if ($embed): ?>.top{display:none!important}.wrap{max-width:none;padding:14px}.side{top:10px;max-height:calc(100vh - 28px)}.tlist{max-height:calc(100vh - 300px)}.tw{max-height:calc(100vh - 250px)}@media(max-width:860px){.wrap{padding:10px}.tw{max-height:none}.side{top:auto}}<?php endif; ?>

/* DESKTOP ONLY: database page fills the screen down to a small bottom gap */
@media(min-width:861px){
 .app{height:calc(100vh - 104px);align-items:stretch}
 .side{position:static;top:auto;height:100%;max-height:none;grid-template-rows:minmax(0,1fr) auto}
 .side .card{height:100%;min-height:0}
 .tlist{flex:1 1 0;min-height:0;max-height:none}
 .rcol{display:flex;flex-direction:column;height:100%;min-height:0}
 .rcol>.tabs{flex:none}
 #pBrowse{flex:1 1 0;min-height:0;display:flex;flex-direction:column}
 #pBrowse>.bar{flex:none}
 #bGrid{flex:1 1 0;min-height:0;display:flex;flex-direction:column}
 #bGrid .dwrap{flex:1 1 0;min-height:0;display:flex;flex-direction:column;overflow:auto}
 #bGrid .dwrap>.tw{flex:1 1 0;min-height:0;max-height:none;height:100%}
 #pStruct,#pSql,#pOver{flex:1 1 0;min-height:0;overflow:auto}
 <?php if ($embed): ?>.app{height:calc(100vh - 28px)}<?php endif; ?>
}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<header class="top">
  <a class="ib" href="index.php" aria-label="Back to files"><i class="fa-solid fa-arrow-left" style="color:#818cf8"></i></a>
  <div class="ttl"><b><i class="fa-solid fa-database" style="color:#a78bfa"></i>Database</b><small id="sub">MySQL viewer</small></div>
  <button class="ib" id="themeBtn" type="button" title="Theme"><i class="fa-solid fa-circle-half-stroke" style="color:#a78bfa"></i></button>
</header>

<main class="wrap">
  <!-- connect -->
  <section id="vConn" class="card conn" hidden>
    <h2><i class="fa-solid fa-plug" style="color:#10b981"></i>Connect to MySQL</h2>
    <p class="s">Credentials are kept only in your login session on the server and are never saved to a file.</p>
    <form id="fConn" class="stack" autocomplete="off">
      <div class="grid2"><label class="f">Host<input class="inp" name="host" value="127.0.0.1" required autocapitalize="off" spellcheck="false"></label><label class="f">Port<input class="inp" name="port" value="3306" inputmode="numeric"></label></div>
      <label class="f">Username<input class="inp" name="user" required autocomplete="off" autocapitalize="off" spellcheck="false"></label>
      <label class="f">Password<span class="pw"><input class="inp" name="pass" id="cPass" type="password" autocomplete="new-password"><button type="button" id="cEye" aria-label="Show password"><i class="fa-solid fa-eye" style="color:#8b5cf6"></i></button></span></label>
      <label class="f">Database <span style="font-weight:400">(optional)</span><input class="inp" name="db" autocomplete="off" autocapitalize="off" spellcheck="false"></label>
      <label class="chk"><input type="checkbox" id="cRem" checked>Remember host, port &amp; username on this device (never the password)</label>
      <div id="cErr" class="err" hidden></div>
      <button class="btn pri" id="cBtn" type="submit"><i class="fa-solid fa-link"></i>Connect</button>
    </form>
  </section>

  <!-- viewer -->
  <section id="vApp" hidden>
    <div class="ctxbar"><button class="btn" id="bTables" type="button"><i class="fa-solid fa-table-list" style="color:var(--ac)"></i><span id="tBtnTxt">Tables</span><i class="fa-solid fa-chevron-up" style="color:var(--mut);font-size:11px"></i></button></div>
    <div class="app">
      <aside class="side" id="side">
        <div class="sh"><b><i class="fa-solid fa-database" style="color:var(--ac)"></i>&nbsp; Tables</b><button class="ib sm" id="sClose" type="button" aria-label="Close"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></div>
        <div class="card">
          <div class="cinfo"><i class="fa-solid fa-circle" style="color:#10b981"></i><span id="cInfo">Connected</span></div>
          <label class="f">Database<select class="inp" id="dbSel"></select></label>
          <input class="inp" id="tFilter" type="search" placeholder="Filter tables…" style="height:38px">
          <div class="tlist" id="tList"></div>
        </div>
        <button class="btn" id="bOut" type="button"><i class="fa-solid fa-right-from-bracket" style="color:#ef4444"></i>Disconnect</button>
      </aside>
      <div class="rcol" style="min-width:0">
        <div class="tabs" id="tabs">
          <button class="tab on" data-t="browse"><i class="fa-solid fa-table" style="color:#38bdf8"></i> Browse</button>
          <button class="tab" data-t="structure"><i class="fa-solid fa-sitemap" style="color:#34d399"></i> Structure</button>
          <button class="tab" data-t="sql"><i class="fa-solid fa-terminal" style="color:#34d399"></i> SQL</button>
          <button class="tab" data-t="overview"><i class="fa-solid fa-chart-bar" style="color:#ec4899"></i> Overview</button>
        </div>
        <div id="pBrowse"></div><div id="pStruct" hidden></div>
        <div id="pSql" hidden>
          <div class="qch" id="qch">
            <button type="button" data-q="sel">SELECT *</button><button type="button" data-q="cnt">COUNT(*)</button><button type="button" data-q="desc">DESCRIBE</button><button type="button" data-q="idx">SHOW INDEX</button><button type="button" data-q="cre">SHOW CREATE</button><button type="button" data-q="stat">TABLE STATUS</button><button type="button" data-q="proc">PROCESSLIST</button>
          </div>
          <textarea class="sql" id="sql" spellcheck="false" autocapitalize="off" autocorrect="off" placeholder="SELECT * FROM table_name LIMIT 50;"></textarea>
          <div class="bar" style="margin:10px 0 0"><button class="btn pri" id="run" type="button"><i class="fa-solid fa-play"></i>Run<span class="mut" style="color:inherit;opacity:.8">Ctrl+Enter</span></button><button class="btn" id="sqlClear" type="button">Clear</button><select class="inp" id="sqlLim" title="Max rows shown"></select><span class="grow"></span><span class="mut" id="sqlInfo"></span></div>
          <div class="hist" id="hist"></div>
          <div class="bar" id="sqlTools" style="margin:14px 0 0" hidden><button class="btn sm" id="sView" type="button"><i class="fa-solid fa-table-cells-large" style="color:#38bdf8"></i></button><button class="btn sm" data-sx="csv" type="button"><i class="fa-solid fa-file-csv" style="color:#10b981"></i>CSV</button><button class="btn sm" data-sx="json" type="button"><i class="fa-solid fa-file-code" style="color:#f59e0b"></i>JSON</button><button class="btn sm" data-sx="copy" type="button"><i class="fa-regular fa-copy" style="color:#818cf8"></i>Copy</button></div>
          <div id="sqlRes" style="margin-top:12px"></div>
        </div>
        <div id="pOver" hidden></div>
      </div>
    </div>
    <div class="sbd" id="sbd" hidden></div>
  </section>
</main>

<!-- row details -->
<div class="sheet" id="rs" hidden><div class="sc">
  <div class="sh2"><button class="ib sm" id="rPrev" type="button" aria-label="Previous"><i class="fa-solid fa-chevron-left" style="color:#818cf8"></i></button><button class="ib sm" id="rNext" type="button" aria-label="Next"><i class="fa-solid fa-chevron-right" style="color:#818cf8"></i></button><b id="rTitle"></b><button class="ib sm" data-x type="button" aria-label="Close"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></div>
  <div class="sb" id="rBody"></div><div class="sf" id="rFoot"></div>
</div></div>
<!-- insert / edit -->
<div class="sheet" id="fs" hidden><div class="sc">
  <div class="sh2"><b id="fTitle"></b><button class="ib sm" data-x type="button" aria-label="Close"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></div>
  <div class="sb" id="fBody"></div>
  <div class="sf"><button class="btn" data-x type="button">Cancel</button><button class="btn pri" id="fSave" type="button"><i class="fa-solid fa-floppy-disk"></i>Save</button></div>
</div></div>
<!-- confirm -->
<div class="sheet cfc" id="cf" hidden><div class="sc" style="width:min(430px,100%)">
  <div class="sh2"><i class="fa-solid fa-triangle-exclamation" style="color:var(--warn)"></i><b id="cfT"></b></div>
  <div class="sb"><p id="cfM"></p><pre id="cfP" hidden></pre></div>
  <div class="sf"><button class="btn" data-x type="button">Cancel</button><button class="btn pri" id="cfY" type="button">Confirm</button></div>
</div></div>

<script>
(() => {
  const CSRF = <?= json_encode($csrf) ?>;
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const ls = { get: (k, d) => { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } }, set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} } };
  const root = document.documentElement, mob = () => matchMedia('(max-width:860px)').matches;
  /* theme + accent shared with the file manager */
  const applyTheme = () => { const t = ls.get('fd_theme', 'auto'); root.classList.toggle('light', !(t === 'dark' || (t === 'auto' && matchMedia('(prefers-color-scheme:dark)').matches))); };
  function applyAccent() { const a = ls.get('fd_accent', null); if (a && /^#[0-9a-f]{6}$/i.test(a)) root.style.setProperty('--ac', a); else root.style.removeProperty('--ac'); }
  applyTheme(); applyAccent(); addEventListener('storage', e => { if (e.key === 'fd_theme') applyTheme(); if (e.key === 'fd_accent') applyAccent(); });
  $('#themeBtn').onclick = () => { const o = ['auto', 'light', 'dark']; ls.set('fd_theme', o[(o.indexOf(ls.get('fd_theme', 'auto')) + 1) % 3]); applyTheme(); };
  const toast = (m, t) => { const d = document.createElement('div'); d.className = 'toast' + (t === 'err' ? ' e' : ''); d.textContent = m; document.body.append(d); setTimeout(() => d.remove(), t === 'err' ? 4200 : 1900); };
  async function api(act, data = {}) {
    const fd = new FormData(); fd.append('csrf', CSRF); fd.append('act', act); Object.entries(data).forEach(([k, v]) => fd.append(k, v));
    try { const r = await fetch(location.pathname + '?fdpage=dbviewer', { method: 'POST', body: fd, credentials: 'same-origin' }); return await r.json(); } catch (e) { return { ok: false, error: 'Network error' }; }
  }
  const st = { db: '', table: '', tab: 'browse', page: 1, pages: 1, per: ls.get('fd_db_per', 50), sort: '', dir: 'asc', q: '', qcol: '', tables: [], pk: [], meta: null, view: ls.get('fd_db_view', innerWidth <= 700 ? 'cards' : 'table'), lim: ls.get('fd_db_lim', 500) };
  const D = { browse: null, sql: null }; let seq = 0;
  const fmtB = b => { const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; b = +b || 0; while (b >= 1024 && i < 4) { b /= 1024; i++; } return (i ? b.toFixed(1) : b) + ' ' + u[i]; };
  const num = n => Number(n).toLocaleString();
  const spin = '<div class="no"><i class="fa-solid fa-spinner fa-spin" style="color:#6366f1"></i></div>';
  const copyText = t => (navigator.clipboard && window.isSecureContext ? navigator.clipboard.writeText(t) : Promise.reject()).catch(() => { const a = document.createElement('textarea'); a.value = t; document.body.append(a); a.select(); try { document.execCommand('copy'); } catch (e) {} a.remove(); });
  function saveBlob(blob, name) { const u = URL.createObjectURL(blob), a = document.createElement('a'); a.href = u; a.download = name; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(u), 3000); }

  /* ---------- sheets ---------- */
  let cfRes = null;
  const lockUI = () => { const o = $$('.sheet').some(s => !s.hidden) || (mob() && $('#side').classList.contains('open')); root.style.overflow = o ? 'hidden' : ''; };
  const openSheet = el => { el.hidden = false; lockUI(); };
  function closeSheet(el) { el.hidden = true; if (el.id === 'cf' && cfRes) { const r = cfRes; cfRes = null; r(false); } lockUI(); }
  document.addEventListener('click', e => { const x = e.target.closest('[data-x]'); if (x) return closeSheet(x.closest('.sheet')); if (e.target.classList.contains('sheet')) closeSheet(e.target); });
  function confirmBox(o) { return new Promise(res => { $('#cfT').textContent = o.title; $('#cfM').innerHTML = o.msg || ''; const p = $('#cfP'); p.hidden = !o.pre; p.textContent = o.pre || ''; const y = $('#cfY'); y.textContent = o.ok || 'Confirm'; y.className = 'btn ' + (o.danger ? 'dng' : 'pri'); cfRes = res; openSheet($('#cf')); }); }
  $('#cfY').onclick = () => { const r = cfRes; cfRes = null; closeSheet($('#cf')); r && r(true); };
  const sideOpen = o => { $('#side').classList.toggle('open', o); $('#sbd').hidden = !o; lockUI(); };
  $('#bTables').onclick = () => sideOpen(true); $('#sClose').onclick = $('#sbd').onclick = () => sideOpen(false);
  addEventListener('resize', () => { if (!mob()) sideOpen(false); });
  addEventListener('keydown', e => { if (e.key === 'Escape') { const s = $$('.sheet').filter(x => !x.hidden).pop(); if (s) closeSheet(s); else sideOpen(false); } });

  /* ---------- data rendering (table or cards) ---------- */
  const shortV = (v, n) => v === null ? '<i class="nl">NULL</i>' : esc(v.length > n ? v.slice(0, n) + '…' : v);
  function tableH(ds, o) {
    const head = ds.cols.map(c => '<th' + (o.sortable ? ' data-c="' + esc(c) + '"' : '') + '>' + esc(c) + (o.sortable && st.sort === c ? '<span class="ar">' + (st.dir === 'asc' ? '▲' : '▼') + '</span>' : '') + '</th>').join('');
    const body = ds.rows.map((r, i) => '<tr data-i="' + i + '">' + r.map(v => v === null ? '<td><i class="nl">NULL</i></td>' : '<td' + (/^-?\d+(\.\d+)?$/.test(v) ? ' class="n"' : '') + ' title="' + esc(v.slice(0, 200)) + '">' + shortV(v, 140) + '</td>').join('') + '</tr>').join('');
    return '<div class="tw"><table><thead><tr>' + head + '</tr></thead><tbody>' + (body || '<tr><td colspan="' + ds.cols.length + '" class="no">No rows</td></tr>') + '</tbody></table></div>';
  }
  function cardsH(ds) {
    if (!ds.rows.length) return '<div class="tw"><div class="no">No rows</div></div>';
    let ti = ds.pk && ds.pk.length ? ds.cols.indexOf(ds.pk[0]) : 0; if (ti < 0) ti = 0;
    const others = ds.cols.map((c, j) => j).filter(j => j !== ti), shown = others.slice(0, 5);
    return '<div class="rcs">' + ds.rows.map((r, i) => '<div class="rc" data-i="' + i + '"><div class="rt"><span class="rk">' + esc(ds.cols[ti]) + '</span><b>' + shortV(r[ti], 60) + '</b></div>'
      + shown.map(j => '<div class="rl"><span>' + esc(ds.cols[j]) + '</span><em>' + shortV(r[j], 70) + '</em></div>').join('')
      + (others.length > 5 ? '<div class="rm">+' + (others.length - 5) + ' more fields</div>' : '') + '</div>').join('') + '</div>';
  }
  function drawGrid(src) { const ds = D[src]; if (!ds) return; const box = src === 'browse' ? $('#bGrid') : $('#sqlRes'); if (!box) return; box.innerHTML = '<div class="dwrap" data-src="' + src + '">' + (st.view === 'cards' ? cardsH(ds) : tableH(ds, { sortable: src === 'browse' })) + '</div>'; syncViewBtns(); }
  function syncViewBtns() { $$('#bView,#sView').forEach(b => { b.innerHTML = '<i class="fa-solid ' + (st.view === 'cards' ? 'fa-table' : 'fa-table-cells-large') + '" style="color:#38bdf8"></i><span class="lb">' + (st.view === 'cards' ? 'Table' : 'Cards') + '</span>'; b.title = 'Switch to ' + (st.view === 'cards' ? 'table' : 'card') + ' view'; }); }
  function toggleView() { st.view = st.view === 'cards' ? 'table' : 'cards'; ls.set('fd_db_view', st.view); drawGrid('browse'); drawGrid('sql'); }
  const plainGrid = (cols, rows) => cols.length ? '<div class="tw"><table class="plain"><thead><tr>' + cols.map(c => '<th>' + esc(c) + '</th>').join('') + '</tr></thead><tbody>' + (rows.length ? rows.map(r => '<tr>' + r.map(v => v === null ? '<td><i class="nl">NULL</i></td>' : '<td title="' + esc(v.slice(0, 200)) + '">' + shortV(v, 140) + '</td>').join('') + '</tr>').join('') : '<tr><td colspan="' + cols.length + '" class="no">No rows</td></tr>') + '</tbody></table></div>' : '';

  /* ---------- connect / boot ---------- */
  function show(c) { $('#vConn').hidden = c; $('#vApp').hidden = !c; if (!c) { sideOpen(false); $('#sub').textContent = 'MySQL viewer'; } }
  { const sv = ls.get('fd_db_conn', null), f = $('#fConn'); if (sv) { f.host.value = sv.host || 'localhost'; f.port.value = sv.port || 3306; f.user.value = sv.user || ''; f.db.value = sv.db || ''; if (sv.user) setTimeout(() => f.pass.focus(), 50); } }
  $('#cEye').onclick = () => { const i = $('#cPass'), s = i.type === 'password'; i.type = s ? 'text' : 'password'; $('#cEye').firstElementChild.className = 'fa-solid ' + (s ? 'fa-eye-slash' : 'fa-eye'); };
  async function boot() {
    const r = await api('dbs');
    if (!r.ok) { show(false); return; }
    show(true);
    $('#dbSel').innerHTML = r.dbs.map(d => '<option value="' + esc(d) + '">' + esc(d) + (r.sys.includes(d) ? '  (system)' : '') + '</option>').join('');
    const want = ls.get('fd_db_last', '') || r.current; st.db = r.dbs.includes(want) ? want : (r.dbs.find(d => !r.sys.includes(d)) || r.dbs[0] || '');
    $('#dbSel').value = st.db; $('#sub').textContent = 'Connected · ' + r.dbs.length + ' databases';
    $('#cInfo').textContent = r.user + '@' + r.host + ' · MySQL ' + r.version; loadTables();
  }
  async function loadTables() {
    $('#tList').innerHTML = spin; st.table = ''; st.meta = null; D.browse = null; $('#pBrowse').innerHTML = ''; $('#pStruct').innerHTML = ''; updBtn();
    if (!st.db) { $('#tList').innerHTML = '<div class="no">No database</div>'; return; }
    ls.set('fd_db_last', st.db);
    const r = await api('tables', { db: st.db });
    if (!r.ok) { $('#tList').innerHTML = '<div class="err">' + esc(r.error) + '</div>'; return; }
    st.tables = r.tables; drawTables();
    if (st.tab === 'overview') return tab('overview');
    if (r.tables.length) pick(r.tables[0].n, true); else { $('#pBrowse').innerHTML = '<div class="no">This database has no tables</div>'; tab(st.tab === 'sql' ? 'sql' : 'browse'); }
  }
  async function loadTablesKeep() { const r = await api('tables', { db: st.db }); if (r.ok) { st.tables = r.tables; drawTables(); } }
  function updBtn() { const f = $('#tFilter').value.trim(); $('#tBtnTxt').textContent = (st.db || 'Database') + (st.table ? ' › ' + st.table : '') + (f ? '  (filter: ' + f + ')' : ''); }
  function drawTables() {
    const f = $('#tFilter').value.toLowerCase().trim();
    $('#tList').innerHTML = st.tables.filter(t => t.n.toLowerCase().includes(f)).map(t => '<div class="ti' + (t.n === st.table ? ' on' : '') + '" data-n="' + esc(t.n) + '" title="' + esc(t.e || (t.v ? 'View' : '')) + ' · ' + fmtB(t.s) + '"><i class="fa-solid ' + (t.v ? 'fa-eye' : 'fa-table') + '"></i><span>' + esc(t.n) + '</span><small>' + (t.r === null ? '' : num(t.r)) + '</small></div>').join('') || '<div class="no">No tables</div>'; updBtn();
  }
  function pick(n, silent) {
    st.table = n; st.page = 1; st.sort = ''; st.dir = 'asc'; st.q = ''; st.qcol = ''; st.meta = null; st.pk = []; drawTables(); updBtn(); if (mob()) sideOpen(false);
    if (!$('#sql').value.trim()) $('#sql').value = 'SELECT * FROM `' + n.replace(/`/g, '``') + '` LIMIT 100;';
    $('#pBrowse').innerHTML = ''; tab(st.tab === 'sql' ? 'sql' : (st.tab === 'overview' ? 'browse' : st.tab));
  }
  const PANES = { browse: 'pBrowse', structure: 'pStruct', sql: 'pSql', overview: 'pOver' };
  function tab(t) {
    st.tab = t; $$('#tabs .tab').forEach(b => b.classList.toggle('on', b.dataset.t === t));
    Object.entries(PANES).forEach(([k, id]) => $('#' + id).hidden = k !== t);
    if (t === 'browse') browse(); else if (t === 'structure') structure(); else if (t === 'sql') renderHist(); else overview();
  }

  /* ---------- browse ---------- */
  const BAR = '<div class="bar" id="bbar"><div class="bl bl1"><b class="tname" id="bName"></b><span class="badge" id="bBadge" hidden></span></div>'
    + '<div class="bl bl2"><input class="inp" id="bq" type="search" placeholder="Search rows…"><select class="inp" id="bqc" aria-label="Search column"></select></div>'
    + '<div class="bl bl3"><button class="btn sm" id="bAdd" type="button"><i class="fa-solid fa-plus" style="color:#10b981"></i><span class="lb">Insert</span></button><button class="btn sm" id="bView" type="button"></button>'
    + '<div class="dd"><button class="btn sm" id="bExp" type="button"><i class="fa-solid fa-file-export" style="color:#f59e0b"></i><span class="lb">Export</span></button><div class="ddm" id="expM" hidden><button type="button" data-exp="csv"><i class="fa-solid fa-file-csv" style="color:#10b981"></i>CSV</button><button type="button" data-exp="json"><i class="fa-solid fa-file-code" style="color:#f59e0b"></i>JSON</button></div></div>'
    + '<button class="btn sm" id="bRef" type="button" title="Reload"><i class="fa-solid fa-rotate" style="color:#22d3ee"></i></button></div>'
    + '<div class="bl bl4"><select class="inp" id="bper" aria-label="Rows per page"></select><span class="grow"></span><span class="pg" style="display:flex;gap:6px;align-items:center"><button class="btn sm" id="bFirst" type="button"><i class="fa-solid fa-angles-left" style="color:#818cf8"></i></button><button class="btn sm" id="bPrev" type="button"><i class="fa-solid fa-chevron-left" style="color:#818cf8"></i></button><input class="inp" id="bPg" type="number" min="1" inputmode="numeric"><button class="btn sm" id="bNext" type="button"><i class="fa-solid fa-chevron-right" style="color:#818cf8"></i></button><button class="btn sm" id="bLast" type="button"><i class="fa-solid fa-angles-right" style="color:#818cf8"></i></button></span><span class="mut" id="bInfo"></span></div></div><div id="bGrid"></div>';
  async function browse() {
    const box = $('#pBrowse'); if (!st.table) { box.innerHTML = '<div class="no">Choose a table</div>'; return; }
    if (!$('#bbar')) box.innerHTML = BAR;
    $('#bName').textContent = st.table; if ($('#bq').value !== st.q) $('#bq').value = st.q;
    $('#bper').innerHTML = [25, 50, 100, 200].map(n => '<option value="' + n + '"' + (n === st.per ? ' selected' : '') + '>' + n + ' / page</option>').join('');
    syncViewBtns(); const my = ++seq; $('#bGrid').innerHTML = spin;
    const r = await api('browse', { db: st.db, table: st.table, page: st.page, per: st.per, sort: st.sort, dir: st.dir, q: st.q, qcol: st.qcol });
    if (my !== seq || !$('#bbar')) return;
    if (!r.ok) { $('#bGrid').innerHTML = '<div class="err">' + esc(r.error) + '</div>'; return; }
    st.page = r.page; st.pages = r.pages; st.pk = r.pk; D.browse = { cols: r.cols, rows: r.rows, pk: r.pk, table: st.table, src: 'browse' };
    $('#bqc').innerHTML = '<option value="">All columns</option>' + r.cols.map(c => '<option' + (c === st.qcol ? ' selected' : '') + ' value="' + esc(c) + '">' + esc(c) + '</option>').join('');
    const bd = $('#bBadge'); bd.hidden = false; bd.className = 'badge' + (r.pk.length ? '' : ' w'); bd.textContent = r.pk.length ? 'PK: ' + r.pk.join(', ') : 'no primary key · read-only';
    $('#bAdd').hidden = false; drawGrid('browse');
    $('#bInfo').textContent = num(r.total) + ' row' + (r.total === 1 ? '' : 's') + ' · page ' + r.page + '/' + r.pages + ' · ' + r.ms + ' ms';
    $('#bPg').value = r.page; $('#bPg').max = r.pages; $('#bPrev').disabled = $('#bFirst').disabled = r.page <= 1; $('#bNext').disabled = $('#bLast').disabled = r.page >= r.pages;
  }
  const goPage = p => { st.page = Math.max(1, Math.min(st.pages, p | 0 || 1)); browse(); };
  $('#pBrowse').addEventListener('click', e => {
    const th = e.target.closest('th[data-c]'); if (th) { const c = th.dataset.c; st.dir = st.sort === c && st.dir === 'asc' ? 'desc' : 'asc'; st.sort = c; st.page = 1; return browse(); }
    const row = e.target.closest('[data-i]'); if (row && row.closest('.dwrap')) return openRow('browse', +row.dataset.i);
    const id = (e.target.closest('button') || {}).id;
    if (id === 'bFirst') goPage(1); else if (id === 'bPrev') goPage(st.page - 1); else if (id === 'bNext') goPage(st.page + 1); else if (id === 'bLast') goPage(st.pages);
    else if (id === 'bRef') browse(); else if (id === 'bView') toggleView(); else if (id === 'bAdd') openForm('insert');
    else if (id === 'bExp') $('#expM').hidden = !$('#expM').hidden;
    const ex = e.target.closest('[data-exp]'); if (ex) { $('#expM').hidden = true; exportBrowse(ex.dataset.exp); }
  });
  document.addEventListener('click', e => { const m = $('#expM'); if (m && !e.target.closest('.dd')) m.hidden = true; });
  let qt; $('#pBrowse').addEventListener('input', e => { if (e.target.id === 'bq') { clearTimeout(qt); qt = setTimeout(() => { st.q = e.target.value.trim(); st.page = 1; browse(); }, 350); } });
  $('#pBrowse').addEventListener('change', e => { const id = e.target.id; if (id === 'bper') { st.per = +e.target.value; ls.set('fd_db_per', st.per); st.page = 1; browse(); } else if (id === 'bPg') goPage(+e.target.value); else if (id === 'bqc') { st.qcol = e.target.value; st.page = 1; if (st.q) browse(); } });
  $('#pBrowse').addEventListener('keydown', e => { if (e.target.id === 'bPg' && e.key === 'Enter') goPage(+e.target.value); });
  async function exportBrowse(fmt) {
    toast('Preparing ' + fmt.toUpperCase() + '…');
    const fd = new FormData(); fd.append('csrf', CSRF); fd.append('act', 'export'); fd.append('fmt', fmt);
    Object.entries({ db: st.db, table: st.table, sort: st.sort, dir: st.dir, q: st.q, qcol: st.qcol }).forEach(([k, v]) => fd.append(k, v));
    try {
      const r = await fetch(location.pathname + '?fdpage=dbviewer', { method: 'POST', body: fd, credentials: 'same-origin' }), cd = r.headers.get('content-disposition') || '';
      if (!cd) { const j = await r.json().catch(() => ({})); return toast(j.error || 'Export failed', 'err'); }
      const m = cd.match(/filename="?([^";]+)"?/); saveBlob(await r.blob(), m ? m[1] : st.table + '.' + fmt); toast('Export ready');
    } catch (e) { toast('Export failed', 'err'); }
  }
  function exportData(ds, fmt, name) {
    if (!ds || !ds.cols.length) return toast('Nothing to export', 'err');
    if (fmt === 'copy') { copyText(JSON.stringify(ds.rows.map(r => Object.fromEntries(ds.cols.map((c, j) => [c, r[j]]))), null, 2)).then(() => toast('Copied as JSON')); return; }
    if (fmt === 'json') return saveBlob(new Blob([JSON.stringify(ds.rows.map(r => Object.fromEntries(ds.cols.map((c, j) => [c, r[j]]))), null, 2)], { type: 'application/json' }), name + '.json');
    const q = v => v === null ? '' : (/[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v);
    saveBlob(new Blob(['\ufeff' + [ds.cols.map(q), ...ds.rows.map(r => r.map(q))].map(r => r.join(',')).join('\r\n')], { type: 'text/csv' }), name + '.csv');
  }

  /* ---------- row details ---------- */
  const rs = { src: 'browse', i: 0 };
  const pkOf = i => { const ds = D.browse; return Object.fromEntries(ds.pk.map(c => [c, ds.rows[i][ds.cols.indexOf(c)]])); };
  function openRow(src, i) { if (!D[src] || !D[src].rows[i]) return; rs.src = src; rs.i = i; drawRow(); openSheet($('#rs')); }
  function drawRow() {
    const ds = D[rs.src], r = ds.rows[rs.i], can = rs.src === 'browse' && ds.pk.length;
    $('#rTitle').textContent = (rs.src === 'browse' ? ds.table + ' · ' : 'Result · ') + 'row ' + (rs.i + 1) + ' / ' + ds.rows.length;
    $('#rBody').innerHTML = ds.cols.map((c, j) => '<div class="kv"><div class="k">' + esc(c) + (ds.pk && ds.pk.includes(c) ? ' <i class="fa-solid fa-key pk"></i>' : '') + '</div><div class="v' + (r[j] === null ? ' nl' : '') + '">' + (r[j] === null ? 'NULL' : esc(r[j])) + '</div><button class="cp" data-cp="' + j + '" title="Copy value" type="button"><i class="fa-regular fa-copy" style="color:#818cf8"></i></button></div>').join('');
    $('#rFoot').innerHTML = (can ? '<button class="btn dng sp" data-ra="del" type="button"><i class="fa-solid fa-trash" style="color:#fb7185"></i>Delete</button>' : '') + '<button class="btn" data-ra="json" type="button"><i class="fa-regular fa-copy" style="color:#818cf8"></i>Copy JSON</button>'
      + (can ? '<button class="btn" data-ra="dup" type="button"><i class="fa-solid fa-clone" style="color:#14b8a6"></i>Duplicate</button><button class="btn pri" data-ra="edit" type="button"><i class="fa-solid fa-pen"></i>Edit</button>' : (rs.src === 'browse' ? '<span class="mut" style="align-self:center">No primary key — read-only</span>' : ''));
    $('#rPrev').disabled = rs.i <= 0; $('#rNext').disabled = rs.i >= ds.rows.length - 1; $('#rBody').scrollTop = 0;
  }
  $('#rPrev').onclick = () => { if (rs.i > 0) { rs.i--; drawRow(); } }; $('#rNext').onclick = () => { if (rs.i < D[rs.src].rows.length - 1) { rs.i++; drawRow(); } };
  $('#rs').addEventListener('click', e => {
    const cp = e.target.closest('[data-cp]'); if (cp) { const v = D[rs.src].rows[rs.i][+cp.dataset.cp]; copyText(v === null ? 'NULL' : v).then(() => toast('Copied')); return; }
    const a = e.target.closest('[data-ra]'); if (!a) return; const ds = D[rs.src];
    if (a.dataset.ra === 'json') copyText(JSON.stringify(Object.fromEntries(ds.cols.map((c, j) => [c, ds.rows[rs.i][j]])), null, 2)).then(() => toast('Copied as JSON'));
    else if (a.dataset.ra === 'edit') openForm('edit', rs.i); else if (a.dataset.ra === 'dup') openForm('dup', rs.i); else if (a.dataset.ra === 'del') delRow(rs.i);
  });
  async function delRow(i) {
    const pkv = pkOf(i);
    if (!await confirmBox({ title: 'Delete this row?', msg: 'It will be permanently removed from <b>' + esc(st.table) + '</b> and cannot be undone.', pre: Object.entries(pkv).map(([k, v]) => k + ' = ' + v).join('\n'), ok: 'Delete', danger: true })) return;
    const r = await api('row_delete', { db: st.db, table: st.table, pk: JSON.stringify(pkv) });
    if (!r.ok) return toast(r.error, 'err'); toast('Row deleted'); closeSheet($('#rs')); browse(); loadTablesKeep();
  }

  /* ---------- insert / edit form ---------- */
  const fm = { mode: 'edit', i: 0, meta: [], vals: null };
  async function getMeta() {
    if (st.meta && st.meta.t === st.table && st.meta.d === st.db) return st.meta;
    const r = await api('meta', { db: st.db, table: st.table }); if (!r.ok) throw new Error(r.error);
    return st.meta = { t: st.table, d: st.db, cols: r.cols, pk: r.pk };
  }
  function fieldH(m, j, mode, v) {
    const auto = /auto_increment/i.test(m.e), gen = /(virtual|stored) generated/i.test(m.e), bin = !!(v && v.b), isN = !!(v && v.n), cur = v && v.v !== undefined ? v.v : '';
    const omit = mode === 'insert' ? (auto || m.d !== null || m.nul) : (mode === 'dup' ? auto : false), ro = gen || bin;
    const ph = auto ? 'auto' : (m.d !== null ? 'default: ' + m.d : '');
    let ctl;
    if (/^enum\(/i.test(m.t)) { const o = [...m.t.matchAll(/'((?:[^']|'')*)'/g)].map(x => x[1].replace(/''/g, "'")); ctl = '<select class="inp fv">' + o.map(x => '<option' + (x === cur ? ' selected' : '') + '>' + esc(x) + '</option>').join('') + '</select>'; }
    else if (/text|blob|json/i.test(m.t) || (/char/i.test(m.t) && /\((\d{3,})\)/.test(m.t))) ctl = '<textarea class="inp fv" rows="3" spellcheck="false" placeholder="' + esc(ph) + '">' + esc(cur) + '</textarea>';
    else ctl = '<input class="inp fv" value="' + esc(cur) + '" placeholder="' + esc(ph) + '" autocomplete="off" autocapitalize="off" spellcheck="false">';
    return '<div class="ff" data-j="' + j + '"' + (ro ? ' data-ro="1"' : '') + '><div class="fl"><span>' + esc(m.n) + '</span><small>' + esc(m.t) + (m.k ? ' · ' + esc(m.k) : '') + (m.nul ? '' : ' · required') + '</small></div>' + ctl
      + '<div class="fo">' + (m.nul && !ro ? '<label class="mini"><input type="checkbox" class="fN"' + (isN ? ' checked' : '') + '> NULL</label>' : '') + (mode !== 'edit' && !ro ? '<label class="mini"><input type="checkbox" class="fD"' + (omit ? ' checked' : '') + '> Use default</label>' : '') + (ro ? '<small class="mut">' + (gen ? 'generated column — read-only' : 'binary value — read-only') + '</small>' : '') + '</div></div>';
  }
  function syncField(ff) { const N = $('.fN', ff), Dc = $('.fD', ff), c = $('.fv', ff), d = !!(Dc && Dc.checked); if (N) N.disabled = d; c.disabled = !!ff.dataset.ro || d || !!(N && N.checked); }
  async function openForm(mode, i) {
    let meta; try { meta = await getMeta(); } catch (e) { return toast(e.message, 'err'); }
    let vals = null;
    if (mode !== 'insert') { const r = await api('row_get', { db: st.db, table: st.table, pk: JSON.stringify(pkOf(i)) }); if (!r.ok) return toast(r.error, 'err'); vals = r.row; }
    Object.assign(fm, { mode, i, meta: meta.cols, vals });
    $('#fTitle').textContent = (mode === 'edit' ? 'Edit row' : mode === 'dup' ? 'Duplicate row' : 'Insert row') + ' · ' + st.table;
    $('#fBody').innerHTML = meta.cols.map((m, j) => fieldH(m, j, mode, vals ? vals[m.n] : null)).join('');
    $$('#fBody .ff').forEach(syncField); openSheet($('#fs')); $('#fBody').scrollTop = 0;
  }
  $('#fBody').addEventListener('change', e => { const ff = e.target.closest('.ff'); if (ff && e.target.type === 'checkbox') syncField(ff); });
  $('#fBody').addEventListener('input', e => { const ff = e.target.closest('.ff'); if (ff && e.target.classList.contains('fv')) { const Dc = $('.fD', ff); if (Dc && Dc.checked) { Dc.checked = false; syncField(ff); } } });
  $('#fSave').onclick = async () => {
    const data = {}; let n = 0;
    $$('#fBody .ff').forEach(ff => {
      if (ff.dataset.ro) return; const m = fm.meta[+ff.dataset.j], N = $('.fN', ff), Dc = $('.fD', ff), c = $('.fv', ff);
      if (fm.mode === 'edit') { const o = fm.vals[m.n] || {}, cur = N && N.checked ? { n: 1 } : { v: c.value }; const same = o.n ? !!cur.n : (!cur.n && cur.v === String(o.v === undefined ? '' : o.v).replace(/\r\n/g, '\n')); if (!same) { data[m.n] = cur; n++; } }
      else { if (Dc && Dc.checked) return; data[m.n] = N && N.checked ? { n: 1 } : { v: c.value }; n++; }
    });
    if (fm.mode === 'edit' && !n) return toast('No changes');
    const b = $('#fSave'); b.disabled = true;
    const body = { db: st.db, table: st.table, data: JSON.stringify(data) }; if (fm.mode === 'edit') body.pk = JSON.stringify(pkOf(fm.i));
    const r = await api(fm.mode === 'edit' ? 'row_update' : 'row_insert', body); b.disabled = false;
    if (!r.ok) return toast(r.error, 'err');
    toast(fm.mode === 'edit' ? 'Row updated' : 'Row inserted'); closeSheet($('#fs')); closeSheet($('#rs')); browse(); if (fm.mode !== 'edit') loadTablesKeep();
  };

  /* ---------- structure ---------- */
  async function structure() {
    const box = $('#pStruct'); if (!st.table) { box.innerHTML = '<div class="no">Choose a table</div>'; return; } box.innerHTML = spin;
    const r = await api('structure', { db: st.db, table: st.table });
    if (!r.ok) { box.innerHTML = '<div class="err">' + esc(r.error) + '</div>'; return; }
    const keep = ['Field', 'Type', 'Null', 'Key', 'Default', 'Extra', 'Comment'], ix = keep.map(k => r.cols.indexOf(k));
    const cols = keep.filter((k, i) => ix[i] >= 0), rows = r.rows.map(x => ix.filter(i => i >= 0).map(i => x[i]));
    const want = ['Key_name', 'Column_name', 'Non_unique', 'Index_type', 'Seq_in_index'], jx = want.map(k => r.icols.indexOf(k)).filter(i => i >= 0);
    const t = st.tables.find(x => x.n === st.table), sum = t ? '<div class="sum"><span class="badge">' + (t.v ? 'View' : esc(t.e || 'Table')) + '</span><span class="badge">' + (t.r === null ? '—' : '≈ ' + num(t.r)) + ' rows</span><span class="badge">' + fmtB(t.s) + '</span><span class="badge">' + rows.length + ' columns</span></div>' : '';
    box.innerHTML = sum + '<h4 class="sec">Columns</h4>' + plainGrid(cols, rows) + '<h4 class="sec">Indexes</h4>' + plainGrid(jx.map(i => r.icols[i]), r.irows.map(x => jx.map(i => x[i]))) + (r.create ? '<h4 class="sec">CREATE TABLE</h4><button class="btn sm" id="cpCr" type="button"><i class="fa-regular fa-copy" style="color:#818cf8"></i>Copy</button><pre class="cr" id="crTxt"></pre>' : '');
    if (r.create) { $('#crTxt').textContent = r.create; $('#cpCr').onclick = () => copyText(r.create).then(() => toast('Copied')); }
  }

  /* ---------- overview ---------- */
  function overview() {
    const T = st.tables, tot = T.reduce((a, t) => a + t.s, 0), rows = T.reduce((a, t) => a + (t.r || 0), 0), mx = Math.max(1, ...T.map(t => t.s));
    $('#pOver').innerHTML = '<div class="ovs"><div class="ov"><b>' + T.length + '</b><small>Tables</small></div><div class="ov"><b>' + num(rows) + '</b><small>Rows (approx.)</small></div><div class="ov"><b>' + fmtB(tot) + '</b><small>Total size</small></div></div>'
      + '<div class="ol">' + (T.slice().sort((a, b) => b.s - a.s).map(t => '<div class="oi" data-n="' + esc(t.n) + '"><div class="r1"><i class="fa-solid ' + (t.v ? 'fa-eye' : 'fa-table') + '" style="color:var(--ac)"></i><b>' + esc(t.n) + '</b><small>' + fmtB(t.s) + '</small></div><div class="r2"><span>' + esc(t.v ? 'View' : (t.e || '')) + '</span><span>' + (t.r === null ? '—' : '≈ ' + num(t.r) + ' rows') + '</span></div><div class="pb"><i style="width:' + Math.max(1.5, t.s / mx * 100) + '%"></i></div></div>').join('') || '<div class="no">No tables</div>') + '</div>';
  }
  $('#pOver').addEventListener('click', e => { const o = e.target.closest('.oi'); if (o) { st.tab = 'browse'; pick(o.dataset.n); } });

  /* ---------- SQL ---------- */
  $('#sqlLim').innerHTML = [100, 500, 1000, 5000].map(n => '<option value="' + n + '"' + (n === st.lim ? ' selected' : '') + '>' + num(n) + ' rows max</option>').join('');
  $('#sqlLim').onchange = e => { st.lim = +e.target.value; ls.set('fd_db_lim', st.lim); };
  const hist = () => ls.get('fd_db_hist', []);
  function renderHist() { $('#hist').innerHTML = hist().map((q, i) => '<button type="button" data-i="' + i + '" title="' + esc(q) + '">' + esc(q.replace(/\s+/g, ' ')) + '</button>').join(''); syncViewBtns(); }
  const isRead = s => /^\s*(?:\/\*[\s\S]*?\*\/\s*|--[^\n]*\n\s*|#[^\n]*\n\s*)*(?:select|show|describe|desc|explain|with)\b/i.test(s);
  async function runSql(confirm) {
    const sql = $('#sql').value.trim(); if (!sql) return toast('Type a query first');
    if (!isRead(sql) && !confirm) { if (!await confirmBox({ title: 'Run this statement?', msg: 'It will change data in <b>' + esc(st.db) + '</b> and cannot be undone.', pre: sql, ok: 'Run it' })) return; confirm = true; }
    $('#run').disabled = true; $('#sqlRes').innerHTML = spin; $('#sqlTools').hidden = true;
    const r = await api('query', { db: st.db, sql, lim: st.lim, confirm: confirm ? '1' : '' }); $('#run').disabled = false;
    if (!r.ok) { D.sql = null; $('#sqlRes').innerHTML = '<div class="err">' + esc(r.error) + '</div>'; $('#sqlInfo').textContent = ''; return; }
    ls.set('fd_db_hist', [sql, ...hist().filter(x => x !== sql)].slice(0, 12)); renderHist();
    if (r.aff !== null) { D.sql = null; $('#sqlRes').innerHTML = '<div class="card"><span class="ok"><i class="fa-solid fa-circle-check" style="color:#10b981"></i> Done.</span> ' + num(r.aff) + ' row' + (r.aff === 1 ? '' : 's') + ' affected.</div>'; $('#sqlInfo').textContent = r.ms + ' ms'; if (/^\s*(create|drop|alter|rename|truncate|insert|delete)\b/i.test(sql)) { loadTablesKeep(); if (D.browse) browse(); } return; }
    D.sql = { cols: r.cols, rows: r.rows, pk: [], table: '', src: 'sql' }; $('#sqlTools').hidden = false; drawGrid('sql');
    $('#sqlInfo').textContent = num(r.rows.length) + ' row' + (r.rows.length === 1 ? '' : 's') + (r.more ? ' (first ' + num(r.lim) + ' shown)' : '') + ' · ' + r.ms + ' ms';
  }
  $('#run').onclick = () => runSql(false);
  $('#sqlClear').onclick = () => { $('#sql').value = ''; $('#sqlRes').innerHTML = ''; $('#sqlInfo').textContent = ''; $('#sqlTools').hidden = true; D.sql = null; };
  $('#sql').addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runSql(false); }
    if (e.key === 'Tab') { e.preventDefault(); const t = e.target, s = t.selectionStart; t.setRangeText('    ', s, t.selectionEnd, 'end'); }
  });
  $('#hist').onclick = e => { const b = e.target.closest('button'); if (b) { $('#sql').value = hist()[+b.dataset.i]; $('#sql').focus(); } };
  $('#qch').onclick = e => {
    const b = e.target.closest('button'); if (!b) return; const t = st.table ? '`' + st.table.replace(/`/g, '``') + '`' : '`table_name`';
    $('#sql').value = { sel: 'SELECT * FROM ' + t + ' LIMIT 100;', cnt: 'SELECT COUNT(*) FROM ' + t + ';', desc: 'DESCRIBE ' + t + ';', idx: 'SHOW INDEX FROM ' + t + ';', cre: 'SHOW CREATE TABLE ' + t + ';', stat: 'SHOW TABLE STATUS;', proc: 'SHOW FULL PROCESSLIST;' }[b.dataset.q]; $('#sql').focus();
  };
  $('#sqlRes').addEventListener('click', e => { const row = e.target.closest('[data-i]'); if (row && row.closest('.dwrap')) openRow('sql', +row.dataset.i); });
  $('#sqlTools').addEventListener('click', e => { const b = e.target.closest('button'); if (!b) return; if (b.id === 'sView') return toggleView(); if (b.dataset.sx) exportData(D.sql, b.dataset.sx, 'query_' + new Date().toISOString().slice(0, 19).replace(/[-:T]/g, '')); });

  /* ---------- events ---------- */
  $('#fConn').onsubmit = async e => {
    e.preventDefault(); const b = $('#cBtn'); b.disabled = true; $('#cErr').hidden = true;
    const f = Object.fromEntries(new FormData(e.target)), r = await api('connect', f); b.disabled = false;
    if (!r.ok) { $('#cErr').textContent = r.error; $('#cErr').hidden = false; return; }
    if ($('#cRem').checked) ls.set('fd_db_conn', { host: f.host, port: f.port, user: f.user, db: f.db }); else ls.set('fd_db_conn', null);
    e.target.pass.value = ''; toast('Connected · MySQL ' + r.version); boot();
  };
  $('#bOut').onclick = async () => { await api('disconnect'); D.browse = D.sql = null; st.table = ''; $('#pBrowse').innerHTML = ''; show(false); };
  $('#dbSel').onchange = e => { st.db = e.target.value; loadTables(); };
  $('#tFilter').oninput = drawTables;
  $('#tList').onclick = e => { const t = e.target.closest('.ti'); if (t) pick(t.dataset.n); };
  $('#tabs').onclick = e => { const b = e.target.closest('.tab'); if (b) tab(b.dataset.t); };
  syncViewBtns(); boot();
})();
</script>
<?php if ($embed): ?><script>
document.addEventListener('click',function(e){var a=e.target.closest('a[href]');if(!a||a.target==='_blank')return;var u=new URL(a.href,location.href);if(u.origin!==location.origin)return;e.preventDefault();if(u.pathname.split('/').pop()==='index.php'&&!u.search&&!u.hash){try{window.parent.postMessage('fd-close-page',location.origin)}catch(x){window.top.location.href=u.pathname}return;}window.top.location.href=u.pathname+u.search+u.hash;});
</script><?php endif; ?>
</body>
</html>
<?php
exit;
}

}

namespace FDEditor {
use \RecursiveIteratorIterator; use \RecursiveDirectoryIterator; use \FilesystemIterator; use \ZipArchive; use \DateTime; use \DateTimeZone; use \DirectoryIterator; use \SplFileInfo; use \Exception; use \Throwable; use \finfo;
/* hoisted function declarations (must be unconditional) */
function resolveServerPath($path) {
    $path = trim($path);
    if (empty($path)) return FD_APP_ROOT;
    if (strpos($path, '/') === 0 || preg_match('/^[A-Z]:\\\\/i', $path)) {
        $real = realpath($path);
        if ($real !== false && file_exists($real)) return $real;
    }
    $real = realpath(FD_APP_ROOT . '/' . $path);
    if ($real !== false) return $real;
    return FD_APP_ROOT;
}

function editorFolderSize($dir) {
    if (is_link($dir)) return (int)@filesize($dir);
    $total = 0; foreach ((array)@scandir($dir) as $n) { if ($n === '.' || $n === '..') continue; $p=$dir.'/'.$n; $total += (is_dir($p) && !is_link($p)) ? editorFolderSize($p) : (int)@filesize($p); } return $total;
}

function editorCopyTree($src, $dst) {
    if (is_link($src)) return false;
    if (is_dir($src)) {
        if (!@mkdir($dst, 0755, false)) return false;
        foreach (scandir($src) as $n) {
            if ($n === '.' || $n === '..') continue;
            if (!editorCopyTree($src . '/' . $n, $dst . '/' . $n)) return false;
        }
        return true;
    }
    return @copy($src, $dst);
}

if ($__fdpage === 'editor') {

/**
 * Modern Neon File Manager - Ultimate Advanced IDE Editor (`?fdpage=editor`)
 */

error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

$server_root = realpath($_SERVER['DOCUMENT_ROOT'] ? $_SERVER['DOCUMENT_ROOT'] : FD_APP_ROOT);





$current_base = resolveServerPath($_GET['base'] ?? FD_APP_ROOT);
if (!defined('FD_DATA')) define('FD_DATA', __DIR__ . '/.filedash');

/* Editor file operations: upload, download, clipboard and recycle-bin delete. */




if (isset($_GET['download'])) {
    $f = realpath((string)$_GET['download']);
    if (!$f || !is_file($f) || !is_readable($f)) { http_response_code(404); exit('File not found or not readable'); }
    while (ob_get_level()) @ob_end_clean();
    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . filesize($f));
    header('Content-Disposition: attachment; filename="' . str_replace('"', '', basename($f)) . '"');
    header('X-Content-Type-Options: nosniff');
    readfile($f); exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (isset($_POST['editor_file_action']) || isset($_POST['save_file']) || isset($_POST['create_type']))) {
    /* cross-site requests (another website posting to this editor) are refused */
    $sfs = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
    if ($sfs !== '' && $sfs !== 'same-origin' && $sfs !== 'none') { http_response_code(403); header('Content-Type: application/json'); echo json_encode(['status' => 'error', 'message' => 'Blocked: cross-site request']); exit; }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['editor_file_action'])) {
    header('Content-Type: application/json; charset=utf-8');
    $act = (string)$_POST['editor_file_action'];
    $path = realpath((string)($_POST['path'] ?? ''));
    $dest = realpath((string)($_POST['dest'] ?? ''));
    $json = function($ok, $message, $extra = []) { echo json_encode(array_merge(['status'=>$ok?'success':'error','message'=>$message], $extra)); exit; };
    if ($act === 'upload') {
        $dir = realpath((string)($_POST['target_dir'] ?? ''));
        if (!$dir || !is_dir($dir) || empty($_FILES['files'])) $json(false, 'Invalid upload destination or no files selected');
        $ok = 0; $fail = 0;
        foreach ((array)$_FILES['files']['name'] as $i => $name) {
            if (($_FILES['files']['error'][$i] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) { $fail++; continue; }
            $safe = basename(str_replace(["\0", '/', '\\'], '', (string)$name));
            if ($safe === '' || $safe === '.' || $safe === '..') { $fail++; continue; }
            $target = $dir . '/' . $safe; $base = pathinfo($safe, PATHINFO_FILENAME); $ext = pathinfo($safe, PATHINFO_EXTENSION); $n = 1;
            while (file_exists($target)) $target = $dir . '/' . $base . ' (' . $n++ . ')' . ($ext !== '' ? '.' . $ext : '');
            if (is_uploaded_file($_FILES['files']['tmp_name'][$i]) && @move_uploaded_file($_FILES['files']['tmp_name'][$i], $target)) $ok++; else $fail++;
        }
        $json($ok > 0, "$ok file(s) uploaded" . ($fail ? ", $fail failed" : ''), ['uploaded'=>$ok,'failed'=>$fail]);
    }
    if ($act === 'info') {
        if (!$path || !file_exists($path)) $json(false, 'Item not found');
        $json(true, 'Properties', ['info'=>['name'=>basename($path),'type'=>is_dir($path)?'Folder':(strtoupper(pathinfo($path, PATHINFO_EXTENSION)) ?: 'File'),'size'=>is_file($path)?filesize($path):editorFolderSize($path),'modified'=>filemtime($path),'permissions'=>substr(sprintf('%o', fileperms($path)), -4),'path'=>$path]]);
    }
    if (!$path || !file_exists($path)) $json(false, 'Source item not found');
    if ($act === 'delete') {
        $self = realpath(FD_APP_ROOT); $trash = realpath(FD_APP_ROOT . '/.trash');
        $norm = str_replace('\\','/',$path); $selfn = str_replace('\\','/',$self);
        if ($norm === $selfn || strpos($selfn . '/', rtrim($norm, '/') . '/') === 0 || ($trash && ($norm === str_replace('\\','/',$trash) || strpos($norm, rtrim(str_replace('\\','/',$trash), '/') . '/') === 0))) $json(false, 'This protected folder cannot be deleted');
        if (!defined('TRASH_LIB_ONLY'))
        $moved = trash_move($path); $json($moved, $moved ? 'Moved to Trash' : 'Could not move item to Trash');
    }
    if ($act === 'rename') {
        $new = trim((string)($_POST['name'] ?? ''));
        if ($new === '' || $new === '.' || $new === '..' || preg_match('#[\\\\/]#', $new)) $json(false, 'Invalid name');
        $target = dirname($path) . '/' . $new;
        if (file_exists($target)) $json(false, 'An item with that name already exists');
        $done = @rename($path, $target);
        $json($done, $done ? 'Renamed successfully' : 'Rename failed', ['path'=>$target]);
    }
    if ($act === 'duplicate') {
        $base = basename($path); $ext = is_file($path) ? pathinfo($base, PATHINFO_EXTENSION) : '';
        $stem = is_file($path) ? pathinfo($base, PATHINFO_FILENAME) : $base; $n=1;
        do { $newName=$stem.' copy'.($n>1?' '.$n:'').($ext!==''?'.'.$ext:''); $target=dirname($path).'/'.$newName; $n++; } while(file_exists($target));
        $done=editorCopyTree($path,$target); $json($done,$done?'Duplicated successfully':'Duplicate failed');
    }
    if ($act === 'extract') {
        if (!is_file($path) || strtolower(pathinfo($path,PATHINFO_EXTENSION))!=='zip') $json(false,'Not a ZIP file');
        if (!class_exists('ZipArchive')) $json(false,'PHP ZIP extension is not enabled');
        $zip=new ZipArchive(); if($zip->open($path)!==true) $json(false,'Could not open ZIP');
        $dest=dirname($path).'/'.pathinfo($path,PATHINFO_FILENAME); $n=1; $base=$dest; while(file_exists($dest)) $dest=$base.' ('.$n++.')';
        @mkdir($dest,0755,true); $count=0;
        for($i=0;$i<$zip->numFiles;$i++){ $entry=$zip->getNameIndex($i); if($entry===false || strpos($entry,"\\0")!==false || preg_match('#(^|/)\\.\\.(/|$)#',$entry) || strpos($entry,'/')===0) continue; $to=$dest.'/'.$entry; if(substr($entry,-1)==='/'){@mkdir($to,0755,true);continue;} @mkdir(dirname($to),0755,true); $in=$zip->getStream($entry); if(!$in)continue; $o=@fopen($to,'wb'); if($o){stream_copy_to_stream($in,$o);fclose($o);$count++;} fclose($in); }
        $zip->close(); $json(true,"Extracted $count file(s)",['count'=>$count,'folder'=>basename($dest)]);
    }
    if (in_array($act, ['copy','cut'], true)) {
        if (!$dest || !is_dir($dest)) $json(false, 'Destination folder not found');
        if (is_dir($path) && ($dest === $path || strpos(str_replace('\\','/',$dest) . '/', rtrim(str_replace('\\','/',$path), '/') . '/') === 0)) $json(false, 'Cannot paste a folder into itself');
        $target = $dest . '/' . basename($path);
        if (file_exists($target)) { $json(false, 'An item with the same name already exists'); }
        $done = $act === 'copy' ? editorCopyTree($path, $target) : @rename($path, $target);
        $json($done, $done ? ($act === 'copy' ? 'Copied successfully' : 'Moved successfully') : 'File operation failed');
    }
    $json(false, 'Unknown file operation');
}

// 1. AJAX Save Request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_file'])) {
    header('Content-Type: application/json');
    if (!hash_equals(fdaCsrf(), (string)($_POST['csrf'] ?? ''))) { echo json_encode(['status' => 'error', 'message' => 'Page expired - reload the editor and save again']); exit; }
    $file_path = $_POST['file_path'] ?? '';
    $content = (string)($_POST['content'] ?? '');
    /* browsers turn every "\n" into "\r\n" when posting form data -> save as Linux (LF); only Windows scripts keep CRLF */
    if (!preg_match('/\.(bat|cmd|ps1|vbs|reg)$/i', (string)$file_path)) $content = str_replace(["\r\n", "\r"], "\n", $content);
    
    if ($file_path && file_exists($file_path) && is_file($file_path)) {
        if (file_put_contents($file_path, $content) !== false) {
            echo json_encode(['status' => 'success', 'message' => 'File saved successfully!']);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Failed to write file!']);
        }
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Invalid file path!']);
    }
    exit;
}

// 2. AJAX Create New File or Folder
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_type'])) {
    header('Content-Type: application/json');
    $type = $_POST['create_type'];
    $target_dir = $_POST['target_dir'] ?? FD_APP_ROOT;
    $name = trim($_POST['item_name'] ?? '');

    if (!empty($name) && is_dir($target_dir)) {
        $full_target = $target_dir . '/' . $name;
        if ($type === 'folder') {
            if (!file_exists($full_target)) {
                mkdir($full_target, 0755, true);
                echo json_encode(['status' => 'success', 'message' => 'Folder created successfully!']);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'Folder already exists!']);
            }
        } else {
            if (!file_exists($full_target)) {
                file_put_contents($full_target, '');
                echo json_encode(['status' => 'success', 'message' => 'File created successfully!']);
            } else {
                echo json_encode(['status' => 'error', 'message' => 'File already exists!']);
            }
        }
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Invalid name or directory!']);
    }
    exit;
}

// 3. AJAX Get File Content
if (isset($_GET['get_content'])) {
    header('Content-Type: application/json; charset=utf-8');
    $requested = (string)$_GET['get_content'];
    $file_path = realpath($requested);

    if ($file_path && is_file($file_path) && is_readable($file_path)) {
        $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        $mode = 'clike';
        if (in_array($ext, ['php'])) $mode = 'php';
        elseif (in_array($ext, ['js', 'mjs', 'json'])) $mode = 'javascript';
        elseif (in_array($ext, ['html', 'htm'])) $mode = 'htmlmixed';
        elseif (in_array($ext, ['css', 'scss'])) $mode = 'css';
        elseif (in_array($ext, ['sql'])) $mode = 'sql';
        elseif (in_array($ext, ['md'])) $mode = 'markdown';
        elseif (in_array($ext, ['py', 'pyw'])) $mode = 'python';
        elseif (in_array($ext, ['rb', 'ru', 'gemspec', 'rake'])) $mode = 'ruby';
        elseif ($ext === 'go') $mode = 'go';
        elseif ($ext === 'rs') $mode = 'rust';
        elseif (in_array($ext, ['sh', 'bash', 'zsh', 'ksh', 'env'])) $mode = 'shell';
        elseif (in_array($ext, ['yml', 'yaml'])) $mode = 'yaml';
        elseif ($ext === 'dockerfile' || strtolower(basename($file_path)) === 'dockerfile' || stripos(basename($file_path), 'dockerfile.') === 0) $mode = 'dockerfile';
        elseif (in_array($ext, ['txt', 'log', 'text'])) $mode = 'null';

        echo json_encode([
            'status' => 'success',
            'content' => (string)file_get_contents($file_path),
            'mode' => $mode,
            'ext' => $ext,
            'name' => basename($file_path),
            'path' => $file_path
        ]);
    } else {
        http_response_code(404);
        echo json_encode(['status' => 'error', 'message' => 'File not found or not readable']);
    }
    exit;
}

// 4. AJAX Scan Directory
// if (isset($_GET['scan_dir'])) {
//     header('Content-Type: application/json');
//     $dir_path = $_GET['scan_dir'];
//     $target_dir = resolveServerPath($dir_path);

//     if ($target_dir && is_dir($target_dir)) {
//         $items = scandir($target_dir);
//         $result = [];
//         $parent_dir = dirname($target_dir);

//         foreach ($items as $item) {
//             if ($item === '.') continue;
//             $item_full = $target_dir . '/' . $item;
//             $is_dir = is_dir($item_full);
//             $ext = strtolower(pathinfo($item, PATHINFO_EXTENSION));
//             $is_editable = $is_dir || in_array($ext, ['txt', 'php', 'html', 'css', 'js', 'json', 'md', 'env', 'htaccess', 'sql', 'xml', 'py', 'sh']);

//             $result[] = [
//                 'name' => $item,
//                 'full_path' => $item_full,
//                 'is_dir' => $is_dir,
//                 'is_editable' => $is_editable,
//                 'ext' => $ext
//             ];
//         }
//         echo json_encode([
//             'status' => 'success', 
//             'current' => $target_dir,
//             'parent' => $parent_dir,
//             'items' => $result
//         ]);
//     } else {
//         echo json_encode(['status' => 'error', 'message' => 'Directory not accessible']);
//     }
//     exit;
// }
// 4. AJAX Scan Directory (Ekhane $is_editable er condition update kora holo jate sob dhoroner text/code file edit kora jay)
if (isset($_GET['scan_dir'])) {
    header('Content-Type: application/json');
    $dir_path = $_GET['scan_dir'];
    $target_dir = resolveServerPath($dir_path);

    if ($target_dir && is_dir($target_dir)) {
        $items = scandir($target_dir);
        $result = [];
        $parent_dir = dirname($target_dir);

        foreach ($items as $item) {
            if ($item === '.') continue;
            $item_full = $target_dir . '/' . $item;
            $is_dir = is_dir($item_full);
            $ext = strtolower(pathinfo($item, PATHINFO_EXTENSION));
            
            // Sob dhoroner file editable korar jonno restriction tule dewa holo (shudhu directory baade ba general text file hisebe dhore)
            $is_editable = $is_dir || !in_array($ext, ['exe', 'zip', 'tar', 'gz', 'rar', 'iso', 'img', 'bin', 'pdf', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'mp3', 'mp4']);

            $result[] = [
                'name' => $item,
                'full_path' => $item_full,
                'is_dir' => $is_dir,
                'is_editable' => $is_editable,
                'ext' => $ext,
                'mtime' => @filemtime($item_full) ?: 0,
                'size' => is_file($item_full) ? (@filesize($item_full) ?: 0) : 0
            ];
        }
        echo json_encode([
            'status' => 'success', 
            'current' => $target_dir,
            'parent' => $parent_dir,
            'items' => $result
        ]);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Directory not accessible']);
    }
    exit;
}

$initial_file = $_GET['file'] ?? '';
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <script>(function(){var k='neon_ui_theme';function apply(){var t='dark';try{t=localStorage.getItem(k)||'dark'}catch(e){}document.documentElement.classList.toggle('editor-light',t==='light');document.documentElement.classList.toggle('editor-dark',t!=='light');document.documentElement.classList.toggle('dark',t!=='light')}apply();addEventListener('storage',function(e){if(e.key===k)apply()})})();</script>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta name="theme-color" content="#090d16">
    <title>FileDash Editor - Advance File Manager</title>
    <?php fdJs('tailwind.js'); ?>

    <!-- CodeMirror & Multiple Themes -->
    <?php fdCss('cm/codemirror.min.css'); ?>
    <?php fdCss('cm/theme/dracula.min.css'); ?>
    <?php fdCss('cm/theme/monokai.min.css'); ?>
    <?php fdCss('cm/theme/material.min.css'); ?>
    <?php fdCss('cm/theme/eclipse.min.css'); ?>
    <?php fdCss('cm/theme/solarized.min.css'); ?>

    <!-- Search & Dialog Addons -->
    <?php fdCss('cm/addon/dialog/dialog.min.css'); ?>
    <?php fdCss('cm/addon/search/matchesonscrollbar.css'); ?>

    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: { extend: { colors: { darkBg: '#090d16', sidebarBg: '#0d1322' } } }
        }
    </script>
    <?php fdCss('fa/css/all.min.css'); ?>
    <style>
        html.editor-light body{background:#eef2fb!important;color:#172033!important}
        html.editor-light body [class*="bg-slate-"]{background-color:#f8faff!important;border-color:#d8deeb!important}
        html.editor-light body [class*="text-slate-"]{color:#475569!important}
        html.editor-light body [class*="border-slate-"]{border-color:#d8deeb!important}
        html.editor-light #workspace,html.editor-light .workspace{background:#edf1f8!important}
        html.editor-light .glass-panel{background:rgba(255,255,255,.94)!important;border-color:#d8deeb!important;color:#26334a!important}
        html.editor-light #toolbarRow,html.editor-light #tabBar{background:#f8faff!important;border-color:#d8deeb!important}
        html.editor-light .ibtn{background:#fff!important;border-color:#d6deea!important;color:#475569!important}
        html.editor-light .ibtn:hover{background:#eef2ff!important;color:#3730a3!important}
        html.editor-light #settingsBox{background:#fff!important;border-color:#d5dceb!important;box-shadow:0 16px 35px rgba(30,41,59,.16)!important}
        html.editor-light .sel,html.editor-light #settingsBox select{background:#f5f7fc!important;color:#1e293b!important;border-color:#cbd5e1!important}
        html.editor-light #explorerPanel,html.editor-light #sidebar,html.editor-light .sidebar{background:#f8faff!important;color:#26334a!important;border-color:#d8deeb!important}
        html.editor-light .tree-row,html.editor-light .tab-item{color:#334155!important}
        html.editor-light .tree-row:hover,html.editor-light .tab-item:hover{background:#e8edfa!important}
        html.editor-light .editor-menu-item{color:#26334a!important}
        html.editor-light #editorContextMenu{background:linear-gradient(160deg,#fff,#f1f5fb)!important;border-color:#cbd5e1!important}
        html.editor-light .editor-menu-item:hover{background:#e8edfa!important;color:#111827!important}
        html.editor-light .CodeMirror-dialog{background:#f8fafc!important;color:#1e293b!important;border-color:#cbd5e1!important}
        html.editor-light .CodeMirror-dialog input{background:#fff!important;color:#1e293b!important;border-color:#cbd5e1!important}
        /* Home-inspired light skin: soft lavender canvas, crisp white surfaces, subtle accent glow */
        html.editor-light body{background:radial-gradient(900px 520px at 0% 0%,rgba(99,102,241,.13),transparent 62%),radial-gradient(760px 460px at 100% 100%,rgba(168,85,247,.09),transparent 60%),#f3f5fc!important;color:#182238!important}
        html.editor-light #toolbarRow,html.editor-light #tabBar{background:rgba(255,255,255,.88)!important;border-color:#e0e5f2!important;box-shadow:0 5px 18px rgba(43,56,100,.05)}
        html.editor-light #sidebar,html.editor-light #explorerPanel,html.editor-light .sidebar{background:rgba(255,255,255,.92)!important;border-color:#e1e6f2!important;box-shadow:8px 0 28px rgba(50,65,110,.045)}
        html.editor-light .glass-panel,html.editor-light #settingsBox{background:rgba(255,255,255,.97)!important;border-color:#dfe4f1!important;color:#26334a!important;box-shadow:0 18px 42px rgba(40,52,95,.14)!important}
        html.editor-light .ibtn{background:linear-gradient(180deg,#fff,#f7f8fe)!important;border-color:#e0e5f1!important;color:#53617b!important;box-shadow:0 2px 6px rgba(35,48,90,.04)}
        html.editor-light .ibtn:hover{background:#eef1ff!important;border-color:#c9d0f4!important;color:#4338ca!important}
        html.editor-light .tree-row:hover,html.editor-light .tab-item:hover{background:#eef1ff!important}
        html.editor-light .tab-item.active{background:linear-gradient(135deg,rgba(99,102,241,.16),rgba(168,85,247,.10))!important;color:#4338ca!important;border-color:#c7cdf5!important}
        html.editor-light #settingsBox .sel{background:#f7f8fd!important;color:#24314a!important;border-color:#d9dfed!important}
        html.editor-light #settingsBox label > span{color:#64708a!important}
        html.editor-light #editorWrap{background:#f5f7fc!important}
        /* Create File / Create Folder modal: keep every surface light in Light UI */
        html.editor-light #createModal > .glass-panel{
            background:linear-gradient(145deg,rgba(255,255,255,.99),rgba(247,249,255,.98))!important;
            border-color:#dfe5f2!important;color:#24314a!important;
            box-shadow:0 24px 70px rgba(35,48,90,.22)!important;
        }
        html.editor-light #createModal #modalTitle{color:#202b43!important}
        html.editor-light #createModal #newItemName{
            background:#f7f9fe!important;color:#1e293b!important;
            border-color:#d5ddec!important;box-shadow:inset 0 1px 2px rgba(30,41,59,.04)
        }
        html.editor-light #createModal #newItemName::placeholder{color:#94a3b8!important}
        html.editor-light #createModal .create-actions{
            background:rgba(255,255,255,.98)!important;
            border-top:1px solid #e7ebf4!important;
        }
        html.editor-light #createModal .create-actions button:first-child{
            background:#eef1f8!important;color:#475569!important;
            border:1px solid #dce2ed!important;
        }
        html.editor-light #createModal .create-actions button:first-child:hover{background:#e4e9f4!important;color:#26334a!important}
        html.editor-light #createModal .create-actions button:last-child{
            background:linear-gradient(135deg,#6366f1,#4f46e5)!important;
            color:#fff!important;border:1px solid #4f46e5!important;
            box-shadow:0 4px 12px rgba(79,70,229,.2)
        }
        /* FileDash Home-matched light skin for the IDE interface (CodeMirror editor colors stay independent). */
        html.editor-light {
            --ide-bg:#eef1fb; --ide-card:#ffffff; --ide-card2:#f5f7fd;
            --ide-text:#151a33; --ide-muted:#64708f; --ide-border:rgba(20,26,60,.11);
            --ide-hover:rgba(99,102,241,.09); --ide-shadow:0 12px 34px rgba(30,40,100,.10);
            color-scheme:light;
        }
        html.editor-light body {
            background:var(--ide-bg)!important; color:var(--ide-text)!important;
        }
        html.editor-light body::before {
            content:""; position:fixed; inset:0; z-index:-1; pointer-events:none;
            background:radial-gradient(600px 400px at 8% -5%,color-mix(in srgb,var(--ac,#6366f1) 22%,transparent),transparent),
                       radial-gradient(500px 380px at 100% 100%,color-mix(in srgb,var(--ac2,#ec4899) 16%,transparent),transparent);
        }
        html.editor-light body [class*="bg-slate-950"],
        html.editor-light body [class*="bg-slate-900"],
        html.editor-light body [class*="bg-slate-800"],
        html.editor-light body [class*="bg-darkBg"],
        html.editor-light body [class*="bg-\[#"] {
            background-color:var(--ide-card)!important;
        }
        html.editor-light body [class*="text-slate-100"],
        html.editor-light body [class*="text-slate-200"],
        html.editor-light body [class*="text-slate-300"],
        html.editor-light body [class*="text-gray-100"],
        html.editor-light body [class*="text-gray-200"] { color:var(--ide-text)!important; }
        html.editor-light body [class*="text-slate-400"],
        html.editor-light body [class*="text-slate-500"],
        html.editor-light body [class*="text-gray-400"],
        html.editor-light body [class*="text-gray-500"] { color:var(--ide-muted)!important; }
        html.editor-light body [class*="border-slate-700"],
        html.editor-light body [class*="border-slate-800"],
        html.editor-light body [class*="border-slate-600"] { border-color:var(--ide-border)!important; }
        html.editor-light .glass-panel,
        html.editor-light #sidebar,
        html.editor-light #explorerPanel,
        html.editor-light #workspace,
        html.editor-light .workspace,
        html.editor-light #toolbarRow,
        html.editor-light #tabBar {
            background:rgba(255,255,255,.92)!important;
            border-color:var(--ide-border)!important;
            color:var(--ide-text)!important;
            box-shadow:var(--ide-shadow)!important;
            backdrop-filter:blur(16px);
        }
        html.editor-light .ibtn,
        html.editor-light .bbtn,
        html.editor-light .sel,
        html.editor-light #settingsBox,
        html.editor-light #editorContextMenu {
            background:var(--ide-card)!important; color:var(--ide-muted)!important;
            border-color:var(--ide-border)!important;
            box-shadow:0 4px 14px rgba(30,40,100,.07)!important;
        }
        html.editor-light .ibtn:hover,
        html.editor-light .bbtn:active,
        html.editor-light .tree-row:hover,
        html.editor-light .tab-item:hover,
        html.editor-light .editor-menu-item:hover {
            background:var(--ide-hover)!important; color:var(--ide-text)!important;
        }
        html.editor-light .tab-item.active {
            background:linear-gradient(135deg,rgba(99,102,241,.14),rgba(236,72,153,.08))!important;
            border-color:rgba(99,102,241,.22)!important; color:#4338ca!important;
        }
        html.editor-light .editor-menu-item { color:var(--ide-text)!important; }
        html.editor-light .editor-menu-item i { color:var(--ac,#6366f1)!important; }
        html.editor-light .editor-menu-sep { border-color:var(--ide-border)!important; }
        html.editor-light #settingsBox label>span { color:var(--ide-muted)!important; }
        html.editor-light .sel option { background:#fff!important; color:var(--ide-text)!important; }
        html.editor-light #createModal > .glass-panel,
        html.editor-light #propertiesModal .glass-panel {
            background:rgba(255,255,255,.98)!important; color:var(--ide-text)!important;
            border-color:var(--ide-border)!important;
        }
        html.editor-light #createModal .create-actions {
            background:#fff!important; border-color:var(--ide-border)!important;
        }
        html.editor-light #createModal #newItemName,
        html.editor-light #pathInput,
        html.editor-light #createModal input {
            background:#f5f7fd!important; color:var(--ide-text)!important;
            border-color:var(--ide-border)!important;
        }
        html.editor-light #createModal .create-actions button:first-child {
            background:#f1f3fa!important; color:#475569!important; border:1px solid var(--ide-border)!important;
        }
        html.editor-light #createModal .create-actions button:last-child {
            background:linear-gradient(135deg,var(--ac,#6366f1),var(--ac2,#ec4899))!important;
            color:#fff!important; border:0!important;
        }
        html.editor-light #editorWrap { background:#f7f8fd!important; }
        /* Keep the code canvas governed by its own CodeMirror theme, not the IDE skin. */
        html.editor-light .CodeMirror { box-shadow:none!important; }

        html, body { overscroll-behavior: none; -webkit-tap-highlight-color: transparent; }
        body { position: fixed; top: 0; left: 0; right: 0; height: 100vh; height: 100dvh; }
        .no-scrollbar::-webkit-scrollbar { display: none; }
        .no-scrollbar { -ms-overflow-style: none; scrollbar-width: none; }

        .glass-panel {
            background: rgba(15, 23, 42, 0.92);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.08);
        }

        /* Editor fills whatever space is left */
        #editorWrap { position: relative; flex: 1 1 0%; min-height: 0; }
        #editorWrap .CodeMirror {
            position: absolute; inset: 0; height: auto !important;
            font-family: 'Fira Code', Consolas, Monaco, monospace;
            font-size: 14px; line-height: 1.6;
        }
        .CodeMirror-scroll { overscroll-behavior: contain; }
        .CodeMirror-gutters { border-right: 1px solid rgba(148,163,184,.22) !important; }
        /* Mobile: tighter line-number gutter so the code area gets more width */
        @media (max-width: 767px) {
            .CodeMirror-linenumber { padding: 0 3px 0 2px !important; min-width: 0 !important; font-size: 12.5px; font-weight: 700; }
            /* fold arrows column is hidden on mobile (folding still works from the keyboard) */
            .fold-gutter { display: none !important; width: 0 !important; }
            .fold-m { display: none !important; }
            .CodeMirror pre.CodeMirror-line, .CodeMirror pre.CodeMirror-line-like { padding: 0 3px !important; }
        }
        .CodeMirror-matchingbracket {
            background-color: rgba(99, 102, 241, 0.4) !important;
            color: #ffffff !important; font-weight: bold; border-bottom: 1px solid #6366f1;
        }
        .CodeMirror-dialog {
            background: #0f172a !important; color: #e2e8f0; border-bottom: 1px solid #334155;
            padding: 8px 12px; z-index: 20;
        }
        .CodeMirror-dialog input { background: #1e293b; color: #f1f5f9; border: 1px solid #475569; border-radius: 6px; padding: 4px 8px; outline: none; }
        .CodeMirror-dialog button { color: #a5b4fc; }

        /* Buttons: big touch targets on mobile, compact on desktop */
        .ibtn {
            display: inline-flex; align-items: center; justify-content: center;
            min-width: 36px; height: 36px; padding: 0 8px; border-radius: 10px;
            font-size: 14px; color: #cbd5e1; background: #1e293b; border: 1px solid #334155;
            transition: background .15s; flex-shrink: 0;
        }
        .ibtn:active { background: #334155; }
        @media (min-width: 768px) {
            .ibtn { min-width: 32px; height: 32px; font-size: 12px; padding: 0 8px; border-radius: 8px; }
            .ibtn:hover { background: #334155; }
        }

        /* Tabs */
        .tab-item { flex-shrink: 0; max-width: 220px; height: 34px; }
        .tab-item.active { background: rgba(99, 102, 241, 0.25); border-bottom-color: #6366f1; color: #fff; }
        @media (min-width: 768px) { .tab-item { height: 34px; } }

        /* Sidebar: off-canvas drawer on mobile, collapsible panel on desktop */
        #sidebar { width: 300px; }
        @media (max-width: 767px) {
            #sidebar {
                position: fixed; top: 0; bottom: 0; left: 0; z-index: 100;
                width: min(88vw, 340px);
                transform: translateX(-100%);
                transition: transform .25s ease;
                padding-top: env(safe-area-inset-top);
                padding-bottom: env(safe-area-inset-bottom);
            }
            #sidebar.open { transform: translateX(0); box-shadow: 0 0 40px rgba(0,0,0,.6); }
        }
        @media (min-width: 768px) {
            #sidebar { transition: margin-left .25s ease; }
            #sidebar.collapsed { margin-left: -300px; }
        }
        .tree-row { min-height: 45px; padding-top:6px!important; padding-bottom:6px!important; }
        @media (min-width: 768px) { .tree-row { min-height: 36px; padding-top:6px!important; padding-bottom:6px!important; } }
        .tree-row > i { font-size: 15px; width: 20px !important; }
        @media (min-width: 768px) { .tree-row > i { font-size: 15px; } }

        /* One consistent settings popover on mobile and desktop */
        .sel { background:#0f172a; border:1px solid #334155; border-radius:10px; color:#e2e8f0; padding:8px 10px; font-size:13px; outline:none; width:100%; min-width:0; }
        .sel option { background:#0f172a; }
        #settingsBox { display:none; }
        #settingsBox.show { display:flex; }
        #settingsBox {
            position:absolute; right:0; top:calc(100% + 10px); z-index:120;
            width:230px; flex-direction:column; gap:11px; padding:13px;
            background:#0f172a; border:1px solid #334155; border-radius:14px;
            box-shadow:0 20px 40px rgba(0,0,0,.35);
        }
        #settingsBox label { display:flex; flex-direction:column; align-items:stretch; gap:5px; }
        #settingsBox label > span, #settingsBox label > i { color:#94a3b8; font-size:11px; font-weight:600; }
        #settingsBox label > i { display:none!important; }

        /* Mobile: top toolbar row auto-hides (tabs stay) */
        @media (max-width: 767px) {
            #toolbarRow { max-height: 60px; transition: max-height .2s ease, padding .2s ease, opacity .2s ease; }
            #toolbarRow.toolbar-hidden { max-height: 0; padding-top: 0; padding-bottom: 0; opacity: 0; overflow: hidden; pointer-events: none; }
        }

        /* Mobile bottom bar */
        .bbtn {
            display: flex; flex-direction: column; align-items: center; justify-content: center;
            gap: 1px; padding: 5px 0; font-size: 9px; color: #cbd5e1;
        }
        .bbtn i { font-size: 15px; }
        .bbtn:active { background: #1e293b; }
        #mobileDock .bbtn { flex:1 1 0; min-width:0; padding-left:0; padding-right:0; }
        #mobileDock .bbtn span { white-space:nowrap; overflow:hidden; text-overflow:clip; max-width:100%; font-size:9px; }

        /* Modal becomes bottom sheet on mobile */
        #createModal > div { padding-bottom: calc(1.5rem + env(safe-area-inset-bottom)); }
        @media (max-width: 767px) {
            #createModal { align-items: flex-end; padding: 0; }
            #createModal > div { max-width: 100%; border-bottom-left-radius: 0; border-bottom-right-radius: 0; }
            #newItemName { font-size: 16px; }
            #pathInput { font-size: 13px; }
        }
        @media (max-width: 767px) {
            #createModal { align-items:flex-end; justify-content:center; }
            #createModal > div { width:100%; max-height:min(82dvh,520px); overflow-y:auto; padding-bottom:max(1.5rem,env(safe-area-inset-bottom)); }
            #createModal .create-actions { position:sticky; bottom:0; z-index:2; background:#0f172a; padding-top:10px; padding-bottom:max(8px,env(safe-area-inset-bottom)); }
            #editorContextMenu { max-width:calc(100vw - 12px); }
        }
        .tree-row, .tree-label, .editor-menu-item { font-family: Inter,system-ui,-apple-system,"Noto Sans Bengali","Segoe UI",sans-serif; letter-spacing: 0; }
        /* same font + size as the FileDash home file list */
        .tree-label { font-size: 14px; font-weight: 600; }
        @media (min-width:768px) { .tree-label { font-size: 13.5px; } }
        .editor-menu-item { display:flex; align-items:center; gap:10px; width:100%; padding:11px 13px; color:#e2e8f0; font-size:13px; font-weight:500; text-align:left; border-radius:9px; transition:background .15s,color .15s; }
        .editor-menu-item:hover, .editor-menu-item:focus-visible { background:#263449; color:#fff; outline:none; }
        .editor-menu-item i { color:#a5b4fc; font-size:13px; }
        .editor-menu-item.danger i { color:#fda4af; }
        #editorContextMenu { background:linear-gradient(160deg,#111c30,#0b1220); border-color:#475569; box-shadow:0 18px 48px rgba(0,0,0,.55); padding:6px; }
        .tab-item, .tab-item *, #explorerTree, #explorerTree *, #editorContextMenu, #editorContextMenu * { -webkit-user-select:none; user-select:none; -webkit-touch-callout:none; }
        #explorerTree input, #explorerTree textarea { -webkit-user-select:text; user-select:text; }
        .tab-item { touch-action:pan-x; }
        .crumbs-bar{display:flex;align-items:center;gap:1px;overflow-x:auto;white-space:nowrap;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:3px;scrollbar-width:none;cursor:text;-webkit-overflow-scrolling:touch}
        .crumbs-bar::-webkit-scrollbar{display:none}
        .crumbs-bar .crumb{flex:none;display:inline-flex;align-items:center;gap:5px;padding:4px 8px;border-radius:6px;font-size:12px;color:#cbd5e1;cursor:pointer;transition:background .12s,color .12s}
        .crumbs-bar .crumb:hover{background:rgba(99,102,241,.2);color:#fff}
        .crumbs-bar .crumb.cur{background:rgba(99,102,241,.25);color:#fff;font-weight:600}
        .crumbs-bar .crumb i{color:#818cf8;font-size:11px}
        .crumbs-bar .crumb-sep{flex:none;color:#64748b;font-size:8px}
        .crumbs-bar .crumb-fill{flex:1 0 18px;align-self:stretch;min-height:22px}
        #explorerSearch { transition:opacity .18s ease, transform .18s ease; }
        #explorerSearch.hidden { display:none; }
        #explorerSearch:not(.hidden) { animation:explorerSearchIn .18s ease both; }
        @keyframes explorerSearchIn { from { opacity:0; transform:translateY(-5px); } to { opacity:1; transform:translateY(0); } }
        #explorerSearchToggle { transition:color .15s, background .15s, transform .15s; }
        #explorerSearchToggle:hover { color:#c7d2fe; background:rgba(99,102,241,.16); }
        #explorerSearchToggle:active { transform:scale(.94); }
        .editor-menu-item.danger { color:#fda4af; }
        .editor-menu-sep { border:0; border-top:1px solid #334155; margin:4px 2px; }
        .tree-more { margin-left:auto; width:30px; height:30px; flex-shrink:0; border-radius:7px; color:#94a3b8; }
        /* Mobile notifications are centered; desktop placement remains unchanged. */
        @media (max-width:767px) {
            #toastNotification {
                top: 50% !important;
                left: 50% !important;
                transform: translate(-50%, -50%) !important;
                max-width: min(88vw, 360px);
                width: max-content;
                padding: 14px 18px;
                font-size: 13px;
                line-height: 1.45;
                z-index: 10050;
            }
        }
        @media (min-width:768px) { .tree-more { opacity:0; } .tree-row:hover .tree-more { opacity:1; } }
    </style>
</head>
<body class="bg-darkBg text-slate-100 flex flex-col font-sans overflow-hidden">

    <!-- Toast -->
    <div id="toastNotification" class="fixed left-1/2 -translate-x-1/2 z-[9999] hidden max-w-[90vw] text-center px-5 py-3 rounded-2xl shadow-2xl text-xs font-bold backdrop-blur-xl border" style="top: calc(env(safe-area-inset-top) + 64px)"></div>

    <!-- Top Toolbar -->
    <header class="glass-panel border-b border-slate-800 shadow-2xl flex flex-col z-50 shrink-0" style="padding-top: env(safe-area-inset-top)">
        <div id="toolbarRow" class="px-2 md:px-3 py-1 md:py-2 flex items-center gap-1.5 md:gap-2">

            <button onclick="toggleSidebar()" class="ibtn !bg-indigo-600 !border-indigo-500 text-white" title="Toggle Explorer">
                <i class="fa-solid fa-bars" style="color:#fb7185"></i><span class="hidden sm:inline ml-1.5">Files</span>
            </button>
            <a href="index.php" class="ibtn" title="Manager"><i class="fa-solid fa-house" style="color:#f59e0b"></i></a>

            <!-- Desktop-only edit tools (mobile has them in the bottom bar) -->
            <div class="hidden md:flex items-center gap-1.5">
                <button onclick="undoEdit()" class="ibtn" title="Undo"><i class="fa-solid fa-rotate-left" style="color:#34d399"></i></button>
                <button onclick="redoEdit()" class="ibtn" title="Redo"><i class="fa-solid fa-rotate-right" style="color:#38bdf8"></i></button>
                <button onclick="findText()" class="ibtn" title="Find (Ctrl+F)"><i class="fa-solid fa-magnifying-glass" style="color:#38bdf8"></i></button>
                <button onclick="replaceText()" class="ibtn" title="Replace"><i class="fa-solid fa-retweet" style="color:#f472b6"></i></button>
                <button onclick="openGoLine()" class="ibtn" title="Go to line (Ctrl+G)"><i class="fa-solid fa-arrow-down-1-9 text-amber-400"></i></button>
                <button onclick="formatCode()" class="ibtn" title="Format code (Shift+Alt+F)"><i class="fa-solid fa-wand-magic-sparkles text-fuchsia-400"></i></button>
                <button onclick="openShortcuts()" class="ibtn" title="Keyboard shortcuts (F1)"><i class="fa-solid fa-keyboard text-sky-400"></i></button>
            </div>

            <div class="flex-1"></div>

            <!-- Upload files -->
            <button onclick="document.getElementById('uploadInput').click()" class="ibtn" title="Upload files"><i class="fa-solid fa-cloud-arrow-up text-emerald-400"></i></button>
            <input id="uploadInput" type="file" multiple hidden onchange="uploadFiles(this.files); this.value=''">
            <button onclick="downloadCurrentFile()" class="ibtn" title="Download current file"><i class="fa-solid fa-download text-sky-400"></i></button>
            <!-- Theme / font size -->
            <div class="relative">
                <button id="settingsBtn" onclick="toggleSettings(event)" class="ibtn" title="Editor settings"><i class="fa-solid fa-sliders" style="color:#a78bfa"></i></button>
                <div id="settingsBox" onclick="event.stopPropagation()">
                    <label class="flex flex-col md:flex-row md:items-center gap-1 md:gap-1.5 text-xs text-slate-400">
                        <span><i class="fa-solid fa-circle-half-stroke text-indigo-400 mr-1"></i>UI mode</span>
                        <select id="uiThemeSelect" onchange="changeUiTheme(this.value)" class="sel"><option value="dark">Dark UI</option><option value="light">Light UI</option></select>
                    </label>
                    <label class="flex flex-col md:flex-row md:items-center gap-1 md:gap-1.5 text-xs text-slate-400">
                        <span><i class="fa-solid fa-palette text-indigo-400 mr-1"></i>Theme</span>
                        <i class="fa-solid fa-palette text-indigo-400 hidden md:inline"></i>
                        <select id="themeSelect" onchange="changeTheme(this.value)" class="sel">
                            <option value="dracula">Dracula</option>
                            <option value="monokai">Monokai</option>
                            <option value="material">Material</option>
                            <option value="eclipse">Eclipse</option>
                            <option value="solarized dark">Solarized</option>
                        </select>
                    </label>
                    <label class="flex flex-col md:flex-row md:items-center gap-1 md:gap-1.5 text-xs text-slate-400">
                        <span><i class="fa-solid fa-text-height text-indigo-400 mr-1"></i>Font size</span>
                        <i class="fa-solid fa-text-height text-indigo-400 hidden md:inline"></i>
                        <select id="fontSizeSelect" onchange="changeFontSize(this.value)" class="sel">
                            <option value="12px">12</option>
                            <option value="13px">13</option>
                            <option value="14px">14</option>
                            <option value="15px">15</option>
                            <option value="16px">16</option>
                            <option value="18px">18</option>
                        </select>
                    </label>
                    <label class="flex flex-col md:flex-row md:items-center gap-1 md:gap-1.5 text-xs text-slate-400">
                        <span><i class="fa-solid fa-lightbulb text-indigo-400 mr-1"></i>Auto-complete</span>
                        <select id="acSelect" onchange="changeAc(this.value)" class="sel"><option value="1">On</option><option value="0">Off</option></select>
                    </label>
                    <div class="flex gap-1.5">
                        <button type="button" onclick="formatCode();toggleSettings(event)" class="ibtn flex-1 justify-center"><i class="fa-solid fa-wand-magic-sparkles mr-1.5" style="color:#e879f9"></i>Format</button>
                        <button type="button" onclick="openShortcuts();toggleSettings(event)" class="ibtn flex-1 justify-center"><i class="fa-solid fa-keyboard mr-1.5" style="color:#38bdf8"></i>Shortcuts</button>
                    </div>
                </div>
            </div>

            <button onclick="openCreateModal('file')" class="ibtn" title="New File"><i class="fa-solid fa-file-circle-plus text-indigo-400"></i></button>
            <button onclick="openCreateModal('folder')" class="ibtn" title="New Folder"><i class="fa-solid fa-folder-plus text-amber-400"></i></button>
            <button onclick="saveCurrentFile()" class="ibtn hidden md:inline-flex !bg-emerald-600 !border-emerald-500 text-white font-bold" title="Save (Ctrl+S)">
                <i class="fa-solid fa-floppy-disk" style="color:#10b981"></i><span class="ml-1.5">Save</span>
            </button>
        </div>

        <!-- Multi-Tab Bar -->
        <div id="tabBar" class="flex items-stretch overflow-x-auto no-scrollbar bg-slate-950/80 px-1 border-t border-slate-800 gap-1 min-h-[34px]"></div>
    </header>

    <!-- Workspace -->
    <div class="flex-1 flex min-h-0 overflow-hidden relative">

        <!-- Mobile backdrop for drawer -->
        <div id="backdrop" onclick="closeSidebar()" class="hidden md:hidden fixed inset-0 bg-black/60 backdrop-blur-sm z-[90]"></div>

        <!-- Sidebar Explorer -->
        <aside id="sidebar" class="bg-sidebarBg border-r border-slate-800/80 flex flex-col shadow-2xl shrink-0">
            <div class="p-3 border-b border-slate-800 flex flex-col gap-2">
                <div class="flex items-center justify-between text-xs font-bold text-slate-400 uppercase tracking-wider">
                    <span class="flex items-center gap-2"><i class="fa-solid fa-folder-tree text-indigo-400"></i> Server Explorer</span>
                    <div class="flex items-center gap-1">
                        <button id="explorerSearchToggle" onclick="toggleExplorerSearch()" class="ibtn !min-w-[36px] !h-[36px] md:!min-w-[28px] md:!h-[28px]" title="Search files"><i class="fa-solid fa-magnifying-glass" style="color:#38bdf8"></i></button>
                        <button onclick="fetchDir(currentDir)" class="ibtn !min-w-[36px] !h-[36px] md:!min-w-[28px] md:!h-[28px]" title="Refresh"><i class="fa-solid fa-rotate" style="color:#22d3ee"></i></button>
                        <button onclick="closeSidebar()" class="ibtn md:!hidden !min-w-[36px] !h-[36px] text-rose-400" title="Close"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button>
                    </div>
                </div>
                <div id="explorerSearch" class="hidden">
                    <input type="search" id="explorerSearchInput" placeholder="Search files in this folder..." autocomplete="off" class="w-full bg-slate-900 border border-indigo-500/50 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/30">
                </div>
                <div id="pathBar">
    <div id="crumbs" class="crumbs-bar" title="Click a folder to open it · click the last one (or empty space) to type a path"></div>
    <input type="text" id="pathInput" placeholder="/path/to/folder" autocapitalize="off" autocorrect="off" spellcheck="false"
           class="hidden w-full min-w-0 bg-slate-900 border border-indigo-500/60 rounded-lg px-2.5 py-2 md:py-1 text-[12px] text-slate-200 font-mono focus:outline-none focus:border-indigo-500">
                </div>
            </div>
            <div class="px-3 pt-2 pb-1 flex items-center gap-2 border-b border-slate-800/70">
                <label for="explorerSort" class="text-[11px] font-semibold text-slate-400 whitespace-nowrap">Sort by</label>
                <select id="explorerSort" class="sel !w-full !py-2.5 !px-3 !text-[13px] !font-semibold !min-h-[42px] md:!min-h-[38px]" style="font-family:Inter,system-ui,'Noto Sans Bengali',sans-serif">
                    <option value="name-asc">Name (A–Z)</option><option value="name-desc">Name (Z–A)</option>
                    <option value="date-desc">Date (Oldest)</option><option value="date-asc">Date (Newest)</option>
                    <option value="type">Type</option><option value="size-desc">Size (Largest)</option><option value="size-asc">Size (Smallest)</option>
                </select>
            </div>
            <div id="explorerTree" class="flex-1 overflow-y-auto p-2 space-y-0.5 text-sm md:text-xs" style="overscroll-behavior: contain"></div>
        </aside>

        <!-- Editor Area -->
        <main class="flex-1 min-w-0 flex flex-col bg-slate-950/90 overflow-hidden">
            <div id="editorWrap"><textarea id="codeEditor"></textarea>
                <!-- Search match navigator -->
                <div id="findNav" class="hidden absolute right-2 bottom-2 z-30 flex items-center gap-1 p-1 rounded-xl glass-panel shadow-2xl">
                    <span id="findCount" class="px-2 text-xs font-mono font-bold text-slate-200 whitespace-nowrap">–</span>
                    <button class="ibtn" onmousedown="event.preventDefault()" onclick="findPrev()" title="Previous match (Shift+F3)"><i class="fa-solid fa-chevron-left" style="color:#818cf8"></i></button>
                    <button class="ibtn" onmousedown="event.preventDefault()" onclick="findNext()" title="Next match (F3)"><i class="fa-solid fa-chevron-right" style="color:#818cf8"></i></button>
                    <button class="ibtn !text-rose-400" onmousedown="event.preventDefault()" onclick="closeFind()" title="Close search"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button>
                </div>
            </div>
            <div class="shrink-0 hidden md:flex items-center justify-between gap-3 px-3 py-1 text-[11px] text-slate-400 bg-slate-950 border-t border-slate-800">
                <span id="statusFile" class="truncate font-mono"></span>
                <span class="shrink-0 font-mono"><span id="statusPos">Ln 1, Col 1</span><span id="statusMode" class="ml-2 text-indigo-400"></span></span>
            </div>
        </main>
    </div>

    <!-- Mobile bottom bar: symbols + actions -->
    <nav class="md:hidden shrink-0 bg-slate-950 border-t border-slate-800 z-40" style="padding-bottom: env(safe-area-inset-bottom)">
        <div id="mobileDock" style="display:flex;flex-wrap:nowrap;width:100%">
            <button class="bbtn" onmousedown="event.preventDefault()" onclick="toggleSidebar()"><i class="fa-solid fa-folder-open text-indigo-400"></i><span>Files</span></button>
            <button class="bbtn" onmousedown="event.preventDefault()" onclick="undoEdit()"><i class="fa-solid fa-rotate-left" style="color:#34d399"></i><span>Undo</span></button>
            <button class="bbtn" onmousedown="event.preventDefault()" onclick="redoEdit()"><i class="fa-solid fa-rotate-right" style="color:#38bdf8"></i><span>Redo</span></button>
            <button class="bbtn" onmousedown="event.preventDefault()" onclick="toggleFindReplace('find')"><i class="fa-solid fa-magnifying-glass" style="color:#38bdf8"></i><span>Find</span></button>
            <button class="bbtn" onmousedown="event.preventDefault()" onclick="toggleFindReplace('replace')"><i class="fa-solid fa-retweet" style="color:#f472b6"></i><span>Replace</span></button>
            <button class="bbtn" onmousedown="event.preventDefault()" onclick="openGoLine()"><i class="fa-solid fa-arrow-down-1-9 text-amber-400"></i><span>Line</span></button>
            <button class="bbtn !text-emerald-400 font-bold" onmousedown="event.preventDefault()" onclick="saveCurrentFile()"><i class="fa-solid fa-floppy-disk" style="color:#10b981"></i><span>Save</span></button>
        </div>
    </nav>

    <!-- Create Modal -->
    <!-- Go to line -->
    <div id="goLineModal" class="fixed inset-0 bg-slate-950/70 backdrop-blur-sm z-[210] hidden items-start justify-center p-4 pt-24" onclick="if(event.target===this)closeGoLine()">
        <div class="glass-panel rounded-2xl p-4 w-full max-w-xs shadow-2xl flex flex-col gap-3">
            <div class="flex items-center justify-between text-sm font-bold text-slate-200"><span><i class="fa-solid fa-arrow-down-1-9 text-amber-400 mr-2"></i>Go to line</span><span id="goLineRange" class="text-xs font-medium text-slate-400"></span></div>
            <input id="goLineInput" type="number" inputmode="numeric" min="1" placeholder="Line number" class="w-full bg-slate-900 border border-indigo-500/50 rounded-lg px-3 py-3 text-base text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500/30" onkeydown="if(event.key==='Enter'){event.preventDefault();submitGoLine();}else if(event.key==='Escape'){closeGoLine();}">
            <div class="flex gap-2">
                <button type="button" onclick="closeGoLine()" class="flex-1 py-2.5 rounded-lg text-sm font-semibold bg-slate-800 text-slate-300">Cancel</button>
                <button type="button" onclick="submitGoLine()" class="flex-1 py-2.5 rounded-lg text-sm font-semibold bg-indigo-600 text-white">Go</button>
            </div>
        </div>
    </div>

    <div id="createModal" class="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-[200] hidden items-center justify-center p-4" onclick="if(event.target===this)closeCreateModal()">
        <div class="glass-panel border border-slate-700 rounded-2xl max-w-sm w-full p-6 shadow-2xl space-y-4">
            <h3 id="modalTitle" class="text-sm font-bold text-slate-100 flex items-center gap-2"></h3>
            <input type="text" id="newItemName" placeholder="Enter name..." autocapitalize="off" autocorrect="off" spellcheck="false"
                   class="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-3 md:py-2 text-sm text-slate-200 focus:outline-none focus:border-indigo-500">
            <div class="create-actions flex justify-end gap-2">
                <button onclick="closeCreateModal()" class="px-4 py-3 md:py-2 rounded-xl bg-slate-800 text-slate-300 text-xs">Cancel</button>
                <button onclick="submitCreateItem()" class="px-5 py-3 md:py-2 rounded-xl bg-indigo-600 text-white text-xs font-bold">Create</button>
            </div>
        </div>
    </div>

    <div id="editorPromptModal" class="fixed inset-0 z-[700] hidden items-center justify-center bg-black/70 backdrop-blur-sm p-4" onclick="if(event.target===this)closeEditorPrompt(null)">
        <div class="glass-panel w-full max-w-sm rounded-2xl border border-slate-700 p-5 shadow-2xl">
            <h3 id="editorPromptTitle" class="text-sm font-bold text-slate-100 mb-2">Confirm</h3>
            <p id="editorPromptMessage" class="text-xs text-slate-300 mb-3"></p>
            <input id="editorPromptInput" class="w-full bg-slate-900 border border-slate-700 rounded-xl px-3 py-3 text-sm text-slate-100 outline-none focus:border-indigo-500 hidden" autocomplete="off">
            <div class="flex justify-end gap-2 mt-4"><button type="button" onclick="closeEditorPrompt(null)" class="ibtn">Cancel</button><button id="editorPromptOk" type="button" class="ibtn !bg-indigo-600 !border-indigo-500 !text-white">Continue</button></div>
        </div>
    </div>
    <div id="kbModal" class="fixed inset-0 z-[700] hidden items-center justify-center bg-black/70 backdrop-blur-sm p-4" onclick="if(event.target===this)closeShortcuts()">
        <div class="glass-panel w-full max-w-md max-h-[85dvh] overflow-y-auto rounded-2xl border border-slate-700 p-5 shadow-2xl">
            <div class="flex items-center justify-between"><b class="text-sm text-slate-100"><i class="fa-solid fa-keyboard text-sky-400 mr-2"></i>Keyboard shortcuts</b><button class="ibtn" onclick="closeShortcuts()"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></div>
            <div id="kbBody"></div>
        </div>
    </div>
    <div id="editorContextMenu" class="fixed hidden z-[500] min-w-[190px] max-h-[70dvh] overflow-y-auto rounded-xl border border-slate-700 bg-slate-900 shadow-2xl p-1"></div>
    <div id="propertiesModal" class="fixed inset-0 z-[600] hidden items-center justify-center bg-black/70 p-4">
        <div class="glass-panel w-full max-w-md rounded-2xl p-5 shadow-2xl">
            <div class="flex items-center justify-between mb-3"><b class="text-sm">File properties</b><button class="ibtn" onclick="closeProperties()"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></div>
            <div id="propertiesBody" class="space-y-2 text-xs break-all"></div>
            <div class="flex justify-end mt-4"><button class="ibtn" onclick="closeProperties()">Close</button></div>
        </div>
    </div>
    <!-- CodeMirror Scripts -->
    <?php fdJs('cm/codemirror.min.js'); ?>
    <?php fdJs('cm/mode/xml/xml.min.js'); ?>
    <?php fdJs('cm/mode/javascript/javascript.min.js'); ?>
    <?php fdJs('cm/mode/css/css.min.js'); ?>
    <?php fdJs('cm/mode/htmlmixed/htmlmixed.min.js'); ?>
    <?php fdJs('cm/mode/php/php.min.js'); ?>
    <?php fdJs('cm/mode/clike/clike.min.js'); ?>
    <?php fdJs('cm/mode/sql/sql.min.js'); ?>
    <?php fdJs('cm/mode/python/python.min.js'); ?>
    <?php fdJs('cm/mode/markdown/markdown.min.js'); ?>
    <?php fdJs('cm/addon/edit/matchbrackets.min.js'); ?>
    <?php fdJs('cm/addon/edit/closebrackets.min.js'); ?>
    <?php fdJs('cm/addon/selection/active-line.min.js'); ?>
    <?php fdJs('cm/addon/dialog/dialog.min.js'); ?>
    <?php fdJs('cm/addon/search/searchcursor.min.js'); ?>
    <?php fdJs('cm/addon/search/search.min.js'); ?>
    <?php fdJs('cm/addon/search/annotatescrollbar.min.js'); ?>
    <?php fdJs('cm/addon/search/matchesonscrollbar.min.js'); ?>
    <style>
        .cm-jump{background:rgba(250,204,21,.22)!important}.fold-gutter{width:16px}.fold-m{display:block;cursor:pointer;color:#94a3b8;font-size:11px;text-align:center;user-select:none}.fold-m:hover{color:#a5b4fc}
        .fold-ph{background:rgba(99,102,241,.25);border-radius:5px;padding:0 7px;margin:0 3px;color:#c7d2fe;cursor:pointer;font-size:.85em}
        #acPop{position:fixed;z-index:9990;min-width:150px;max-width:320px;background:#0f172a;border:1px solid #334155;border-radius:10px;box-shadow:0 12px 36px rgba(0,0,0,.5);padding:4px;font:12.5px ui-monospace,Consolas,monospace;color:#cbd5e1}
        #acPop[hidden]{display:none}#acPop .ac-i{padding:5px 9px;border-radius:7px;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}#acPop .ac-i b{color:#818cf8}#acPop .ac-i.on,#acPop .ac-i:hover{background:#4f46e5;color:#fff}#acPop .ac-i.on b{color:#fde68a}
        html.editor-light #acPop{background:#fff;border-color:#cbd5e1;color:#334155;box-shadow:0 12px 36px rgba(15,23,42,.18)}
        .kb-h{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#818cf8;font-weight:700;margin:12px 0 4px}.kb-r{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:6px 0;border-bottom:1px solid rgba(148,163,184,.15);font-size:12.5px}
        .kb-r kbd{font:600 11.5px ui-monospace,Consolas,monospace;background:rgba(99,102,241,.15);border:1px solid rgba(99,102,241,.4);border-radius:7px;padding:2px 8px;white-space:nowrap}
    </style>
    <script>
/* ===== Extra language modes (Ruby · Go · Rust · Shell · YAML · Dockerfile) — built in, no extra files needed ===== */
(function () {
    function W(s) { const o = {}; s.split(' ').forEach(w => { if (w) o[w] = 1; }); return o; }
    function make(name, c) {
        CodeMirror.defineMode(name, function () {
            return {
                name: name, lineComment: c.lc,
                startState: () => ({ blk: 0, ml: null, k: true, f: true }),
                token(stream, st) {
                    if (st.blk) { if (stream.skipTo(c.be)) { stream.match(c.be); st.blk = 0; } else stream.skipToEnd(); return 'comment'; }
                    if (st.ml) { const q = st.ml; let e = false, ch; while ((ch = stream.next()) != null) { if (ch === q && !e) { st.ml = null; break; } e = !e && ch === '\\' && q !== '`'; } return 'string'; }
                    if (stream.sol()) { st.k = true; st.f = true; }
                    if (stream.eatSpace()) return null;
                    if (c.tok) { const r = c.tok(stream, st); if (r !== undefined) { if (r) { st.f = false; } return r; } }
                    st.f = false; st.k = false;
                    if (c.bs && (!c.bsSol || stream.sol()) && stream.match(c.bs)) { st.blk = 1; if (stream.skipTo(c.be)) { stream.match(c.be); st.blk = 0; } else stream.skipToEnd(); return 'comment'; }
                    if (c.lc && stream.match(c.lc)) { stream.skipToEnd(); return 'comment'; }
                    const ch = stream.peek();
                    if (c.q && c.q.indexOf(ch) >= 0) {
                        stream.next(); let e = false, x, closed = false;
                        while ((x = stream.next()) != null) { if (x === ch && !e) { closed = true; break; } e = !e && x === '\\' && ch !== '`'; }
                        if (!closed && c.mlq && c.mlq.indexOf(ch) >= 0) st.ml = ch;
                        return 'string';
                    }
                    if (stream.match(/^(?:0x[\da-f_]+|0b[01_]+|\d[\d_]*(?:\.\d+)?(?:e[+-]?\d+)?)/i)) return 'number';
                    if (stream.match(/^[A-Za-z_][\w]*[?!]?/)) {
                        const w = stream.current();
                        if (c.kw[w]) return 'keyword';
                        if (c.at && c.at[w]) return 'atom';
                        if (c.bi && c.bi[w]) return 'builtin';
                        if (c.ty && /^[A-Z]/.test(w)) return 'variable-3';
                        return null;
                    }
                    stream.next(); return null;
                }
            };
        });
    }
    make('ruby', {
        lc: '#', bs: '=begin', bsSol: true, be: '=end', q: '"\'`', mlq: '"\'',
        kw: W('BEGIN END alias and begin break case class def defined? do else elsif end ensure for if in module next not or redo rescue retry return self super then undef unless until when while yield require require_relative include extend attr_accessor attr_reader attr_writer private protected public lambda proc loop raise'),
        at: W('true false nil'), bi: W('puts print p pp gets format sprintf printf each map select reject reduce inject new initialize to_s to_i to_a to_h length size join split'), ty: true,
        tok(s) { if (s.match(/^@@?\w+/) || s.match(/^\$\w+/)) return 'variable-2'; if (s.match(/^:[A-Za-z_]\w*[?!]?/)) return 'atom'; }
    });
    make('go', {
        lc: '//', bs: '/*', be: '*/', q: '"\'`', mlq: '`',
        kw: W('break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var'),
        at: W('true false nil iota'), bi: W('append cap close complex copy delete imag len make new panic print println real recover string int int8 int16 int32 int64 uint uint8 uint16 uint32 uint64 uintptr float32 float64 bool byte rune error any Println Printf Sprintf Errorf'), ty: true
    });
    make('rust', {
        lc: '//', bs: '/*', be: '*/', q: '"',
        kw: W('as async await break const continue crate dyn else enum extern fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait type unsafe use where while'),
        at: W('true false None Some Ok Err'), bi: W('i8 i16 i32 i64 i128 isize u8 u16 u32 u64 u128 usize f32 f64 bool char str String Vec Option Result Box Rc Arc'), ty: true,
        tok(s) {
            if (s.match(/^'(?:\\.|[^\\'])'/)) return 'string';
            if (s.match(/^'\w+/)) return 'atom';
            if (s.match(/^#!?\[[^\]]*\]/)) return 'meta';
            if (s.match(/^[A-Za-z_]\w*!/)) return 'builtin';
        }
    });
    make('shell', {
        lc: '#', q: '"\'`', mlq: '"\'',
        kw: W('if then else elif fi for while until do done case esac in function select time return exit break continue local export readonly declare unset shift source alias'),
        bi: W('echo printf cd ls cat grep sed awk cut sort uniq find xargs chmod chown mkdir rm cp mv ln tar curl wget ssh scp git docker sudo apt apt-get yum npm pip python php read test eval exec kill ps head tail touch sleep wc tee'),
        tok(s) { if (s.match(/^\$(?:\{[^}]*\}|\(\(?|\w+|[@*#?!$-])/)) return 'variable-2'; }
    });
    make('yaml', {
        lc: '#', q: '"\'',
        kw: {}, at: W('true false null yes no on off True False Null Yes No On Off ~'),
        tok(s, st) {
            if (st.k) {
                if (s.sol() && s.match(/^(?:---|\.\.\.)\s*$/)) return 'meta';
                if (s.match(/^-(?=\s|$)/)) return 'operator';
                if (s.match(/^(?:"[^"]*"|'[^']*'|[^\s#:'"{}\[\],&*!|>%@`-][^#]*?)(?=:(?:\s|$))/)) { st.k = false; return 'attribute'; }
                st.k = false;
            }
            if (s.match(/^[&*][\w-]+/)) return 'variable-2';
            if (s.match(/^![\w!<>-]*/)) return 'meta';
            if (s.match(/^[|>][+-]?\s*$/)) return 'operator';
        }
    });
    make('dockerfile', {
        lc: '#', q: '"\'',
        kw: W('as AS'), at: {},
        tok(s, st) {
            if (st.f) { st.f = false; if (s.match(/^(?:FROM|RUN|CMD|LABEL|MAINTAINER|EXPOSE|ENV|ADD|COPY|ENTRYPOINT|VOLUME|USER|WORKDIR|ARG|ONBUILD|STOPSIGNAL|HEALTHCHECK|SHELL)\b/i)) return 'keyword'; }
            if (s.match(/^\$(?:\{[^}]*\}|\w+)/)) return 'variable-2';
        }
    });
})();
    </script>

    <script>
        const editorEndpoint = window.location.pathname;
        const FD_CSRF = <?= json_encode(fdaCsrf()) ?>;
        const isMobile = () => window.innerWidth < 768;
        const store = {
            get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : v; } catch (e) { return d; } },
            set(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
        };

        const savedUiTheme = store.get('neon_ui_theme', 'dark');
        document.documentElement.classList.toggle('editor-light', savedUiTheme === 'light');
        document.documentElement.classList.toggle('editor-dark', savedUiTheme !== 'light');
        document.documentElement.classList.toggle('dark', savedUiTheme !== 'light');
        const uiThemeSelect = document.getElementById('uiThemeSelect'); if (uiThemeSelect) uiThemeSelect.value = savedUiTheme;
        /* Editor code theme (Dracula etc.) is its own setting — independent of the FileDash skin and of the IDE Light/Dark UI. */
        const savedTheme = store.get('neon_theme', 'dracula');
        const savedFont = store.get('neon_font', '13px');

        /* Ctrl+/ (Cmd+/) — toggle comment on the selected lines (or the current line); comment style follows the language at that spot */
        function toggleLineComment(cm) {
            const styleAt = (ln, ch) => {
                const m = (cm.getModeAt({ line: ln, ch: ch + 1 }).name || '').toLowerCase();
                if (m === 'css') return ['/* ', ' */'];
                if (m === 'xml' || m === 'html' || m === 'htmlmixed' || m === 'markdown') return ['<!-- ', ' -->'];
                if (m === 'python' || m === 'ruby' || m === 'shell' || m === 'yaml' || m === 'dockerfile') return ['# ', ''];
                if (m === 'sql') return ['-- ', ''];
                return ['// ', ''];
            };
            const lines = new Set();
            cm.listSelections().forEach(r => {
                const a = r.from(), b = r.to();
                let end = b.line; if (b.line > a.line && b.ch === 0) end--;
                for (let i = a.line; i <= end; i++) lines.add(i);
            });
            const info = [...lines].sort((x, y) => x - y).map(ln => {
                const t = cm.getLine(ln), ind = t.length - t.trimStart().length;
                return { ln, t, ind, blank: !t.trim(), st: styleAt(ln, ind) };
            });
            const real = info.filter(i => !i.blank);
            if (!real.length) return;
            const isCom = i => { const o = i.st[0].trim(), c = i.st[1].trim(), x = i.t.trim(); return x.startsWith(o) && (!c || x.endsWith(c)); };
            const un = real.every(isCom);
            const minInd = Math.min(...real.map(i => i.ind));
            cm.operation(() => {
                real.forEach(i => {
                    const o = i.st[0], c = i.st[1];
                    if (un) {
                        const lead = i.ind, body = i.t.slice(lead);
                        let rest = body.startsWith(o) ? body.slice(o.length) : body.slice(o.trim().length);
                        if (c) rest = rest.endsWith(c) ? rest.slice(0, -c.length) : rest.replace(new RegExp(c.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*$'), '');
                        cm.replaceRange(i.t.slice(0, lead) + rest, { line: i.ln, ch: 0 }, { line: i.ln, ch: i.t.length });
                    } else {
                        cm.replaceRange(i.t.slice(0, minInd) + o + i.t.slice(minInd) + c, { line: i.ln, ch: 0 }, { line: i.ln, ch: i.t.length });
                    }
                });
            });
        }

        /* ---------- Line shortcuts: duplicate (Ctrl+D) · move (Alt+↑/↓) · delete (Ctrl+Shift+K) ---------- */
        function selLineRange(cm, r) {
            const a = r.from(), b = r.to(); let end = b.line; if (b.line > a.line && b.ch === 0) end--;
            return { from: a.line, to: end };
        }
        function duplicateLines(cm) {
            cm.operation(() => {
                const sels = cm.listSelections().slice().reverse();
                sels.forEach(r => {
                    const a = r.from(), b = r.to();
                    if (!r.empty() && a.line === b.line) { cm.replaceRange(cm.getRange(a, b), b); return; }
                    const g = selLineRange(cm, r); const lines = []; for (let i = g.from; i <= g.to; i++) lines.push(cm.getLine(i));
                    cm.replaceRange('\n' + lines.join('\n'), { line: g.to, ch: cm.getLine(g.to).length });
                });
            });
        }
        function moveLines(cm, dir) {
            const r = cm.listSelections()[0], g = selLineRange(cm, r), last = cm.lastLine();
            if ((dir < 0 && g.from === 0) || (dir > 0 && g.to >= last)) return;
            const a = r.anchor, h = r.head;
            cm.operation(() => {
                const block = []; for (let i = g.from; i <= g.to; i++) block.push(cm.getLine(i));
                if (dir < 0) {
                    const other = cm.getLine(g.from - 1);
                    cm.replaceRange(block.join('\n') + '\n' + other, { line: g.from - 1, ch: 0 }, { line: g.to, ch: cm.getLine(g.to).length });
                } else {
                    const other = cm.getLine(g.to + 1);
                    cm.replaceRange(other + '\n' + block.join('\n'), { line: g.from, ch: 0 }, { line: g.to + 1, ch: other.length });
                }
                cm.setSelection({ line: a.line + dir, ch: a.ch }, { line: h.line + dir, ch: h.ch });
            });
        }
        function deleteLines(cm) {
            cm.operation(() => {
                const set = new Set(); cm.listSelections().forEach(r => { const g = selLineRange(cm, r); for (let i = g.from; i <= g.to; i++) set.add(i); });
                [...set].sort((x, y) => y - x).forEach(n => {
                    if (cm.lineCount() === 1) cm.replaceRange('', { line: 0, ch: 0 }, { line: 0, ch: cm.getLine(0).length });
                    else if (n === cm.lastLine()) cm.replaceRange('', { line: n - 1, ch: cm.getLine(n - 1).length }, { line: n, ch: cm.getLine(n).length });
                    else cm.replaceRange('', { line: n, ch: 0 }, { line: n + 1, ch: 0 });
                });
            });
        }

        let editor = CodeMirror.fromTextArea(document.getElementById('codeEditor'), {
            theme: savedTheme,
            lineNumbers: true,
            autoCloseBrackets: true,
            matchBrackets: true,
            styleActiveLine: true,
            gutters: ['CodeMirror-linenumbers', 'fold-gutter'],
            indentUnit: 4,
            tabSize: 4,
            lineWrapping: store.get('neon_wrap', '1') !== '0',
            extraKeys: {
                'Ctrl-G': () => openGoLine(), 'Cmd-G': () => openGoLine(),
                'Ctrl-/': toggleLineComment, 'Cmd-/': toggleLineComment,
                'Ctrl-D': duplicateLines, 'Cmd-D': duplicateLines,
                'Alt-Up': cm => moveLines(cm, -1), 'Alt-Down': cm => moveLines(cm, 1),
                'Ctrl-Shift-K': deleteLines, 'Cmd-Shift-K': deleteLines,
                'Ctrl-Space': cm => acOpen(cm, true), 'Shift-Alt-F': () => formatCode(),
                'Ctrl-Shift-[': () => foldHere(), 'Ctrl-Shift-]': () => unfoldHere(), 'F1': () => openShortcuts(),
                Tab: cm => cm.somethingSelected() ? cm.indentSelection('add') : cm.replaceSelection('    ', 'end'),
                'Shift-Tab': cm => cm.indentSelection('subtract')
            }
        });
        editor.getWrapperElement().style.fontSize = savedFont;
        document.getElementById('themeSelect').value = savedTheme;
        document.getElementById('fontSizeSelect').value = savedFont;
        document.getElementById('acSelect').value = store.get('neon_ac', '1');

        /* ================= Code folding (gutter arrows · Ctrl+Shift+[ / ]) ================= */
        const FOLD_INDENT_MODES = /^(python|yaml|markdown|htmlmixed|xml|ruby|dockerfile|shell|sql)$/;
        function foldKind(cm) { const m = cm.getDoc().modeOption; return FOLD_INDENT_MODES.test(typeof m === 'string' ? m : (m && m.name) || '') ? 'indent' : 'brace'; }
        function indentOf(t) { return t.length - t.trimStart().length; }
        function braceOpenAt(cm, n) {
            const t = cm.getLine(n); const m = t.match(/[{\[(]\s*(?:\/\/.*|#.*|\/\*.*\*\/)?$/); if (!m) return -1;
            const idx = m.index; const tt = cm.getTokenTypeAt({ line: n, ch: idx + 1 }) || '';
            return /comment|string/.test(tt) ? -1 : idx;
        }
        function foldRange(cm, n) {
            if (foldKind(cm) === 'indent') {
                const t = cm.getLine(n); if (!t.trim()) return null; const i0 = indentOf(t); let end = -1;
                for (let m = n + 1, c = cm.lineCount(); m < c && m < n + 20000; m++) { const x = cm.getLine(m); if (!x.trim()) continue; if (indentOf(x) > i0) end = m; else break; }
                return end < 0 ? null : { from: { line: n, ch: t.length }, to: { line: end, ch: cm.getLine(end).length } };
            }
            const idx = braceOpenAt(cm, n); if (idx < 0) return null;
            let depth = 1; const lc = cm.lineCount();
            for (let ln = n; ln < lc && ln < n + 20000; ln++) {
                const s = cm.getLine(ln);
                for (let ch = ln === n ? idx + 1 : 0; ch < s.length; ch++) {
                    const c = s[ch]; if ('{[('.indexOf(c) < 0 && '}])'.indexOf(c) < 0) continue;
                    if (/comment|string/.test(cm.getTokenTypeAt({ line: ln, ch: ch + 1 }) || '')) continue;
                    if ('{[('.indexOf(c) >= 0) depth++; else if (--depth === 0) return ln === n ? null : { from: { line: n, ch: cm.getLine(n).length }, to: { line: ln, ch: ch } };
                }
            }
            return null;
        }
        function foldableQuick(cm, n) {
            const t = cm.getLine(n);
            if (foldKind(cm) === 'indent') { if (!t.trim()) return false; const i0 = indentOf(t); for (let m = n + 1, c = cm.lineCount(); m < c && m < n + 40; m++) { const x = cm.getLine(m); if (!x.trim()) continue; return indentOf(x) > i0; } return false; }
            return braceOpenAt(cm, n) >= 0 && n < cm.lastLine();
        }
        function foldMarkAt(cm, n) { return cm.getAllMarks().find(m => m.__fold && m.find() && m.find().from.line === n); }
        function toggleFold(cm, n) {
            const ex = foldMarkAt(cm, n); if (ex) { ex.clear(); foldRefresh(); return; }
            const r = foldRange(cm, n); if (!r) return;
            const w = document.createElement('span'); w.className = 'fold-ph'; w.textContent = '⋯'; w.title = 'Click to unfold';
            const mk = cm.markText(r.from, r.to, { collapsed: true, replacedWith: w }); mk.__fold = true; w.onclick = () => { mk.clear(); foldRefresh(); };
            foldRefresh();
        }
        let foldT;
        function foldRefresh() {
            clearTimeout(foldT); foldT = setTimeout(() => {
                const cm = editor, vp = cm.getViewport();
                cm.operation(() => {
                    for (let n = vp.from; n < vp.to; n++) {
                        let el = null;
                        if (foldableQuick(cm, n)) { el = document.createElement('span'); el.className = 'fold-m'; el.textContent = foldMarkAt(cm, n) ? '▸' : '▾'; }
                        cm.setGutterMarker(n, 'fold-gutter', el);
                    }
                });
            }, 120);
        }
        editor.on('gutterClick', (cm, line, gutter) => { if (gutter === 'fold-gutter') toggleFold(cm, line); });
        ['change', 'viewportChange', 'swapDoc'].forEach(ev => editor.on(ev, foldRefresh));
        function foldHere() { const n = editor.getCursor().line; if (!foldMarkAt(editor, n)) toggleFold(editor, n); }
        function unfoldHere() { const n = editor.getCursor().line; const m = foldMarkAt(editor, n); if (m) { m.clear(); foldRefresh(); } }

        /* ================= Auto-complete (words from the file + language keywords + HTML tags) ================= */
        const AC_WORDS = {
            javascript: 'async await break case catch class const continue debugger default delete else export extends finally for function if import instanceof let new return static super switch this throw try typeof var void while yield true false null undefined console.log document window addEventListener removeEventListener querySelector querySelectorAll getElementById getElementsByClassName createElement appendChild removeChild classList innerHTML textContent setAttribute getAttribute setTimeout setInterval clearTimeout JSON stringify parse Promise fetch localStorage sessionStorage length push pop shift unshift map filter reduce forEach includes indexOf slice splice join split replace trim toString parseInt parseFloat Math floor ceil round random Date Object keys values entries Array isArray',
            php: 'abstract array as break case catch class clone const continue default do echo else elseif empty endforeach endif endwhile extends final finally fn for foreach function global if implements include include_once instanceof interface isset list namespace new null print private protected public require require_once return static switch throw trait try unset use var while true false $_GET $_POST $_SESSION $_SERVER $_FILES $_COOKIE $_REQUEST $this count strlen strpos str_replace substr trim explode implode json_encode json_decode file_get_contents file_put_contents is_array is_string in_array array_map array_filter array_merge array_keys array_values array_slice htmlspecialchars preg_match preg_replace date time strtotime sprintf printf var_dump print_r die exit mysqli_connect mysqli_query PDO prepare execute fetch fetchAll session_start header password_hash password_verify',
            css: 'align-items animation background background-color background-image border border-radius bottom box-shadow box-sizing color content cursor display flex flex-direction flex-wrap font-family font-size font-weight gap grid grid-template-columns height justify-content left letter-spacing line-height margin margin-bottom margin-left margin-right margin-top max-height max-width min-height min-width opacity overflow padding padding-bottom padding-left padding-right padding-top position right text-align text-decoration text-transform top transform transition visibility white-space width z-index !important absolute relative fixed sticky none block inline-block center solid pointer auto hidden',
            html: 'a abbr article aside audio b body br button canvas code div footer form h1 h2 h3 h4 h5 h6 head header hr html i iframe img input label li link main meta nav ol option p pre script section select small span strong style table tbody td textarea tfoot th thead title tr ul video',
            attr: 'class id href src alt title type name value placeholder style target rel action method onclick onchange oninput disabled checked readonly required selected hidden data- aria-label colspan rowspan width height for autocomplete',
            python: 'and as assert async await break class continue def del elif else except finally for from global if import in is lambda None nonlocal not or pass raise return try while with yield True False print len range str int float list dict set tuple open self isinstance enumerate zip sorted append join split strip format',
            sql: 'SELECT FROM WHERE INSERT INTO VALUES UPDATE SET DELETE CREATE TABLE ALTER DROP INDEX JOIN LEFT RIGHT INNER OUTER ON GROUP BY ORDER HAVING LIMIT OFFSET DISTINCT COUNT SUM AVG MIN MAX AS AND OR NOT NULL LIKE IN BETWEEN EXISTS UNION PRIMARY KEY FOREIGN REFERENCES DEFAULT AUTO_INCREMENT VARCHAR INT TEXT DATETIME TIMESTAMP',
            clike: 'abstract break case catch char class const continue default do double else enum extends final float for if implements import include int interface long new null package private protected public return short static struct switch this throw try typedef union unsigned void volatile while true false string bool printf main System out println String',
            ruby: 'begin break case class def do else elsif end ensure false for if in module next nil not or raise require rescue retry return self super then true unless until when while yield puts attr_accessor initialize include extend each map select',
            go: 'break case chan const continue default defer else fallthrough for func go if import interface map package range return select struct switch type var append cap copy delete len make new panic recover fmt Println Printf Sprintf Errorf string int bool error nil true false',
            rust: 'as async await break const continue crate dyn else enum fn for if impl in let loop match mod move mut pub ref return self Self struct trait type unsafe use where while println! format! vec! String Vec Option Result Some None Ok Err Box',
            shell: 'if then else elif fi for while do done case esac function echo cd ls cat grep sed awk find chmod chown mkdir rm cp mv tar curl wget export source sudo apt git docker exit return local read test',
            yaml: 'true false null version services image build ports volumes environment depends_on command container_name restart networks name on jobs steps runs-on uses with run env',
            dockerfile: 'FROM RUN CMD LABEL EXPOSE ENV ADD COPY ENTRYPOINT VOLUME USER WORKDIR ARG ONBUILD HEALTHCHECK SHELL AS'
        };
        Object.keys(AC_WORDS).forEach(k => AC_WORDS[k] = AC_WORDS[k].split(' '));
        const acEl = document.createElement('div'); acEl.id = 'acPop'; acEl.hidden = true; document.body.appendChild(acEl);
        let acS = null, acT;
        const acEnabled = () => store.get('neon_ac', '1') !== '0';
        function acClose() { acS = null; acEl.hidden = true; }
        function acKind(cm, pos) {
            const m = ((cm.getModeAt(pos) || {}).name || '').toLowerCase();
            if (m === 'javascript' || m === 'json') return 'javascript'; if (m === 'php') return 'php'; if (m === 'css') return 'css';
            if (m === 'xml' || m === 'htmlmixed' || m === 'html') return 'html'; return AC_WORDS[m] ? m : 'clike';
        }
        function acOpen(cm, manual) {
            if (!acEnabled() && !manual) return;
            if (cm.somethingSelected()) return acClose();
            const cur = cm.getCursor(), line = cm.getLine(cur.line);
            const kind = acKind(cm, cur), dash = kind === 'css' || kind === 'html';
            const re = dash ? /[\w$@!-]/ : /[\w$@]/; let s = cur.ch; while (s > 0 && re.test(line.charAt(s - 1))) s--;
            const prefix = line.slice(s, cur.ch);
            const tok = cm.getTokenAt(cur); if (/comment/.test(tok.type || '')) return acClose();
            if (prefix.length < (manual ? 1 : 2) && !(kind === 'html' && /<\/?$/.test(line.slice(0, s)) && prefix.length >= 1)) return acClose();
            let pool = []; const low = prefix.toLowerCase();
            const afterLt = kind === 'html' && /<\/?$/.test(line.slice(0, s));
            if (afterLt) pool = AC_WORDS.html.slice();
            else if (kind === 'html' && /attribute/.test(tok.type || '')) pool = AC_WORDS.attr.slice();
            else {
                pool = (AC_WORDS[kind] || []).slice();
                const txt = cm.getValue(); const seen = new Set(pool); const rx = /[\w$@-]{3,}/g; let m, n = 0;
                const src = txt.length > 250000 ? txt.slice(Math.max(0, cm.indexFromPos(cur) - 125000), cm.indexFromPos(cur) + 125000) : txt;
                while ((m = rx.exec(src)) && n < 5000) { let w = m[0]; if (!dash) w = w.replace(/-.*$/, ''); if (w.length >= 3 && !seen.has(w)) { seen.add(w); pool.push(w); n++; } }
            }
            const out = []; const seen2 = new Set();
            pool.forEach(w => { const lw = w.toLowerCase(); if (lw.startsWith(low) && w !== prefix && !seen2.has(w)) { seen2.add(w); out.push(w); } });
            out.sort((a, b) => (a.startsWith(prefix) ? 0 : 1) - (b.startsWith(prefix) ? 0 : 1) || a.length - b.length || a.localeCompare(b));
            if (!out.length) return acClose();
            acS = { list: out.slice(0, 8), i: 0, from: { line: cur.line, ch: s }, to: cur, prefix };
            acDraw();
        }
        function acDraw() {
            const S = acS; if (!S) return;
            acEl.innerHTML = S.list.map((w, i) => '<div class="ac-i' + (i === S.i ? ' on' : '') + '" data-i="' + i + '"><b>' + esc2(w.slice(0, S.prefix.length)) + '</b>' + esc2(w.slice(S.prefix.length)) + '</div>').join('');
            acEl.hidden = false;
            const c = editor.cursorCoords(S.from, 'window'), h = acEl.offsetHeight, w = acEl.offsetWidth;
            let top = c.bottom + 3; if (top + h > innerHeight - 8) top = Math.max(8, c.top - h - 3);
            acEl.style.top = top + 'px'; acEl.style.left = Math.max(8, Math.min(c.left, innerWidth - w - 8)) + 'px';
        }
        function esc2(s) { return String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c])); }
        function acPick(i) {
            const S = acS; if (!S) return; const w = S.list[i == null ? S.i : i];
            editor.replaceRange(w, S.from, editor.getCursor()); acClose(); editor.focus();
        }
        acEl.addEventListener('mousedown', e => { e.preventDefault(); const it = e.target.closest('.ac-i'); if (it) acPick(+it.dataset.i); });
        editor.on('keydown', (cm, e) => {
            if (!acS) return;
            const k = e.key; let used = true;
            if (k === 'ArrowDown') { acS.i = (acS.i + 1) % acS.list.length; acDraw(); }
            else if (k === 'ArrowUp') { acS.i = (acS.i - 1 + acS.list.length) % acS.list.length; acDraw(); }
            else if (k === 'Enter' || k === 'Tab') acPick();
            else if (k === 'Escape') acClose();
            else used = false;
            if (used) { e.preventDefault(); e.codemirrorIgnore = true; e.stopPropagation(); }
        });
        editor.on('inputRead', (cm, ch) => { clearTimeout(acT); if (!acEnabled() || (ch.origin && ch.origin !== '+input')) return; acT = setTimeout(() => acOpen(cm, false), 90); });
        editor.on('cursorActivity', cm => { if (!acS) return; const c = cm.getCursor(); if (c.line !== acS.from.line || c.ch < acS.from.ch) acClose(); });
        ['blur', 'scroll', 'swapDoc'].forEach(ev => editor.on(ev, acClose));
        function changeAc(v) { store.set('neon_ac', v); if (v === '0') acClose(); }

        /* ================= Format / beautify (Shift+Alt+F) ================= */
        function isMinified(t) { const n = t.split('\n').length; return t.length / n > 160; }
        function cssBreak(s) {
            let out = '', i = 0, q = null, paren = 0;
            while (i < s.length) {
                const c = s[i];
                if (q) { out += c; if (c === '\\') out += s[++i] || ''; else if (c === q) q = null; i++; continue; }
                if (c === '"' || c === "'") { q = c; out += c; i++; continue; }
                if (c === '/' && s[i + 1] === '*') { const e = s.indexOf('*/', i + 2), end = e < 0 ? s.length : e + 2; out += s.slice(i, end) + '\n'; i = end; continue; }
                if (c === '(') paren++; else if (c === ')') paren--;
                if (c === '}' && paren <= 0 && !/\n[ \t]*$/.test(out)) out += '\n';
                out += c; if (paren <= 0 && (c === '{' || c === ';' || c === '}')) out += '\n'; i++;
            }
            return out.replace(/\n[ \t]*(?=\n)/g, '').replace(/\n[ \t]+/g, '\n');
        }
        function jsBreak(s) {
            let out = '', i = 0, q = null, paren = 0;
            while (i < s.length) {
                const c = s[i];
                if (q) { out += c; if (c === '\\') out += s[++i] || ''; else if (c === q) q = null; i++; continue; }
                if (c === '"' || c === "'" || c === '`') { q = c; out += c; i++; continue; }
                if (c === '/' && s[i + 1] === '/') { let e = s.indexOf('\n', i); if (e < 0) e = s.length; out += s.slice(i, e); i = e; continue; }
                if (c === '/' && s[i + 1] === '*') { const e = s.indexOf('*/', i + 2), end = e < 0 ? s.length : e + 2; out += s.slice(i, end); i = end; continue; }
                if (c === '(') paren++; else if (c === ')') paren--;
                if (c === '}' && !/\n[ \t]*$/.test(out)) out += '\n';
                out += c;
                if (c === '{' || (c === ';' && paren <= 0)) out += '\n';
                else if (c === '}') { const rest = s.slice(i + 1, i + 12).replace(/^\s+/, ''); if (!/^(?:[)\],;.]|else\b|catch\b|finally\b|while\b)/.test(rest)) out += '\n'; }
                i++;
            }
            return out.replace(/\n[ \t]*(?=\n)/g, '').replace(/\n[ \t]+/g, '\n');
        }
        function formatCode() {
            const cm = editor, doc = cm.getDoc(); const mo = doc.modeOption; const mode = typeof mo === 'string' ? mo : (mo && mo.name) || '';
            const ext = (activeFile || '').split('.').pop().toLowerCase();
            const text = cm.getValue(); const scroll = cm.getScrollInfo(); const cur = cm.getCursor();
            let next = null, reindent = true;
            if (ext === 'json') { try { next = JSON.stringify(JSON.parse(text), null, 4); reindent = false; } catch (e) { return showToast('Invalid JSON — cannot format', 'error'); } }
            else if (mode === 'css') { if (isMinified(text)) next = cssBreak(text); }
            else if (mode === 'javascript') { if (isMinified(text)) next = jsBreak(text); }
            else if (mode === 'htmlmixed' || mode === 'xml') { if (isMinified(text)) next = text.replace(/>\s*</g, '>\n<'); }
            else if (mode === 'php' || mode === 'clike') { /* re-indent only */ }
            else return showToast('Format is not available for this file type', 'error');
            cm.operation(() => {
                if (next !== null && next !== text) cm.replaceRange(next, { line: 0, ch: 0 }, { line: cm.lastLine(), ch: cm.getLine(cm.lastLine()).length });
                if (reindent) { cm.execCommand('selectAll'); cm.execCommand('indentAuto'); }
                for (let n = 0, c = cm.lineCount(); n < c; n++) { const t = cm.getLine(n), tr = t.replace(/[ \t]+$/, ''); if (tr !== t) cm.replaceRange(tr, { line: n, ch: 0 }, { line: n, ch: t.length }); }
                cm.setCursor(next !== null && next !== text ? { line: 0, ch: 0 } : cur);
            });
            cm.scrollTo(scroll.left, scroll.top); cm.focus(); showToast('Code formatted');
        }

        /* ================= Keyboard shortcut help ================= */
        const KB_LIST = [
            ['Editing', [['Ctrl + S', 'Save file'], ['Ctrl + /', 'Comment / uncomment lines'], ['Ctrl + D', 'Duplicate line / selection'], ['Alt + ↑ / ↓', 'Move line up / down'], ['Ctrl + Shift + K', 'Delete line'], ['Tab / Shift + Tab', 'Indent / outdent'], ['Shift + Alt + F', 'Format code']]],
            ['Search & navigate', [['Ctrl + F', 'Find'], ['Ctrl + Shift + F / Ctrl + H', 'Replace'], ['F3 / Shift + F3', 'Find next / previous'], ['Ctrl + G', 'Go to line']]],
            ['Assist', [['Ctrl + Space', 'Show suggestions'], ['↑ ↓  Enter / Tab', 'Choose suggestion'], ['Esc', 'Close suggestions'], ['Ctrl + Shift + [  /  ]', 'Fold / unfold current block'], ['F1  or  ?', 'This help']]]
        ];
        function openShortcuts() {
            document.getElementById('kbBody').innerHTML = KB_LIST.map(g => '<div class="kb-h">' + g[0] + '</div>' + g[1].map(r => '<div class="kb-r"><span>' + r[1] + '</span><kbd>' + r[0] + '</kbd></div>').join('')).join('');
            const m = document.getElementById('kbModal'); m.classList.remove('hidden'); m.classList.add('flex');
        }
        function closeShortcuts() { const m = document.getElementById('kbModal'); m.classList.add('hidden'); m.classList.remove('flex'); }
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') closeShortcuts();
            if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey && !e.target.closest('input,textarea,select,[contenteditable],.CodeMirror')) { e.preventDefault(); openShortcuts(); }
        });
        foldRefresh();

        // Server-provided values (safely JSON-encoded)
        let currentDir = <?php echo json_encode($current_base, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
        const initFile = <?php echo json_encode($initial_file, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;

        let openTabs = [];
        let activeFile = '';
        let createType = 'file';
        let docs = {};              // file -> { doc, mode }
        let lastItems = [], lastParent = '';
        let lastDirty = false;

        const emptyDoc = new CodeMirror.Doc('// Open a file from the explorer\n// or create a new one.', 'javascript');

        /* ---------- Session restore: open tabs + unsaved text survive refresh / leaving to Home and coming back ---------- */
        const DRAFT_KEY = 'neon_editor_drafts';
        let drafts = {};
        try { drafts = JSON.parse(store.get(DRAFT_KEY, '') || '{}') || {}; } catch (e) { drafts = {}; }
        try { const st = JSON.parse(store.get('neon_server_tabs', '[]')); if (Array.isArray(st)) openTabs = st.filter(x => typeof x === 'string' && x); } catch (e) {}
        const savedActive = store.get('neon_server_active', '');
        if (initFile) {
            if (!openTabs.includes(initFile)) openTabs.push(initFile);
            activeFile = initFile;
        } else if (savedActive && openTabs.includes(savedActive)) activeFile = savedActive;
        const initLine = <?php echo (int)($_GET['line'] ?? 0); ?>;
        if (initFile && initLine > 0) {
            let tries = 0;
            const iv = setInterval(() => {
                if (docs[initFile] && activeFile === initFile && editor.getDoc() === docs[initFile].doc) {
                    clearInterval(iv); const ln = Math.min(initLine, editor.lineCount()) - 1;
                    editor.setCursor({ line: ln, ch: 0 }); editor.scrollIntoView({ line: ln, ch: 0 }, 200);
                    const h = editor.addLineClass(ln, 'background', 'cm-jump'); setTimeout(() => editor.removeLineClass(ln, 'background', 'cm-jump'), 2800);
                } else if (++tries > 60) clearInterval(iv);
            }, 150);
        }
        else activeFile = openTabs[0] || '';
        function syncDrafts() {
            const out = {};
            openTabs.forEach(f => {
                if (docs[f]) { if (isDirty(f)) out[f] = { text: docs[f].doc.getValue() }; }
                else if (drafts[f]) out[f] = drafts[f];          // tab not loaded yet: keep its saved draft
            });
            drafts = out;
            try { if (Object.keys(out).length) localStorage.setItem(DRAFT_KEY, JSON.stringify(out)); else localStorage.removeItem(DRAFT_KEY); } catch (e) {}
        }
        function applyDraft(file) {
            const d = drafts[file], doc = docs[file] && docs[file].doc;
            if (doc && d && typeof d.text === 'string' && d.text !== doc.getValue()) doc.setValue(d.text);   // makes the tab dirty again
        }
        function preloadTab(file) {
            if (docs[file]) return;
            fetch(`${editorEndpoint}?fdpage=editor&get_content=${encodeURIComponent(file)}`, {credentials:'same-origin', cache:'no-store'})
                .then(res => res.json())
                .then(data => {
                    if (!openTabs.includes(file) || docs[file]) return;
                    if (data.status === 'success') { docs[file] = { doc: new CodeMirror.Doc(data.content, data.mode), mode: data.mode }; applyDraft(file); renderTabs(); }
                    else removeTab(file);
                }).catch(() => {});
        }
        let draftTimer;
        const syncDraftsSoon = () => { clearTimeout(draftTimer); draftTimer = setTimeout(syncDrafts, 400); };
        addEventListener('pagehide', syncDrafts);
        document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') syncDrafts(); });

        /* ---------- Explorer ---------- */
        function fetchDir(dirPath) {
            fetch(`${editorEndpoint}?fdpage=editor&scan_dir=${encodeURIComponent(dirPath)}`, {credentials:'same-origin', cache:'no-store'})
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'success') {
                        currentDir = data.current;
                        document.getElementById('pathInput').value = currentDir;buildCrumbs();
                        lastItems = data.items; lastParent = data.parent;
                        renderExplorer(lastItems, lastParent);
                    } else {
                        showToast(data.message || 'Directory not accessible', 'error');
                    }
                })
                .catch(() => showToast('Network error', 'error'));
        }

        function jumpToPath() { fetchDir(document.getElementById('pathInput').value); }
        const HOME_DIR = <?php echo json_encode($server_root, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
const crumbsBar = document.getElementById('crumbs'), pathInputEl = document.getElementById('pathInput');
function pathEdit(on) {
    crumbsBar.classList.toggle('hidden', on); pathInputEl.classList.toggle('hidden', !on);
    if (on) { pathInputEl.value = currentDir; pathInputEl.focus(); pathInputEl.select(); }
}
function buildCrumbs() {
    crumbsBar.innerHTML = '';
    const win = currentDir.indexOf('\\') > -1 && currentDir.indexOf('/') < 0, sep = win ? '\\' : '/';
    const trim = p => p.replace(/[\\/]+$/, '');
    const home = trim(HOME_DIR || ''), cur = trim(currentDir) || sep;
    const crumbs = [];
    if (home && (cur === home || cur.startsWith(home + sep))) {
        crumbs.push({ label: 'Home', icon: 'fa-solid fa-house', path: HOME_DIR });
        let acc = home; cur.slice(home.length).split(sep).filter(Boolean).forEach(p => { acc += sep + p; crumbs.push({ label: p, path: acc }); });
    } else {
        const parts = cur.split(sep).filter(Boolean); let acc = '';
        if (win) { const d = parts.shift() || ''; acc = d; crumbs.push({ label: d, icon: 'fa-solid fa-hard-drive', path: d + sep }); }
        else crumbs.push({ label: '', icon: 'fa-solid fa-hard-drive', path: '/' });
        parts.forEach(p => { acc += sep + p; crumbs.push({ label: p, path: acc }); });
    }
    crumbs.forEach((c, i) => {
        const last = i === crumbs.length - 1, b = document.createElement('span');
        b.className = 'crumb' + (last ? ' cur' : ''); b.title = c.path;
        if (c.icon) { const ic = document.createElement('i'); ic.className = c.icon; b.append(ic); }
        if (c.label) b.append(document.createTextNode(c.label));
        b.addEventListener('click', e => { e.stopPropagation(); if (last) pathEdit(true); else fetchDir(c.path); });
        if (i) { const sp = document.createElement('i'); sp.className = 'fa-solid fa-chevron-right crumb-sep'; crumbsBar.append(sp); }
        crumbsBar.append(b);
    });
    const fill = document.createElement('span'); fill.className = 'crumb-fill'; crumbsBar.append(fill);
    crumbsBar.scrollLeft = crumbsBar.scrollWidth;
}
crumbsBar.addEventListener('click', () => pathEdit(true));
pathInputEl.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); jumpToPath(); pathEdit(false); } else if (e.key === 'Escape') pathEdit(false); });
pathInputEl.addEventListener('blur', () => setTimeout(() => pathEdit(false), 120));
buildCrumbs();
        
        let suppressTreeClickUntil = 0;
        function treeRow(iconClass, label, onclick, opts = {}) {
            const div = document.createElement('div');
            div.className = 'tree-row flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg transition truncate ' +
                (opts.disabled ? 'text-slate-500' : 'cursor-pointer text-slate-300 hover:bg-slate-800/60 hover:text-white active:bg-slate-800') +
                (opts.active ? ' bg-indigo-500/20 text-white' : '');
            const i = document.createElement('i');
            i.className = iconClass + ' w-4 text-center shrink-0';
            const s = document.createElement('span');
            s.className = 'tree-label truncate';
            s.textContent = label;
            div.append(i, s);
            if (onclick) div.addEventListener('click', e => { if(Date.now()<suppressTreeClickUntil){e.preventDefault();return;} onclick(e); });
            return div;
        }

        let explorerSort = store.get('neon_explorer_sort','name-asc');
        const sortControl=document.getElementById('explorerSort'); sortControl.value=explorerSort;
        sortControl.addEventListener('change',()=>{explorerSort=sortControl.value;store.set('neon_explorer_sort',explorerSort);renderExplorer(lastItems,lastParent);});
        function sortExplorerItems(items) {
            const list=items.filter(it=>it.name!=='..').slice();
            const val=(it,k)=>Number(it[k]||0);
            list.sort((a,b)=>{
                if(explorerSort==='type') return (b.is_dir-a.is_dir)||String(a.name).localeCompare(String(b.name));
                if(explorerSort.startsWith('date')) return (explorerSort==='date-desc'?1:-1)*(val(a,'mtime')-val(b,'mtime'));
                if(explorerSort.startsWith('size')) return (explorerSort==='size-desc'?-1:1)*(val(a,'size')-val(b,'size'));
                const n=String(a.name).localeCompare(String(b.name),undefined,{numeric:true,sensitivity:'base'});
                return explorerSort==='name-desc'?-n:n;
            }); return list;
        }
        function renderExplorer(items, parentDir) {
            const tree = document.getElementById('explorerTree');
            tree.innerHTML = '';
            const searchInput=document.getElementById('explorerSearchInput'); if(searchInput && searchInput.value) searchInput.value='';
            const up = treeRow('fa-solid fa-arrow-turn-up text-indigo-300', 'Parent Directory', () => fetchDir(parentDir));
            up.classList.add('text-indigo-200','bg-indigo-500/10','border','border-indigo-500/30','font-semibold','cursor-pointer','hover:bg-indigo-500/20'); up.title='Go to parent directory';
            up.dataset.parentRow='1';
            tree.appendChild(up);

            sortExplorerItems(items).forEach(item => {
                    const row = treeRow(item.is_dir ? 'fa-solid fa-folder text-amber-400' : (item.is_editable ? 'fa-solid fa-file-code text-indigo-400' : 'fa-solid fa-file text-slate-600'), item.name,
                        item.is_dir ? () => fetchDir(item.full_path) : (item.is_editable ? () => { openFileInTab(item.full_path); closeSidebar(); } : null),
                        { active: item.full_path === activeFile, disabled: !item.is_dir && !item.is_editable });
                    row.dataset.path=item.full_path; row.dataset.dir=item.is_dir?'1':'0'; row.dataset.searchName=item.name.toLowerCase();
                    if (!item.is_dir || item.is_dir) {
                        const more=document.createElement('button');more.type='button';more.className='tree-more';more.title='More actions';more.innerHTML='<i class="fa-solid fa-ellipsis-vertical" style="color:#a78bfa"></i>';
                        more.onclick=e=>{e.stopPropagation();const r=e.currentTarget.parentElement.getBoundingClientRect();showEditorMenu(r.left+Math.min(r.width-12,220),r.top+24,{path:item.full_path,is_dir:item.is_dir});};
                        row.appendChild(more);
                    }
                    tree.appendChild(row);
                });
        }

        let explorerSearchPinned = false;
        function showExplorerSearch(pin=false) {
            const box=document.getElementById('explorerSearch'), input=document.getElementById('explorerSearchInput');
            explorerSearchPinned = explorerSearchPinned || pin;
            box.classList.remove('hidden');
            if (pin) input.focus();
        }
        function hideExplorerSearch(force=false) {
            const box=document.getElementById('explorerSearch'), input=document.getElementById('explorerSearchInput');
            if (!force && (explorerSearchPinned || input.value.trim() || document.activeElement === input)) return;
            box.classList.add('hidden');
            if (force) { explorerSearchPinned=false; input.value=''; filterExplorerItems(''); }
        }
        function toggleExplorerSearch() {
            const box=document.getElementById('explorerSearch');
            if (box.classList.contains('hidden')) showExplorerSearch(true);
            else { explorerSearchPinned=false; hideExplorerSearch(true); }
        }
        const explorerSearchToggle=document.getElementById('explorerSearchToggle');
        const explorerSearchHeader=explorerSearchToggle.closest('.p-3');
        /* hover-peek is for mouse only: on touch, the emulated mouseenter opened the box and the real click then closed it (2 taps needed) */
        const canHover=()=>matchMedia('(hover:hover) and (pointer:fine)').matches;
        explorerSearchToggle.addEventListener('mouseenter',()=>{ if(canHover()) showExplorerSearch(false); });
        explorerSearchHeader.addEventListener('mouseleave',()=>{ if(canHover()) hideExplorerSearch(false); });
        document.getElementById('explorerSearchInput').addEventListener('keydown',e=>{
            if(e.key==='Escape'){ explorerSearchPinned=false; hideExplorerSearch(true); explorerSearchToggle.focus(); }
        });
        function filterExplorerItems(q) {
            const term=(q||'').trim().toLowerCase();
            document.querySelectorAll('#explorerTree .tree-row[data-search-name]').forEach(row=>{
                row.style.display=!term || row.dataset.searchName.includes(term)?'':'none';
            });
        }
        document.getElementById('explorerSearchInput').addEventListener('input',e=>filterExplorerItems(e.target.value));

        /* ---------- Explorer context actions ---------- */
        const contextMenu = document.getElementById('editorContextMenu');
        let contextTarget = null, longPressTimer = null;
        function hideEditorMenu() { contextMenu.classList.add('hidden'); contextMenu.innerHTML = ''; }
        function showEditorMenu(x, y, target, isTab = false) {
            contextTarget = target;
            const p = target.path, dir = !!target.is_dir, name = p.split(/[\\/]/).pop();
            const clip = (() => { try { return JSON.parse(store.get('neon_editor_clip', 'null')); } catch(e) { return null; } })();
            const items = [];
            if (!isTab && dir) items.push(['fa-folder-open','Open folder',() => fetchDir(p)]);
            if (!dir && !isTab) items.push(['fa-file-code','Open in editor',() => openFileInTab(p)]);
            if (!dir) items.push(['fa-download','Download',() => location.href = editorEndpoint + '?fdpage=editor&download=' + encodeURIComponent(p)]);
            if (isTab) items.push([editor.getOption('lineWrapping') ? 'fa-text-width' : 'fa-align-left', editor.getOption('lineWrapping') ? 'No wrap' : 'Wrap text', () => { const v=!editor.getOption('lineWrapping'); editor.setOption('lineWrapping',v); store.set('neon_wrap',v?'1':'0'); editor.refresh(); }]);
            items.push('-');
            items.push(['fa-copy','Copy',() => setEditorClipboard('copy', p)]);
            items.push(['fa-scissors','Cut',() => setEditorClipboard('cut', p)]);
            if (dir && clip) { items.push(['fa-paste','Paste into folder',() => pasteEditorClipboard(p)]); items.push(['fa-clipboard-check','Paste inside this folder',() => pasteEditorClipboard(p)]); }
            if (!dir && clip) items.push(['fa-paste','Paste here (parent folder)',() => pasteEditorClipboard(p.substring(0,p.lastIndexOf('/')) || '/')]);
            items.push(['fa-star','Toggle favorite',() => toggleEditorFavorite(p)]);
            items.push(['fa-pen','Rename',() => renameEditorPath(p)]);
            items.push(['fa-clone','Duplicate',() => runEditorAction('duplicate',{path:p})]);
            if (!dir && p.toLowerCase().endsWith('.zip')) items.push(['fa-box-open','Extract here',() => runEditorAction('extract',{path:p})]);
            items.push(['fa-link','Share link',() => shareEditorPath(p)]);
            items.push(['fa-link','Copy full path',() => copyEditorText(p)]);
            items.push(['fa-circle-info','Properties',() => showProperties(p)]);
            items.push('-');
            items.push(['fa-trash','Move to Trash',() => deleteEditorPath(p), true]);
            contextMenu.innerHTML = '';
            items.forEach(item => {
                if (item === '-') { const hr=document.createElement('hr'); hr.className='editor-menu-sep'; contextMenu.append(hr); return; }
                const [ic, label, fn, danger] = item, b=document.createElement('button');
                b.type='button'; b.className='editor-menu-item' + (danger?' danger':'');
                b.innerHTML='<i class="fa-solid '+ic+' w-4" style="color:'+(danger?'#fb7185':({'fa-folder-open':'#f59e0b','fa-file-code':'#8b5cf6','fa-download':'#10b981','fa-copy':'#818cf8','fa-scissors':'#f43f5e','fa-paste':'#c084fc','fa-clipboard-check':'#c084fc','fa-star':'#f59e0b','fa-pen':'#3b82f6','fa-clone':'#14b8a6','fa-box-open':'#f97316','fa-link':'#ec4899','fa-circle-info':'#38bdf8','fa-text-width':'#38bdf8','fa-align-left':'#38bdf8'}[ic]||'#a5b4fc'))+'"></i><span></span>';
                b.querySelector('span').textContent=label;
                b.onclick=()=>{ hideEditorMenu(); fn(); }; contextMenu.append(b);
            });
            contextMenu.classList.remove('hidden');
            const w=contextMenu.offsetWidth, h=contextMenu.offsetHeight;
            contextMenu.style.left=Math.max(6,Math.min(x,innerWidth-w-6))+'px';
            contextMenu.style.top=Math.max(6,Math.min(y,innerHeight-h-6))+'px';
        }
        function setEditorClipboard(type, path) {
            store.set('neon_editor_clip', JSON.stringify({type, path}));
            showToast((type==='cut'?'Cut: ':'Copied: ')+path.split(/[\\/]/).pop());
        }
        async function editorAction(action, data={}) {
            const fd=new FormData(); fd.append('editor_file_action',action);
            Object.entries(data).forEach(([k,v])=>fd.append(k,v));
            const r=await fetch(editorEndpoint + '?fdpage=editor',{method:'POST',body:fd,credentials:'same-origin'});
            return r.json();
        }
        async function pasteEditorClipboard(dest=currentDir) {
            let c; try { c=JSON.parse(store.get('neon_editor_clip','null')); } catch(e) {}
            if (!c || !c.path) return showToast('Clipboard is empty','error');
            const r=await editorAction(c.type,{path:c.path,dest});
            showToast(r.message,r.status);
            if (r.status==='success') { if(c.type==='cut') store.set('neon_editor_clip',''); fetchDir(currentDir); }
        }
        let editorPromptResolve=null;
        function editorPrompt(opts={}) {
            return new Promise(resolve=>{
                editorPromptResolve=resolve;
                const m=document.getElementById('editorPromptModal'), inp=document.getElementById('editorPromptInput');
                document.getElementById('editorPromptTitle').textContent=opts.title||'Confirm';
                document.getElementById('editorPromptMessage').textContent=opts.message||'';
                document.getElementById('editorPromptOk').textContent=opts.confirm||'Continue';
                inp.classList.toggle('hidden',!opts.input);inp.value=opts.value||'';
                document.getElementById('editorPromptOk').onclick=()=>closeEditorPrompt(opts.input?inp.value:true);
                inp.onkeydown=e=>{if(e.key==='Enter' && opts.input){e.preventDefault();closeEditorPrompt(inp.value);}};
                m.classList.remove('hidden');m.classList.add('flex'); if(opts.input){inp.focus();inp.select();}
            });
        }
        function closeEditorPrompt(value){const m=document.getElementById('editorPromptModal');m.classList.add('hidden');m.classList.remove('flex');if(editorPromptResolve){editorPromptResolve(value);editorPromptResolve=null;}}
        async function deleteEditorPath(path) {
            const name=path.split(/[\\/]/).pop();
            if (!await editorPrompt({title:'Move to Trash',message:'Move “'+name+'” to Trash?',confirm:'Move to Trash'})) return;
            const r=await editorAction('delete',{path});
            showToast(r.message,r.status);
            if(r.status==='success') {
                if(openTabs.includes(path)) removeTab(path);
                fetchDir(currentDir);
            }
        }
        async function runEditorAction(action,data) {
            try { const r=await editorAction(action,data);showToast(r.message,r.status);if(r.status==='success')fetchDir(currentDir); }
            catch(e){showToast('Operation failed','error');}
        }
        async function renameEditorPath(path) {
            const old=path.split(/[\\/]/).pop(), name=await editorPrompt({title:'Rename item',message:'Enter the new file or folder name:',value:old,input:true,confirm:'Rename'});if(name===null || !String(name).trim() || name===old)return;
            const r=await editorAction('rename',{path,name:String(name).trim()});showToast(r.message,r.status);
            if(r.status==='success'){if(openTabs.includes(path)){openTabs=openTabs.map(x=>x===path?r.path:x);if(docs[path]){docs[r.path]=docs[path];delete docs[path];}if(activeFile===path)activeFile=r.path;renderTabs();}fetchDir(currentDir);}
        }
        async function toggleEditorFavorite(path) {
            try { const fd=new FormData();fd.append('path',path);const r=await fetch('index.php?api=fav',{method:'POST',body:fd}).then(x=>x.json());showToast(r.ok?(r.fav?'Added to favorites':'Removed from favorites'):(r.error||'Favorite failed'),r.ok?'success':'error'); }
            catch(e){showToast('Favorite action failed','error');}
        }
        async function shareEditorPath(path) {
            try { const fd=new FormData();fd.append('path',path);fd.append('ttl','86400');const r=await fetch('index.php?api=share',{method:'POST',body:fd}).then(x=>x.json());if(!r.ok)return showToast(r.error||'Share failed','error');const url=new URL('index.php?s='+r.token,location.href).href;await copyEditorText(url);showToast('Share link copied'); }
            catch(e){showToast('Share failed','error');}
        }
        async function copyEditorText(value) { try { await navigator.clipboard.writeText(value);showToast('Copied'); } catch(e) { const t=document.createElement('textarea');t.value=value;document.body.append(t);t.select();document.execCommand('copy');t.remove();showToast('Copied'); } }
        async function showProperties(path) {
            const r=await editorAction('info',{path});
            if(r.status!=='success') return showToast(r.message,'error');
            const d=r.info, rows=[['Name',d.name],['Type',d.type],['Size',d.size===null?'—':formatBytes(d.size)],['Modified',new Date(d.modified*1000).toLocaleString()],['Permissions',d.permissions],['Path',d.path]];
            const body=document.getElementById('propertiesBody'); body.innerHTML='';
            rows.forEach(([k,v])=>{const row=document.createElement('div');row.className='flex justify-between gap-4 border-b border-slate-700/70 py-2';const a=document.createElement('span');a.className='text-slate-400 shrink-0';a.textContent=k;const b=document.createElement('b');b.className='text-right text-slate-200 font-medium';b.textContent=v;row.append(a,b);body.append(row);});
            const m=document.getElementById('propertiesModal');m.classList.remove('hidden');m.classList.add('flex');
        }
        function formatBytes(n){if(n<1024)return n+' B';if(n<1048576)return (n/1024).toFixed(1)+' KB';if(n<1073741824)return (n/1048576).toFixed(1)+' MB';return (n/1073741824).toFixed(2)+' GB';}
        function closeProperties(){const m=document.getElementById('propertiesModal');m.classList.add('hidden');m.classList.remove('flex');}
        function downloadCurrentFile() {
            if (!activeFile) return showToast('No file is currently open', 'error');
            location.href = editorEndpoint + '?fdpage=editor&download=' + encodeURIComponent(activeFile);
        }
        async function uploadFiles(files) {
            if(!files || !files.length) return;
            const fd=new FormData();fd.append('editor_file_action','upload');fd.append('target_dir',currentDir);
            [...files].forEach(f=>fd.append('files[]',f,f.name));
            try { const r=await fetch(editorEndpoint + '?fdpage=editor',{method:'POST',body:fd,credentials:'same-origin'});const d=await r.json();showToast(d.message,d.status);if(d.status==='success')fetchDir(currentDir); }
            catch(e){showToast('Upload failed','error');}
        }
        function dismissMenuOutside(e){ if(!e.target.closest('#editorContextMenu')) hideEditorMenu(); }
        document.addEventListener('pointerdown',dismissMenuOutside,true);
        document.addEventListener('touchstart',dismissMenuOutside,{capture:true,passive:true});
        document.addEventListener('click',dismissMenuOutside,true);
        document.addEventListener('keydown',e=>{if(e.key==='Escape')hideEditorMenu();});
        document.getElementById('explorerTree').addEventListener('contextmenu',e=>{
            const row=e.target.closest('.tree-row[data-path]');
            e.preventDefault();
            // Right-clicking empty space targets the folder currently being viewed,
            // so users can paste after navigating inside the destination folder.
            if(row) showEditorMenu(e.clientX,e.clientY,{path:row.dataset.path,is_dir:row.dataset.dir==='1'});
            else showEditorMenu(e.clientX,e.clientY,{path:currentDir,is_dir:true});
        });
        document.getElementById('explorerTree').addEventListener('touchstart',e=>{
            const row=e.target.closest('.tree-row[data-path]');const t=e.touches[0];
            longPressTimer=setTimeout(()=>{
                suppressTreeClickUntil=Date.now()+900;
                try{getSelection().removeAllRanges();}catch(_){}
                if(row) showEditorMenu(t.clientX,t.clientY,{path:row.dataset.path,is_dir:row.dataset.dir==='1'});
                else showEditorMenu(t.clientX,t.clientY,{path:currentDir,is_dir:true});
            },520);
        },{passive:true});
        ['touchend','touchmove','touchcancel'].forEach(ev=>document.getElementById('explorerTree').addEventListener(ev,()=>clearTimeout(longPressTimer),{passive:true}));

        /* ---------- Tabs & documents ---------- */
        function isDirty(file) { return !!(docs[file] && !docs[file].doc.isClean()); }

        function openFileInTab(filePath) {
            if (!openTabs.includes(filePath)) openTabs.push(filePath);
            switchTab(filePath);
        }

        function renderTabs() {
            const tabBar = document.getElementById('tabBar');
            tabBar.innerHTML = '';
            if (openTabs.length === 0) {
                tabBar.innerHTML = '<span class="text-xs text-slate-500 py-2.5 px-2">No active tabs</span>';
            }
            let activeEl = null;
            openTabs.forEach(file => {
                const name = file.split(/[\\/]/).pop();
                const isActive = file === activeFile;
                const tab = document.createElement('div');
                tab.className = 'tab-item pl-3 pr-1 text-xs font-medium cursor-pointer flex items-center gap-2 text-slate-300 hover:text-white border-b-2 border-transparent transition ' + (isActive ? 'active' : '');
                tab.title = file;
                tab.addEventListener('click', () => switchTab(file));

                const icon = document.createElement('i');
                icon.className = 'fa-solid fa-file-lines text-indigo-400';
                const label = document.createElement('span');
                label.className = 'truncate';
                label.textContent = name;
                tab.append(icon, label);

                if (isDirty(file)) {
                    const dot = document.createElement('span');
                    dot.className = 'w-2 h-2 rounded-full bg-amber-400 shrink-0';
                    tab.appendChild(dot);
                }

                const close = document.createElement('button');
                close.type = 'button';
                close.className = 'w-8 h-8 flex items-center justify-center rounded-md hover:text-rose-400 hover:bg-slate-800/70 shrink-0';
                close.innerHTML = '<i class="fa-solid fa-xmark" style="color:#fb7185"></i>';
                close.addEventListener('click', e => { e.stopPropagation(); closeTab(file); });
                tab.appendChild(close);

                tabBar.appendChild(tab);
                if (isActive) activeEl = tab;
            });
            tabBar.querySelectorAll('.tab-item').forEach((tab, i) => {
                const file=openTabs[i];
                tab.addEventListener('contextmenu',e=>{e.preventDefault();e.stopPropagation();showEditorMenu(e.clientX,e.clientY,{path:file,is_dir:false},true);});
                let timer, tabLongPressed=false;
                tab.addEventListener('touchstart',e=>{const t=e.touches[0];tabLongPressed=false;timer=setTimeout(()=>{tabLongPressed=true;try{getSelection().removeAllRanges();}catch(_){}showEditorMenu(t.clientX,t.clientY,{path:file,is_dir:false},true);},520);},{passive:true});
                tab.addEventListener('touchend',()=>clearTimeout(timer),{passive:true});
                tab.addEventListener('touchmove',()=>clearTimeout(timer),{passive:true});
                tab.addEventListener('touchcancel',()=>clearTimeout(timer),{passive:true});
                tab.addEventListener('click',e=>{if(tabLongPressed){e.preventDefault();e.stopImmediatePropagation();tabLongPressed=false;}},true);
            });
            if (activeEl) activeEl.scrollIntoView({ inline: 'nearest', block: 'nearest' });
            lastDirty = isDirty(activeFile);
            store.set('neon_server_tabs', JSON.stringify(openTabs));
            store.set('neon_server_active', activeFile);
            syncDrafts();
        }

        function showEmpty() {
            editor.swapDoc(emptyDoc);
            editor.setOption('readOnly', 'nocursor');
            updateStatus();
        }

        function attachDoc(file) {
            editor.swapDoc(docs[file].doc);
            editor.setOption('readOnly', false);
            ignoreScrollUntil = Date.now() + 350;
            setToolbar(false);
            editor.refresh();
            updateStatus();
            if (!isMobile()) editor.focus();
        }

        function switchTab(file) {
            activeFile = file;
            renderTabs();
            renderExplorer(lastItems, lastParent);
            if (docs[file]) { attachDoc(file); return; }
            fetch(`${editorEndpoint}?fdpage=editor&get_content=${encodeURIComponent(file)}`, {credentials:'same-origin', cache:'no-store'})
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'success') {
                        docs[file] = { doc: new CodeMirror.Doc(data.content, data.mode), mode: data.mode };
                        applyDraft(file);
                        if (activeFile === file) attachDoc(file);
                        renderTabs();
                    } else {
                        showToast(data.message || 'File not found', 'error');
                        removeTab(file);
                    }
                })
                .catch(() => showToast('Network error', 'error'));
        }

        function removeTab(file) {
            const idx = openTabs.indexOf(file);
            openTabs = openTabs.filter(f => f !== file);
            delete docs[file];
            if (activeFile === file) {
                activeFile = openTabs.length ? openTabs[Math.min(idx, openTabs.length - 1)] : '';
                if (activeFile) { switchTab(activeFile); return; }
                showEmpty();
            }
            renderTabs();
            renderExplorer(lastItems, lastParent);
        }

        async function closeTab(file) {
            if (isDirty(file) && !await editorPrompt({title:'Unsaved changes',message:'This file has unsaved changes. Close without saving?',confirm:'Close anyway'})) return;
            removeTab(file);
        }

        editor.on('change', () => {
            syncDraftsSoon();
            const d = isDirty(activeFile);
            if (d !== lastDirty) renderTabs();
        });
        editor.on('cursorActivity', updateStatus);

        function updateStatus() {
            const pos = editor.getCursor();
            document.getElementById('statusPos').textContent = `Ln ${pos.line + 1}, Col ${pos.ch + 1}`;
            document.getElementById('statusFile').textContent = activeFile ? activeFile : 'No file open';
            document.getElementById('statusMode').textContent = activeFile && docs[activeFile] ? docs[activeFile].mode : '';
        }

        /* ---------- Toast ---------- */
        let toastTimer;
        function showToast(message, type = 'success') {
            const toast = document.getElementById('toastNotification');
            toast.textContent = message;
            toast.className = 'fixed left-1/2 -translate-x-1/2 z-[9999] max-w-[90vw] text-center px-5 py-3 rounded-2xl shadow-2xl text-xs font-bold backdrop-blur-xl border ' +
                (type === 'success'
                    ? 'bg-emerald-950/90 border-emerald-500/50 text-emerald-300 shadow-emerald-900/50'
                    : 'bg-rose-950/90 border-rose-500/50 text-rose-300 shadow-rose-900/50');
            clearTimeout(toastTimer);
            toastTimer = setTimeout(() => toast.classList.add('hidden'), 2500);
        }

        /* ---------- Actions ---------- */
        function saveCurrentFile() {
            if (!activeFile || !docs[activeFile]) {
                showToast('No file is currently open to save!', 'error');
                return;
            }
            const file = activeFile, entry = docs[file];
            const formData = new FormData();
            formData.append('save_file', '1');
            formData.append('csrf', FD_CSRF);
            formData.append('file_path', file);
            formData.append('content', entry.doc.getValue());

            fetch(editorEndpoint + '?fdpage=editor', { method: 'POST', body: formData, credentials:'same-origin' })
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'success') { entry.doc.markClean(); renderTabs(); }
                    showToast(data.message, data.status);
                })
                .catch(() => showToast('Network error - not saved!', 'error'));
        }

        function undoEdit() { editor.undo(); }
        function redoEdit() { editor.redo(); }
        let mobileSearchMode = '';
        function findText() { CodeMirror.commands.find(editor); }
        function replaceText() { CodeMirror.commands.replace(editor); }
        function toggleFindReplace(mode) {
            if (isMobile() && mobileSearchMode === mode && editor.getWrapperElement().querySelector('.CodeMirror-dialog')) {
                const d = editor.getWrapperElement().querySelector('.CodeMirror-dialog');
                if (d) d.remove();
                closeFind(); mobileSearchMode = ''; editor.focus(); return;
            }
            mobileSearchMode = isMobile() ? mode : '';
            mode === 'replace' ? replaceText() : findText();
        }

        /* ---------- Search: jump to next / previous match ---------- */
        const findNav = document.getElementById('findNav');
        const findCount = document.getElementById('findCount');
        function findNext() { CodeMirror.commands.findNext(editor); updateFindCount(); }
        function findPrev() { CodeMirror.commands.findPrev(editor); updateFindCount(); }
        // "3 / 12": which match you are on / how many matches in this file
        let findTimer;
        function updateFindCount() {
            clearTimeout(findTimer);
            findTimer = setTimeout(() => {
                if (findNav.classList.contains('hidden')) return;
                const st = editor.state.search, q = st && st.query;
                if (!q) { findCount.textContent = '–'; return; }
                const cur = editor.getCursor('from'), cs = editor.getSearchCursor(q, { line: 0, ch: 0 }, { caseFold: typeof q === 'string' && q === q.toLowerCase() });
                let total = 0, idx = 0;
                while (cs.findNext()) {
                    total++;
                    if (!idx) { const f = cs.from(); if (f.line === cur.line && f.ch === cur.ch) idx = total; }
                    if (total >= 5000) break;
                }
                findCount.textContent = total === 0 ? 'No match' : (idx ? idx : '–') + ' / ' + total + (total >= 5000 ? '+' : '');
            }, 60);
        }
        editor.on('cursorActivity', updateFindCount);
        editor.on('change', updateFindCount);
        /* ---------- Go to line (Ctrl+G / toolbar button) ---------- */
        function openGoLine() {
            const m = document.getElementById('goLineModal'), inp = document.getElementById('goLineInput');
            document.getElementById('goLineRange').textContent = '1 – ' + editor.lineCount();
            inp.max = editor.lineCount(); inp.value = '';
            m.classList.remove('hidden'); m.classList.add('flex'); setTimeout(() => inp.focus(), 30);
        }
        function closeGoLine() {
            const m = document.getElementById('goLineModal'); m.classList.add('hidden'); m.classList.remove('flex'); editor.focus();
        }
        function submitGoLine() {
            let n = parseInt(document.getElementById('goLineInput').value, 10);
            if (isNaN(n)) return;
            n = Math.max(1, Math.min(n, editor.lineCount()));
            closeGoLine();
            editor.setCursor({ line: n - 1, ch: 0 });
            editor.scrollIntoView({ line: n - 1, ch: 0 }, Math.floor(editor.getScrollInfo().clientHeight / 2));
            editor.focus();
        }
        function closeFind() { findNav.classList.add('hidden'); findCount.textContent = '–'; editor.execCommand('clearSearch'); }
        // show the arrows whenever a find / replace box opens (button, Ctrl+F, ...)
        /* live find: while typing in the Find / Replace box, jump to the first match automatically (wraps around) */
        function attachLiveFind(dlg) {
            const inp = dlg.querySelector('input[type=text], input:not([type])');
            if (!inp || dlg.dataset.live) return;
            const label = (dlg.textContent || '').trim();
            if (!/^(Search|Replace:|Find)/i.test(label)) return;      // not the "With:" / "Replace?" steps
            dlg.dataset.live = '1';
            const start = editor.getCursor('from');
            inp.addEventListener('input', () => {
                const q = inp.value;
                if (!q || (q.length > 1 && q[0] === '/' )) return;     // empty, or /regex/ syntax → leave to CodeMirror
                const opt = { caseFold: q === q.toLowerCase() };
                // nearest match to where the search started: first one at/after it vs. last one before it
                let after = editor.getSearchCursor(q, start, opt), before = null, hit = null;
                const hasAfter = after.findNext();
                const bc = editor.getSearchCursor(q, { line: 0, ch: 0 }, opt);
                while (bc.findNext()) { const f = bc.from(); if (f.line > start.line || (f.line === start.line && f.ch >= start.ch)) break; before = { from: f, to: bc.to() }; }
                if (hasAfter && before) {
                    const dA = after.from().line - start.line, dB = start.line - before.from.line;
                    hit = (dB < dA) ? before : { from: after.from(), to: after.to() };
                } else if (hasAfter) hit = { from: after.from(), to: after.to() };
                else if (before) hit = before;
                if (!hit) { updateFindCount(); return; }
                editor.setSelection(hit.to, hit.from);                 // head at match start → Enter keeps this match instead of skipping it
                editor.scrollIntoView({ from: hit.from, to: hit.to }, Math.floor(editor.getScrollInfo().clientHeight / 2.5));
                // make the ‹ › arrows work right away (before Enter): feed CodeMirror's search state
                const st = editor.state.search || (editor.state.search = { posFrom: null, posTo: null, lastQuery: null, query: null, overlay: null });
                st.query = q; st.queryText = q; st.posFrom = hit.from; st.posTo = hit.to;
                findNav.classList.remove('hidden');
                updateFindCount();
            });
        }
        new MutationObserver(() => {
            const dlg = editor.getWrapperElement().querySelector('.CodeMirror-dialog');
            if (dlg) { findNav.classList.remove('hidden'); attachLiveFind(dlg); updateFindCount(); }
        }).observe(editor.getWrapperElement(), { childList: true });

        function changeUiTheme(mode) {
            const light = mode === 'light';
            document.documentElement.classList.toggle('editor-light', light);
            document.documentElement.classList.toggle('editor-dark', !light);
            document.documentElement.classList.toggle('dark', !light);
            store.set('neon_ui_theme', light ? 'light' : 'dark');
        }

        function changeTheme(themeName) {
            editor.setOption('theme', themeName);
            store.set('neon_theme', themeName);
        }

        function changeFontSize(size) {
            editor.getWrapperElement().style.fontSize = size;
            editor.refresh();
            store.set('neon_font', size);
        }

        /* ---------- Create modal ---------- */
        function openCreateModal(type) {
            createType = type;
            document.getElementById('modalTitle').innerHTML = type === 'file'
                ? '<i class="fa-solid fa-file-circle-plus text-indigo-400"></i> <span>Create New File</span>'
                : '<i class="fa-solid fa-folder-plus text-amber-400"></i> <span>Create New Folder</span>';
            const input = document.getElementById('newItemName');
            input.value = '';
            const m = document.getElementById('createModal');
            m.classList.remove('hidden'); m.classList.add('flex');
            setTimeout(() => input.focus(), 50);
        }

        function closeCreateModal() {
            const m = document.getElementById('createModal');
            m.classList.remove('flex'); m.classList.add('hidden');
            m.style.top = ''; m.style.height = ''; m.firstElementChild.style.maxHeight = '';
        }

        function submitCreateItem() {
            const name = document.getElementById('newItemName').value.trim();
            if (!name) { showToast('Please enter a valid name!', 'error'); return; }

            const formData = new FormData();
            formData.append('create_type', createType);
            formData.append('target_dir', currentDir);
            formData.append('item_name', name);

            fetch(editorEndpoint + '?fdpage=editor', { method: 'POST', body: formData, credentials:'same-origin' })
                .then(res => res.json())
                .then(data => {
                    showToast(data.message, data.status);
                    if (data.status === 'success') {
                        closeCreateModal();
                        fetchDir(currentDir);
                        if (createType === 'file') openFileInTab(currentDir + '/' + name);
                    }
                })
                .catch(() => showToast('Network error', 'error'));
        }
        document.getElementById('newItemName').addEventListener('keydown', e => { if (e.key === 'Enter') submitCreateItem(); });

        /* ---------- Sidebar & settings ---------- */
        function toggleSidebar() {
            const sb = document.getElementById('sidebar');
            if (isMobile()) {
                const open = sb.classList.toggle('open');
                document.getElementById('backdrop').classList.toggle('hidden', !open);
            } else {
                sb.classList.toggle('collapsed');
                setTimeout(() => editor.refresh(), 300);
            }
        }

        function closeSidebar() {
            if (!isMobile()) return;
            document.getElementById('sidebar').classList.remove('open');
            document.getElementById('backdrop').classList.add('hidden');
        }

        function toggleSettings(e) {
            e.stopPropagation();
            document.getElementById('settingsBox').classList.toggle('show');
        }
        document.addEventListener('click', () => document.getElementById('settingsBox').classList.remove('show'));

        /* ---------- Auto-hide toolbar on mobile (keyboard open / scroll down) ---------- */
        const toolbarRow = document.getElementById('toolbarRow');
        let keyboardOpen = false, toolbarHidden = false, lastTop = 0, ignoreScrollUntil = 0, maxViewH = 0;

        function setToolbar(hide) {
            if (!isMobile()) hide = false;
            if (hide === toolbarHidden) return;
            toolbarHidden = hide;
            toolbarRow.classList.toggle('toolbar-hidden', hide);
            if (hide) document.getElementById('settingsBox').classList.remove('show');
            ignoreScrollUntil = Date.now() + 350;       // layout change must not retrigger scroll logic
            setTimeout(() => editor.refresh(), 230);
        }

        function updateKeyboard() {
            const h = window.visualViewport ? window.visualViewport.height : window.innerHeight;
            maxViewH = Math.max(maxViewH, h, window.innerHeight);
            keyboardOpen = isMobile() && h < maxViewH - 150;
            setToolbar(keyboardOpen);
        }

        editor.on('scroll', () => {
            if (!isMobile() || keyboardOpen || Date.now() < ignoreScrollUntil) { lastTop = editor.getScrollInfo().top; return; }
            const top = editor.getScrollInfo().top, delta = top - lastTop;
            if (top < 10) setToolbar(false);
            else if (delta > 12) setToolbar(true);
            else if (delta < -12) setToolbar(false);
            if (Math.abs(delta) > 12 || top < 10) lastTop = top;
        });

        /* ---------- Viewport / keyboard handling ---------- */
        if (window.visualViewport) {
            const vv = window.visualViewport;
            const fit = () => {
                if (vv.scale <= 1.01) document.body.style.height = vv.height + 'px';
                window.scrollTo(0, 0);
                updateKeyboard();
                const modal = document.getElementById('createModal');
                if (!modal.classList.contains('hidden')) {
                    modal.style.top = vv.offsetTop + 'px';
                    modal.style.height = vv.height + 'px';
                    modal.firstElementChild.style.maxHeight = Math.max(220, vv.height - 12) + 'px';
                }
                editor.refresh();
            };
            vv.addEventListener('resize', fit);
            fit();
        }
        window.addEventListener('resize', () => {
            if (!isMobile()) closeSidebar();
            const modal = document.getElementById('createModal');
            if (modal.classList.contains('hidden')) { modal.style.top = ''; modal.style.height = ''; modal.firstElementChild.style.maxHeight = ''; }
            maxViewH = 0;
            updateKeyboard();
            if (!isMobile()) setToolbar(false);
            editor.refresh();
        });
        window.addEventListener('orientationchange', () => setTimeout(() => { maxViewH = 0; updateKeyboard(); editor.refresh(); }, 300));

        /* ---------- Shortcuts & safety ---------- */
        document.addEventListener('keydown', function (e) {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
                e.preventDefault();
                saveCurrentFile();
            } else if (e.key === 'F3') {
                e.preventDefault();
                e.shiftKey ? findPrev() : findNext();
            } else if (e.key === 'Escape') {
                closeCreateModal();
                closeSidebar();
                document.getElementById('settingsBox').classList.remove('show');
            }
        });
        window.addEventListener('beforeunload', e => {
            if (openTabs.some(isDirty)) { e.preventDefault(); e.returnValue = ''; }
        });

        /* ---------- Init ---------- */
        renderTabs();
        showEmpty();
        if (activeFile) switchTab(activeFile);
        openTabs.filter(f => f !== activeFile).forEach(preloadTab);
        fetchDir(currentDir);
    </script>
</body>
</html>
<?php
} }

namespace FDIndex {
use \RecursiveIteratorIterator; use \RecursiveDirectoryIterator; use \FilesystemIterator; use \ZipArchive; use \DateTime; use \DateTimeZone; use \DirectoryIterator; use \SplFileInfo; use \Exception; use \Throwable; use \finfo;
/* hoisted function declarations (must be unconditional) */
function resolveServerPath($path) {
    global $server_root;
    $path = trim($path);
    if ($path === '') return $server_root;
    if (strpos($path, '/') === 0 || preg_match('/^[A-Z]:[\\\\\/]/i', $path)) {
        $real = realpath($path);
        if ($real !== false && file_exists($real)) return $real;
    }
    $real = realpath($server_root . '/' . $path);
    return $real !== false ? $real : $server_root;
}

function streamFile($f, $mime, $attachment = false) {
    $size = filesize($f); $start = 0; $end = $size - 1;
    while (ob_get_level()) @ob_end_clean();
    header('Accept-Ranges: bytes');
    if (isset($_SERVER['HTTP_RANGE']) && preg_match('/bytes=(\d*)-(\d*)/', $_SERVER['HTTP_RANGE'], $m)) {
        if ($m[1] !== '') $start = (int)$m[1];
        if ($m[2] !== '') $end = min((int)$m[2], $end);
        if ($start > $end || $start >= $size) { http_response_code(416); exit; }
        http_response_code(206);
        header("Content-Range: bytes $start-$end/$size");
    }
    header('Content-Type: ' . $mime);
    header('X-Content-Type-Options: nosniff');
    if ($attachment) header('Content-Disposition: attachment; filename="' . str_replace('"', '', basename($f)) . '"');
    header('Content-Length: ' . ($end - $start + 1));
    $fp = fopen($f, 'rb'); fseek($fp, $start); $left = $end - $start + 1;
    while ($left > 0 && !feof($fp)) { $b = fread($fp, min(65536, $left)); echo $b; $left -= strlen($b); }
    fclose($fp); exit;
}

function fdInit() {
    if (is_dir(FD_DATA)) return;
    @mkdir(FD_DATA, 0755, true);
    @file_put_contents(FD_DATA . '/.htaccess', "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
    @file_put_contents(FD_DATA . '/index.html', '');
}

function fdRead($n, $d = []) { $f = FD_DATA . "/$n.json"; if (!is_file($f)) return $d; $j = json_decode((string)@file_get_contents($f), true); return is_array($j) ? $j : $d; }

function fdWrite($n, $v) { fdInit(); @file_put_contents(FD_DATA . "/$n.json", json_encode($v, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT), LOCK_EX); }

function fdLog($a, $d = '') {
    fdInit(); $f = FD_DATA . '/activity.log';
    @file_put_contents($f, json_encode(['t' => time(), 'a' => $a, 'd' => substr((string)$d, 0, 300), 'ip' => $_SERVER['REMOTE_ADDR'] ?? '', 'ua' => substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 250)], JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
    if (@filesize($f) > 300000) { $l = @file($f); if ($l) @file_put_contents($f, implode('', array_slice($l, -600)), LOCK_EX); }
}

function jout($a, $c = 200) { while (ob_get_level()) @ob_end_clean(); http_response_code($c); header('Content-Type: application/json; charset=utf-8'); echo json_encode($a, JSON_UNESCAPED_UNICODE); exit; }

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function fdCopy($s, $d) {
    if (is_dir($s)) { if (!@mkdir($d, 0755)) return false; foreach (scandir($s) as $i) { if ($i === '.' || $i === '..') continue; if (!fdCopy("$s/$i", "$d/$i")) return false; } return true; }
    return @copy($s, $d);
}

function fdIsPrivate($ip) { return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE); }

function fdAbsUrl($base, $loc) {
    if (preg_match('#^https?://#i', $loc)) return $loc;
    $p = parse_url($base); $o = $p['scheme'] . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
    if (strpos($loc, '//') === 0) return $p['scheme'] . ':' . $loc;
    if ($loc !== '' && $loc[0] === '/') return $o . $loc;
    return $o . preg_replace('#/[^/]*$#', '/', $p['path'] ?? '/') . $loc;
}

function fdJobPath($id, $ext = 'json') {
    return FD_DATA . '/download_' . $id . '.' . $ext;
}

function fdJobUpdate($id, $downloaded, $total, $state = 'downloading') {
    if ($id === '') return;
    fdInit();
    @file_put_contents(fdJobPath($id), json_encode([
        'downloaded' => (int)$downloaded,
        'total' => (int)$total,
        'state' => $state,
        'updated' => time()
    ]), LOCK_EX);
}

function fdDownload($url, $destDir, $saveAs, $allowPrivate, $maxBytes, $blockExt, &$err, $jobId = '') {
    if (!function_exists('curl_init')) { $err = 'PHP cURL extension is not enabled on this server'; return false; }
    if (!is_dir($destDir) || !is_writable($destDir)) { $err = 'Destination folder is not writable'; return false; }
    $tmp = $destDir . '/.dl_' . bin2hex(random_bytes(4)) . '.part';
    $hdr = []; $ok = false; $got = 0; $total = 0;
    $cancelFile = $jobId !== '' ? fdJobPath($jobId, 'cancel') : '';
    $lastUpdate = 0;
    fdJobUpdate($jobId, 0, 0, 'starting');

    for ($hop = 0; $hop < 6; $hop++) {
        $p = parse_url($url);
        if (!$p || empty($p['host']) || !in_array(strtolower($p['scheme'] ?? ''), ['http', 'https'], true)) { $err = 'Only valid http(s) URLs are allowed'; break; }
        $host = trim($p['host'], '[]'); $port = $p['port'] ?? (strtolower($p['scheme']) === 'https' ? 443 : 80);
        $ips = filter_var($host, FILTER_VALIDATE_IP) ? [$host] : (fdAndroidDns($host) ?: []);
        if (!$ips) { $err = 'Could not resolve host “' . $host . '”'; break; }
        if (!$allowPrivate) foreach ($ips as $ip) if (fdIsPrivate($ip)) { $err = 'Local / private addresses are blocked'; break 2; }

        $fp = @fopen($tmp, 'wb');
        if (!$fp) { $err = 'Could not create temporary download file'; break; }
        $hdr = []; $got = 0; $total = 0; $tooLarge = false;
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_TIMEOUT => 900,
            CURLOPT_USERAGENT => 'Mozilla/5.0 FileDash/2',
            CURLOPT_RESOLVE => [$host . ':' . $port . ':' . $ips[0]],
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_HTTPHEADER => ['Accept-Encoding: identity'],
            CURLOPT_WRITEFUNCTION => function ($c, $d) use ($fp, &$got, &$total, $maxBytes, $jobId, $cancelFile, &$lastUpdate, &$tooLarge) {
                if ($cancelFile !== '' && is_file($cancelFile)) return 0;
                $len = strlen($d);
                if ($got + $len > $maxBytes) { $tooLarge = true; return 0; }
                $written = fwrite($fp, $d);
                if ($written === false || $written === 0) return 0;
                $got += $written;
                if (microtime(true) - $lastUpdate >= 0.25) {
                    fdJobUpdate($jobId, $got, $total);
                    $lastUpdate = microtime(true);
                }
                return $written;
            },
            CURLOPT_HEADERFUNCTION => function ($c, $l) use (&$hdr, &$total, $jobId, &$got) {
                if (stripos($l, 'HTTP/') === 0) {
                    $hdr = [];
                    $total = 0;
                    $got = 0;
                }
                $x = explode(':', $l, 2);
                if (count($x) === 2) {
                    $key = strtolower(trim($x[0]));
                    $hdr[$key] = trim($x[1]);
                    if ($key === 'content-length') {
                        $total = (int)$hdr[$key];
                        fdJobUpdate($jobId, $got, $total);
                    }
                }
                return strlen($l);
            },
        ]);
        curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $cerr = curl_error($ch);
        curl_close($ch);
        fclose($fp);

        if ($cancelFile !== '' && is_file($cancelFile)) { $err = 'Download cancelled'; break; }
        if ($tooLarge) { $err = 'File is larger than the allowed limit (' . round($maxBytes / 1048576) . ' MB)'; break; }
        if ($code >= 300 && $code < 400 && !empty($hdr['location'])) {
            $url = fdAbsUrl($url, $hdr['location']);
            fdJobUpdate($jobId, 0, 0, 'redirecting');
            continue;
        }
        if ($code >= 200 && $code < 300) { $ok = true; break; }
        $err = $code ? "Server answered HTTP $code" : ($cerr ?: 'Download failed');
        break;
    }

    if (!$ok) {
        @unlink($tmp);
        fdJobUpdate($jobId, $got, $total, ($err === 'Download cancelled' ? 'cancelled' : 'error'));
        @unlink($cancelFile);
        if (!$err) $err = 'Too many redirects';
        return false;
    }

    $name = trim((string)$saveAs);
    if ($name === '' && !empty($hdr['content-disposition'])) {
        $cd = $hdr['content-disposition'];
        if (preg_match("/filename\\*=UTF-8''([^;]+)/i", $cd, $m)) $name = rawurldecode($m[1]);
        elseif (preg_match('/filename="?([^";]+)"?/i', $cd, $m)) $name = $m[1];
    }
    if ($name === '') $name = rawurldecode(basename((string)parse_url($url, PHP_URL_PATH)));
    $name = trim(preg_replace('/[\\\\\/:*?"<>|\x00-\x1f]+/u', '_', $name), " .");
    if ($name === '') $name = 'download_' . time();
    if (strlen($name) > 150) { $e2 = pathinfo($name, PATHINFO_EXTENSION); $name = substr(pathinfo($name, PATHINFO_FILENAME), 0, 120) . ($e2 ? '.' . $e2 : ''); }
    if (in_array(strtolower(pathinfo($name, PATHINFO_EXTENSION)), $blockExt, true)) {
        @unlink($tmp); @unlink($cancelFile); fdJobUpdate($jobId, $got, $total, 'error');
        $err = 'Saving “.' . strtolower(pathinfo($name, PATHINFO_EXTENSION)) . '” files from a URL is blocked for safety';
        return false;
    }
    $dest = $destDir . '/' . $name; $i = 1; $in = pathinfo($name);
    while (file_exists($dest)) { $dest = $destDir . '/' . $in['filename'] . ' (' . $i++ . ')' . (isset($in['extension']) ? '.' . $in['extension'] : ''); }
    if (!@rename($tmp, $dest)) {
        @unlink($tmp); @unlink($cancelFile); fdJobUpdate($jobId, $got, $total, 'error');
        $err = 'Could not save the file';
        return false;
    }
    $savedSize = (int)@filesize($dest);
    fdJobUpdate($jobId, $savedSize, $savedSize, 'complete');
    @unlink($cancelFile);
    return ['name' => basename($dest), 'size' => $savedSize, 'path' => $dest];
}

function fdActMap() {
    return ['upload' => ['fa-cloud-arrow-up', '#6366f1'], 'delete' => ['fa-trash', '#ef4444'], 'download' => ['fa-download', '#10b981'], 'create' => ['fa-folder-plus', '#f59e0b'], 'rename' => ['fa-pen', '#3b82f6'],
            'paste' => ['fa-paste', '#8b5cf6'], 'zip' => ['fa-file-zipper', '#f97316'], 'star' => ['fa-star', '#f59e0b'], 'share' => ['fa-link', '#ec4899'], 'share-open' => ['fa-arrow-up-right-from-square', '#ec4899'],
            'account' => ['fa-user-gear', '#8b5cf6'], 'login' => ['fa-right-to-bracket', '#10b981'], 'login-fail' => ['fa-shield-halved', '#ef4444'], 'logout' => ['fa-right-from-bracket', '#94a3b8'],
            'web' => ['fa-globe', '#06b6d4'], 'extract' => ['fa-box-open', '#f97316'], 'duplicate' => ['fa-clone', '#14b8a6']];
}

function fdUA($ua) {
    $ua = (string)$ua; if ($ua === '') return null;
    $os = 'Unknown OS'; $dev = 'Desktop'; $model = '';
    if (preg_match('/Android ([\d.]+)/', $ua, $m)) { $os = 'Android ' . $m[1]; $dev = stripos($ua, 'Mobile') !== false ? 'Phone' : 'Tablet'; if (preg_match('/Android [\d.]+; ([^;)]+)/', $ua, $mm)) $model = trim($mm[1]); }
    elseif (preg_match('/iPhone|iPad|iPod/', $ua, $m)) { $os = 'iOS' . (preg_match('/OS (\d+)/', $ua, $v) ? ' ' . $v[1] : ''); $dev = $m[0] === 'iPad' ? 'Tablet' : 'Phone'; $model = $m[0]; }
    elseif (preg_match('/Windows NT ([\d.]+)/', $ua, $m)) $os = ['10.0' => 'Windows 10/11', '6.3' => 'Windows 8.1', '6.1' => 'Windows 7'][$m[1]] ?? 'Windows';
    elseif (stripos($ua, 'Mac OS X') !== false) $os = 'macOS';
    elseif (stripos($ua, 'CrOS') !== false) $os = 'ChromeOS';
    elseif (stripos($ua, 'Linux') !== false) $os = 'Linux';
    $br = 'Unknown browser';
    foreach (['Edg' => 'Edge', 'OPR' => 'Opera', 'SamsungBrowser' => 'Samsung Internet', 'Firefox' => 'Firefox', 'FxiOS' => 'Firefox', 'CriOS' => 'Chrome', 'Chrome' => 'Chrome', 'Version' => 'Safari'] as $k => $n)
        if (preg_match('/' . $k . '\/(\d+)/', $ua, $m)) { $br = $n . ' ' . $m[1]; break; }
    return ['dev' => $dev, 'model' => $model, 'os' => $os, 'br' => $br];
}

function fdActLines() {
    $f = FD_DATA . '/activity.log'; if (!is_file($f)) return []; $out = [];
    foreach (array_reverse((array)@file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) as $ln) {
        $r = json_decode($ln, true);
        if (is_array($r) && isset($r['t'], $r['a'])) { $r['id'] = substr(md5($ln), 0, 12); $r['d'] = (string)($r['d'] ?? ''); $r['ip'] = (string)($r['ip'] ?? ''); $out[] = $r; }
    }
    return $out;
}

function fdActList($g) {
    $q = trim((string)($g['q'] ?? '')); $from = (int)($g['from'] ?? 0); $to = (int)($g['to'] ?? 0); $kind = (string)($g['kind'] ?? ''); $pg = max(1, (int)($g['pg'] ?? 1)); $per = 20;
    $rows = array_values(array_filter(fdActLines(), function ($r) use ($q, $from, $to, $kind) {
        if ($kind !== '' && $r['a'] !== $kind) return false; if ($from && $r['t'] < $from) return false; if ($to && $r['t'] > $to) return false;
        return $q === '' || stripos($r['d'] . ' ' . $r['a'] . ' ' . $r['ip'], $q) !== false;
    }));
    $total = count($rows); $pages = max(1, (int)ceil($total / $per)); $pg = min($pg, $pages); $map = fdActMap();
    ob_start();
    echo '<div id="actMeta" data-total="' . $total . '" data-pg="' . $pg . '" data-pages="' . $pages . '" hidden></div>';
    if (!$total) echo '<div class="empty"><i class="fa-solid fa-scroll" style="color:#a78bfa"></i><b>' . ($q . $kind !== '' || $from || $to ? 'No matching activity' : 'No activity yet') . '</b><div>' . ($q . $kind !== '' || $from || $to ? 'Try a different search or date range' : 'Uploads, downloads, deletes and more will show up here') . '</div></div>';
    else echo '<div class="ahint">Tap an entry for details · Hold 500ms to delete</div>';
    foreach (array_slice($rows, ($pg - 1) * $per, $per) as $r) {
        $detail = $r['d'] !== '' ? $r['d'] : $r['a'];
        if (preg_match('/^Downloaded\s+(.+)$/i', $detail, $downloadMatch)) {
            // Keep the Downloaded label colored like other activity labels/values.
            $detail = '<span class="ad-label">Downloaded:</span> <span class="ad-value">' . h(trim($downloadMatch[1])) . '</span>';
        } elseif (strpos($detail, ':') !== false && strpos($detail, '.') !== false) {
            [$label, $value] = explode(':', $detail, 2);
            $detail = '<span class="ad-label">' . h(trim($label)) . ':</span> <span class="ad-value">' . h(trim($value)) . '</span>';
        } else {
            $detail = h($detail);
        }
        [$ic, $col] = $map[$r['a']] ?? ['fa-circle-dot', '#94a3b8'];
        if (stripos($r['d'], 'File:') === 0) {$ic = 'fa-file-circle-plus';}
        $lmap = ['login' => 'Signed in', 'login-fail' => 'Failed sign-in', 'logout' => 'Signed out', 'account' => 'Account changed', 'db' => 'Database']; $u = fdUA($r['ua'] ?? '');
        $info = ['lab' => $lmap[$r['a']] ?? ucfirst((string)$r['a']), 't' => (int)$r['t'], 'ip' => (string)$r['ip'], 'note' => (string)$r['d'], 'dev' => $u['dev'] ?? '', 'model' => $u['model'] ?? '', 'os' => $u['os'] ?? '', 'br' => $u['br'] ?? '', 'ok' => $r['a'] !== 'login-fail'];
        echo '<div class="it act" data-id="' . h($r['id']) . '" data-info="' . h(json_encode($info, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) . '" data-a="' . h($r['a']) . '" data-t="' . (int)$r['t'] . '" data-day style="--c:' . $col . '"><span class="ico"><i class="fa-solid ' . $ic . '"></i></span><span class="tx2"><b>' . $detail . '</b><small>' . h(ucfirst($r['a'])) . ($r['ip'] ? ' · ' . h($r['ip']) : '') . '</small></span><span class="tm"></span>'
           . '<button class="mb ad" data-pact="logdel" data-id="' . h($r['id']) . '" title="Delete entry"><i class="fa-solid fa-trash" style="color:var(--bad)"></i></button></div>';
    }
    if ($pages > 1) {
        $b = fn($t, $ic, $to, $dis) => '<button class="mb" data-pg="' . $to . '" title="' . $t . '"' . ($dis ? ' disabled' : '') . '><i class="fa-solid ' . $ic . '" style="color:#818cf8"></i></button>';
        echo '<div class="pgn">' . $b('First', 'fa-angles-left', 1, $pg <= 1) . $b('Previous', 'fa-chevron-left', $pg - 1, $pg <= 1) . '<span>' . $pg . ' / ' . $pages . '</span>' . $b('Next', 'fa-chevron-right', $pg + 1, $pg >= $pages) . $b('Last', 'fa-angles-right', $pages, $pg >= $pages) . '</div>';
    }
    return ob_get_clean();
}

function fdContentSearch($q, $path) {
    $q = trim($q);
    if (strlen($q) < 2) return ['ok' => true, 'q' => $q, 'results' => [], 'files' => 0, 'matches' => 0, 'truncated' => false];
    $root = resolveServerPath($path); if (!is_dir($root)) $root = dirname($root);
    $skipDir = ['.git', 'node_modules', '.filedash', '.trash', 'vendor', '.idea', '.vscode', '__pycache__'];
    $binExt = ['zip', 'rar', 'tar', 'gz', 'tgz', 'bz2', '7z', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'ico', 'bmp', 'pdf', 'exe', 'dll', 'so', 'mp4', 'mp3', 'wav', 'ogg', 'mkv', 'avi', 'mov', 'iso', 'bin', 'woff', 'woff2', 'ttf', 'eot', 'otf', 'psd', 'sqlite', 'db'];
    $t0 = microtime(true); $files = 0; $matches = 0; $res = []; $trunc = false;
    try {
        $dirIt = new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS);
        $flt = new RecursiveCallbackFilterIterator($dirIt, function ($cur, $key, $iter) use ($skipDir) {
            if ($iter->hasChildren()) return !in_array($cur->getFilename(), $skipDir, true) && !$cur->isLink();
            return $cur->isFile();
        });
        foreach (new RecursiveIteratorIterator($flt, RecursiveIteratorIterator::LEAVES_ONLY) as $f) {
            if (microtime(true) - $t0 > 8 || $files >= 20000) { $trunc = true; break; }
            if (in_array(strtolower($f->getExtension()), $binExt, true)) continue;
            $sz = $f->getSize(); if ($sz < 1 || $sz > 2 * 1024 * 1024) continue;
            $fp = @fopen($f->getPathname(), 'rb'); if (!$fp) continue;
            if (strpos((string)fread($fp, 4096), "\0") !== false) { fclose($fp); continue; }
            rewind($fp); $files++; $n = 0; $hits = [];
            while (($line = fgets($fp)) !== false) {
                $n++; $pos = stripos($line, $q); if ($pos === false) continue;
                $st = max(0, $pos - 60); $snip = trim(substr($line, $st, 190));
                if (function_exists('mb_convert_encoding')) $snip = mb_convert_encoding($snip, 'UTF-8', 'UTF-8');
                $hits[] = ['l' => $n, 's' => ($st > 0 ? '… ' : '') . $snip];
                if (count($hits) >= 5) break;
            }
            fclose($fp);
            if ($hits) {
                $full = $f->getPathname(); $matches += count($hits);
                $res[] = ['p' => $full, 'rel' => ltrim(str_replace('\\', '/', substr($full, strlen($root))), '/'), 'name' => $f->getFilename(), 'hits' => $hits];
                if (count($res) >= 100) { $trunc = true; break; }
            }
        }
    } catch (Throwable $e) {}
    return ['ok' => true, 'q' => $q, 'results' => $res, 'files' => $files, 'matches' => $matches, 'truncated' => $trunc];
}

function fdPage($p) {
    $bin = ['zip', 'rar', 'tar', 'gz', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf', 'exe', 'mp4', 'mp3', 'iso', 'lock', 'bin', 'mkv', 'avi', 'mov', '7z', 'ico', 'bmp'];
    $prv = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'mp4', 'webm', 'm4v', 'mp3', 'wav', 'ogg', 'm4a', 'pdf'];
    ob_start();
    $back = '<button class="ib" data-closepage aria-label="Back"><i class="fa-solid fa-arrow-left" style="color:#818cf8"></i></button>';
    if ($p === 'favorites') {
        $fav = array_values(array_filter(fdRead('favorites'), 'file_exists'));
        usort($fav, fn($a, $b) => (is_dir($b) <=> is_dir($a)) ?: strcasecmp(basename($a), basename($b)));
        echo '<div class="pgh">' . $back . '<h2><i class="fa-solid fa-star" style="color:#f59e0b"></i>Favorites</h2><span class="cnt">' . count($fav) . '</span></div>';
        if (!$fav) echo '<div class="empty"><i class="fa-regular fa-star" style="color:#f59e0b"></i><b>No favorites yet</b><div>Open the ⋯ menu on any file or folder → Add to favorites</div></div>';
        foreach ($fav as $f) {
            $dir = is_dir($f); $ext = strtolower(pathinfo($f, PATHINFO_EXTENSION)); [$t, $ic] = ftype($ext, $dir);
            $href = $dir ? '?path=' . urlencode($f) : (!in_array($ext, $bin, true) ? '?fdpage=editor&file=' . urlencode($f) : (in_array($ext, $prv, true) ? '?raw=' . urlencode($f) : '?download=' . urlencode($f)));
            $tgt = (!$dir && in_array($ext, $prv, true)) ? ' target="_blank" rel="noopener"' : '';
            echo '<div class="it t-' . $t . '"><a class="nm" href="' . h($href) . '"' . $tgt . '><span class="ico"><i class="fa-solid ' . $ic . '"></i></span><span class="tx2"><b>' . h(basename($f)) . '</b><small>' . h(dirname($f)) . ($dir ? '' : ' · ' . h(formatSize(@filesize($f)))) . '</small></span></a>'
               . '<span class="ia"><a class="mb" href="?path=' . h(urlencode(dirname($f))) . '" title="Open folder"><i class="fa-solid fa-folder-open" style="color:#f59e0b"></i></a><button class="mb" data-pact="unfav" data-path="' . h($f) . '" title="Remove"><i class="fa-solid fa-star" style="color:#f59e0b"></i></button></span></div>';
        }
    } elseif ($p === 'activity') {
        $all = fdActLines(); $kinds = []; foreach ($all as $r) $kinds[$r['a']] = 1;
        echo '<div class="pgh">' . $back . '<h2><i class="fa-solid fa-scroll" style="color:var(--ac)"></i>Activity log</h2></div>';
        echo '<div class="abar"><span class="cnt" id="actCnt">' . count($all) . '</span><span class="sp"></span>'
           . '<button class="mb" data-atog="apS" title="Search"><i class="fa-solid fa-magnifying-glass" style="color:#38bdf8"></i><span class="lb">Search</span></button>'
           . '<button class="mb" data-atog="apD" title="Date"><i class="fa-solid fa-calendar-days" style="color:#f59e0b"></i><span class="lb">Date</span></button>'
           . '<button class="mb" data-atog="apK" title="Type"><i class="fa-solid fa-filter" style="color:#a78bfa"></i><span class="lb">Type</span></button>'
           . '<button class="mb" data-pact="areset" id="aReset" title="Reset filters" hidden><i class="fa-solid fa-rotate-left" style="color:#34d399"></i><span class="lb">Reset</span></button>'
           . '<button class="mb" data-pact="clearlog" title="Clear all"' . ($all ? '' : ' hidden') . '><i class="fa-solid fa-broom" style="color:var(--bad)"></i><span class="lb">Clear all</span></button></div>';
        echo '<div class="apan" id="apS" hidden><div class="in" style="flex:1"><i class="fa-solid fa-magnifying-glass" style="color:#38bdf8"></i><input id="aq" type="search" placeholder="Search activity…" autocomplete="off"></div></div>';
        echo '<div class="apan" id="apD" hidden><input type="date" id="aFrom" aria-label="From"><span style="color:var(--mut)">–</span><input type="date" id="aTo" aria-label="To">'
           . '<span class="pre"><button class="chip" data-preset="0">Today</button><button class="chip" data-preset="7">7d</button><button class="chip" data-preset="30">30d</button><button class="chip" data-preset="all">All</button></span></div>';
        echo '<div class="apan" id="apK" hidden><button class="chip on" data-ak="">All</button>'; foreach (array_keys($kinds) as $k) echo '<button class="chip" data-ak="' . h($k) . '">' . h(ucfirst($k)) . '</button>'; echo '</div>';
        echo '<div id="actList" class="stackl">' . fdActList([]) . '</div>';
    } elseif ($p === 'links') {
        $L = fdRead('links'); uasort($L, fn($a, $b) => $b['created'] <=> $a['created']); $D = fdRead('downloads');
        echo '<div class="pgh">' . $back . '<h2><i class="fa-solid fa-link" style="color:var(--ac2)"></i>Shared links</h2></div>';
        echo '<section class="pcard"><h3><i class="fa-solid fa-globe" style="color:#06b6d4"></i>Download from web</h3><form id="pgUrlForm"><div class="fld"><div class="lbl">File URL</div><input class="inp" name="url" type="url" inputmode="url" placeholder="https://example.com/file.zip" required autocomplete="off"></div>'
           . '<div class="fld"><div class="lbl">Save as (optional)</div><input class="inp" name="name" placeholder="my-file.zip" autocomplete="off"></div><div class="hint">Saves into: <b id="pgDest"></b></div><button class="btn pri" type="submit" id="pgUrlGo"><i class="fa-solid fa-cloud-arrow-down"></i>Download</button><div id="pgUrlProgress" class="url-progress-box" hidden><div class="url-progress-btn"><span class="url-percent">0%</span><span class="url-progress-label"><i class="fa-solid fa-spinner fa-spin"></i>Downloading...</span><span class="url-size">0 B / ?</span></div><button type="button" class="btn url-cancel">Cancel</button></div></form></section>';
        echo '<section class="pcard"><h3><i class="fa-solid fa-clock-rotate-left" style="color:#38bdf8"></i>Recent web downloads</h3>';
        if (!$D) echo '<div class="empty sm">Nothing downloaded yet.</div>';
        foreach (array_slice($D, 0, 8) as $d) echo '<div class="it act" data-t="' . (int)$d['t'] . '" style="--c:' . ($d['ok'] ? '#10b981' : '#ef4444') . '"><span class="ico"><i class="fa-solid ' . ($d['ok'] ? 'fa-circle-check' : 'fa-circle-xmark') . '"></i></span><span class="tx2"><b>' . h($d['ok'] ? $d['name'] : ($d['err'] ?: 'Failed')) . '</b><small>' . h(parse_url($d['url'], PHP_URL_HOST) ?: $d['url']) . ($d['ok'] ? ' · ' . h(formatSize($d['size'])) : '') . '</small></span><span class="tm" data-ago="' . (int)$d['t'] . '"></span></div>';
        echo '</section><section class="pcard"><h3><i class="fa-solid fa-share-nodes" style="color:#ec4899"></i>Share links<span>' . count($L) . '</span></h3>';
        if (!$L) echo '<div class="empty sm">No active links. Use ⋯ → Share link on any file.</div>';
        foreach ($L as $tk => $l) echo '<div class="it act" data-exp="' . (int)$l['exp'] . '" style="--c:#ec4899"><span class="ico"><i class="fa-solid fa-link"></i></span><span class="tx2"><b>' . h($l['name']) . '</b><small><span class="expt"></span> · ' . (int)$l['views'] . ' view(s)</small></span><span class="ia"><button class="mb" data-pact="copylink" data-token="' . h($tk) . '" title="Copy link"><i class="fa-solid fa-copy" style="color:#818cf8"></i></button><button class="mb" data-pact="revoke" data-token="' . h($tk) . '" title="Revoke"><i class="fa-solid fa-ban" style="color:var(--bad)"></i></button></span></div>';
        echo '</section>';
    } else echo '<div class="empty"><b>Not found</b></div>';
    return ob_get_clean();
}

function getFolderSize($dir) {
    global $size_deadline, $sizes_incomplete;
    $size = 0; if (!is_dir($dir)) return 0;
    try {
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS));
        foreach ($it as $file) {
            if (microtime(true) > $size_deadline) { $sizes_incomplete = true; return null; }
            if ($file->isFile()) $size += $file->getSize();
        }
    } catch (Exception $e) {}
    return $size;
}

function formatSize($b) {
    if ($b === null) return '…';
    if ($b >= 1073741824) return number_format($b / 1073741824, 2) . ' GB';
    if ($b >= 1048576) return number_format($b / 1048576, 2) . ' MB';
    if ($b >= 1024) return number_format($b / 1024, 1) . ' KB';
    if ($b > 1) return $b . ' B';
    if ($b == 1) return '1 B';
    return '—';
}

function iniBytes($v) { $v = trim((string)$v); $l = strtolower(substr($v, -1)); $n = (float)$v; return (int)($l === 'g' ? $n * 1073741824 : ($l === 'm' ? $n * 1048576 : ($l === 'k' ? $n * 1024 : $n))); }

function ftype($ext, $dir) {
    if ($dir) return ['folder', 'fa-folder'];
    static $m = null;
    if ($m === null) { $m = [];
        foreach (['image'=>'jpg jpeg png gif webp bmp svg ico avif','video'=>'mp4 mkv avi mov webm flv wmv m4v','audio'=>'mp3 wav ogg flac m4a aac',
                  'doc'=>'pdf doc docx xls xlsx ppt pptx odt txt rtf csv md','archive'=>'zip rar 7z tar gz tgz bz2',
                  'code'=>'php js ts html htm css scss json xml yml yaml py java c cpp h go rb rs sh sql ini conf log env vue'] as $t => $s)
            foreach (explode(' ', $s) as $x) $m[$x] = $t; }
    $t = $m[$ext] ?? 'other';
    $ic = ['pdf'=>'fa-file-pdf','doc'=>'fa-file-word','docx'=>'fa-file-word','xls'=>'fa-file-excel','xlsx'=>'fa-file-excel','csv'=>'fa-file-csv','ppt'=>'fa-file-powerpoint','pptx'=>'fa-file-powerpoint','txt'=>'fa-file-lines','md'=>'fa-file-lines','log'=>'fa-file-lines'];
    $ti = ['image'=>'fa-file-image','video'=>'fa-file-video','audio'=>'fa-file-audio','doc'=>'fa-file-lines','archive'=>'fa-file-zipper','code'=>'fa-file-code','other'=>'fa-file'];
    return [$t, $ic[$ext] ?? $ti[$t]];
}

function fdPref($k, $ok, $def) {
    $c = (string)($_COOKIE['fd_' . $k] ?? ''); $g = isset($_GET[$k]) ? (string)$_GET[$k] : null;
    if ($g !== null && in_array($g, $ok, true)) {
        if ($g !== $c && !headers_sent()) setcookie('fd_' . $k, $g, ['expires' => time() + 31536000, 'path' => '/', 'samesite' => 'Lax']);
        return $g;
    }
    return in_array($c, $ok, true) ? $c : $def;
}

function qs($o = []) {
    global $current_path;
    $q = ['path' => $current_path];
    if (isset($_GET['sizes'])) $q['sizes'] = 1;
    foreach ($o as $k => $v) { if ($v === null) unset($q[$k]); else $q[$k] = $v; }
    return '?' . http_build_query($q);
}

if ($__fdpage === 'index') {

/**
 * FileDash v2 — Neon Smart File Manager  (save as: index.php)
 * Works with your existing: ?fdpage=actions, ?fdpage=trash, ?fdpage=dashboard, ?fdpage=editor
 * Single self-contained file (CSS + JS inside). FontAwesome CDN only.
 */

error_reporting(E_ALL);
ini_set('display_errors', '0');

$server_root = realpath($_SERVER['DOCUMENT_ROOT'] ? $_SERVER['DOCUMENT_ROOT'] : FD_APP_ROOT);



$current_path = resolveServerPath($_GET['path'] ?? $server_root);

if (!defined('FD_DATA')) define('FD_DATA', __DIR__ . '/.filedash');   // must exist before fdLog() is used below
/* ---------- delete → move to .trash (Recycle Bin, see ?fdpage=trash) ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && in_array($_POST['action'] ?? '', ['delete', 'multi_delete'], true)) {
    $trash_dir = FD_APP_ROOT . '/.trash';
    if (!is_dir($trash_dir)) @mkdir($trash_dir, 0755, true);
    $trash_real = rtrim((string)realpath($trash_dir), '/\\'); $self_real = rtrim((string)realpath(FD_APP_ROOT), '/\\');
    $list = $_POST['action'] === 'delete' ? [$_POST['item_path'] ?? ''] : (array)($_POST['files'] ?? []);
    $ok = 0; $fail = 0; $moved = [];
    foreach ($list as $p) {
        $real = is_string($p) ? realpath($p) : false;
        if ($real === false) { $fail++; continue; }
        $r = rtrim($real, '/\\');
        // never trash: the trash itself, things already in it, the app folder, or any parent of it
        if ($r === $trash_real || strpos($r . '/', $trash_real . '/') === 0 || strpos(str_replace('\\', '/', $self_real) . '/', str_replace('\\', '/', $r) . '/') === 0) { $fail++; continue; }
        $name = basename($real);
        if (trash_move($real)) { $ok++; $moved[] = $name; } else $fail++;
    }
    if ($ok) fdLog('delete', 'Moved to Trash: ' . implode(', ', array_slice($moved, 0, 3)) . (count($moved) > 3 ? ' +' . (count($moved) - 3) . ' more' : ''));
    $back = 'index.php?path=' . urlencode($current_path) . ($ok ? '&msg=' . urlencode("$ok item(s) moved to Trash") : '') . ($fail ? '&error=' . urlencode("$fail item(s) could not be moved") : '');
    header('Location: ' . $back); exit;
}

/* ---------- streaming (Range support: video seek works) ---------- */



// Single file download
if (isset($_GET['download'])) {
    $f = realpath($_GET['download']);
    if ($f && is_file($f)) { fdLog('download', basename($f)); streamFile($f, 'application/octet-stream', true); }
    http_response_code(404); exit('Not found');
}
// Inline preview (images / video / audio / pdf only — safe whitelist)
if (isset($_GET['raw'])) {
    $f = realpath($_GET['raw']);
    $mimes = ['jpg'=>'image/jpeg','jpeg'=>'image/jpeg','png'=>'image/png','gif'=>'image/gif','webp'=>'image/webp','bmp'=>'image/bmp','ico'=>'image/x-icon',
              'mp4'=>'video/mp4','webm'=>'video/webm','m4v'=>'video/mp4','mp3'=>'audio/mpeg','wav'=>'audio/wav','ogg'=>'audio/ogg','m4a'=>'audio/mp4','pdf'=>'application/pdf'];
    if ($f && is_file($f)) { $e = strtolower(pathinfo($f, PATHINFO_EXTENSION)); if (isset($mimes[$e])) streamFile($f, $mimes[$e]); }
    http_response_code(404); exit('Not found');
}


/* ================= FileDash extras: favorites · activity log · share links · web download ================= */
$FD_ALLOW_PRIVATE_URLS = true;          // true = also allow downloading from LAN / localhost addresses
$FD_MAX_DOWNLOAD       = 2147483648;     // 2 GB per web download
$FD_BLOCK_EXT          = ['php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7', 'phps', 'pht']; // never saved from a URL
if (!defined('FD_DATA')) define('FD_DATA', __DIR__ . '/.filedash');























/** Download $url into $destDir. Returns ['name','size','path'] or false (+ $err). Blocks private IPs unless allowed; follows redirects manually and re-checks each hop. */



/* ---- public share link: index.php?s=TOKEN ---- */
if (isset($_GET['s'])) {
    $tok = preg_replace('/[^a-f0-9]/', '', (string)$_GET['s']); $L = fdRead('links'); $l = $L[$tok] ?? null;
    if (!$l || ($l['exp'] && $l['exp'] < time()) || !is_file($l['path'])) { http_response_code(404); exit('This link has expired or does not exist.'); }
    if (!isset($_SERVER['HTTP_RANGE']) || strpos($_SERVER['HTTP_RANGE'], 'bytes=0-') === 0) { $L[$tok]['views'] = ($l['views'] ?? 0) + 1; fdWrite('links', $L); fdLog('share-open', $l['name']); }
    streamFile($l['path'], 'application/octet-stream', true);
}

/* ---- JSON / fragment API ---- */
if (isset($_GET['api'])) {
    $api = (string)$_GET['api']; $P = $_POST;
    if ($api === 'actlist') { header('Content-Type: text/html; charset=utf-8'); echo fdActList($_GET); exit; }
    if ($api === 'content_search') { jout(fdContentSearch((string)($_GET['q'] ?? ''), (string)($_GET['path'] ?? ''))); }
    if ($api === 'page') { header('Content-Type: text/html; charset=utf-8'); echo fdPage((string)($_GET['p'] ?? '')); exit; }
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') jout(['ok' => false, 'error' => 'POST required'], 405);
    switch ($api) {
        case 'log':
            if (in_array($P['a'] ?? '', ['upload', 'create', 'rename', 'paste', 'zip'], true)) fdLog($P['a'], $P['d'] ?? '');
            jout(['ok' => true]);
        case 'fav':
            $p = (string)($P['path'] ?? ''); if ($p === '' || strpos($p, "\0") !== false || !file_exists($p)) jout(['ok' => false, 'error' => 'Item not found']);
            $favs = fdRead('favorites'); $ix = array_search($p, $favs, true);
            $want = isset($P['set']) ? ($P['set'] === '1') : ($ix === false);
            if ($want && $ix === false) $favs[] = $p; if (!$want && $ix !== false) unset($favs[$ix]);
            fdWrite('favorites', array_values($favs)); fdLog('star', ($want ? 'Added to favorites: ' : 'Removed from favorites: ') . basename($p));
            jout(['ok' => true, 'fav' => $want]);
        case 'dup':
            $src = realpath((string)($P['path'] ?? '')); if (!$src) jout(['ok' => false, 'error' => 'Item not found']);
            $in = pathinfo($src); $isd = is_dir($src); $base = $isd ? basename($src) : $in['filename']; $ext = (!$isd && isset($in['extension'])) ? '.' . $in['extension'] : '';
            $n = 1; do { $dest = dirname($src) . '/' . $base . ' copy' . ($n > 1 ? " $n" : '') . $ext; $n++; } while (file_exists($dest));
            if (!fdCopy($src, $dest)) jout(['ok' => false, 'error' => 'Could not duplicate']);
            fdLog('duplicate', basename($src) . ' → ' . basename($dest)); jout(['ok' => true]);
        case 'extract':
            $src = realpath((string)($P['path'] ?? '')); if (!$src || !is_file($src) || strtolower(pathinfo($src, PATHINFO_EXTENSION)) !== 'zip') jout(['ok' => false, 'error' => 'Not a ZIP file']);
            if (!class_exists('ZipArchive')) jout(['ok' => false, 'error' => 'PHP zip extension is not enabled']);
            $z = new ZipArchive; if ($z->open($src) !== true) jout(['ok' => false, 'error' => 'Could not open the ZIP']);
            $dest = dirname($src) . '/' . pathinfo($src, PATHINFO_FILENAME); $n = 1; $d0 = $dest; while (file_exists($dest)) $dest = $d0 . ' (' . $n++ . ')';
            @mkdir($dest, 0755); $cnt = 0;
            for ($i = 0; $i < $z->numFiles; $i++) {
                $nm = $z->getNameIndex($i); if ($nm === false || strpos($nm, "\0") !== false || preg_match('#(^|/|\\\\)\.\.(/|\\\\|$)#', $nm) || $nm[0] === '/' || preg_match('#^[A-Za-z]:#', $nm)) continue;
                $t = $dest . '/' . $nm;
                if (substr($nm, -1) === '/') { @mkdir($t, 0755, true); continue; }
                @mkdir(dirname($t), 0755, true); $in = $z->getStream($nm); if (!$in) continue; $out = fopen($t, 'wb'); stream_copy_to_stream($in, $out); fclose($out); fclose($in); $cnt++;
            }
            $z->close(); fdLog('extract', basename($src) . " → $cnt file(s)"); jout(['ok' => true, 'count' => $cnt, 'folder' => basename($dest)]);
        case 'share':
            $f = realpath((string)($P['path'] ?? '')); if (!$f || !is_file($f)) jout(['ok' => false, 'error' => 'Only files can be shared']);
            $ttl = (int)($P['ttl'] ?? 86400); if (!in_array($ttl, [3600, 86400, 604800, 0], true)) $ttl = 86400;
            $tok = bin2hex(random_bytes(10)); $L = fdRead('links');
            $L[$tok] = ['path' => $f, 'name' => basename($f), 'exp' => $ttl ? time() + $ttl : 0, 'views' => 0, 'created' => time()];
            fdWrite('links', $L); fdLog('share', 'Share link created: ' . basename($f)); jout(['ok' => true, 'token' => $tok]);
        case 'unshare':
            $tok = preg_replace('/[^a-f0-9]/', '', (string)($P['token'] ?? '')); $L = fdRead('links');
            if (isset($L[$tok])) { fdLog('share', 'Share link revoked: ' . $L[$tok]['name']); unset($L[$tok]); fdWrite('links', $L); }
            jout(['ok' => true]);
        case 'log_del':
            $id = preg_replace('/[^a-f0-9]/', '', (string)($P['id'] ?? '')); $f = FD_DATA . '/activity.log'; $done = false;
            if ($id !== '' && is_file($f)) {
                $out = []; foreach ((array)@file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $ln) { if (!$done && substr(md5($ln), 0, 12) === $id) { $done = true; continue; } $out[] = $ln; }
                if ($done) @file_put_contents($f, $out ? implode("\n", $out) . "\n" : '', LOCK_EX);
            }
            jout($done ? ['ok' => true] : ['ok' => false, 'error' => 'Entry not found']);
        case 'clear_log':
            @unlink(FD_DATA . '/activity.log'); jout(['ok' => true]);
        case 'url_progress':
            if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
            $id = strtolower((string)($P['id'] ?? ''));
            if (!preg_match('/^[a-f0-9]{32}$/', $id)) jout(['ok' => false, 'error' => 'Invalid download ID'], 400);
            $data = is_file(fdJobPath($id)) ? json_decode((string)@file_get_contents(fdJobPath($id)), true) : [];
            jout(['ok' => true, 'downloaded' => (int)($data['downloaded'] ?? 0), 'total' => (int)($data['total'] ?? 0), 'state' => $data['state'] ?? 'starting']);
        case 'url_cancel':
            if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
            $id = strtolower((string)($P['id'] ?? ''));
            if (!preg_match('/^[a-f0-9]{32}$/', $id)) jout(['ok' => false, 'error' => 'Invalid download ID'], 400);
            @file_put_contents(fdJobPath($id, 'cancel'), '1', LOCK_EX);
            jout(['ok' => true]);
        case 'url_download':
            @set_time_limit(0); @ignore_user_abort(true);
            if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
            $jobId = strtolower((string)($P['id'] ?? ''));
            if (!preg_match('/^[a-f0-9]{32}$/', $jobId)) jout(['ok' => false, 'error' => 'Invalid download ID'], 400);
            fdInit();
            @unlink(fdJobPath($jobId, 'cancel'));
            fdJobUpdate($jobId, 0, 0, 'starting');
            $dir = realpath((string)($P['dir'] ?? '')) ?: $current_path; $err = '';
            $res = fdDownload(trim((string)($P['url'] ?? '')), $dir, (string)($P['name'] ?? ''), $FD_ALLOW_PRIVATE_URLS, $FD_MAX_DOWNLOAD, $FD_BLOCK_EXT, $err, $jobId);
            $D = fdRead('downloads'); array_unshift($D, ['t' => time(), 'url' => substr(trim((string)($P['url'] ?? '')), 0, 400), 'name' => $res ? $res['name'] : '', 'size' => $res ? $res['size'] : 0, 'ok' => (bool)$res, 'err' => $err, 'dir' => $dir]);
            fdWrite('downloads', array_slice($D, 0, 30));
            if (!$res) { fdLog('web', 'Download failed: ' . $err); jout(['ok' => false, 'error' => $err]); }
            fdLog('web', 'Downloaded ' . $res['name'] . ' (' . formatSize($res['size']) . ') from ' . (parse_url($P['url'], PHP_URL_HOST) ?: 'web'));
            jout(['ok' => true, 'name' => $res['name'], 'size' => $res['size']]);
    }
    jout(['ok' => false, 'error' => 'Unknown action'], 400);
}

/* ---- server-rendered pages (loaded into the main area without a reload) ---- */




/** filtered + paginated activity list (HTML fragment). Params: q, from, to (unix), kind, pg */





/* ---------- helpers ---------- */
$size_deadline = microtime(true) + (isset($_GET['sizes']) ? 120 : 1.5);
$sizes_incomplete = false;








/* sort / order / hidden-files are remembered (cookie) — set once, stays after reload & folder change */


$sort = fdPref('sort', ['name', 'size', 'date', 'type'], 'date');
$order = fdPref('order', ['asc', 'desc'], 'desc');
$show_hidden = fdPref('hidden', ['0', '1'], '0') === '1';



/* ---------- read directory ---------- */
$fav_set = array_flip(array_filter(fdRead('favorites'), 'is_string'));
$raw_items = is_dir($current_path) ? (scandir($current_path) ?: []) : [];
$items = []; $n_dirs = 0; $n_files = 0; $total_bytes = 0;
foreach ($raw_items as $item) {
    if ($item === '.' || $item === '..') continue;
    if (!$show_hidden && $item[0] === '.') continue;
    $fp = $current_path . '/' . $item;
    $is_dir = is_dir($fp);
    $size = $is_dir ? getFolderSize($fp) : (@filesize($fp) ?: 0);
    $ext = strtolower(pathinfo($item, PATHINFO_EXTENSION));
    $items[] = ['name'=>$item,'full_path'=>$fp,'is_dir'=>$is_dir,'size'=>$size,'mtime'=>@filemtime($fp) ?: 0,'ext'=>$ext,'perm'=>substr(sprintf('%o', @fileperms($fp)), -4)];
    $is_dir ? $n_dirs++ : $n_files++;
    $total_bytes += (int)$size;
}
usort($items, function ($a, $b) use ($sort, $order) {
    if ($a['is_dir'] !== $b['is_dir']) return $a['is_dir'] ? -1 : 1;
    if ($sort === 'size') $r = ((int)$a['size']) <=> ((int)$b['size']);
    elseif ($sort === 'date') $r = $a['mtime'] <=> $b['mtime'];
    elseif ($sort === 'type') $r = strcmp($a['ext'], $b['ext']);
    else $r = strcasecmp($a['name'], $b['name']);
    return $order === 'desc' ? -$r : $r;
});

/* ---------- storage & misc ---------- */
$total_space = @disk_total_space($current_path) ?: 1000000000;
$free_space  = @disk_free_space($current_path) ?: 500000000;
$used_percent = max(1, round((($total_space - $free_space) / $total_space) * 100));
$post_max = iniBytes(ini_get('post_max_size')); $up_max = iniBytes(ini_get('upload_max_filesize'));
$upload_limit = $post_max > 0 ? min($up_max ?: PHP_INT_MAX, $post_max) : ($up_max ?: 0);
$flash = $_GET['msg'] ?? $_GET['message'] ?? $_GET['success'] ?? '';
$flash_err = $_GET['error'] ?? $_GET['err'] ?? '';

/* breadcrumb */
$norm = str_replace('\\', '/', $current_path);
$isUnix = ($norm !== '' && $norm[0] === '/');
$crumbs = []; $acc = '';
foreach (array_values(array_filter(explode('/', $norm), 'strlen')) as $i => $p) {
    $acc = (!$isUnix && $i === 0) ? $p : $acc . '/' . $p;
    $crumbs[] = [$p, (!$isUnix && $i === 0) ? $p . '/' : $acc];
}
$e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
/* quick access: phone storage etc. (shown only when the folder exists, e.g. Termux / Android) */
$quick = [];
foreach ([['Phone storage', '/sdcard', 'fa-mobile-screen'], ['Downloads', '/sdcard/Download', 'fa-download'], ['Pictures', '/sdcard/Pictures', 'fa-image'], ['DCIM (Camera)', '/sdcard/DCIM', 'fa-camera'], ['Movies', '/sdcard/Movies', 'fa-film'], ['Music', '/sdcard/Music', 'fa-music'], ['Documents', '/sdcard/Documents', 'fa-file-lines']] as $qq)
    if (@is_dir($qq[1]) && @is_readable($qq[1])) $quick[] = $qq;
$cfg = ['path' => $current_path, 'root' => $server_root, 'limit' => $upload_limit, 'flash' => $flash, 'err' => $flash_err, 'upUrl' => '?fdpage=actions&path=' . urlencode($current_path)];
$binary_exts = ['zip','rar','tar','gz','png','jpg','jpeg','gif','webp','pdf','exe','mp4','mp3','iso','lock','bin','mkv','avi','mov','7z','ico','bmp'];
$prev_exts = ['jpg','jpeg','png','gif','webp','bmp','mp4','webm','m4v','mp3','wav','ogg','m4a','pdf'];
?>
<!DOCTYPE html>
<html lang="en" class="">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, interactive-widget=resizes-content">
<meta name="theme-color" content="#6366f1">
<script>
/* saved look (theme · accent · view): browser storage + cookie, applied BEFORE first paint → no flash on reload */
window.FDP=(function(){
 var ck=function(k){var m=document.cookie.match(new RegExp('(?:^|; )fd_'+k+'=([^;]*)'));return m?decodeURIComponent(m[1]):null;};
 var P={
  get:function(k,d){try{var v=localStorage.getItem('fd_'+k);if(v!==null)return JSON.parse(v);}catch(e){}var c=ck(k);return c===null?d:c;},
  set:function(k,v){try{localStorage.setItem('fd_'+k,JSON.stringify(v));}catch(e){}document.cookie='fd_'+k+'='+encodeURIComponent(v)+';path=/;max-age=31536000;SameSite=Lax';},
  del:function(k){try{localStorage.removeItem('fd_'+k);}catch(e){}document.cookie='fd_'+k+'=;path=/;max-age=0;SameSite=Lax';},
  hsl:function(h){var n=parseInt(h.slice(1),16),r=(n>>16)/255,g=(n>>8&255)/255,b=(n&255)/255,mx=Math.max(r,g,b),mn=Math.min(r,g,b),H=0,S=0,L=(mx+mn)/2;if(mx!==mn){var d=mx-mn;S=L>.5?d/(2-mx-mn):d/(mx+mn);H=mx===r?(g-b)/d+(g<b?6:0):mx===g?(b-r)/d+2:(r-g)/d+4;H*=60;}return [H,S*100,L*100];},
  theme:function(){var t=P.get('theme','auto'),dark=t==='dark'||(t==='auto'&&matchMedia('(prefers-color-scheme:dark)').matches);document.documentElement.classList.toggle('light',!dark);},
  accent:function(){var a=P.get('accent',null),r=document.documentElement.style,m=document.querySelector('meta[name=theme-color]');
   if(!a||!/^#[0-9a-f]{6}$/i.test(a)){r.removeProperty('--ac');r.removeProperty('--ac2');if(m)m.content='#6366f1';return;}
   var x=P.hsl(a);r.setProperty('--ac',a);r.setProperty('--ac2','hsl('+((x[0]+45)%360)+' '+Math.max(x[1],55)+'% '+Math.min(Math.max(x[2],52),62)+'%)');if(m)m.content=a;}
 };
 return P;})();
FDP.theme();FDP.accent();
</script>
<title>FileDash — Smart File Manager</title>
<?php fdCss('fa/css/all.min.css'); ?>
<style>
:root{--ac:#6366f1;--ac2:#ec4899;--bg:#0a0e1a;--bg2:#080b15;--card:#111827;--card2:#172033;--tx:#e8eaf6;--mut:#8f9bb8;--bd:rgba(255,255,255,.08);--hov:rgba(129,140,248,.13);--sh:0 12px 34px rgba(0,0,0,.4);--ok:#10b981;--bad:#ef4444;--warn:#f59e0b;color-scheme:dark}
html.light{--bg:#eef1fb;--bg2:#fff;--card:#fff;--card2:#f4f6fd;--tx:#151a33;--mut:#64708f;--bd:rgba(20,26,60,.1);--hov:rgba(99,102,241,.09);--sh:0 12px 34px rgba(30,40,100,.12);color-scheme:light}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html,body{min-height:100%}html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{font-family:Inter,system-ui,-apple-system,"Noto Sans Bengali",Segoe UI,sans-serif;background:var(--bg);color:var(--tx);font-size:14px;line-height:1.45;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;z-index:-1;background:radial-gradient(600px 400px at 8% -5%,color-mix(in srgb,var(--ac) 22%,transparent),transparent),radial-gradient(500px 380px at 100% 100%,color-mix(in srgb,var(--ac2) 16%,transparent),transparent)}
a{color:inherit;text-decoration:none}button,input,select{font:inherit;color:inherit}button{cursor:pointer;border:0;background:none}
[hidden]{display:none!important}
::-webkit-scrollbar{width:7px;height:7px}::-webkit-scrollbar-thumb{background:color-mix(in srgb,var(--mut) 45%,transparent);border-radius:9px}
kbd{font:600 10.5px Inter,sans-serif;padding:2px 7px;border-radius:6px;border:1px solid var(--bd);background:var(--card2);color:var(--mut)}
.app{display:flex;min-height:100vh}
/* sidebar */
#side{width:262px;flex:none;background:color-mix(in srgb,var(--bg2) 92%,transparent);border-right:1px solid var(--bd);display:flex;flex-direction:column;height:100vh;position:sticky;top:0;overflow-y:auto;z-index:60}
.brand{display:flex;align-items:center;gap:11px;padding:20px 18px 14px}
.logo{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;color:#fff;font-size:17px;background:linear-gradient(135deg,var(--ac),var(--ac2));box-shadow:0 8px 22px color-mix(in srgb,var(--ac) 45%,transparent)}
.brand b{font-size:16px;display:block;line-height:1.1}.brand small{color:var(--mut);font-size:11px}
.nav{padding:6px 12px;display:flex;flex-direction:column;gap:3px}
.nav a{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:12px;color:var(--mut);font-weight:500;transition:.15s}
.nav a i{width:20px;text-align:center}.nav a:hover{background:var(--hov);color:var(--tx)}
.nav a.on{color:#fff;background:linear-gradient(135deg,var(--ac),var(--ac2));box-shadow:0 8px 20px color-mix(in srgb,var(--ac) 35%,transparent)}
.sec{padding:14px 20px 4px;font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--mut);font-weight:700;display:flex;justify-content:space-between}
.mini{padding:0 12px;display:flex;flex-direction:column;gap:2px;font-size:13px}
.mini a{display:flex;align-items:center;gap:9px;padding:7px 10px;border-radius:10px;color:var(--mut);white-space:nowrap;overflow:hidden}
.mini a span{overflow:hidden;text-overflow:ellipsis;flex:1}.mini a:hover{background:var(--hov);color:var(--tx)}
.mini a .x{opacity:0;font-size:11px}.mini a:hover .x{opacity:.8}.mini small{padding:4px 10px;color:var(--mut);opacity:.7}
.store{margin:auto 12px 14px;padding:14px;border-radius:16px;background:var(--card2);border:1px solid var(--bd)}
.store div.t{display:flex;justify-content:space-between;font-size:12px;color:var(--mut);margin-bottom:9px}
.bar{height:8px;border-radius:9px;background:var(--bd);overflow:hidden}.bar i{display:block;height:100%;border-radius:9px;background:linear-gradient(90deg,var(--ac),var(--ac2))}
.store small{display:block;margin-top:7px;color:var(--mut);font-size:11.5px}
.bd{position:fixed;inset:0;background:rgba(3,6,20,.6);backdrop-filter:blur(3px);z-index:55;opacity:0;pointer-events:none;transition:.25s}.bd.show{opacity:1;pointer-events:auto}
/* main */
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.top{position:sticky;top:0;z-index:40;display:flex;align-items:center;gap:10px;padding:12px 24px;background:color-mix(in srgb,var(--bg) 78%,transparent);backdrop-filter:blur(16px);border-bottom:1px solid var(--bd)}
.ib{width:40px;height:40px;border-radius:12px;display:inline-grid;place-items:center;background:var(--card);border:1px solid var(--bd);color:var(--mut);transition:.15s;flex:none}.ib:hover{color:var(--tx);background:var(--hov);transform:translateY(-1px)}
.srch{flex:1;max-width:680px;display:flex;align-items:center;gap:12px;height:50px;padding:0 18px;border-radius:15px;background:var(--card);border:1px solid var(--bd);transition:.2s}
.srch:focus-within{border-color:var(--ac);box-shadow:0 0 0 4px color-mix(in srgb,var(--ac) 18%,transparent)}
.srch input{flex:1;background:none;border:0;outline:0;min-width:0}.srch i{color:var(--mut)}
.sp{flex:1}
.av{width:40px;height:40px;border-radius:50%;display:grid;place-items:center;font-weight:700;color:#fff;background:linear-gradient(135deg,var(--ac2),var(--ac));flex:none;cursor:pointer;transition:.15s}
button.av:hover{transform:scale(1.06);box-shadow:0 6px 18px color-mix(in srgb,var(--ac) 45%,transparent)}
.av.lg{width:46px;height:46px;font-size:18px;cursor:default}
.acct{position:fixed;top:62px;right:max(12px,env(safe-area-inset-right));z-index:450;width:230px;padding:8px;border-radius:16px;background:var(--card);border:1px solid var(--bd);box-shadow:var(--sh);animation:pop .15s}
.acct .ah{display:flex;align-items:center;gap:12px;padding:10px 10px 12px;border-bottom:1px solid var(--bd);margin-bottom:6px}
.acct .ah>div{min-width:0}.acct .ah b{display:block;font-size:14.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.acct .ah small{display:flex;align-items:center;gap:6px;color:var(--mut);font-size:12px;margin-top:2px}.acct .ah small i{color:var(--ac);font-size:11px}
.acct .lo{display:flex;align-items:center;gap:11px;padding:11px 12px;border-radius:11px;color:var(--bad);font-weight:600}.acct .lo:hover{background:color-mix(in srgb,var(--bad) 12%,transparent)}.acct .lo i{width:16px;text-align:center}
.work{padding:20px 24px 40px;display:flex;flex-direction:column;gap:16px}
.btn{height:38px;padding:0 15px;border-radius:11px;font-weight:600;font-size:13px;background:var(--card);border:1px solid var(--bd);display:inline-flex;align-items:center;gap:8px;white-space:nowrap;transition:.15s}
.btn:hover{background:var(--hov);transform:translateY(-1px)}
.btn.pri{color:#fff;border-color:transparent;background:linear-gradient(135deg,var(--ac),var(--ac2));box-shadow:0 8px 20px color-mix(in srgb,var(--ac) 35%,transparent)}
.btn.dng{color:var(--bad)}.btn.dng:hover{background:var(--bad);color:#fff}.btn.sm{height:33px;padding:0 12px;font-size:12.5px}
/* stat cards */
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.cd{padding:14px 16px;border-radius:16px;background:var(--card);border:1px solid var(--bd);display:flex;align-items:center;gap:13px;position:relative;overflow:hidden;box-shadow:var(--sh)}
.cd .ci{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;font-size:17px;color:var(--c);background:color-mix(in srgb,var(--c) 16%,transparent)}
.cd b{font-size:19px;display:block;line-height:1.1}.cd small{color:var(--mut);font-size:12px}
/* path bar */
.pathbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:10px 12px;border-radius:15px;background:var(--card);border:1px solid var(--bd)}
.crumbs{display:flex;align-items:center;gap:2px;flex:1;min-width:200px;overflow-x:auto;white-space:nowrap;scrollbar-width:none}.crumbs::-webkit-scrollbar{display:none}
.crumbs a,.crumbs span{padding:5px 9px;border-radius:9px;color:var(--mut);font-weight:500}.crumbs a:hover{background:var(--hov);color:var(--tx)}.crumbs span.cur{color:var(--tx);font-weight:700}.crumbs .sl{opacity:.4;padding:0}
.jump{display:flex;gap:8px;flex:1;min-width:240px}
.jump input{flex:1;min-width:0;height:34px;padding:0 11px;border-radius:10px;background:var(--card2);border:1px solid var(--bd);outline:0;font:12px ui-monospace,Consolas,monospace}.jump input:focus{border-color:var(--ac)}
/* toolbar */
.tools{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between}
.grp{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.chips{display:flex;gap:6px;overflow-x:auto;scrollbar-width:none;max-width:100%}.chips::-webkit-scrollbar{display:none}
.chip{padding:6px 13px;border-radius:99px;font-size:12.5px;font-weight:600;background:var(--card);border:1px solid var(--bd);color:var(--mut);white-space:nowrap;transition:.15s}
.chip.on{color:#fff;border-color:transparent;background:linear-gradient(135deg,var(--ac),var(--ac2))}.chip:hover:not(.on){background:var(--hov);color:var(--tx)}
.sel{height:36px;padding:0 10px;border-radius:10px;background:var(--card);border:1px solid var(--bd);outline:0;cursor:pointer}
.seg{display:flex;padding:3px;gap:2px;border-radius:11px;background:var(--card);border:1px solid var(--bd)}.seg button{width:34px;height:28px;border-radius:8px;color:var(--mut)}.seg button.on{color:#fff;background:linear-gradient(135deg,var(--ac),var(--ac2))}
/* selection bar */
.selbar{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:10px 14px;border-radius:14px;position:sticky;top:76px;z-index:30;background:color-mix(in srgb,var(--ac) 14%,var(--card));border:1px solid color-mix(in srgb,var(--ac) 40%,transparent);box-shadow:var(--sh);animation:pop .18s}
@keyframes pop{from{opacity:0;transform:translateY(-6px)}}
/* file list */
.lhead,.fi{display:grid;grid-template-columns:36px minmax(0,1fr) 100px 150px 64px 236px;align-items:center;gap:10px}
.lhead{padding:4px 14px;font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--mut);font-weight:700}
.lhead a:hover{color:var(--ac)}.lhead a.on{color:var(--ac)}
.list{display:flex;flex-direction:column;gap:6px}
.fi{padding:9px 14px;border-radius:14px;background:var(--card);border:1px solid var(--bd);position:relative;transition:.15s;animation:in .3s both;cursor:default}
@keyframes in{from{opacity:0;transform:translateY(8px)}}
.fi:hover{border-color:color-mix(in srgb,var(--ac) 45%,var(--bd));box-shadow:var(--sh)}
.fi.sel-on{background:color-mix(in srgb,var(--ac) 15%,var(--card));border-color:var(--ac)}
.fi.cut{opacity:.45}.fi.dragover{outline:2px dashed var(--ok)}
.chk input{appearance:none;width:19px;height:19px;border-radius:6px;border:2px solid var(--bd);background:var(--card2);cursor:pointer;display:grid;place-items:center;transition:.15s}
.chk input:checked{background:var(--ac);border-color:var(--ac)}.chk input:checked::after{content:"✓";color:#fff;font-size:12px;font-weight:700}
.nm{display:flex;align-items:center;gap:12px;min-width:0}
.ico{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;font-size:17px;flex:none;overflow:hidden;color:var(--tc);background:color-mix(in srgb,var(--tc) 16%,transparent)}
.ico img{width:100%;height:100%;object-fit:cover}
.tx{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600}
.nm:hover .tx{color:var(--ac)}
.cs,.cdt,.cp{color:var(--mut);font-size:12.5px;white-space:nowrap}.cp{font-family:ui-monospace,Consolas,monospace;font-size:11.5px}
.acts{display:flex;justify-content:flex-end;gap:4px}
.acts button,.acts a,.more{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;background:var(--card2);color:var(--mut);font-size:12px;transition:.15s}
.acts button:hover,.acts a:hover{color:#fff;background:var(--ac)}.acts .d:hover{background:var(--bad)}
.more{display:none}
.t-folder{--tc:var(--ac)}.t-image{--tc:#ec4899}.t-video{--tc:#8b5cf6}.t-audio{--tc:#06b6d4}.t-doc{--tc:#3b82f6}.t-archive{--tc:#f97316}.t-code{--tc:#10b981}.t-other{--tc:#94a3b8}
.empty{padding:60px 20px;text-align:center;color:var(--mut)}.empty i{font-size:54px;opacity:.5;margin-bottom:10px;display:block}
/* grid + gallery */
.v-grid .lhead,.v-gallery .lhead{display:none}
.v-grid .list{display:grid;grid-template-columns:repeat(auto-fill,minmax(158px,1fr));gap:14px}
.v-gallery .list{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:14px}
.v-grid .fi,.v-gallery .fi{display:flex;flex-direction:column;align-items:center;text-align:center;padding:20px 12px 14px;gap:8px}
.v-grid .nm,.v-gallery .nm{flex-direction:column;gap:10px;width:100%}
.v-grid .ico{width:62px;height:62px;border-radius:17px;font-size:27px}
.v-gallery .ico{width:calc(100% + 24px);height:160px;margin:-20px -12px 0;border-radius:14px 14px 0 0;font-size:46px}
.v-grid .tx,.v-gallery .tx{max-width:100%}
.v-grid .cdt,.v-grid .cp,.v-gallery .cdt,.v-gallery .cp{display:none}
.v-grid .chk,.v-gallery .chk{position:absolute;top:10px;left:10px;opacity:0;transition:.15s}
.v-grid .fi:hover .chk,.v-gallery .fi:hover .chk,.sel-mode .chk{opacity:1}
.v-grid .acts,.v-gallery .acts{position:absolute;top:8px;right:8px;opacity:0;transition:.15s;flex-direction:column}
.v-grid .fi:hover .acts,.v-gallery .fi:hover .acts{opacity:1}
.v-gallery .chk{top:10px}
/* modals */
.modal{position:fixed;inset:0;z-index:300;display:none;place-items:center;padding:16px;background:rgba(3,6,20,.65);backdrop-filter:blur(6px)}.modal.open{display:grid;animation:fade .18s}
@keyframes fade{from{opacity:0}}
.mc{width:100%;max-width:440px;background:var(--card);border:1px solid var(--bd);border-radius:22px;padding:22px;box-shadow:var(--sh);animation:pop .2s}
.mc h3{display:flex;align-items:center;justify-content:space-between;gap:10px;font-size:17px;margin-bottom:16px}

.inp{width:100%;height:42px;padding:0 14px;border-radius:12px;background:var(--card2);border:1px solid var(--bd);outline:0}.inp:focus{border-color:var(--ac);box-shadow:0 0 0 4px color-mix(in srgb,var(--ac) 16%,transparent)}
.mf{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}
.drop{border:2px dashed var(--bd);border-radius:16px;padding:30px 16px;text-align:center;color:var(--mut);position:relative;transition:.2s;background:var(--card2)}.drop:hover,.drop.over{border-color:var(--ac);background:var(--hov)}
.drop i{font-size:34px;color:var(--ac);margin-bottom:8px;display:block}.drop input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%}
.swatches{display:flex;gap:8px;flex-wrap:wrap}.sw{width:30px;height:30px;border-radius:50%;border:3px solid transparent;box-shadow:0 0 0 1px var(--bd)}.sw.on{border-color:var(--card);box-shadow:0 0 0 2px var(--ac)}
/* ctx menu, toast, tray, palette, preview, drop overlay */
.ctx{position:fixed;z-index:400;min-width:200px;background:var(--card);border:1px solid var(--bd);border-radius:14px;box-shadow:var(--sh);padding:6px;animation:pop .12s}
.ctx button{display:flex;align-items:center;gap:11px;width:100%;padding:9px 12px;border-radius:9px;text-align:left; font-weight: bold}.ctx button:hover{background:var(--hov)}.ctx button i{width:16px;text-align:center;color:var(--mut)}.ctx .r{color:var(--bad)}.ctx hr{border:0;border-top:1px solid var(--bd);margin:5px 4px}
.toasts{position:fixed;right:18px;bottom:18px;z-index:600;display:flex;flex-direction:column;gap:9px;pointer-events:none}
.toast{pointer-events:auto;min-width:240px;max-width:380px;padding:12px 16px;border-radius:14px;background:var(--card);border:1px solid var(--bd);border-left:4px solid var(--ac);box-shadow:var(--sh);display:flex;align-items:center;gap:10px;animation:sl .3s}
.toast.ok{border-left-color:var(--ok)}.toast.err{border-left-color:var(--bad)}.toast.warn{border-left-color:var(--warn)}.toast.out{opacity:0;transform:translateX(30px);transition:.25s}
@keyframes sl{from{opacity:0;transform:translateX(40px)}}
.tray{position:fixed;right:18px;bottom:18px;width:360px;max-width:calc(100vw - 24px);z-index:350;background:var(--card);border:1px solid var(--bd);border-radius:18px;box-shadow:var(--sh);overflow:hidden}
.tray h4{display:flex;justify-content:space-between;align-items:center;padding:12px 14px;background:var(--card2);font-size:13.5px}
.tl{max-height:240px;overflow:auto;padding:8px}.ui{padding:8px;font-size:12.5px}.ui .r1{display:flex;justify-content:space-between;gap:8px;font-weight:600}.ui .r1 span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ui .bar{height:6px;margin:6px 0 3px}.ui small{color:var(--mut)}
.dz{position:fixed;inset:10px;z-index:380;border:3px dashed var(--ac);border-radius:26px;background:color-mix(in srgb,var(--bg) 85%,var(--ac));display:grid;place-items:center;text-align:center;font-size:20px;font-weight:700;color:var(--ac);backdrop-filter:blur(4px)}
.dz i{font-size:54px;display:block;margin-bottom:10px}
.pal{position:fixed;inset:0;z-index:500;display:none;justify-items:center;align-items:start;padding-top:12vh;background:rgba(3,6,20,.55);backdrop-filter:blur(5px)}.pal.open{display:grid}
.pc{width:min(600px,92vw);background:var(--card);border:1px solid var(--bd);border-radius:20px;box-shadow:var(--sh);overflow:hidden;animation:pop .15s}
.pc input{width:100%;padding:17px 20px;background:none;border:0;border-bottom:1px solid var(--bd);outline:0;font-size:16px}
.pc ul{list-style:none;max-height:330px;overflow:auto;padding:6px}.pc li{display:flex;gap:12px;align-items:center;padding:10px 14px;border-radius:11px;cursor:pointer}.pc li.on,.pc li:hover{background:var(--hov);color:var(--ac)}.pc li i{width:18px;text-align:center}.pc li small{margin-left:auto;color:var(--mut)}
.pv{position:fixed;inset:0;z-index:450;display:none;flex-direction:column;background:rgba(3,6,20,.92);backdrop-filter:blur(8px)}.pv.open{display:flex}
.pvh{display:flex;align-items:center;gap:10px;padding:12px 16px;color:#fff}.pvh b{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pvh .ib{background:rgba(255,255,255,.1);color:#fff;border-color:transparent}
.pvb{flex:1;display:grid;place-items:center;padding:10px;min-height:0}.pvb img,.pvb video{max-width:100%;max-height:100%;border-radius:12px}.pvb iframe{width:100%;height:100%;border:0;border-radius:12px;background:#fff}.pvb audio{width:min(520px,92%)}
/* extras */
.fi[data-fav="1"] .ico{position:relative}
.fi[data-fav="1"] .ico::after{content:"\f005";font-family:"Font Awesome 6 Free";font-weight:900;position:absolute;right:2px;bottom:1px;font-size:9px;line-height:1;color:#f59e0b;text-shadow:0 0 4px rgba(0,0,0,.5)}
.fi[data-fav="1"] .stb{color:#f59e0b}
.lbl{font-size:12.5px;font-weight:600;color:var(--mut);margin:0 0 6px}.fld{margin-bottom:12px}.hint{font-size:12px;color:var(--mut);margin-bottom:6px;word-break:break-all}.hint b{color:var(--tx)}
select.inp{cursor:pointer}.ir{display:flex;justify-content:space-between;gap:14px;padding:9px 0;border-bottom:1px solid var(--bd)}.ir:last-child{border:0}.ir span{color:var(--mut);flex:none}.ir b{font-weight:600;text-align:right;word-break:break-all}
#page .pgh{display:flex;align-items:center;gap:12px}#page .pgh h2{font-size:18px;display:flex;align-items:center;gap:10px;flex:1;min-width:0}
#page .cnt{padding:3px 11px;border-radius:99px;background:var(--card);border:1px solid var(--bd);color:var(--mut);font-size:12.5px;font-weight:600}
#page .chips{margin:-2px 0}
.dh{font-size:11px;text-transform:uppercase;letter-spacing:.09em;color:var(--mut);font-weight:700;margin:6px 4px -4px}
.it{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:center;padding:9px 12px;border-radius:14px;background:var(--card);border:1px solid var(--bd);transition:.15s}//.it:hover{border-color:color-mix(in srgb,var(--ac) 45%,var(--bd))}
.it:hover { border-color: var(--ac); transform: translateY(-2px); box-shadow: 0 6px 18px color-mix(in srgb,var(--ac) 15%,transparent);}
.it:active { transform: scale(.985); background: var(--hov);}
.it.act{grid-template-columns:38px minmax(0,1fr) auto auto;gap:12px}
.it .nm{display:flex;align-items:center;gap:12px;min-width:0}
.it .ico{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;font-size:16px;flex:none;color:var(--tc,var(--c));background:color-mix(in srgb,var(--tc,var(--c)) 16%,transparent)}
.it.act .tx2 b{white-space:normal;word-break:break-word;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.tx2{min-width:0;display:block}.tx2 b{display:block;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.tx2 small{display:block;color:var(--mut);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.it .tm{color:var(--mut);font-size:12px;white-space:nowrap}.ia{display:flex;gap:6px}
.mb{width:32px;height:32px;border-radius:10px;display:grid;place-items:center;background:var(--card2);color:var(--mut);border:1px solid var(--bd);transition:.15s}.mb:hover{background:var(--hov);color:var(--tx)}
.pcard{padding:16px;border-radius:18px;background:var(--card);border:1px solid var(--bd);display:flex;flex-direction:column;gap:10px}
.pcard h3{font-size:14.5px;display:flex;align-items:center;gap:9px;margin-bottom:2px}.pcard h3 i{color:var(--ac)}.pcard h3 span{margin-left:auto;color:var(--mut);font-size:12px;font-weight:500}
.empty.sm{padding:14px 0}
/* Activity details popup: same floating card as Settings > Security > Recent sign-ins */
.si{position:fixed;z-index:200;width:min(320px,calc(100vw - 24px));background:var(--card);border:1px solid var(--bd);border-radius:14px;box-shadow:0 24px 60px rgba(0,0,0,.45);padding:14px;animation:siIn .16s ease both}
.si[hidden]{display:none}
@keyframes siIn{from{opacity:0;transform:translateY(6px) scale(.97)}to{opacity:1;transform:none}}
.si h4{display:flex;align-items:center;gap:8px;font-size:14px;margin-bottom:10px;padding-right:30px;position:relative}.si .si-close{position:absolute;right:0;top:-5px;width:28px;height:28px;display:grid;place-items:center;border:1px solid var(--bd);border-radius:8px;background:var(--card2);color:var(--mut);cursor:pointer;font-size:14px}.si .si-close:hover{background:var(--bad);border-color:var(--bad);color:#fff}
.si .k{display:flex;justify-content:space-between;gap:14px;padding:6px 0;border-top:1px solid var(--bd);font-size:12.5px}
.si .k span{color:var(--mut)}.si .k b{font-weight:600;text-align:right;word-break:break-word}
/* keyboard shortcut help */
.kbh{font-size:11px;text-transform:uppercase;letter-spacing:.09em;color:var(--ac);font-weight:700;margin:14px 2px 4px}.kbh:first-child{margin-top:0}
.kbr{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:7px 2px;border-bottom:1px solid var(--bd);font-size:13px}.kbr:last-child{border:0}
.kbr kbd{font:600 11.5px ui-monospace,Consolas,monospace;background:color-mix(in srgb,var(--ac) 13%,transparent);border:1px solid color-mix(in srgb,var(--ac) 38%,var(--bd));border-radius:7px;padding:2px 8px;white-space:nowrap}
/* search inside file contents */
.srch{position:relative}
.cs-tg{display:inline-flex;align-items:center;gap:6px;height:28px;padding:0 10px;border-radius:99px;border:1px solid var(--bd);background:var(--card2);color:var(--mut);font-size:12px;font-weight:600;white-space:nowrap;transition:.15s;flex:none}
.cs-tg:hover{color:var(--tx)}.cs-tg.on{color:#fff;background:linear-gradient(135deg,var(--ac),var(--ac2));border-color:transparent}.cs-tg[hidden]{display:none}
@media(max-width:700px){.cs-tg span{display:none}.cs-tg{width:30px;padding:0;justify-content:center}}
#csRes{position:absolute;left:0;right:0;top:calc(100% + 8px);z-index:90;max-height:70vh;overflow:auto;background:var(--card);border:1px solid var(--bd);border-radius:16px;box-shadow:var(--sh);padding:8px}
#csRes[hidden]{display:none}
#csRes .cs-h{display:flex;justify-content:space-between;gap:10px;padding:6px 8px 10px;color:var(--mut);font-size:12px}
#csRes .cs-f{padding:8px 8px 3px;font-weight:700;font-size:13px;display:flex;gap:8px;align-items:baseline;min-width:0}.cs-f small{color:var(--mut);font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#csRes a.cs-m{display:flex;gap:10px;padding:6px 10px;border-radius:9px;font-size:12.5px;color:var(--tx);min-width:0}#csRes a.cs-m:hover{background:var(--hov)}
#csRes a.cs-m i{font-style:normal;color:var(--ac);font-weight:700;min-width:38px;flex:none}#csRes a.cs-m span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:ui-monospace,Consolas,monospace}
#csRes mark{background:color-mix(in srgb,var(--warn) 45%,transparent);color:inherit;border-radius:3px;padding:0 1px}
#csRes .cs-e{padding:22px;text-align:center;color:var(--mut)}
/* activity toolbar / pagination */
.abar{display:flex;align-items:center;gap:6px}.abar .sp{flex:1}
.abar .mb .lb{display:none}
@media(min-width:768px){.abar .mb{width:auto;height:34px;padding:0 13px;display:inline-flex;align-items:center;gap:7px;font-size:13px;font-weight:600;color:var(--tx)}.abar .mb .lb{display:inline}.abar .mb[hidden]{display:none}}
.mb.on{color:#fff;background:linear-gradient(135deg,var(--ac),var(--ac2));border-color:transparent}.mb[disabled]{opacity:.35;pointer-events:none}
.apan{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px;border-radius:14px;background:var(--card);border:1px solid var(--bd);animation:pop .15s}
.apan .in{display:flex;align-items:center;gap:9px;height:38px;padding:0 12px;border-radius:11px;background:var(--card2);border:1px solid var(--bd)}.apan .in input{flex:1;min-width:0;background:none;border:0;outline:0}.apan .in i{color:var(--mut)}
.apan input[type=date]{height:38px;padding:0 10px;border-radius:10px;background:var(--card2);border:1px solid var(--bd);outline:0;font-size:13px;min-width:0;flex:1 1 120px}
.apan .pre{display:flex;gap:6px;flex-wrap:wrap}.apan .chip{padding:5px 11px}
.stackl{display:flex;flex-direction:column;gap:8px}
.pgn{display:flex;justify-content:center;align-items:center;gap:6px;margin-top:4px}.pgn span{min-width:64px;text-align:center;color:var(--mut);font-size:12.5px;font-weight:600}
.ahint{display:none;font-size:11.5px;color:var(--mut);text-align:center}
@media (max-width:900px){.ad{display:none}.ahint{display:block}.it.act[data-id]{cursor:pointer}.it.act[data-id]:active{background:color-mix(in srgb,var(--bad) 10%,var(--card))}}
/* mobile */
.bnav,.fab{display:none}
@media (max-width:1000px){.cards{grid-template-columns:repeat(2,1fr)}.lhead,.fi{grid-template-columns:36px minmax(0,1fr) 90px 150px 0 226px}.cp{display:none}}
@media (max-width:900px){
 #side{position:fixed;left:0;top:0;bottom:0;height:auto;max-width:86vw;transform:translateX(-100%);transition:.28s cubic-bezier(.4,0,.2,1);box-shadow:var(--sh)}#side.open{transform:none}
 .top{padding:10px 12px}.work{padding:12px 12px 100px}.srch kbd,.hide-m{display:none}
 .lhead{display:none}.fi{grid-template-columns:34px minmax(0,1fr) auto 34px}.cdt,.cp{display:none}.acts{display:none}.more{display:grid}
 .v-grid .list{grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px}.v-gallery .list{grid-template-columns:repeat(2,1fr);gap:10px}.v-gallery .ico{height:120px}
 .v-grid .more,.v-gallery .more{position:absolute;top:6px;right:6px}.v-grid .chk,.v-gallery .chk{opacity:1}
 .bnav{display:grid;grid-template-columns:repeat(5,1fr);position:fixed;left:0;right:0;bottom:0;z-index:70;padding:6px 6px calc(6px + env(safe-area-inset-bottom));background:color-mix(in srgb,var(--bg2) 92%,transparent);backdrop-filter:blur(16px);border-top:1px solid var(--bd)}
 .bnav button{display:flex;flex-direction:column;align-items:center;gap:2px;font-size:10.5px;color:var(--mut);font-weight:600;padding:6px 0}.bnav button i{font-size:18px}.bnav .add i{width:50px;height:50px;border-radius:50%;display:grid;place-items:center;margin-top:-26px;font-size:20px;color:#fff;background:linear-gradient(135deg,var(--ac),var(--ac2));box-shadow:0 10px 24px color-mix(in srgb,var(--ac) 50%,transparent)}
 .fab{position:fixed;left:50%;transform:translateX(-50%);bottom:calc(76px + env(safe-area-inset-bottom));z-index:71;flex-direction:column;gap:8px}.fab.open{display:flex;animation:pop .18s}.fab button{display:flex;align-items:center;gap:12px;min-width:176px;padding:12px 22px;border-radius:99px;font-family:inherit;font-size:14px;font-weight:500;line-height:1.45;letter-spacing:normal;color:var(--tx);background:var(--card);border:1px solid var(--bd);box-shadow:var(--sh)}.fab button i{width:18px;text-align:center;color:var(--mut)}
 .toasts{left:12px;right:12px;bottom:84px}.tray{left:10px;right:10px;width:auto;bottom:84px}
 .mc{max-width:none;align-self:end;border-radius:24px 24px 0 0}.modal{align-items:end;padding:0}
 .ctx{left:50%!important;top:50%!important;right:auto;bottom:auto;width:min(300px,86vw);max-height:78vh;overflow-y:auto;transform:translate(-50%,-50%);border-radius:18px;padding:8px;box-shadow:0 0 0 100vmax rgba(3,6,20,.55),var(--sh);animation:popc .16s}
 @keyframes popc{from{opacity:0;transform:translate(-50%,-47%) scale(.96)}}
 .ctx button{padding:12px 14px}
 .selbar{top:72px}
 /* mobile fit */
 .top{padding-left:max(12px,env(safe-area-inset-left));padding-right:max(12px,env(safe-area-inset-right))}
 .srch{min-width:0;max-width:none;flex:1 1 auto}.top .sp{display:none}.top{gap:8px}
 .work{padding-left:max(12px,env(safe-area-inset-left));padding-right:max(12px,env(safe-area-inset-right));gap:12px}
 .list>*,.cards>*{min-width:0}
 .cd>div:last-child{min-width:0}.cd b,.cd small{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
 .pathbar{padding:8px 10px}.crumbs{min-width:0;flex:1 1 100%}
 .tools{flex-direction:column;align-items:stretch;gap:8px}
 .tools>.grp{width:100%;min-width:0}.tools>.grp:first-child{display:none}
 .tools .chips{width:100%}
 .tools>.grp:last-child .sel{flex:1 1 110px;min-width:0}
 .selbar{flex-wrap:nowrap;gap:8px;padding:8px 10px}
 #selTxt{flex:none}#selTxt b{display:grid;place-items:center;min-width:30px;height:30px;padding:0 7px;border-radius:9px;color:#fff;background:linear-gradient(135deg,var(--ac),var(--ac2))}
 .selbar .grp{flex:1;min-width:0;flex-wrap:nowrap;justify-content:space-between;gap:4px}
 .selbar .btn.sm{flex:1 1 0;min-width:0;justify-content:center;padding:0;height:36px}
 /* background must not scroll under menus / popups */
 html.lock,html.lock body{overflow:hidden;overscroll-behavior:none}
 .ctx,.mc{overscroll-behavior:contain}
 /* popups follow the visual viewport → they sit ABOVE the keyboard */
 .modal{inset:auto;left:0;right:0;top:var(--vvt,0px);height:var(--vvh,100%)}
 .mc{max-height:calc(100% - 6px);overflow-y:auto}
 /* smart dock: hides on scroll-down / keyboard, returns on scroll-up */
 .bnav{transition:transform .28s cubic-bezier(.4,0,.2,1)}
 .fab,.toasts,.tray{transition:bottom .28s cubic-bezier(.4,0,.2,1),opacity .2s}
 body.dock-off .bnav{transform:translateY(calc(100% + 40px))}
 body.dock-off .fab{opacity:0;pointer-events:none}
 body.dock-off .toasts,body.dock-off .tray{bottom:calc(14px + env(safe-area-inset-bottom))}
}
@media (max-width:520px){.cards{grid-template-columns:repeat(2,1fr);gap:8px}.cd{padding:10px;gap:9px}.cd .ci{width:34px;height:34px}.cd b{font-size:15px}}
/* stats: one card, one row, 4 items split by | */
.cards{display:flex;gap:0;padding:12px 4px;border-radius:16px;background:var(--card);border:1px solid var(--bd);box-shadow:var(--sh)}
.cards .cd{flex:1 1 0;min-width:0;padding:2px 10px;border:0;border-radius:0;background:none;box-shadow:none;justify-content:center}
.cards .cd+.cd::before{content:"";position:absolute;left:0;top:12%;bottom:12%;width:1px;background:var(--bd)}
@media (max-width:700px){
 .cards{padding:10px 0}
 .cards .cd{flex-direction:column;gap:5px;padding:0 4px;text-align:center}
 .cards .cd .ci{width:28px;height:28px;border-radius:9px;font-size:13px}
 .cards .cd b{font-size:14px}.cards .cd small{font-size:11px;display:block}
}
/* sidebar polish */
#side{background:linear-gradient(180deg,color-mix(in srgb,var(--card) 72%,transparent),color-mix(in srgb,var(--bg2) 95%,transparent));backdrop-filter:blur(18px);scrollbar-width:thin;box-shadow:inset -1px 0 0 rgba(255,255,255,.03)}
#side::before{content:"";position:absolute;inset:0 0 auto 0;height:200px;z-index:-1;pointer-events:none;background:radial-gradient(240px 150px at 18% 0,color-mix(in srgb,var(--ac) 28%,transparent),transparent)}
.brand{padding:24px 18px 18px}
.logo{border-radius:15px;box-shadow:0 10px 24px color-mix(in srgb,var(--ac) 50%,transparent),inset 0 1px 0 rgba(255,255,255,.35)}
.brand b{font-size:17px;letter-spacing:.2px;background:linear-gradient(90deg,var(--tx),var(--ac));-webkit-background-clip:text;background-clip:text;color:transparent}
.brand small{letter-spacing:.3px}
.nav{padding:8px 12px;gap:4px}
.nav a{padding:11px 14px;border-radius:14px;transition:background .18s,color .18s,transform .18s}
.nav a i{width:22px;font-size:15px;transition:color .18s}
.nav a:not(.on):hover{transform:translateX(3px)}.nav a:not(.on):hover i{color:var(--ac)}
.nav a.on{box-shadow:0 10px 22px color-mix(in srgb,var(--ac) 38%,transparent),inset 0 1px 0 rgba(255,255,255,.25)}
.sec{padding:20px 22px 8px;justify-content:flex-start;align-items:center;gap:10px}
.sec::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--bd),transparent)}
.mini{padding:0 12px;gap:3px}
.mini a{padding:9px 12px;border-radius:12px;transition:background .18s,color .18s,transform .18s}
.mini a:hover{transform:translateX(3px)}
.mini a>i:first-child{width:20px;text-align:center;font-size:15px}
.mini{font-size:14px}.mini a{font-weight:500}
.sec{font-size:12px}.sec span{display:flex;align-items:center;gap:8px;color:var(--sc,var(--mut))}.sec span i{font-size:13px}
.mini small{padding:6px 12px;font-style:italic}
.store{margin:auto 12px 16px;padding:16px;border-radius:18px;background:linear-gradient(145deg,color-mix(in srgb,var(--ac) 15%,var(--card2)),var(--card2));border:1px solid color-mix(in srgb,var(--ac) 26%,var(--bd));box-shadow:var(--sh)}
.store div.t{font-weight:600}
.bar{height:9px}.bar i{box-shadow:0 0 12px color-mix(in srgb,var(--ac) 60%,transparent)}
/* soft navigation bar + calm list refresh */
#nbar{position:fixed;top:0;left:0;height:3px;width:0;z-index:700;opacity:0;pointer-events:none;background:linear-gradient(90deg,var(--ac),var(--ac2));box-shadow:0 0 10px var(--ac)}
#nbar.on{opacity:1;width:82%;transition:width 6s cubic-bezier(.1,.7,.2,1)}
#nbar.done{width:100%;opacity:0;transition:width .18s ease-out,opacity .35s .12s}
#list.still .fi{animation:none}
/* theme switch: Telegram-style circular reveal from the toggle button */
::view-transition-old(root),::view-transition-new(root){animation:none;mix-blend-mode:normal;display:block}
::view-transition-old(root){z-index:1}::view-transition-new(root){z-index:2}
html.nt,html.nt *,html.nt *::before,html.nt *::after{transition:none!important}
/* theme switch (mobile + desktop): new layer starts fully hidden → no first-frame flash, GPU-friendly reveal */
::view-transition-new(root){clip-path:circle(0px at var(--tx,50%) var(--ty,0%));will-change:clip-path}
::view-transition-old(root){will-change:auto}
@media (max-width:900px){
 #pasteBtn{display:none!important}   /* Paste lives in the bottom dock on mobile */
}
html.tt,html.tt *,html.tt *::before,html.tt *::after{transition:background-color .4s ease,color .4s ease,border-color .4s ease,box-shadow .4s ease!important}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
.it.act .ad-value {color: #10b981;}

#urlProgress,.url-progress-box{display:flex;flex-direction:column;gap:10px;margin-top:16px}
.url-progress-btn{width:100%;min-height:46px;display:flex;align-items:center;justify-content:space-between;gap:8px;padding:0 13px;border:1px solid transparent;border-radius:14px;overflow:hidden;background-image:linear-gradient(90deg,transparent 0%,transparent var(--url-progress,0%),var(--card2) var(--url-progress,0%),var(--card2) 100%),linear-gradient(135deg,var(--ac),var(--ac2));color:#fff;font:inherit;font-size:13px;font-weight:600;cursor:default;transition:background-image .2s linear}
.url-progress-label{display:flex;align-items:center;gap:7px;white-space:nowrap}
.url-progress-label,.url-progress-label i{color:#fff}
#urlPercent,.url-percent{color:#fff;min-width:38px;text-align:left}
#urlSize,.url-size{font-size:12px;white-space:nowrap;color:#fff}
#urlCancel,.url-cancel{width:100%;justify-content:center}
#urlCancel:disabled,.url-cancel:disabled{opacity:.65;cursor:wait}
@media(max-width:420px){.url-progress-btn{gap:5px;padding:0 9px;font-size:12px}#urlSize,.url-size{font-size:11px}.url-progress-label{gap:5px}}
.fd-embed-frame{display:block;width:100%;height:calc(100vh - 92px);min-height:560px;border:0;border-radius:14px;background:transparent}


/* mobile search icon -> floating search field (desktop untouched) */
#sBtn{display:none}
@media(max-width:900px){
 #sBtn{display:grid}#sBtn.has{color:var(--ac)}
 .top .sp{display:block;flex:1}
 .top .srch{display:none}
 .top.sopen{backdrop-filter:none;-webkit-backdrop-filter:none}
 .top.sopen .srch{display:flex;position:fixed;z-index:80;left:max(10px,env(safe-area-inset-left));right:max(10px,env(safe-area-inset-right));top:calc(10px + env(safe-area-inset-top));height:52px;max-width:none;box-shadow:0 0 0 100vmax rgba(3,6,20,.5),var(--sh);background:var(--card);animation:sPop .16s}
 .top.sopen #csRes{left:0;right:0}
 #sClose{display:grid;flex:none}
 @keyframes sPop{from{opacity:0;transform:translateY(-8px)}}
}
#sClose{display:none}

/* ===== Embedded tabs (Trash / Dashboard / Settings / Database): pre-loaded frames, shown instantly ===== */
#embedHost:not(.show){position:fixed;left:-300vw;top:0;width:100vw;height:100dvh;visibility:hidden;pointer-events:none;padding:0;overflow:hidden}
#embedHost[hidden]{display:none}
#embedHost .eh-in{position:relative;width:100%;height:calc(100vh - 92px);min-height:560px}
#embedHost:not(.show) .eh-in{height:100%;min-height:0}
#embedHost .fd-embed-frame{position:absolute;left:0;top:0;width:100%;height:100%;min-height:0;border:0;border-radius:14px;background:transparent;visibility:hidden;pointer-events:none}
#embedHost .fd-embed-frame.on{visibility:visible;pointer-events:auto}
@media (max-width:900px){
  /* full height under the header; the dock simply floats over it and hides/shows on scroll */
  #embedHost.show{padding:0!important;gap:0}
  #embedHost .eh-in{height:calc(100dvh - var(--toph,62px));min-height:0}
  #embedHost .fd-embed-frame{border-radius:0}
}
</style>
</head>
<body>
<div id="nbar"></div>
<div class="app">

<!-- ================= SIDEBAR ================= -->
<aside id="side">
  <div class="brand"><div class="logo"><i class="fa-solid fa-folder-tree"></i></div><div><b>FileDash</b><small>Smart File Manager</small></div></div>
  <nav class="nav">
      <a href="index.php" class="on"><i class="fa-solid fa-folder-open" style="color:#38bdf8"></i><span>All Files</span></a>
      <a href="#favorites" data-page="favorites"><i class="fa-solid fa-star" style="color:#fbbf24"></i><span>Favorites</span></a>
      <a href="#links" data-page="links"><i class="fa-solid fa-link" style="color:#f472b6"></i><span>Shared links</span></a>
      <a href="#activity" data-page="activity"><i class="fa-solid fa-scroll" style="color:#a78bfa"></i><span>Activity log</span></a>
      <a href="#trash" data-page="trash"><i class="fa-solid fa-trash" style="color:#fb7185"></i><span>Trash</span></a>
      <a href="#dashboard" data-page="dashboard"><i class="fa-solid fa-chart-pie" style="color:#34d399"></i><span>Dashboard</span></a>
      <a href="#dbviewer" data-page="dbviewer"><i class="fa-solid fa-database" style="color:#a78bfa"></i><span>Database</span></a>
      <a href="?fdpage=editor"><i class="fa-solid fa-code" style="color:#fb923c"></i><span>IDE Studio</span></a>
      <a href="#settings" data-page="settings"><i class="fa-solid fa-gear" style="color:#22d3ee"></i><span>Settings</span></a>
</nav>
  <?php if ($quick): ?>
  <div class="sec"><span style="--sc:#f59e0b"><i class="fa-solid fa-bolt" style="color:#f59e0b"></i>Quick access</span></div>
  <div class="mini" id="quick">
    <?php $qcol = ['#6366f1', '#10b981', '#ec4899', '#f59e0b', '#ef4444', '#a855f7', '#0ea5e9', '#14b8a6']; foreach ($quick as $qi => $qq): ?><a href="?path=<?= urlencode($qq[1]) ?>" title="<?= $e($qq[1]) ?>"><i class="fa-solid <?= $qq[2] ?>" style="color:<?= $qcol[$qi % count($qcol)] ?>"></i><span><?= $e($qq[0]) ?></span></a><?php endforeach; ?>
  </div>
  <?php endif; ?>
  <div class="sec"><span style="--sc:#f43f5e"><i class="fa-solid fa-thumbtack" style="color:#f43f5e"></i>Pinned folders</span></div>
  <div class="mini" id="pins"></div>
  <div class="sec"><span style="--sc:#38bdf8"><i class="fa-solid fa-clock-rotate-left" style="color:#38bdf8"></i>Recently visited</span></div>
  <div class="mini" id="recents"></div>
  <div class="store">
    <div class="t"><span>Storage</span><span><?= $used_percent ?>% used</span></div>
    <div class="bar"><i style="width:<?= $used_percent ?>%"></i></div>
    <small><?= $e(formatSize($free_space)) ?> free of <?= $e(formatSize($total_space)) ?></small>
  </div>
</aside>
<div class="bd" id="bd"></div>

<!-- ================= MAIN ================= -->
<div class="main">
<header class="top">
  <button class="ib" id="menuBtn" style="display:none" aria-label="Menu"><i class="fa-solid fa-bars" style="color:var(--ac)"></i></button>
  <div class="srch"><i class="fa-solid fa-magnifying-glass" style="color:var(--ac)"></i><input id="q" type="search" placeholder="Search in this folder…  ( / )" autocomplete="off"><button type="button" id="csBtn" class="cs-tg" title="Also search inside file contents"><i class="fa-solid fa-file-lines" style="color:#38bdf8"></i><span>Contents</span></button><button type="button" id="sClose" class="ib" aria-label="Close search"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button><kbd>Ctrl K</kbd><div id="csRes" hidden></div></div>
  <span class="sp"></span>
  <button class="ib" id="sBtn" aria-label="Search" title="Search"><i class="fa-solid fa-magnifying-glass" style="color:var(--ac)"></i></button>
  <button class="btn pri sm" id="pasteBtn" hidden><i class="fa-solid fa-paste"></i><span id="pasteN">Paste</span></button>
  <button class="ib hide-m" id="kbBtn" title="Keyboard shortcuts (?)"><i class="fa-solid fa-keyboard" style="color:#38bdf8"></i></button>
  <button class="ib hide-m" id="palBtn" title="Command palette (Ctrl+K)"><i class="fa-solid fa-terminal" style="color:#34d399"></i></button>
  <button class="ib" id="accBtn" title="Accent color"><i class="fa-solid fa-palette" style="color:var(--ac)"></i></button>
  <button class="ib" id="themeBtn" title="Theme"><i class="fa-solid fa-circle-half-stroke" style="color:#a78bfa"></i></button>
  <?php $fd_user = (string)($_SESSION['fd_user'] ?? 'admin'); $fd_ini = strtoupper(function_exists('mb_substr') ? mb_substr($fd_user, 0, 1) : substr($fd_user, 0, 1)); ?>
  <button class="av" id="avBtn" type="button" aria-label="Account" aria-haspopup="true" aria-expanded="false"><?= htmlspecialchars($fd_ini, ENT_QUOTES, 'UTF-8') ?></button>
  <div class="acct" id="acct" hidden>
    <div class="ah"><span class="av lg"><?= htmlspecialchars($fd_ini, ENT_QUOTES, 'UTF-8') ?></span><div><b><?= htmlspecialchars($fd_user, ENT_QUOTES, 'UTF-8') ?></b><small><i class="fa-solid fa-shield-halved" style="color:#10b981"></i> Admin</small></div></div>
    <a class="lo" href="?fdpage=logout"><i class="fa-solid fa-right-from-bracket" style="color:#ef4444"></i>Logout</a>
  </div>
</header>

<main class="work" id="work">
  <div id="cfgBox" hidden data-cfg="<?= $e(json_encode($cfg, JSON_UNESCAPED_UNICODE)) ?>"></div>

  <!-- quick stats -->
  <section class="cards">
    <div class="cd" style="--c:#f59e0b"><div class="ci"><i class="fa-solid fa-folder"></i></div><div><b><?= $n_dirs ?></b><small>Folders</small></div></div>
    <div class="cd" style="--c:#6366f1"><div class="ci"><i class="fa-solid fa-file"></i></div><div><b><?= $n_files ?></b><small>Files</small></div></div>
    <div class="cd" style="--c:#10b981"><div class="ci"><i class="fa-solid fa-database"></i></div><div><b><?= $e(formatSize($total_bytes)) ?></b><small>In this folder</small></div></div>
    <div class="cd" style="--c:#ec4899"><div class="ci"><i class="fa-solid fa-hard-drive"></i></div><div><b><?= $e(formatSize($free_space)) ?></b><small>Free space</small></div></div>
  </section>

  <!-- breadcrumb + jump -->
  <section class="pathbar">
    <nav class="crumbs" aria-label="Breadcrumb">
      <a href="?path=<?= urlencode($server_root) ?>"><i class="fa-solid fa-house" style="color:var(--ac)"></i></a>
      <?php foreach ($crumbs as $i => $c): ?><span class="sl">›</span>
        <?php if ($i === count($crumbs) - 1): ?><span class="cur"><?= $e($c[0]) ?></span><?php else: ?><a href="?path=<?= urlencode($c[1]) ?>"><?= $e($c[0]) ?></a><?php endif; ?>
      <?php endforeach; ?>
    </nav>
    <form action="index.php" method="GET" class="jump hide-m">
      <input type="text" name="path" value="<?= $e($current_path) ?>" spellcheck="false" aria-label="Path">
      <button class="btn pri sm" type="submit">Jump</button>
    </form>
  </section>

  <!-- toolbar -->
  <section class="tools">
    <div class="grp">
      <button class="btn pri hide-m" data-open="uploadModal"><i class="fa-solid fa-cloud-arrow-up"></i>Upload</button>
      <button class="btn hide-m" data-open="folderModal"><i class="fa-solid fa-folder-plus" style="color:#f59e0b"></i>New Folder</button>
      <button class="btn hide-m" data-open="fileModal"><i class="fa-solid fa-file-circle-plus" style="color:#818cf8"></i>New File</button>
      <button class="btn hide-m" data-open="urlModal"><i class="fa-solid fa-globe" style="color:#06b6d4"></i>From URL</button>
    </div>
    <div class="grp" style="min-width:0">
      <div class="chips" id="chips">
        <button class="chip on" data-f="">All</button><button class="chip" data-f="fav">★ Favorites</button><button class="chip" data-f="folder">Folders</button><button class="chip" data-f="image">Images</button><button class="chip" data-f="video">Video</button><button class="chip" data-f="audio">Audio</button><button class="chip" data-f="doc">Docs</button><button class="chip" data-f="code">Code</button><button class="chip" data-f="archive">Archives</button>
      </div>
    </div>
    <div class="grp">
      <select class="sel" id="sortSel" aria-label="Sort">
        <?php foreach (['name'=>'Name','size'=>'Size','date'=>'Modified','type'=>'Type'] as $k => $l): foreach (['asc'=>'↑','desc'=>'↓'] as $o => $ar): ?>
          <option value="<?= $e(qs(['sort'=>$k,'order'=>$o])) ?>" <?= ($sort === $k && $order === $o) ? 'selected' : '' ?>><?= $l ?> <?= $ar ?></option>
        <?php endforeach; endforeach; ?>
      </select>
      <div class="seg" id="viewSeg"><button data-v="list" title="List"><i class="fa-solid fa-list"></i></button><button data-v="grid" title="Grid"><i class="fa-solid fa-grip"></i></button><button data-v="gallery" title="Gallery"><i class="fa-solid fa-image"></i></button></div>
      <a class="ib" id="hidBtn" href="<?= $e(qs(['hidden' => $show_hidden ? 0 : 1])) ?>" title="<?= $show_hidden ? 'Hide' : 'Show' ?> hidden files" style="<?= $show_hidden ? 'color:var(--ac)' : '' ?>"><i class="fa-solid fa-eye<?= $show_hidden ? '' : '-slash' ?>"></i></a>
      <button class="ib" id="reloadBtn" title="Refresh"><i class="fa-solid fa-rotate" style="color:#22d3ee"></i></button>
    </div>
  </section>

  <div id="szNote" style="display:contents">
  <?php if ($sizes_incomplete): ?>
  <div style="font-size:12.5px;color:var(--mut)">⏱ Some folder sizes are skipped to keep the page fast. <a href="<?= $e(qs(['sizes'=>1])) ?>" style="color:var(--ac);font-weight:600">Calculate all folder sizes</a></div>
  <?php endif; ?>
  </div>

  <!-- multi form -->
  <form id="multiForm" action="?fdpage=actions&path=<?= urlencode($current_path) ?>" method="POST">
    <input type="hidden" name="action" id="multiAction" value="multi_download">

    <div class="selbar" id="selbar" hidden>
      <span id="selTxt" style="font-weight:600"></span>
      <div class="grp">
        <button type="button" class="btn sm" id="sbAll"><i class="fa-solid fa-check-double" style="color:#34d399"></i><span class="hide-m">Invert</span></button>
        <button type="button" class="btn sm" data-multi="star"><i class="fa-solid fa-star" style="color:#f59e0b"></i><span class="hide-m">Star</span></button>
        <button type="button" class="btn sm" data-multi="copy"><i class="fa-solid fa-copy" style="color:#818cf8"></i><span class="hide-m">Copy</span></button>
        <button type="button" class="btn sm" data-multi="move"><i class="fa-solid fa-scissors" style="color:#f43f5e"></i><span class="hide-m">Cut</span></button>
        <button type="button" class="btn sm pri" data-multi="zip"><i class="fa-solid fa-file-zipper"></i><span class="hide-m">ZIP</span></button>
        <button type="button" class="btn sm dng" data-multi="del"><i class="fa-solid fa-trash" style="color:#fb7185"></i><span class="hide-m">Delete</span></button>
        <button type="button" class="btn sm" id="sbClear"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button>
      </div>
    </div>

    <div id="view" class="v-list" style="margin-top:12px">
      <script>(function(){var v=FDP.get('view',null);if(v!=='list'&&v!=='grid'&&v!=='gallery')v='list';document.getElementById('view').className='v-'+v;})();</script>
      <div class="lhead">
        <span><input type="checkbox" id="selectAll" style="accent-color:var(--ac)"></span>
        <?php
        $h = function($k, $l) use ($sort, $order) { $n = ($sort === $k && $order === 'asc') ? 'desc' : 'asc'; return '<a href="' . htmlspecialchars(qs(['sort'=>$k,'order'=>($sort === $k ? $n : 'asc')])) . '" class="' . ($sort === $k ? 'on' : '') . '">' . $l . ($sort === $k ? ($order === 'asc' ? ' ↑' : ' ↓') : '') . '</a>'; };
        echo $h('name', 'Name') . $h('size', 'Size') . $h('date', 'Modified') . $h('type', 'Perm');
        ?>
        <span style="text-align:right">Actions</span>
      </div>

      <div class="list" id="list">
      <?php if ($current_path !== $server_root): ?>
        <a class="fi" href="?path=<?= urlencode(dirname($current_path)) ?>" style="grid-column:1/-1;display:flex;gap:12px;align-items:center;color:var(--ac);font-weight:600" data-up="1"><i class="fa-solid fa-arrow-turn-up" style="transform:rotate(-90deg)"></i> .. Parent directory</a>
      <?php endif; ?>

      <?php foreach ($items as $i => $it):
          [$type, $faIcon] = ftype($it['ext'], $it['is_dir']);
          $is_dir = $it['is_dir']; $full = $it['full_path'];
          $editable = !$is_dir && !in_array($it['ext'], $binary_exts, true);
          $previewable = !$is_dir && in_array($it['ext'], $prev_exts, true);
          $thumb = ($type === 'image' && $previewable && $it['size'] < 4194304);
          $href = $is_dir ? '?path=' . urlencode($full) : ($editable ? '?fdpage=editor&file=' . urlencode($full) : '?download=' . urlencode($full));
      ?>
        <div class="fi t-<?= $type ?>" style="animation-delay:<?= min($i, 18) * 18 ?>ms"
             data-path="<?= $e($full) ?>" data-name="<?= $e(strtolower($it['name'])) ?>" data-label="<?= $e($it['name']) ?>" data-type="<?= $type ?>" data-dir="<?= $is_dir ? 1 : 0 ?>"
             data-fav="<?= isset($fav_set[$full]) ? 1 : 0 ?>" data-size="<?= $it['size'] === null ? -1 : (int)$it['size'] ?>" data-mtime="<?= (int)$it['mtime'] ?>" data-perm="<?= $e($it['perm']) ?>"
             data-edit="<?= $editable ? 1 : 0 ?>" data-prev="<?= $previewable ? 1 : 0 ?>" data-ext="<?= $e($it['ext']) ?>" data-href="<?= $e($href) ?>">
          <label class="chk"><input type="checkbox" name="files[]" value="<?= $e($full) ?>" class="file-checkbox" aria-label="Select"></label>
          <a class="nm" href="<?= $e($href) ?>" title="<?= $e($it['name']) ?>">
            <span class="ico"><?php if ($thumb): ?><img loading="lazy" src="?raw=<?= rawurlencode($full) ?>" alt=""><?php else: ?><i class="fa-solid <?= $faIcon ?>"></i><?php endif; ?></span>
            <span class="tx"><?= $e($it['name']) ?></span>
          </a>
          <span class="cs"><?= $e(formatSize($it['size'])) ?></span>
          <span class="cdt"><?= $it['mtime'] ? date('d M Y, h:i A', $it['mtime']) : '-' ?></span>
          <span class="cp"><?= $e($it['perm']) ?></span>
          <div class="acts">
            <button type="button" class="stb" data-act="fav" title="Favorite"><i class="fa-solid fa-star"></i></button>
            <button type="button" data-act="copy" title="Copy"><i class="fa-solid fa-copy" style="color:#818cf8"></i></button>
            <button type="button" data-act="move" title="Cut / Move"><i class="fa-solid fa-scissors" style="color:#f43f5e"></i></button>
            <button type="button" data-act="rename" title="Rename"><i class="fa-solid fa-pen" style="color:#3b82f6"></i></button>
            <?php if ($editable): ?><a href="?fdpage=editor&file=<?= urlencode($full) ?>" title="Edit"><i class="fa-solid fa-code" style="color:#8b5cf6"></i></a><?php endif; ?>
            <?php if (!$is_dir): ?><a href="?download=<?= urlencode($full) ?>" title="Download"><i class="fa-solid fa-download" style="color:#10b981"></i></a><?php endif; ?>
            <button type="button" class="d" data-act="delete" title="Delete"><i class="fa-solid fa-trash" style="color:#fb7185"></i></button>
          </div>
          <button type="button" class="more" data-act="menu" aria-label="More"><i class="fa-solid fa-ellipsis-vertical" style="color:#a78bfa"></i></button>
        </div>
      <?php endforeach; ?>
      </div>

      <div class="empty" id="empty" <?= $items ? 'hidden' : '' ?>><i class="fa-regular fa-folder-open" style="color:#f59e0b"></i><b>This folder is empty</b><div>Drag &amp; drop files here, or tap ＋</div></div>
      <div class="empty" id="noMatch" hidden><i class="fa-solid fa-magnifying-glass" style="color:#38bdf8"></i><b>No matching items</b></div>
    </div>
  </form>
</main>
<section class="work" id="page" hidden></section>
<div class="work" id="embedHost"><div class="eh-in" id="ehIn"></div></div>
</div>
</div>

<!-- mobile bottom nav -->
<nav class="bnav" id="bnav">
  <button id="bnFiles" style="color: #38bdf8;"><i class="fa-solid fa-folder-open" style="color:#38bdf8"></i>Files</button>
<button id="bnFav" style="color: #fbbf24;"><i class="fa-solid fa-star" style="color:#f59e0b"></i>Starred</button>
<button class="add" id="bnAdd" style="color: #34d399;"><i class="fa-solid fa-plus"></i></button>
<button id="bnPaste" style="color: #c084fc;"><i class="fa-solid fa-paste" style="color:#c084fc"></i>Paste</button>
<button id="bnMenu" style="color: var(--ac);"><i class="fa-solid fa-bars" style="color:var(--ac)"></i>Menu</button>
</nav>
<div class="fab" id="fab">
  <button data-open="uploadModal" style="color: #38bdf8;"><i class="fa-solid fa-cloud-arrow-up" style="color: #38bdf8;"></i>Upload</button>
  <button data-open="folderModal" style="color: #fbbf24;"><i class="fa-solid fa-folder-plus" style="color: #fbbf24;"></i>New Folder</button>
  <button data-open="fileModal" style="color: #34d399;"><i class="fa-solid fa-file-circle-plus" style="color: #34d399;"></i>New File</button>
  <button data-open="urlModal" style="color: #c084fc;"><i class="fa-solid fa-globe" style="color: #c084fc;"></i>From URL</button>
</div>

<!-- hidden single-action form (matches ?fdpage=actions) -->
<form id="actionForm" action="?fdpage=actions&path=<?= urlencode($current_path) ?>" method="POST" hidden>
  <input type="hidden" name="action" id="formAction"><input type="hidden" name="item_path" id="formItemPath"><input type="hidden" name="dest_path" id="formDestPath"><input type="hidden" name="new_name" id="formNewName">
</form>

<!-- ================= MODALS ================= -->
<div class="modal" id="uploadModal"><div class="mc" style="max-width:480px">
  <h3><span><i class="fa-solid fa-cloud-arrow-up" style="color:var(--ac)"></i>&nbsp; Upload files</span><button class="ib" data-close style="width:34px;height:34px"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></h3>
  <div class="drop" id="dropBox"><i class="fa-solid fa-folder-open" style="color:#f59e0b"></i><div>Drag &amp; drop files or <b style="color:var(--ac)">browse</b></div><small id="limitTxt"></small><input type="file" id="fileIn" multiple></div>
  <div class="mf"><button class="btn" data-close type="button">Close</button></div>
</div></div>

<div class="modal" id="folderModal"><div class="mc">
  <h3><span><i class="fa-solid fa-folder-plus" style="color:#f59e0b"></i>&nbsp; New folder</span><button class="ib" data-close style="width:34px;height:34px"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></h3>
  <form action="?fdpage=actions&path=<?= urlencode($current_path) ?>" method="POST"><input type="hidden" name="action" value="create_folder">
    <input class="inp" type="text" name="folder_name" required placeholder="Folder name…" autocomplete="off">
    <div class="mf"><button class="btn" type="button" data-close>Cancel</button><button class="btn pri" type="submit">Create</button></div></form>
</div></div>

<div class="modal" id="fileModal"><div class="mc">
  <h3><span><i class="fa-solid fa-file-circle-plus" style="color:#818cf8"></i>&nbsp; New file</span><button class="ib" data-close style="width:34px;height:34px"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></h3>
  <form action="?fdpage=actions&path=<?= urlencode($current_path) ?>" method="POST"><input type="hidden" name="action" value="create_file">
    <input class="inp" type="text" name="file_name" required placeholder="e.g. index.php" autocomplete="off">
    <div class="mf"><button class="btn" type="button" data-close>Cancel</button><button class="btn pri" type="submit">Create</button></div></form>
</div></div>

<div class="modal" id="renameModal"><div class="mc">
  <h3><span><i class="fa-solid fa-pen" style="color:var(--ac)"></i>&nbsp; Rename</span><button class="ib" data-close style="width:34px;height:34px"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></h3>
  <form action="?fdpage=actions&path=<?= urlencode($current_path) ?>" method="POST"><input type="hidden" name="action" value="rename"><input type="hidden" name="item_path" id="renamePath">
    <input class="inp" type="text" name="new_name" id="renameIn" required autocomplete="off">
    <div class="mf"><button class="btn" type="button" data-close>Cancel</button><button class="btn pri" type="submit">Rename</button></div></form>
</div></div>

<div class="si" id="si" hidden></div>

<div class="modal" id="kbModal"><div class="mc" style="max-height:86vh;overflow:auto">
  <h3><span><i class="fa-solid fa-keyboard" style="color:var(--ac)"></i>&nbsp; Keyboard shortcuts</span><button class="ib" type="button" data-close style="width:34px;height:34px"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></h3>
  <div id="kbBodyHome"></div>
</div></div>

<div class="modal" id="confirmModal"><div class="mc">
  <h3><span id="cfTitle"><i class="fa-solid fa-triangle-exclamation" style="color:var(--warn)"></i>&nbsp; Confirm</span></h3>
  <p id="cfMsg" style="color:var(--mut)"></p>
  <div class="mf"><button class="btn" type="button" data-close>Cancel</button><button class="btn dng" type="button" id="cfOk">Delete</button></div>
</div></div>

<div class="modal" id="urlModal"><div class="mc">
  <h3><span><i class="fa-solid fa-globe" style="color:#06b6d4"></i>&nbsp; Download from URL</span><button class="ib" data-close style="width:34px;height:34px"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></h3>
  <form id="urlForm">
    <div class="fld"><div class="lbl">File URL</div><input class="inp" name="url" type="url" inputmode="url" required placeholder="https://example.com/file.zip" autocomplete="off"></div>
    <div class="fld"><div class="lbl">Save as (optional)</div><input class="inp" name="name" autocomplete="off"></div>
    <div class="hint">Saves into the folder you are viewing.</div>
    <div class="mf" id="urlActions"><button class="btn" type="button" data-close>Cancel</button><button class="btn pri" type="submit" id="urlGo"><i class="fa-solid fa-cloud-arrow-down"></i>Download</button></div>
    <div id="urlProgress" hidden>
      <button type="button" class="url-progress-btn" disabled>
        <span id="urlPercent">0%</span>
        <span class="url-progress-label"><i class="fa-solid fa-spinner fa-spin"></i>Downloading...</span>
        <span id="urlSize">0 B / ?</span>
      </button>
      <button type="button" class="btn" id="urlCancel">Cancel</button>
    </div>
  </form>
</div></div>

<div class="modal" id="infoModal"><div class="mc">
  <h3><span><i class="fa-solid fa-circle-info" style="color:var(--ac)"></i>&nbsp; Properties</span><button class="ib" data-close style="width:34px;height:34px"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></h3>
  <div id="infoBody"></div>
  <div class="mf"><button class="btn pri" type="button" data-close>Close</button></div>
</div></div>

<div class="modal" id="shareModal"><div class="mc">
  <h3><span><i class="fa-solid fa-link" style="color:var(--ac2)"></i>&nbsp; Share link</span><button class="ib" data-close style="width:34px;height:34px"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></h3>
  <div class="hint" style="margin:-6px 0 12px">File: <b id="shName"></b></div>
  <div class="fld"><div class="lbl">Link expires after</div><select class="inp" id="shTtl"><option value="3600">1 hour</option><option value="86400" selected>1 day</option><option value="604800">7 days</option><option value="0">Never</option></select></div>
  <div id="shOut" hidden><div class="lbl">Your link</div><div style="display:flex;gap:8px"><input class="inp" id="shUrl" readonly><button class="btn pri" type="button" id="shCopy"><i class="fa-solid fa-copy"></i>Copy</button></div></div>
  <div class="mf"><button class="btn" type="button" data-close>Close</button><button class="btn pri" type="button" id="shGo"><i class="fa-solid fa-link"></i>Create link</button></div>
</div></div>

<div class="modal" id="accModal"><div class="mc">
  <h3><span><i class="fa-solid fa-palette" style="color:var(--ac)"></i>&nbsp; Accent color</span><button class="ib" data-close style="width:34px;height:34px"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></h3>
  <div class="swatches" id="sws"></div>
  <div style="margin-top:14px;display:flex;align-items:center;gap:10px"><input type="color" id="accPick" value="#6366f1" style="width:44px;height:36px;border:0;background:none"><span style="color:var(--mut)">Custom color</span></div>
  <div class="mf"><button class="btn" id="accReset" type="button">Reset</button><button class="btn pri" type="button" data-close>Done</button></div>
</div></div>

<!-- overlays -->
<div class="dz" id="dz" hidden><div><i class="fa-solid fa-cloud-arrow-up" style="color:#6366f1"></i>Drop files to upload here</div></div>
<div class="tray" id="tray" hidden><h4><span id="trayT">Uploading…</span><button id="trayX" class="ib" style="width:28px;height:28px"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></h4><div class="tl" id="trayL"></div></div>
<div class="ctx" id="ctx" hidden></div>
<div class="toasts" id="toasts"></div>
<div class="pal" id="pal"><div class="pc"><input id="palIn" placeholder="Type a command or file name…" autocomplete="off"><ul id="palL"></ul></div></div>
<div class="pv" id="pv"><div class="pvh"><b id="pvName"></b><button class="ib" id="pvPrev"><i class="fa-solid fa-chevron-left" style="color:#818cf8"></i></button><button class="ib" id="pvNext"><i class="fa-solid fa-chevron-right" style="color:#818cf8"></i></button><a class="ib" id="pvDl"><i class="fa-solid fa-download" style="color:#10b981"></i></a><button class="ib" id="pvX"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></div><div class="pvb" id="pvB"></div></div>

<script>
const CFG = <?= json_encode($cfg, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS) ?>;
(() => {
'use strict';
const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const ls = { get: (k, d) => { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } }, set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} } };
const fmt = b => { const u = ['B', 'KB', 'MB', 'GB']; let i = 0, x = b; while (x >= 1024 && i < 3) { x /= 1024; i++; } return (i ? x.toFixed(1) : x) + ' ' + u[i]; };
const base = p => p.replace(/[\\/]+$/, '').split(/[\\/]/).pop() || p;
const rows = () => $$('#list .fi[data-path]');
const sel = () => rows().filter(r => $('.file-checkbox', r).checked);

/* ---------- mobile: lock background scroll while a menu / popup is open ---------- */
(() => {
  const els = [...document.querySelectorAll('.modal,#pv,#pal,#ctx')];
  const sync = () => { const c = document.getElementById('ctx'); const open = innerWidth <= 900 && ((c && !c.hidden) || document.querySelector('.modal.open,#pv.open,#pal.open')); document.documentElement.classList.toggle('lock', !!open); };
  /* hard block: nothing behind a menu / popup can be dragged (works even where overflow:hidden is ignored) */
  document.addEventListener('touchmove', e => { if (document.documentElement.classList.contains('lock') && !e.target.closest('.ctx,.mc,.pc,.tl,#pvB')) e.preventDefault(); }, { passive: false });
  document.addEventListener('wheel', e => { if (document.documentElement.classList.contains('lock') && !e.target.closest('.ctx,.mc,.pc,.tl,#pvB')) e.preventDefault(); }, { passive: false });
  /* keep the focused field visible inside a popup when the keyboard opens */
  document.addEventListener('focusin', e => { if (e.target.closest && e.target.closest('.mc')) setTimeout(() => e.target.scrollIntoView({ block: 'nearest' }), 320); });
  const mo = new MutationObserver(sync); els.forEach(el => mo.observe(el, { attributes: true, attributeFilter: ['class', 'hidden'] })); addEventListener('resize', sync);
  /* popups sit above the on-screen keyboard (iOS / Android) */
  const vv = window.visualViewport;
  if (vv) { const set = () => { const r = document.documentElement.style; r.setProperty('--vvh', vv.height + 'px'); r.setProperty('--vvt', vv.offsetTop + 'px'); }; vv.addEventListener('resize', set); vv.addEventListener('scroll', set); set(); }
})();

/* ---------- toast / modal ---------- */
function toast(m, t = '', ms = 3800) { const d = document.createElement('div'); d.className = 'toast ' + t; d.innerHTML = `<i class="fa-solid ${{ ok: 'fa-circle-check', err: 'fa-circle-exclamation', warn: 'fa-triangle-exclamation' }[t] || 'fa-circle-info'}" style="color:${{ ok: '#10b981', err: '#ef4444', warn: '#f59e0b' }[t] || '#38bdf8'}"></i><span>${esc(m)}</span>`; $('#toasts').append(d); setTimeout(() => { d.classList.add('out'); setTimeout(() => d.remove(), 260); }, ms); }
const openM = id => { $('#' + id).classList.add('open'); const i = $('#' + id + ' input:not([type=hidden]):not([type=file])'); i && setTimeout(() => i.focus(), 40); };
const closeM = el => (el.closest ? el.closest('.modal') : el).classList.remove('open');
document.addEventListener('click', e => { const o = e.target.closest('[data-open]'); if (o) { $('#fab').classList.remove('open'); openM(o.dataset.open); } const c = e.target.closest('[data-close]'); if (c) closeM(c); if (e.target.classList.contains('modal')) closeM(e.target); });
function confirmBox(msg, ok, cb) { $('#cfMsg').innerHTML = msg; $('#cfOk').textContent = ok; $('#cfOk').onclick = () => { closeM($('#confirmModal')); cb(); }; openM('confirmModal'); }

/* ---------- theme & accent (remembered; applied before first paint) ---------- */
const root = document.documentElement;
addEventListener('storage', e => { if (e.key === 'fd_theme') FDP.theme(); if (e.key === 'fd_accent') FDP.accent(); });
$('#themeBtn').onclick = () => {
  const btn = $('#themeBtn'), r = btn.getBoundingClientRect(), x = r.left + r.width / 2, y = r.top + r.height / 2;
  const rad = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));
  const next = root.classList.contains('light') ? 'dark' : 'light';
  /* instant swap: no per-element colour transitions (they are what made it laggy); storage write is deferred */
  const apply = () => { root.classList.add('nt'); root.classList.toggle('light', next === 'light'); $$('#ehIn iframe').forEach(f => { try { f.contentDocument.documentElement.classList.toggle('light', next === 'light'); } catch (e) {} }); };
  const done = () => { FDP.set('theme', next); requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove('nt'))); };
  if (!document.startViewTransition) { apply(); done(); return; }   /* reveal plays even when the OS says "reduce motion" (common on desktops) */
  root.style.setProperty('--tx', x + 'px'); root.style.setProperty('--ty', y + 'px');   // Telegram-style reveal on mobile + desktop
  const vt = document.startViewTransition(apply);
  vt.ready.then(() => root.animate({ clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${rad}px at ${x}px ${y}px)`] },
    { duration: 640, easing: 'cubic-bezier(.35,0,.15,1)', fill: 'forwards', pseudoElement: '::view-transition-new(root)' })).catch(() => {});
  vt.finished.finally(done);
};
matchMedia('(prefers-color-scheme:dark)').addEventListener && matchMedia('(prefers-color-scheme:dark)').addEventListener('change', () => FDP.theme());
const COLS = ['#6366f1', '#8b5cf6', '#ec4899', '#ef4444', '#f97316', '#eab308', '#22c55e', '#14b8a6', '#06b6d4', '#3b82f6'];
$('#sws').innerHTML = COLS.map(c => `<button class="sw" data-c="${c}" style="background:${c}" aria-label="${c}"></button>`).join('');
const markSw = () => { const a = FDP.get('accent', null); $$('.sw').forEach(s => s.classList.toggle('on', s.dataset.c === a)); if (a) $('#accPick').value = a; };
$('#accBtn').onclick = () => { markSw(); openM('accModal'); };
$('#sws').onclick = e => { const c = e.target.dataset.c; if (c) { FDP.set('accent', c); FDP.accent(); markSw(); } };
$('#accPick').oninput = e => { FDP.set('accent', e.target.value); FDP.accent(); markSw(); };
$('#accReset').onclick = () => { FDP.del('accent'); FDP.accent(); markSw(); };

/* ---------- profile menu ---------- */
const acct = $('#acct'), avBtn = $('#avBtn');
const closeAcct = () => { acct.hidden = true; avBtn.setAttribute('aria-expanded', 'false'); };
avBtn.onclick = e => { e.stopPropagation(); acct.hidden = !acct.hidden; avBtn.setAttribute('aria-expanded', String(!acct.hidden)); };
document.addEventListener('click', e => { if (!e.target.closest('#acct')) closeAcct(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeAcct(); });

/* ---------- sidebar (mobile) ---------- */
const side = $('#side'), bd = $('#bd');
const toggleSide = o => { side.classList.toggle('open', o); bd.classList.toggle('show', o); };
$('#menuBtn').onclick = $('#bnMenu').onclick = () => toggleSide(true); bd.onclick = () => toggleSide(false);
if (innerWidth <= 900) $('#menuBtn').style.display = 'inline-grid'; addEventListener('resize', () => { $('#menuBtn').style.display = innerWidth <= 900 ? 'inline-grid' : 'none'; });
$('#bnAdd').onclick = e => { e.stopPropagation(); $('#fab').classList.toggle('open'); }; document.addEventListener('click', e => { if (!e.target.closest('#fab,#bnAdd')) $('#fab').classList.remove('open'); if (!e.target.closest('#ctx') && Date.now() - ctxT > 350) $('#ctx').hidden = true; });
$('#reloadBtn').onclick = async () => { const i = $('#reloadBtn i'); i.classList.add('fa-spin'); await softReload(); i.classList.remove('fa-spin'); };
$('#bnFiles').onclick = () => go('index.php');

/* ---------- smart bottom dock (mobile) — works on every tab ---------- */
(() => {
  const mob = () => innerWidth <= 900, fab = $('#fab');
  const dock = off => { document.body.classList.toggle('dock-off', off); if (off) fab.classList.remove('open'); };
  let kb = false, popup = false;
  /* one tracker per scroller (window, inner containers, embedded iframes) */
  const mk = () => { let last = 0; return (y, atEnd) => {
    if (!mob()) return; y = Math.max(0, y); const d = y - last;
    if (Math.abs(d) < 8) return; last = y;
    if (kb || popup) return dock(true);
    dock(d > 0 && y > 60 && !atEnd);
  }; };
  const win = mk();
  addEventListener('scroll', () => win(scrollY, innerHeight + scrollY >= document.documentElement.scrollHeight - 40), { passive: true });
  const seen = new WeakMap();
  /* scrolls inside inner containers (capture: scroll events don't bubble) */
  document.addEventListener('scroll', e => {
    const t = e.target; if (!t || t === document || t === document.documentElement || t === document.body || !t.scrollHeight) return;
    let f = seen.get(t); if (!f) seen.set(t, f = mk());
    f(t.scrollTop, t.scrollTop + t.clientHeight >= t.scrollHeight - 40);
  }, { passive: true, capture: true });
  const isField = el => el && /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName) && !/^(checkbox|radio|file|color|button|submit)$/.test(el.type || '');
  addEventListener('focusin', e => { if (mob() && isField(e.target)) { kb = true; dock(true); } });
  addEventListener('focusout', () => setTimeout(() => { if (!isField(document.activeElement)) { kb = false; dock(false); } }, 120));
  addEventListener('resize', () => { if (!mob()) dock(false); });
  /* embedded pages (Database / Settings / Dashboard / Trash): hook their own scroll + keyboard */
  const hook = f => { let w, d; try { w = f.contentWindow; d = f.contentDocument; } catch (e) { return; } if (!w || !d) return;
    const fw = mk(), fe = () => { const de = d.documentElement; return de.scrollTop || d.body.scrollTop || 0; };
    w.addEventListener('scroll', () => { const de = d.documentElement; const y = fe(); fw(y, w.innerHeight + y >= de.scrollHeight - 40); }, { passive: true });
    d.addEventListener('scroll', e => { const t = e.target; if (!t || t === d || !t.scrollHeight) return; let g = seen.get(t); if (!g) seen.set(t, g = mk()); g(t.scrollTop, t.scrollTop + t.clientHeight >= t.scrollHeight - 40); }, { passive: true, capture: true });
    /* tapping / touching inside an embedded page closes the floating mobile search (like on Home) */
    const sc = () => { window.fdSearchClose && window.fdSearchClose(); };
    d.addEventListener('pointerdown', sc, { passive: true, capture: true }); d.addEventListener('touchstart', sc, { passive: true, capture: true });
    /* a popup / sheet / modal opened inside the page -> the dock steps out of the way until it is closed */
    const POP = '.cf,.sheet,.sbd,#sheet,#modal,.modal,[role=dialog],dialog';
    const chk = () => {
      if (f.dataset.p !== curPage) return; let on = false;
      try { for (const el of d.querySelectorAll(POP)) { if (el.hidden) continue; const cs = w.getComputedStyle(el); if (cs.display === 'none' || cs.visibility === 'hidden') continue; const r = el.getBoundingClientRect(); if (r.width < w.innerWidth * .5 || r.height < w.innerHeight * .5) continue; on = true; break; } } catch (e) {}
      if (on !== popup) { popup = on; if (mob()) dock(on || kb); }
    };
    let raf = 0; const sched = () => { cancelAnimationFrame(raf); raf = requestAnimationFrame(chk); };
    try { new MutationObserver(sched).observe(d.documentElement, { subtree: true, childList: true, attributes: true, attributeFilter: ['class', 'hidden', 'style', 'open'] }); } catch (e) {}
    /* swipe direction also drives the dock (works even when the page is too short to scroll) */
    let ty = null, acc = 0;
    d.addEventListener('touchstart', e => { ty = e.touches[0].clientY; acc = 0; }, { passive: true });
    d.addEventListener('touchmove', e => { if (ty === null || !mob() || popup) return; const y = e.touches[0].clientY, dy = ty - y; ty = y; acc = (acc * dy < 0 ? 0 : acc) + dy; if (Math.abs(acc) < 14) return; dock(kb ? true : acc > 0); acc = 0; }, { passive: true });
    d.addEventListener('focusin', e => { if (mob() && isField(e.target)) { kb = true; dock(true); } });
    d.addEventListener('focusout', () => setTimeout(() => { if (!isField(d.activeElement)) { kb = false; dock(popup); } }, 120));
  };
  document.addEventListener('load', e => { const f = e.target; if (f && f.classList && f.classList.contains('fd-embed-frame')) { if (f.dataset.p === curPage) dock(false); hook(f); } }, true);
  const setTop = () => { const t = document.querySelector('.top'); if (t) document.documentElement.style.setProperty('--toph', t.offsetHeight + 'px'); };
  setTop(); addEventListener('resize', setTop); addEventListener('orientationchange', setTop);
  /* switching tabs always brings the dock back */
  addEventListener('hashchange', () => { kb = false; popup = false; dock(false); });
})();

/* ---------- pinned + recent folders ---------- */
function pinList() {
  const pins = ls.get('fd_pins', []), rec = ls.get('fd_recent', []).filter(p => p !== CFG.path).slice(0, 6);
  const PC = ['#f43f5e', '#f59e0b', '#10b981', '#38bdf8', '#a855f7', '#ec4899', '#14b8a6', '#6366f1'];
  $('#pins').innerHTML = pins.map((p, i) => `<a href="?path=${encodeURIComponent(p)}" title="${esc(p)}"><i class="fa-solid fa-thumbtack" style="color:${PC[i % PC.length]}"></i><span>${esc(base(p))}</span><i class="fa-solid fa-xmark x" data-unpin="${esc(p)}"></i></a>`).join('') || '<small>Right-click a folder → Pin</small>';
  $('#recents').innerHTML = rec.map((p, i) => `<a href="?path=${encodeURIComponent(p)}" title="${esc(p)}"><i class="fa-solid fa-folder-open" style="color:${PC[(i + 3) % PC.length]}"></i><span>${esc(base(p))}</span></a>`).join('') || '<small>Nothing yet</small>';
}
$('#pins').onclick = e => { const u = e.target.dataset.unpin; if (u) { e.preventDefault(); ls.set('fd_pins', ls.get('fd_pins', []).filter(p => p !== u)); pinList(); } };
const pin = p => { const a = ls.get('fd_pins', []); if (!a.includes(p)) { a.push(p); ls.set('fd_pins', a); toast('Pinned: ' + base(p), 'ok'); pinList(); } };
ls.set('fd_recent', [CFG.path, ...ls.get('fd_recent', []).filter(p => p !== CFG.path)].slice(0, 10)); pinList();

/* ---------- view mode / filter / search ---------- */
function setView(v) { const el = $('#view'); el.className = 'v-' + v; $$('#viewSeg button').forEach(b => b.classList.toggle('on', b.dataset.v === v)); FDP.set('view', v); }
$('#viewSeg').onclick = e => { const b = e.target.closest('button'); b && setView(b.dataset.v); };
setView(FDP.get('view', 'list'));
$('#sortSel').onchange = e => go(e.target.value);
let flt = '';
function filter() { const q = cs.on ? '' : $('#q').value.toLowerCase().trim(); let n = 0; rows().forEach(r => { const ok = (!flt || (flt === 'fav' ? r.dataset.fav === '1' : r.dataset.type === flt)) && (!q || r.dataset.name.includes(q)); r.style.display = ok ? '' : 'none'; if (ok) n++; }); $('#noMatch').hidden = n > 0 || rows().length === 0; }
$('#q').oninput = () => curPage ? pageSearch() : filter(); $('#chips').onclick = e => { const c = e.target.closest('.chip'); if (!c) return; flt = c.dataset.f; $$('.chip').forEach(x => x.classList.toggle('on', x === c)); filter(); };

/* ---------- selection ---------- */
let lastIdx = -1;
function upd() { const s = sel(), n = s.length; rows().forEach(r => r.classList.toggle('sel-on', $('.file-checkbox', r).checked)); $('#view').classList.toggle('sel-mode', n > 0); $('#selbar').hidden = n === 0; $('#selTxt').textContent = n + ' selected · ' + fmt(0).replace('0 B', '') ; const sz = s.reduce((a, r) => a + (parseFloat(r.querySelector('.cs').textContent) || 0), 0); $('#selTxt').innerHTML = '<b>' + n + '</b><span class="hide-m"> item(s) selected</span>'; }
$('#list').addEventListener('click', e => {
  const r = e.target.closest('.fi[data-path]'); if (!r) return;
  const act = e.target.closest('[data-act]'); if (act) { e.preventDefault(); e.stopPropagation(); return doAct(act.dataset.act, r, e); }
  const cb = $('.file-checkbox', r), vis = rows().filter(x => x.style.display !== 'none'), idx = vis.indexOf(r);
  if (e.target.closest('.chk')) { setTimeout(() => { if (e.shiftKey && lastIdx > -1) { const [a, b] = [Math.min(idx, lastIdx), Math.max(idx, lastIdx)]; vis.slice(a, b + 1).forEach(x => $('.file-checkbox', x).checked = true); } lastIdx = idx; upd(); }, 0); return; }
  if (e.ctrlKey || e.metaKey) { e.preventDefault(); cb.checked = !cb.checked; lastIdx = idx; upd(); return; }
  if (e.shiftKey && lastIdx > -1) { e.preventDefault(); const [a, b] = [Math.min(idx, lastIdx), Math.max(idx, lastIdx)]; vis.slice(a, b + 1).forEach(x => $('.file-checkbox', x).checked = true); upd(); return; }
  if (e.target.closest('a.nm')) { if (sel().length) { e.preventDefault(); cb.checked = !cb.checked; upd(); } else if (r.dataset.prev === '1') { e.preventDefault(); openPreview(r); } }
});
const selAll = on => { rows().filter(r => r.style.display !== 'none').forEach(r => $('.file-checkbox', r).checked = on); upd(); };
$('#view').addEventListener('change', e => { if (e.target.id === 'selectAll') selAll(e.target.checked); });
$('#sbAll').onclick = () => { rows().forEach(r => { const c = $('.file-checkbox', r); c.checked = !c.checked; }); upd(); }; $('#sbClear').onclick = () => { rows().forEach(r => $('.file-checkbox', r).checked = false); $('#selectAll').checked = false; upd(); };

/* ---------- clipboard (multi copy / cut / paste) ---------- */
function clipSet(type, paths) { ls.set('fd_clip', { type, paths }); clipUI(); rows().forEach(r => r.classList.toggle('cut', type === 'move' && paths.includes(r.dataset.path))); toast((type === 'move' ? 'Cut ' : 'Copied ') + paths.length + ' item(s) — open a folder and Paste', 'ok'); }
function clipUI() { const c = ls.get('fd_clip', null); const has = c && c.paths && c.paths.length; $('#pasteBtn').hidden = !has; if (has) $('#pasteN').textContent = 'Paste (' + c.paths.length + ')'; const bp = $('#bnPaste'); if (bp) bp.style.opacity = has ? '' : '.4'; }
async function paste(dest = CFG.path) {
  const c = ls.get('fd_clip', null); if (!c || !c.paths.length) return; const act = c.type === 'copy' ? 'paste_copy' : 'paste_move'; logA('paste', (c.type === 'copy' ? 'Copied ' : 'Moved ') + c.paths.length + ' item(s) to ' + base(dest));
  if (c.paths.length === 1) { $('#formAction').value = act; $('#formItemPath').value = c.paths[0]; $('#formDestPath').value = dest; if (c.type === 'move') { localStorage.removeItem('fd_clip'); clipUI(); } softPost($('#actionForm')); return; }
  toast('Pasting ' + c.paths.length + ' items…'); let ok = 0;
  for (const p of c.paths) { const fd = new FormData(); fd.append('action', act); fd.append('item_path', p); fd.append('dest_path', dest); try { const r = await fetch(CFG.upUrl, { method: 'POST', body: fd }); if (r.ok) ok++; } catch (e) {} }
  if (c.type === 'move') { localStorage.removeItem('fd_clip'); clipUI(); } toast(ok + ' pasted', 'ok'); softReload();
}
$('#pasteBtn').onclick = $('#bnPaste').onclick = () => paste(); clipUI();
$('#selbar').addEventListener('click', e => { const m = e.target.closest('[data-multi]'); if (!m) return; const s = sel().map(r => r.dataset.path), k = m.dataset.multi;
  if (k === 'star') toggleFav(sel(), true);
  if (k === 'copy' || k === 'move') clipSet(k, s);
  if (k === 'zip') { logA('zip', s.length + ' item(s) zipped'); $('#multiAction').value = 'multi_download'; $('#multiForm').submit(); toast('Preparing ZIP…'); }
  if (k === 'del') confirmBox(`Move <b>${s.length}</b> selected item(s) to Trash?`, 'Delete', () => softPost($('#multiForm'), 'index.php?path=' + encodeURIComponent(CFG.path), { action: 'multi_delete' })); });

/* ---------- row actions ---------- */
function doAct(a, r, ev) {
  const p = r.dataset.path, n = r.dataset.label, dir = r.dataset.dir === '1';
  if (a === 'copy') clipSet('copy', [p]); else if (a === 'move') clipSet('move', [p]);
  else if (a === 'rename') { $('#renamePath').value = p; $('#renameIn').value = n; openM('renameModal'); const i = $('#renameIn'); setTimeout(() => { i.focus(); const d = n.lastIndexOf('.'); i.setSelectionRange(0, d > 0 ? d : n.length); }, 60); }
  else if (a === 'delete') confirmBox(`Move <b>${esc(n)}</b> to Trash?`, 'Delete', () => softPost($('#actionForm'), 'index.php?path=' + encodeURIComponent(CFG.path), { action: 'delete', item_path: p }));
  else if (a === 'fav') toggleFav([r]);
  else if (a === 'menu') ctxFor(r, ev);
}
const goto = r => { if (r.dataset.prev === '1') openPreview(r); else go(r.dataset.href); };

/* ---------- context menu (right-click / long-press / ⋯) ---------- */
let ctxT = 0, ctxAnc = null, ctxAcc = false;
const CTXC = {'fa-folder-open':'#f59e0b','fa-eye':'#06b6d4','fa-code':'#8b5cf6','fa-download':'#10b981','fa-pen':'#3b82f6','fa-clone':'#14b8a6','fa-box-open':'#f97316','fa-link':'#ec4899','fa-copy':'#6366f1','fa-scissors':'#f43f5e','fa-paste':'#8b5cf6','fa-thumbtack':'#eab308','fa-circle-info':'#0ea5e9','fa-trash':'#ef4444','fa-cloud-arrow-up':'#6366f1','fa-circle-half-stroke':'#a855f7','fa-palette':'#ec4899','fa-chart-pie':'#22c55e','fa-star':'#f59e0b'};
function ctxShow(x, y, items) { ctxT = Date.now(); const accIc = ctxAcc; ctxAcc = false; const m = $('#ctx'); m.innerHTML = ''; items.filter(Boolean).forEach(it => { if (it === '-') return m.append(document.createElement('hr')); const b = document.createElement('button'); if (it.r) b.className = 'r'; b.innerHTML = `<i class="fa-solid ${it.i}" style="color:${accIc ? 'var(--ac)' : (CTXC[it.i] || '')}"></i><span>${it.t}</span>`; b.onclick = ev => { ev.stopPropagation(); m.hidden = true; it.fn(); }; m.append(b); }); const anc = ctxAnc; ctxAnc = null; m.style.cssText = ''; m.hidden = false;
  if (innerWidth <= 900) { /* mobile: smart spot – below the card, else above it, else middle; always clear of the bottom dock */
    const nav = $('.bnav'), dockH = nav && getComputedStyle(nav).display !== 'none' && !document.body.classList.contains('dock-off') ? nav.offsetHeight : 0, T = 10, B = innerHeight - dockH - 10, maxH = B - T;
    m.style.setProperty('max-height', maxH + 'px', 'important'); const h = Math.min(m.offsetHeight, maxH), w = m.offsetWidth; let top;
    if (anc && h <= B - anc.bottom - 6) top = anc.bottom + 6;
    else if (anc && h <= anc.top - T - 6) top = anc.top - h - 6;
    else top = T + (maxH - h) / 2;
    top = Math.max(T, Math.min(top, B - h));
    m.style.setProperty('left', Math.max(6, (innerWidth - w) / 2) + 'px', 'important'); m.style.setProperty('top', top + 'px', 'important'); m.style.setProperty('transform', 'none', 'important'); m.style.animation = 'pop .16s'; return; }
  m.style.left = Math.max(6, Math.min(x, innerWidth - m.offsetWidth - 6)) + 'px'; m.style.top = Math.max(6, Math.min(y, innerHeight - m.offsetHeight - 6)) + 'px'; }
function ctxFor(r, e) { const dir = r.dataset.dir === '1', p = r.dataset.path; const c = r.getBoundingClientRect(); ctxAnc = c; const x = e && e.clientX != null ? e.clientX : c.left, y = e && e.clientY != null ? e.clientY : c.bottom, clip = ls.get('fd_clip', null);
  ctxShow(x, y, [{ i: dir ? 'fa-folder-open' : 'fa-eye', t: dir ? 'Open' : (r.dataset.prev === '1' ? 'Preview' : 'Open'), fn: () => goto(r) },
    r.dataset.edit === '1' && { i: 'fa-code', t: 'Edit in IDE', fn: () => location.href = '?fdpage=editor&file=' + encodeURIComponent(p) },
    !dir && { i: 'fa-download', t: 'Download', fn: () => location.href = '?download=' + encodeURIComponent(p) }, '-',
    { i: 'fa-copy', t: 'Copy', fn: () => clipSet('copy', selPaths(r)) }, { i: 'fa-scissors', t: 'Cut', fn: () => clipSet('move', selPaths(r)) },
    dir && clip && { i: 'fa-paste', t: 'Paste into folder', fn: () => paste(p) },
    { i: 'fa-star', t: r.dataset.fav === '1' ? 'Remove favorite' : 'Add to favorites', fn: () => toggleFav([r]) },
    { i: 'fa-pen', t: 'Rename', fn: () => doAct('rename', r) },
    { i: 'fa-clone', t: 'Duplicate', fn: async () => { const x = await api('dup', { path: p }); if (x.ok) { toast('Duplicated', 'ok'); softReload(); } else toast(x.error || 'Failed', 'err'); } },
    !dir && r.dataset.ext === 'zip' && { i: 'fa-box-open', t: 'Extract here', fn: async () => { toast('Extracting…'); const x = await api('extract', { path: p }); if (x.ok) { toast('Extracted ' + x.count + ' file(s) → ' + x.folder, 'ok'); softReload(); } else toast(x.error || 'Failed', 'err'); } },
    !dir && { i: 'fa-link', t: 'Share link', fn: () => openShare(p, r.dataset.label) },
    { i: 'fa-link', t: 'Copy full path', fn: () => navigator.clipboard.writeText(p).then(() => toast('Path copied', 'ok')) },
    dir && { i: 'fa-thumbtack', t: 'Pin to sidebar', fn: () => pin(p) }, { i: 'fa-circle-info', t: 'Properties', fn: () => showInfo(r) },'-', { i: 'fa-trash', t: 'Delete', r: 1, fn: () => doAct('delete', r) }]); }
const selPaths = r => { const s = sel().map(x => x.dataset.path); return s.includes(r.dataset.path) ? s : [r.dataset.path]; };
$('#list').addEventListener('contextmenu', e => { const r = e.target.closest('.fi[data-path]'); if (r) { e.preventDefault(); ctxFor(r, e); } });
let lp; $('#list').addEventListener('touchstart', e => { const r = e.target.closest('.fi[data-path]'); if (!r) return; const t = e.touches[0]; lp = setTimeout(() => { navigator.vibrate && navigator.vibrate(12); ctxFor(r, { clientX: t.clientX, clientY: t.clientY }); }, 520); }, { passive: true });
['touchend', 'touchmove', 'touchcancel'].forEach(ev => $('#list').addEventListener(ev, () => clearTimeout(lp), { passive: true }));
$('#work').addEventListener('contextmenu', e => { if (e.target.closest('.fi,input,button,a,select')) return; e.preventDefault(); const c = ls.get('fd_clip', null); ctxAcc = true; ctxShow(e.clientX, e.clientY, [{ i: 'fa-cloud-arrow-up', t: 'Upload files', fn: () => openM('uploadModal') }, { i: 'fa-folder-plus', t: 'New folder', fn: () => openM('folderModal') }, { i: 'fa-file-circle-plus', t: 'New file', fn: () => openM('fileModal') }, { i: 'fa-globe', t: 'Download from URL', fn: () => openM('urlModal') }, c && { i: 'fa-paste', t: 'Paste here', fn: () => paste() }, { i: 'fa-rotate', t: 'Refresh', fn: () => softReload() }]); });

/* ---------- upload (drag & drop, progress, speed, limit check) ---------- */
$('#limitTxt').textContent = CFG.limit ? 'Server limit per file: ' + fmt(CFG.limit) : '';
const queue = []; let running = false;
function addFiles(files) { files = [...files]; if (!files.length) return; const tooBig = files.filter(f => CFG.limit && f.size > CFG.limit); if (tooBig.length) { toast(tooBig.length + ' file(s) exceed the server limit (' + fmt(CFG.limit) + ') and were skipped', 'warn', 6000); files = files.filter(f => !tooBig.includes(f)); }
  files.forEach(f => queue.push({ f, st: 'wait', pc: 0, sp: 0 })); closeM($('#uploadModal')); $('#tray').hidden = false; draw(); if (!running) run(); }
function draw() { const done = queue.filter(q => q.st === 'done' || q.st === 'fail').length; $('#trayT').textContent = done === queue.length ? 'Uploads finished' : `Uploading ${done + 1} of ${queue.length}`;
  $('#trayL').innerHTML = queue.map(q => `<div class="ui"><div class="r1"><span>${esc(q.f.name)}</span><span>${fmt(q.f.size)}</span></div><div class="bar"><i style="width:${q.pc}%;${q.st === 'fail' ? 'background:var(--bad)' : q.st === 'done' ? 'background:var(--ok)' : ''}"></i></div><small>${q.st === 'up' ? q.pc.toFixed(0) + '% · ' + fmt(q.sp) + '/s' : { wait: 'Waiting…', done: '✓ Done', fail: '✕ Failed' }[q.st]}</small></div>`).join(''); }
async function run() { running = true; for (const q of queue) { if (q.st !== 'wait') continue; q.st = 'up'; draw(); await new Promise(res => { const x = new XMLHttpRequest(), fd = new FormData(), t0 = Date.now(); fd.append('action', 'upload'); fd.append('files[]', q.f, q.f.name); x.open('POST', CFG.upUrl);
    x.upload.onprogress = e => { q.pc = e.loaded / e.total * 100; q.sp = e.loaded / ((Date.now() - t0) / 1000 || 1); draw(); }; x.onload = () => { q.st = x.status < 400 ? 'done' : 'fail'; if (q.st === 'done') logA('upload', q.f.name + ' (' + fmt(q.f.size) + ')'); q.pc = 100; draw(); res(); }; x.onerror = () => { q.st = 'fail'; draw(); res(); }; x.send(fd); }); }
  running = false; const ok = queue.filter(q => q.st === 'done').length; toast(ok + ' file(s) uploaded', ok ? 'ok' : 'err'); if (ok) { softReload(); setTimeout(() => { if (!running) { $('#tray').hidden = true; queue.length = 0; } }, 1800); } }
$('#fileIn').onchange = e => { addFiles(e.target.files); e.target.value = ''; }; $('#trayX').onclick = () => $('#tray').hidden = true;
let dn = 0; const hasF = e => e.dataTransfer && [...e.dataTransfer.types].includes('Files');
addEventListener('dragenter', e => { if (hasF(e)) { dn++; $('#dz').hidden = false; } }); addEventListener('dragleave', e => { if (hasF(e) && --dn <= 0) { dn = 0; $('#dz').hidden = true; } });
addEventListener('dragover', e => hasF(e) && e.preventDefault()); addEventListener('drop', e => { if (!hasF(e)) return; e.preventDefault(); dn = 0; $('#dz').hidden = true; const fs = [...e.dataTransfer.files].filter(f => f.size > 0 || f.type); addFiles(fs); });
document.addEventListener('paste', e => { if (/INPUT|TEXTAREA/.test(e.target.tagName)) return; const fs = [...(e.clipboardData?.files || [])]; if (fs.length) addFiles(fs.map(f => f.name === 'image.png' ? new File([f], 'pasted-' + Date.now() + '.png', { type: f.type }) : f)); });

/* ---------- preview (image / video / audio / pdf) ---------- */
let pvList = [], pvI = 0;
function openPreview(r) { pvList = rows().filter(x => x.dataset.prev === '1' && x.style.display !== 'none'); pvI = Math.max(0, pvList.indexOf(r)); $('#pv').classList.add('open'); document.body.style.overflow = 'hidden'; showPv(); }
function showPv() { const r = pvList[pvI], u = '?raw=' + encodeURIComponent(r.dataset.path), t = r.dataset.type, x = r.dataset.ext; $('#pvName').textContent = r.dataset.label + ' (' + (pvI + 1) + '/' + pvList.length + ')'; $('#pvDl').href = '?download=' + encodeURIComponent(r.dataset.path);
  $('#pvB').innerHTML = t === 'image' ? `<img src="${u}" alt="">` : t === 'video' ? `<video src="${u}" controls autoplay playsinline></video>` : t === 'audio' ? `<audio src="${u}" controls autoplay></audio>` : `<iframe src="${u}"></iframe>`; }
const closePv = () => { $('#pv').classList.remove('open'); $('#pvB').innerHTML = ''; document.body.style.overflow = ''; };
const navPv = d => { pvI = (pvI + d + pvList.length) % pvList.length; showPv(); }; $('#pvX').onclick = closePv; $('#pvPrev').onclick = () => navPv(-1); $('#pvNext').onclick = () => navPv(1);

/* ---------- command palette ---------- */
let pc = [], pi = 0;
const cmds = () => [{ i: 'fa-cloud-arrow-up', t: 'Upload files', fn: () => openM('uploadModal') }, { i: 'fa-folder-plus', t: 'New folder', fn: () => openM('folderModal') }, { i: 'fa-file-circle-plus', t: 'New file', fn: () => openM('fileModal') },
  { i: 'fa-star', t: 'Favorites', fn: () => location.hash = 'favorites' }, { i: 'fa-link', t: 'Shared links', fn: () => location.hash = 'links' }, { i: 'fa-scroll', t: 'Activity log', fn: () => location.hash = 'activity' }, { i: 'fa-globe', t: 'Download from URL', fn: () => openM('urlModal') }, { i: 'fa-keyboard', t: 'Keyboard shortcuts', fn: showKb }, { i: 'fa-database', t: 'Database viewer', fn: () => location.hash = 'dbviewer' },
  { i: 'fa-rotate', t: 'Refresh', fn: () => softReload() }, { i: 'fa-check-double', t: 'Select all', fn: () => { $('#selectAll').checked = true; selAll(true); } },
  { i: 'fa-paste', t: 'Paste here', fn: () => paste() }, { i: 'fa-circle-half-stroke', t: 'Toggle theme', fn: () => $('#themeBtn').click() }, { i: 'fa-palette', t: 'Accent color', fn: () => openM('accModal') },
  { i: 'fa-list', t: 'List view', fn: () => setView('list') }, { i: 'fa-grip', t: 'Grid view', fn: () => setView('grid') }, { i: 'fa-image', t: 'Gallery view', fn: () => setView('gallery') },
  { i: 'fa-thumbtack', t: 'Pin this folder', fn: () => pin(CFG.path) }, { i: 'fa-trash', t: 'Go to Trash', fn: () => location.hash = 'trash' }, { i: 'fa-chart-pie', t: 'Go to Dashboard', fn: () => location.hash = 'dashboard' }, { i: 'fa-code', t: 'Open IDE Studio', fn: () => location.href = '?fdpage=editor' }, { i: 'fa-right-from-bracket', t: 'Logout', fn: () => location.href = '?fdpage=logout' }];
function palDraw() { const q = $('#palIn').value.toLowerCase().trim(); pc = cmds().concat(rows().map(r => ({ i: r.dataset.dir === '1' ? 'fa-folder' : 'fa-file', t: 'Open: ' + r.dataset.label, fn: () => goto(r) }))).filter(c => !q || c.t.toLowerCase().includes(q)).slice(0, 40); pi = Math.min(pi, Math.max(0, pc.length - 1));
  $('#palL').innerHTML = pc.map((c, i) => `<li data-i="${i}" class="${i === pi ? 'on' : ''}"><i class="fa-solid ${c.i}" style="color:${CTXC[c.i] || '#818cf8'}"></i><span>${esc(c.t)}</span></li>`).join('') || '<li>No match</li>'; }
const palOpen = () => { $('#pal').classList.add('open'); $('#palIn').value = ''; pi = 0; palDraw(); $('#palIn').focus(); }, palClose = () => $('#pal').classList.remove('open');
$('#palBtn').onclick = palOpen; $('#palIn').oninput = () => { pi = 0; palDraw(); };
$('#palIn').onkeydown = e => { if (e.key === 'ArrowDown') { pi = Math.min(pi + 1, pc.length - 1); palDraw(); e.preventDefault(); } else if (e.key === 'ArrowUp') { pi = Math.max(0, pi - 1); palDraw(); e.preventDefault(); } else if (e.key === 'Enter') { const c = pc[pi]; palClose(); c && c.fn(); } else if (e.key === 'Escape') palClose(); };
$('#palL').onclick = e => { const li = e.target.closest('li[data-i]'); if (li) { const c = pc[+li.dataset.i]; palClose(); c && c.fn(); } }; $('#pal').onmousedown = e => { if (e.target.id === 'pal') palClose(); };

/* ---------- keyboard shortcut help ( ? ) ---------- */
const KB_HOME = [
  ['Navigate', [['/', 'Focus the search bar'], ['Ctrl + K', 'Command palette'], ['Backspace', 'Go to parent folder'], ['Esc', 'Close popup / clear selection'], ['?', 'This help']]],
  ['Files & folders', [['Ctrl + A', 'Select all'], ['Ctrl + C', 'Copy selected'], ['Ctrl + X', 'Cut selected'], ['Ctrl + V', 'Paste'], ['F2', 'Rename selected'], ['Delete', 'Delete selected']]],
  ['Search', [['Contents button', 'Search inside file contents of this folder'], ['Enter', 'Run content search now']]]
];
function showKb() { $('#kbBodyHome').innerHTML = KB_HOME.map(g => '<div class="kbh">' + g[0] + '</div>' + g[1].map(r => '<div class="kbr"><span>' + r[1] + '</span><kbd>' + r[0] + '</kbd></div>').join('')).join(''); openM('kbModal'); }
$('#kbBtn').onclick = showKb;

/* ---------- keyboard ---------- */
document.addEventListener('keydown', e => {
  const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName), mod = e.ctrlKey || e.metaKey;
  if (mod && e.key.toLowerCase() === 'k') { e.preventDefault(); $('#pal').classList.contains('open') ? palClose() : palOpen(); return; }
  if (e.key === 'Escape') { if ($('#pv').classList.contains('open')) return closePv(); const m = $('.modal.open'); if (m) return closeM(m); $('#ctx').hidden = true; if (sel().length) $('#sbClear').click(); return; }
  if ($('#pv').classList.contains('open')) { if (e.key === 'ArrowLeft') navPv(-1); if (e.key === 'ArrowRight') navPv(1); return; }
  if (typing || $('.modal.open') || $('#pal').classList.contains('open')) return;
  const s = sel();
  if (e.key === '/') { e.preventDefault(); $('#q').focus(); }
  else if (e.key === '?') { e.preventDefault(); showKb(); }
  else if (mod && e.key.toLowerCase() === 'a') { e.preventDefault(); $('#selectAll').checked = true; selAll(true); }
  else if (mod && e.key.toLowerCase() === 'c' && s.length) { e.preventDefault(); clipSet('copy', s.map(r => r.dataset.path)); }
  else if (mod && e.key.toLowerCase() === 'x' && s.length) { e.preventDefault(); clipSet('move', s.map(r => r.dataset.path)); }
  else if (mod && e.key.toLowerCase() === 'v') { e.preventDefault(); paste(); }
  else if (e.key === 'Delete' && s.length) { $('[data-multi=del]').click(); }
  else if (e.key === 'F2' && s.length === 1) { e.preventDefault(); doAct('rename', s[0]); }
  else if (e.key === 'Backspace') { const up = $('[data-up]'); if (up) go(up.href); }
});

/* ---------- extras: favorites · info · share · web download · pages ---------- */
const logA = (a, d) => { try { const fd = new FormData(); fd.append('a', a); fd.append('d', d); navigator.sendBeacon('index.php?api=log', fd); } catch (e) {} };
async function api(name, data = {}) { const fd = new FormData(); Object.entries(data).forEach(([k, v]) => fd.append(k, v)); try { const r = await fetch('index.php?api=' + name, { method: 'POST', body: fd }); return await r.json(); } catch (e) { return { ok: false, error: 'Network error' }; } }
function copyText(t) { return (navigator.clipboard && window.isSecureContext ? navigator.clipboard.writeText(t) : Promise.reject()).catch(() => { const i = document.createElement('input'); i.value = t; document.body.append(i); i.select(); try { document.execCommand('copy'); } catch (e) {} i.remove(); }); }

async function toggleFav(rs, on) {
  let n = 0, last = null;
  for (const r of rs) { const res = await api('fav', Object.assign({ path: r.dataset.path }, on === undefined ? {} : { set: on ? 1 : 0 })); if (res.ok) { r.dataset.fav = res.fav ? '1' : '0'; n++; last = res.fav; } else toast(res.error || 'Failed', 'err'); }
  if (n) toast(n === 1 ? (last ? '★ Added to favorites' : 'Removed from favorites') : '★ ' + n + ' item(s) added to favorites', 'ok');
  if (flt === 'fav') filter();
}
function showInfo(r) {
  const sz = +r.dataset.size, mt = +r.dataset.mtime, dir = r.dataset.dir === '1';
  const R = [['Name', r.dataset.label], ['Type', dir ? 'Folder' : (r.dataset.ext ? r.dataset.ext.toUpperCase() + ' file' : 'File')], ['Size', sz >= 0 ? fmt(sz) : '—'], ['Modified', mt ? new Date(mt * 1000).toLocaleString() : '—'], ['Permissions', r.dataset.perm || '—'], ['Location', r.dataset.path], ['Favorite', r.dataset.fav === '1' ? 'Yes ★' : 'No']];
  $('#infoBody').innerHTML = R.map(([k, v]) => `<div class="ir"><span>${k}</span><b>${esc(v)}</b></div>`).join(''); openM('infoModal');
}
let shPath = '';
function openShare(p, n) { shPath = p; $('#shName').textContent = n; $('#shOut').hidden = true; $('#shGo').hidden = false; openM('shareModal'); }
$('#shGo').onclick = async () => { const r = await api('share', { path: shPath, ttl: $('#shTtl').value }); if (!r.ok) return toast(r.error || 'Failed', 'err'); $('#shUrl').value = new URL('index.php?s=' + r.token, location.href.split(/[?#]/)[0]).href; $('#shOut').hidden = false; $('#shGo').hidden = true; };
$('#shCopy').onclick = () => copyText($('#shUrl').value).then(() => toast('Link copied', 'ok'));

function urlJobId() {
  const bytes = new Uint8Array(16);
  if (window.crypto && typeof window.crypto.getRandomValues === 'function') {
    window.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}
function urlBytes(n) {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  return (n / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + units[i];
}
async function urlGo(url, name, btn, after) {
  const modalMode = btn && (btn.id === 'urlGo' || btn.id === 'pgUrlGo');
  if (!modalMode) {
    const old = btn ? btn.innerHTML : '';
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>Downloading…'; }
    const id = urlJobId();
    const r = await api('url_download', { url, name, dir: CFG.path, id });
    if (btn) { btn.disabled = false; btn.innerHTML = old; }
    if (r.ok) { toast('Downloaded: ' + r.name + ' (' + fmt(r.size) + ')', 'ok', 5000); after && after(); }
    else toast(r.error || 'Download failed', 'err', 7000);
    return;
  }

  const sharedMode = btn.id === 'pgUrlGo';
  const form = btn.closest('form');
  const actions = sharedMode ? btn : $('#urlActions');
  const progress = sharedMode ? $('#pgUrlProgress', form) : $('#urlProgress');
  const percentEl = sharedMode ? $('.url-percent', progress) : $('#urlPercent');
  const sizeEl = sharedMode ? $('.url-size', progress) : $('#urlSize');
  const barEl = $('.url-progress-btn', progress);
  const cancel = sharedMode ? $('.url-cancel', progress) : $('#urlCancel');
  const label = $('.url-progress-label', progress);
  const id = urlJobId();
  let finished = false, cancelled = false;
  actions.hidden = true;
  progress.hidden = false;
  percentEl.textContent = '0%';
  barEl.style.setProperty('--url-progress', '0%');
  sizeEl.textContent = '0 B / ?';
  label.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>Downloading...';
  cancel.disabled = false;
  cancel.textContent = 'Cancel';
  cancel.onclick = async () => {
    if (finished || cancelled) return;
    cancelled = true;
    cancel.disabled = true;
    cancel.textContent = 'Cancelling…';
    await api('url_cancel', { id });
  };

  const request = api('url_download', { url, name, dir: CFG.path, id }).then(r => { finished = true; return r; });
  while (!finished) {
    const p = await api('url_progress', { id });
    if (p.ok) {
      const downloaded = p.downloaded || 0, total = p.total || 0;
      const pct = total ? Math.min(99, Math.floor(downloaded / total * 100)) : 0;
      percentEl.textContent = total ? pct + '%' : '—';
      barEl.style.setProperty('--url-progress', pct + '%');
      sizeEl.textContent = urlBytes(downloaded) + ' / ' + (total ? urlBytes(total) : '?');
    }
    if (!finished) await new Promise(resolve => setTimeout(resolve, 350));
  }
  const r = await request;
  progress.hidden = true;
  actions.hidden = false;
  cancel.disabled = false;
  cancel.onclick = null;
  if (r.ok) {
    percentEl.textContent = '100%';
    barEl.style.setProperty('--url-progress', '100%');
    toast('Downloaded: ' + r.name + ' (' + fmt(r.size) + ')', 'ok', 5000);
    after && after();
  } else toast(r.error || (cancelled ? 'Download cancelled' : 'Download failed'), cancelled ? 'info' : 'err', 7000);
}
$('#urlForm').onsubmit = e => {
  e.preventDefault();
  const f = e.target;
  urlGo(f.url.value.trim(), f.name.value.trim(), $('#urlGo'), () => {
    closeM($('#urlModal'));
    f.reset();
    softReload();
  });
};

/* pages: #favorites  #links  #activity */
const PAGES = { favorites: 'Favorites', links: 'Shared links', activity: 'Activity log', trash: 'Trash', dashboard: 'Dashboard', dbviewer: 'Database', settings: 'Settings' };
const EMBED_PAGES = { trash: '?fdpage=trash', dashboard: '?fdpage=dashboard', settings: '?fdpage=settings', dbviewer: '?fdpage=dbviewer' };
/* frames are created once (pre-loaded in the background) and only shown/hidden afterwards → opening a tab is instant */
const EMBED_SRC = n => EMBED_PAGES[n] + '&embed=1', EMBED_FRESH = { trash: 20000, dashboard: 20000 };
function embedFrame(name) {
  let f = $('#ehIn iframe[data-p="' + name + '"]');
  if (!f) {
    f = document.createElement('iframe'); f.className = 'fd-embed-frame'; f.title = PAGES[name]; f.dataset.p = name;
    f.addEventListener('load', () => { f._t = Date.now(); }); f.src = EMBED_SRC(name); $('#ehIn').append(f);
  }
  return f;
}
function embedShow(name) {
  $$('#ehIn iframe').forEach(x => x.classList.toggle('on', x.dataset.p === name));
  $('#embedHost').classList.toggle('show', !!name);
  if (!name) return;
  const f = embedFrame(name); f.classList.add('on');
  if (!f._t) return;
  try { /* shown from cache: quietly refresh lists that may have changed, or reset a sub-page to its start */
    if (name === 'trash' || name === 'dashboard') {
      const w = f.contentWindow, base = new URL(EMBED_SRC(name), location.href);
      if (w.location.pathname + w.location.search !== base.pathname + base.search || Date.now() - f._t > EMBED_FRESH[name]) w.location.replace(base.href);
    }
  } catch (e) {}
  iframeSearch(f, '');
}
(function () {
  if (navigator.connection && navigator.connection.saveData) return;
  const order = ['settings', 'trash', 'dbviewer', 'dashboard']; let i = 0;
  const next = () => { if (i >= order.length) return; embedFrame(order[i++]); setTimeout(next, 600); };
  const start = () => setTimeout(next, 400);
  if (document.readyState === 'complete') start(); else addEventListener('load', start, { once: true });
})();
const dayLbl = t => { const d = new Date(t * 1e3), n = new Date(), y = new Date(Date.now() - 864e5), same = (a, b) => a.toDateString() === b.toDateString(); return same(d, n) ? 'Today' : same(d, y) ? 'Yesterday' : d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }); };
const agoTxt = t => { const s = Math.max(0, Date.now() / 1e3 - t); return s < 60 ? 'just now' : s < 3600 ? Math.floor(s / 60) + ' min ago' : s < 86400 ? Math.floor(s / 3600) + ' h ago' : Math.floor(s / 86400) + ' d ago'; };
function expTxt(e) { if (!e) return 'Never expires'; const s = e - Date.now() / 1e3; if (s <= 0) return 'Expired'; return 'Expires in ' + (s < 3600 ? Math.ceil(s / 60) + ' min' : s < 86400 ? Math.ceil(s / 3600) + ' h' : Math.ceil(s / 86400) + ' d'); }
function fixTimes(root) {
  let last = ''; $$('.it[data-t]', root).forEach(it => { const t = +it.dataset.t, tm = $('.tm', it); if (tm && !tm.dataset.ago) tm.textContent = new Date(t * 1e3).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); if (it.dataset.day !== undefined) { const l = dayLbl(t); if (l !== last) { last = l; const d = document.createElement('div'); d.className = 'dh'; d.textContent = l; it.before(d); } } });
  $$('[data-ago]', root).forEach(el => el.textContent = agoTxt(+el.dataset.ago)); $$('.it[data-exp]', root).forEach(el => { $('.expt', el).textContent = expTxt(+el.dataset.exp); });
}
let curPage = '';
/* ---- top search bar: searches only inside the page/tab that is currently open ---- */
const Q_HOME = 'Search in this folder…  ( / )';
const Q_PAGE = { favorites: 'Search favorites…', links: 'Search shared links & downloads…', activity: 'Search activity…', trash: 'Search trash…', dashboard: 'Search dashboard…', dbviewer: 'Search tables…', settings: 'Search settings…' };
const cs = { on: false, t: null, seq: 0 };
function csHide() { cs.seq++; const r = $('#csRes'); if (r) r.hidden = true; }
function csSet(v) {
  cs.on = v; $('#csBtn').classList.toggle('on', v); $('#q').placeholder = v ? 'Search inside files in this folder…' : (curPage ? Q_PAGE[curPage] : Q_HOME);
  if (v) { filter(); csRun(); $('#q').focus(); } else { csHide(); filter(); }
}
async function csRun() {
  const q = $('#q').value.trim(), box = $('#csRes');
  if (q.length < 2) { csHide(); return; }
  const my = ++cs.seq; box.hidden = false; box.innerHTML = '<div class="cs-e"><i class="fa-solid fa-spinner fa-spin" style="color:#6366f1"></i> Searching…</div>';
  let j; try { j = await (await fetch('index.php?api=content_search&q=' + encodeURIComponent(q) + '&path=' + encodeURIComponent(CFG.path))).json(); } catch (e) { if (my === cs.seq) box.innerHTML = '<div class="cs-e">Search failed</div>'; return; }
  if (my !== cs.seq) return;
  const rq = esc(q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), hl = s => esc(s).replace(new RegExp(rq, 'gi'), m => '<mark>' + m + '</mark>');
  if (!j.results.length) { box.innerHTML = '<div class="cs-e"><i class="fa-solid fa-magnifying-glass" style="color:#38bdf8"></i><br>No file contains “' + esc(q) + '”<br><small>' + j.files + ' files searched</small></div>'; return; }
  box.innerHTML = '<div class="cs-h"><span>' + j.matches + ' match' + (j.matches === 1 ? '' : 'es') + ' in ' + j.results.length + ' file' + (j.results.length === 1 ? '' : 's') + (j.truncated ? ' (partial)' : '') + '</span><span>' + j.files + ' searched</span></div>'
    + j.results.map(f => '<div class="cs-f"><i class="fa-solid fa-file-code" style="color:var(--ac)"></i>' + esc(f.name) + '<small>' + esc(f.rel) + '</small></div>'
      + f.hits.map(h => '<a class="cs-m" href="?fdpage=editor&file=' + encodeURIComponent(f.p) + '&line=' + h.l + '"><i>L' + h.l + '</i><span>' + hl(h.s) + '</span></a>').join('')).join('');
}
$('#csBtn').onclick = () => csSet(!cs.on);
$('#q').addEventListener('input', () => { if (!cs.on || curPage) return; clearTimeout(cs.t); cs.t = setTimeout(csRun, 350); });
$('#q').addEventListener('keydown', e => { if (e.key === 'Enter' && cs.on && !curPage) { clearTimeout(cs.t); csRun(); } if (e.key === 'Escape') csHide(); });
document.addEventListener('click', e => { if (!e.target.closest('.srch')) csHide(); });
function pageQ() { return $('#q').value.toLowerCase().trim(); }
function setQ(name) { const q = $('#q'); if (cs.on) { cs.on = false; $('#csBtn').classList.remove('on'); } csHide(); $('#csBtn').hidden = !!name; q.value = ''; q.placeholder = name ? Q_PAGE[name] : Q_HOME; if (window.fdSearchSync) fdSearchSync(); }
function textFilter(root, sel, q, scopeSel) {
  let n = 0, total = 0;
  $$(sel, root).forEach(el => {
    const vis = !scopeSel || !el.closest(scopeSel + '[hidden]');
    const ok = !q || el.textContent.toLowerCase().includes(q);
    el.style.display = ok ? '' : 'none';
    if (vis) { total++; if (ok) n++; }
  });
  return { n, total };
}
function pageSearch() {
  const q = pageQ(), pg = $('#page');
  if (curPage === 'activity') {
    const a = $('#aq'); if (a) a.value = $('#q').value;
    clearTimeout(actT); actT = setTimeout(() => { act.q = $('#q').value.trim(); act.pg = 1; actLoad(); }, 300); return;
  }
  const iframe = EMBED_PAGES[curPage] ? $('#ehIn iframe[data-p="' + curPage + '"]') : null;
  if (iframe) return iframeSearch(iframe, q);
  const r = textFilter(pg, '.it', q);
  let nm = $('#pgNoMatch', pg);
  if (q && r.total && !r.n) { if (!nm) { nm = document.createElement('div'); nm.id = 'pgNoMatch'; nm.className = 'empty'; nm.innerHTML = '<i class="fa-solid fa-magnifying-glass" style="color:#38bdf8"></i><b>No matches</b><div>Try a different search</div>'; pg.append(nm); } nm.hidden = false; }
  else if (nm) nm.hidden = true;
}
function iframeSearch(iframe, q) {
  let d; try { d = iframe.contentDocument; } catch (e) { return; }
  if (!d || !d.body) return;
  if (curPage === 'trash') { const i = d.getElementById('search'); if (i) { i.value = q; i.dispatchEvent(new Event('input', { bubbles: true })); } return; }
  if (curPage === 'dbviewer') { const i = d.getElementById('tFilter'); if (i) { i.value = q; i.dispatchEvent(new Event('input', { bubbles: true })); } return; }
  if (curPage === 'dashboard') { textFilter(d, '.cd, .fi, .fo, .ci, a.row.lnk, .tips li', q); return; }
  if (curPage === 'settings') {
    textFilter(d, '.panel:not([hidden]) .card .row, .panel:not([hidden]) .kv > div, .panel:not([hidden]) .tile, .panel:not([hidden]) .act', q);
    d.querySelectorAll('.panel[hidden] .row, .panel[hidden] .kv > div, .panel[hidden] .tile, .panel[hidden] .act').forEach(el => el.style.display = '');
  }
}
/* iframe pages: re-apply once loaded, and when switching a tab inside Settings */
document.addEventListener('load', e => { const f = e.target; if (f && f.classList && f.classList.contains('fd-embed-frame') && f.dataset.p === curPage) { try { f.contentDocument.addEventListener('click', () => setTimeout(() => { if (pageQ()) iframeSearch(f, pageQ()); }, 0)); } catch (x) {} if (pageQ()) iframeSearch(f, pageQ()); } }, true);

const act = { q: '', from: 0, to: 0, kind: '', pg: 1 };
async function actLoad() {
  const l = $('#actList'); if (!l) return;
  const qs = new URLSearchParams({ api: 'actlist', q: act.q, from: act.from, to: act.to, kind: act.kind, pg: act.pg });
  try { l.innerHTML = await (await fetch('index.php?' + qs)).text(); } catch (e) { l.innerHTML = '<div class="empty"><b>Could not load</b></div>'; return; }
  const m = $('#actMeta', l); if (m) { act.pg = +m.dataset.pg; $('#actCnt').textContent = m.dataset.total; }
  fixTimes(l); actMark();
}
function actMark() {
  const on = { apS: !!act.q, apD: !!(act.from || act.to), apK: !!act.kind };
  Object.entries(on).forEach(([k, v]) => $$('[data-atog="' + k + '"]').forEach(b => b.classList.toggle('on', v)));
  const r = $('#aReset'); if (r) r.hidden = !(on.apS || on.apD || on.apK);
}
const actSi = document.getElementById('si');
const actSiHide = () => { actSi.hidden = true; };
function showActInfo(row, x, y) {
  let d;
  try { d = JSON.parse(row.dataset.info || '{}'); } catch (e) { return; }
  const k = (a, b) => b ? `<div class="k"><span>${a}</span><b>${esc(b)}</b></div>` : '';
  const dev = [d.model, d.dev].filter(Boolean).join(' · ');
  actSi.innerHTML = `<h4><i class="fa-solid ${d.ok ? 'fa-circle-check' : 'fa-circle-xmark'}" style="color:${d.ok ? '#34d399' : '#fb7185'}"></i>${esc(d.lab)}<button type="button" class="si-close" aria-label="Close" title="Close"><i class="fa-solid fa-xmark" style="color:#fb7185"></i></button></h4>`
    + k('When', new Date(d.t * 1000).toLocaleString())
    + k('What happened', d.note)
    + k('Device', dev)
    + k('System', d.os)
    + k('Browser', d.br)
    + k('IP address', d.ip)
    + (d.br ? '' : '<div class="k"><span>Browser info</span><b>Not recorded (old entry)</b></div>');
  actSi.hidden = false;
  if (!x && !y) { const c = row.getBoundingClientRect(); x = c.left + c.width / 2; y = c.top + c.height / 2; }
  const w = actSi.offsetWidth, h = actSi.offsetHeight;
  if (innerWidth <= 900) { /* mobile: level with the tapped card, always above the bottom dock */
    const c = row.getBoundingClientRect(), n = document.querySelector('.bnav'); let B = innerHeight;
    if (n && getComputedStyle(n).display !== 'none') B = Math.min(B, n.getBoundingClientRect().top);
    B -= 12; const T = 12, hh = Math.min(h, B - T);
    actSi.style.maxHeight = (B - T) + 'px'; actSi.style.overflowY = 'auto';
    actSi.style.left = Math.max(12, Math.min(c.left + c.width / 2 - w / 2, innerWidth - w - 12)) + 'px';
    actSi.style.top = Math.max(T, Math.min(c.top, B - hh)) + 'px'; return;
  }
  actSi.style.left = Math.max(12, Math.min(x - w / 2, innerWidth - w - 12)) + 'px';
  actSi.style.top = Math.max(12, Math.min(y + 14, innerHeight - h - 12)) + 'px';
}
actSi.addEventListener('click', e => { if (e.target.closest('.si-close')) actSiHide(); });
document.addEventListener('click', e => { if (!e.target.closest('#si') && !e.target.closest('.it.act[data-id]')) actSiHide(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') actSiHide(); });
let actT;
async function showPage(name) {
  actSiHide(); curPage = name; setQ(name); const pg = $('#page'); $('#work').hidden = true; pg.hidden = false; scrollTo(0, 0);
  if (EMBED_PAGES[name]) {
    pg.innerHTML = ''; pg.hidden = true; embedShow(name);
    document.title = PAGES[name] + ' — FileDash'; return;
  }
  embedShow(null);
  pg.innerHTML = '<div class="empty"><i class="fa-solid fa-spinner fa-spin"></i>Loading…</div>';
  try { const r = await fetch('index.php?api=page&p=' + name); pg.innerHTML = await r.text(); } catch (e) { pg.innerHTML = '<div class="empty"><b>Could not load</b></div>'; }
  if (name === 'activity') Object.assign(act, { q: '', from: 0, to: 0, kind: '', pg: 1 });
  fixTimes(pg); const d = $('#pgDest'); if (d) d.textContent = CFG.path; document.title = PAGES[name] + ' — FileDash';
}
function route() {
  const n = location.hash.slice(1); $$('.nav a').forEach(a => a.classList.toggle('on', a.dataset.page ? a.dataset.page === n : (!PAGES[n] && a.getAttribute('href') === 'index.php')));
  if (PAGES[n]) showPage(n); else { curPage = ''; setQ(''); embedShow(null); $('#page').hidden = true; $('#work').hidden = false; document.title = 'FileDash — Smart File Manager'; }
}
const closePage = () => { history.pushState(null, '', location.pathname + location.search); route(); };
addEventListener('message', e => { if (e.origin === location.origin && e.data === 'fd-close-page') closePage(); });
addEventListener('hashchange', route);
$('.nav').addEventListener('click', e => { if (e.target.closest('[data-page]')) toggleSide(false); });
$('#bnFav').onclick = () => { location.hash = 'favorites'; };
$('#page').addEventListener('click', async e => {
  if (e.target.closest('[data-closepage]')) return closePage();
  const tg = e.target.closest('[data-atog]'); if (tg) { const id = tg.dataset.atog; ['apS', 'apD', 'apK'].forEach(k => { const el = $('#' + k); el.hidden = k === id ? !el.hidden : true; }); if (id === 'apS' && !$('#apS').hidden) $('#aq').focus(); return; }
  const ak = e.target.closest('[data-ak]'); if (ak) { act.kind = ak.dataset.ak; act.pg = 1; $$('#apK .chip').forEach(x => x.classList.toggle('on', x === ak)); return actLoad(); }
  const pr = e.target.closest('[data-preset]'); if (pr) {
    const v = pr.dataset.preset, d0 = new Date(), iso = d => d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); d0.setHours(0, 0, 0, 0);
    if (v === 'all') { act.from = act.to = 0; $('#aFrom').value = $('#aTo').value = ''; } else { const f = new Date(d0); f.setDate(f.getDate() - +v); act.from = f / 1e3; act.to = 0; $('#aFrom').value = iso(f); $('#aTo').value = v === '0' ? iso(d0) : ''; if (v === '0') act.to = d0 / 1e3 + 86399; }
    act.pg = 1; return actLoad();
  }
  const pgb = e.target.closest('[data-pg]'); if (pgb) { act.pg = +pgb.dataset.pg; await actLoad(); return $('#actList').scrollIntoView({ block: 'start', behavior: 'smooth' }); }
  const lb = e.target.closest('[data-pact="logdel"]');
  const row = e.target.closest('.it.act[data-id]');
  if (lb) { const r = lb.closest('.it'), id = r.dataset.id; return confirmBox('Delete this log entry?<br><b>' + esc($('.tx2 b', r).textContent) + '</b>', 'Delete', async () => { const x = await api('log_del', { id }); if (x.ok) { toast('Entry deleted', 'ok'); actLoad(); } else toast(x.error || 'Failed', 'err'); }); }
  if (row) {
    if (actLongPressed) { actLongPressed = false; clearTimeout(actSuppressTimer); return; }
    showActInfo(row, e.clientX, e.clientY); return;
  }
  if (e.target.closest('[data-pact="areset"]')) { Object.assign(act, { q: '', from: 0, to: 0, kind: '', pg: 1 }); $('#aq').value = $('#aFrom').value = $('#aTo').value = ''; $('#q').value = ''; $$('#apK .chip').forEach((x, i) => x.classList.toggle('on', i === 0)); return actLoad(); }
  const b = e.target.closest('[data-pact]'); if (!b) return; const a = b.dataset.pact;
  if (a === 'unfav') { const r = await api('fav', { path: b.dataset.path, set: 0 }); if (r.ok) { b.closest('.it').remove(); $$('#list .fi').forEach(x => { if (x.dataset.path === b.dataset.path) x.dataset.fav = '0'; }); const n = $$('#page .it').length; $('#page .cnt').textContent = n; if (!n) showPage('favorites'); } }
  else if (a === 'clearlog') confirmBox('Clear the whole activity log?', 'Clear', async () => { await api('clear_log'); showPage('activity'); });
  else if (a === 'copylink') copyText(new URL('index.php?s=' + b.dataset.token, location.href.split(/[?#]/)[0]).href).then(() => toast('Link copied', 'ok'));
  else if (a === 'revoke') { await api('unshare', { token: b.dataset.token }); toast('Link revoked', 'ok'); showPage('links'); }
});
let actHoldTimer = null;
let actLongPressed = false;
let actSuppressTimer = null;

$('#page').addEventListener('pointerdown', e => {
  if (!matchMedia('(pointer: coarse)').matches) return;
  const row = e.target.closest('.it.act[data-id]');
  if (!row || e.target.closest('button, a, input')) return;
  clearTimeout(actHoldTimer);
  clearTimeout(actSuppressTimer);
  actLongPressed = false;
  actHoldTimer = setTimeout(() => {
    actHoldTimer = null;
    actLongPressed = true;
    const id = row.dataset.id;
    confirmBox('Delete this log entry?<br><b>' + esc($('.tx2 b', row).textContent) + '</b>', 'Delete', async () => {
      const x = await api('log_del', { id });
      if (x.ok) { toast('Entry deleted', 'ok'); actLoad(); }
      else toast(x.error || 'Failed', 'err');
    });
    actSuppressTimer = setTimeout(() => { actLongPressed = false; }, 1000);
  }, 500);
});

['pointerup', 'pointerleave', 'pointercancel', 'pointermove'].forEach(ev => {
  $('#page').addEventListener(ev, () => {
    clearTimeout(actHoldTimer);
    actHoldTimer = null;
  });
});
$('#page').addEventListener('input', e => { if (e.target.id !== 'aq') return; $('#q').value = e.target.value; clearTimeout(actT); actT = setTimeout(() => { act.q = e.target.value.trim(); act.pg = 1; actLoad(); }, 300); });
$('#page').addEventListener('change', e => { if (e.target.id !== 'aFrom' && e.target.id !== 'aTo') return; const f = $('#aFrom').value, t = $('#aTo').value; act.from = f ? new Date(f + 'T00:00:00') / 1e3 : 0; act.to = t ? new Date(t + 'T23:59:59') / 1e3 : 0; act.pg = 1; actLoad(); });
$('#page').addEventListener('submit', e => { if (e.target.id !== 'pgUrlForm') return; e.preventDefault(); const f = e.target; urlGo(f.url.value.trim(), f.name.value.trim(), $('#pgUrlGo'), () => { f.reset(); showPage('links'); }); });

/* ---------- mobile search icon ---------- */
(function(){const top=document.querySelector('.top'),b=document.getElementById('sBtn'),c=document.getElementById('sClose');if(!top||!b)return;
const q=()=>document.getElementById('q');
function sync(){b.classList.toggle('has',!!(q()&&q().value))}
function open(){top.classList.add('sopen');setTimeout(()=>{const i=q();i&&i.focus()},30)}
function close(){if(!top.classList.contains('sopen'))return;top.classList.remove('sopen');const i=q();i&&i.blur();sync()}
b.addEventListener('click',open);c&&c.addEventListener('click',close);
document.addEventListener('input',e=>{if(e.target&&e.target.id==='q')sync()});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&top.classList.contains('sopen'))close();if(e.key==='Enter'&&e.target&&e.target.id==='q'&&top.classList.contains('sopen')&&innerWidth<=900)setTimeout(close,0)});
document.addEventListener('click',e=>{if(top.classList.contains('sopen')&&!e.target.closest('.srch')&&!e.target.closest('#sBtn'))close()});
window.fdSearchSync=sync;window.fdSearchClose=close;
})();
/* ---------- soft navigation: folders / sort / hidden / refresh swap in place (no full page reload) ---------- */
const nbar = $('#nbar'); let navSeq = 0, loadedKey = '';
const pkey = () => location.pathname.replace(/index\.php$/, '') + location.search;
const barOn = () => { nbar.classList.remove('done'); void nbar.offsetWidth; nbar.classList.add('on'); };
const barOff = () => { nbar.classList.remove('on'); nbar.classList.add('done'); setTimeout(() => nbar.classList.remove('done'), 700); };
const cleanUrl = h => { const u = new URL(h, location.href); ['sort', 'order', 'hidden', 'msg', 'message', 'success', 'error', 'err'].forEach(k => u.searchParams.delete(k)); return u.pathname + u.search; };
function softUrl(href) {
  try {
    const u = new URL(href, location.href), norm = p => p.replace(/index\.php$/, '');
    if (u.origin !== location.origin || norm(u.pathname) !== norm(location.pathname)) return null;
    if (['download', 'raw', 's', 'api'].some(k => u.searchParams.has(k))) return null;
    return u.href;
  } catch (e) { return null; }
}
const go = u => { const s = softUrl(u); if (s) load(s); else location.href = u; };
const softReload = () => load(location.href, { replace: true, still: true });
const softPost = (form, url, over) => { const fd = new FormData(form); if (over) Object.entries(over).forEach(([k, v]) => fd.set(k, v)); return load(url || form.getAttribute('action'), { body: fd, still: true, replace: true }); };
const visit = () => { ls.set('fd_recent', [CFG.path, ...ls.get('fd_recent', []).filter(p => p !== CFG.path)].slice(0, 10)); pinList(); };
const flashNow = () => { if (CFG.flash) toast(CFG.flash, 'ok'); if (CFG.err) toast(CFG.err, 'err', 6000); CFG.flash = CFG.err = ''; };
function swap(doc, still) {
  const g = s => doc.querySelector(s), list = $('#list');
  list.classList.toggle('still', still);
  $('.cards').innerHTML = g('.cards').innerHTML;
  $('.crumbs').innerHTML = g('.crumbs').innerHTML;
  $('.jump input[name=path]').value = g('.jump input[name=path]').value;
  $('#sortSel').innerHTML = g('#sortSel').innerHTML;
  $('#hidBtn').replaceWith(g('#hidBtn'));
  $('#szNote').innerHTML = g('#szNote').innerHTML;
  $('.lhead').innerHTML = g('.lhead').innerHTML;
  list.innerHTML = g('#list').innerHTML;
  $('#empty').hidden = g('#empty').hidden;
  $('.store').innerHTML = g('.store').innerHTML;
  ['#multiForm', '#actionForm', '#folderModal form', '#fileModal form', '#renameModal form'].forEach(s => { const a = g(s), b = $(s); if (a && b) b.setAttribute('action', a.getAttribute('action')); });
  Object.assign(CFG, JSON.parse(g('#cfgBox').dataset.cfg));
  if (!still) { $('#q').value = ''; flt = ''; $$('#chips .chip').forEach((x, i) => x.classList.toggle('on', i === 0)); }
  csHide(); lastIdx = -1; upd(); filter(); visit(); clipUI();
  toggleSide(false); $('#ctx').hidden = true; closeAcct(); $('#fab').classList.remove('open');
}
async function load(url, o = {}) {
  const my = ++navSeq; barOn(); let r, html;
  try { r = await fetch(url, o.body ? { method: 'POST', body: o.body, cache: 'no-store' } : { cache: 'no-store' }); html = await r.text(); }
  catch (e) { if (my === navSeq) barOff(); if (o.body) toast('Network error', 'err'); else location.href = url; return false; }
  if (my !== navSeq) return false;
  const doc = new DOMParser().parseFromString(html, 'text/html');
  if (!doc.getElementById('list') || !doc.getElementById('cfgBox')) { location.href = r.url || url; return false; }   // login page / unexpected reply → normal navigation
  swap(doc, !!o.still);
  const hash = location.hash;
  if (o.push === false) { /* back / forward: address bar already right */ }
  else if (o.replace) history.replaceState(null, '', cleanUrl(r.url) + hash);
  else history.pushState(null, '', cleanUrl(r.url));
  loadedKey = pkey();
  if (!o.replace) { route(); if (!o.still) scrollTo(0, 0); }
  barOff(); flashNow(); return true;
}
document.addEventListener('click', e => {
  if (e.defaultPrevented || e.button || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  const a = e.target.closest('a[href]'); if (!a || (a.target && a.target !== '_self') || a.hasAttribute('download')) return;
  const h = a.getAttribute('href'); if (h[0] === '#' || /^(mailto|tel|javascript):/i.test(h)) return;
  const u = softUrl(a.href); if (!u) return;
  e.preventDefault(); load(u);
});
$('.jump').addEventListener('submit', e => { e.preventDefault(); go('?path=' + encodeURIComponent(e.target.path.value.trim())); });
addEventListener('popstate', () => { if (pkey() !== loadedKey) load(location.href, { push: false }); });
['#folderModal form', '#fileModal form', '#renameModal form'].forEach(s => $(s).addEventListener('submit', e => {
  e.preventDefault();
  const f = e.target;

  if (f.matches('#folderModal form')) logA('create', 'Folder: ' + f.folder_name.value);
  else if (f.matches('#fileModal form')) logA('create', 'File: ' + f.file_name.value);
  else if (f.matches('#renameModal form')) logA('rename', base(f.item_path.value) + ' → ' + f.new_name.value);

  closeM(f);
  softPost(f);
  f.reset();
}));

/* activity beacons for actions that go straight to ?fdpage=actions */
route();

/* ---------- flash messages from ?fdpage=actions (?msg= / ?error=) ---------- */
flashNow();
history.replaceState(null, '', cleanUrl(location.href) + location.hash); loadedKey = pkey();
upd(); filter();
})();
</script>
</body>
</html>

<?php
} }
