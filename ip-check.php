<?php
/**
 * ip-check.php
 *
 * クライアントのIPv4/IPv6を可能な限り収集し、許可IP（単体 or CIDR）と照合するための関数群。
 * 
 * 機能強化:
 * - JavaScript + 外部APIを使用したクライアント側IP検出（IPv4 over IPv6環境対策）
 * - セッションを使用したIP情報の保持
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * セッション開始（未開始の場合のみ）
 */
function mw_session_start() {
    if (session_status() === PHP_SESSION_NONE) {
        @session_start();
    }
}

/**
 * 公開IPとして妥当か（プライベート/予約を除外）
 *
 * @param string $ip
 * @return bool
 */
function mw_is_public_ip(string $ip): bool
{
    if ($ip === '') {
        return false;
    }

    // zone index を除去（例: fe80::1%lo0）
    $ip = preg_replace('/%.+$/', '', $ip);

    // FILTER_FLAG_NO_PRIV_RANGE / NO_RES_RANGE は IPv4/IPv6 ともに動作
    return filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) !== false;
}

/**
 * ヘッダ値（X-Forwarded-For 等）からIP候補を抽出
 *
 * @param string $value
 * @return string[]
 */
function mw_extract_ips_from_header_value(string $value): array
{
    if ($value === '') {
        return [];
    }

    // X-Forwarded-For: "client, proxy1, proxy2" のような形式を想定
    $parts = preg_split('/[\s,]+/', $value);
    if (!$parts) {
        return [];
    }

    $ips = [];
    foreach ($parts as $p) {
        $ip = trim($p);
        if ($ip === '') {
            continue;
        }

        // 末尾ポートを除去（IPv4:port のみ想定。IPv6:port は [v6]:port で来ることが多い）
        if (preg_match('/^\d{1,3}(\.\d{1,3}){3}:\d+$/', $ip)) {
            $ip = preg_replace('/:\d+$/', '', $ip);
        }

        // [IPv6]:port 形式
        if (preg_match('/^\[(.+)\]:(\d+)$/', $ip, $m)) {
            $ip = $m[1];
        }

        // zone index を除去
        $ip = preg_replace('/%.+$/', '', $ip);

        if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
            $ips[] = $ip;
        }
    }

    return array_values(array_unique($ips));
}

/**
 * 可能な限りクライアントIP（IPv4/IPv6）を収集する。
 * セッションおよびPOSTデータも利用する。
 *
 * @param array $options (互換性のために残すが使用しない)
 * @return array{ipv4:string[], ipv6:string[], all:string[]}
 */
function mw_get_client_ips(array $options = []): array
{
    mw_session_start();

    // 1. セッションから過去に収集したIPを復元
    $collected = $_SESSION['mw_ip_collected'] ?? ['ipv4' => [], 'ipv6' => [], 'all' => []];
    $candidates = $collected['all'] ?? [];

    // 2. HTTPヘッダから収集
    $headerKeys = [
        'HTTP_CF_CONNECTING_IP',   // Cloudflare
        'HTTP_X_REAL_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_CLIENT_IP',
        'REMOTE_ADDR',
    ];

    foreach ($headerKeys as $k) {
        if (!empty($_SERVER[$k])) {
            $candidates = array_merge($candidates, mw_extract_ips_from_header_value((string) $_SERVER[$k]));
        }
    }

    // 3. POSTデータから収集 (JS Collectorからの戻り値など)
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // JS Collectorが送ってくるキー
        if (!empty($_POST['mw_ip_denied_client_ip'])) {
            $candidates = array_merge($candidates, mw_extract_ips_from_header_value((string) $_POST['mw_ip_denied_client_ip']));
        }
        
        // 汎用的なキー
        $postKeys = ['client_ip', 'client_ipv4', 'client_ipv6', 'ip', 'ipv4', 'ipv6'];
        foreach ($postKeys as $k) {
            if (!empty($_POST[$k])) {
                $candidates = array_merge($candidates, mw_extract_ips_from_header_value((string) $_POST[$k]));
            }
        }
    }

    // 4. 重複排除・検証・分類
    $candidates = array_values(array_unique(array_filter(array_map('trim', $candidates), 'mw_is_public_ip')));

    $ipv4 = [];
    $ipv6 = [];
    foreach ($candidates as $ip) {
        if (strpos($ip, ':') !== false) {
            $ipv6[] = $ip;
        } else {
            $ipv4[] = $ip;
        }
    }

    $result = [
        'ipv4' => array_values(array_unique($ipv4)),
        'ipv6' => array_values(array_unique($ipv6)),
        'all' => $candidates,
    ];

    // 5. セッションに保存
    $_SESSION['mw_ip_collected'] = $result;

    return $result;
}

/**
 * 許可IPリストに、クライアントIP（複数候補）のいずれかが一致するか
 *
 * @param array $clientIps mw_get_client_ips() の返り値
 * @param array $allowedList
 * @return bool
 */
function mw_client_is_allowed(array $clientIps, array $allowedList): bool
{
    $allowedList = array_values(array_filter(array_map('trim', $allowedList), static function ($v) {
        return $v !== '';
    }));

    if (!$allowedList) {
        return false;
    }

    // 収集できた全候補を総当たりで照合
    foreach ($allowedList as $allowed) {
        foreach ($clientIps['all'] ?? [] as $ip) {
            if (mw_ip_matches((string) $ip, (string) $allowed)) {
                return true;
            }
        }
    }

    return false;
}

/**
 * JavaScriptを使用して外部APIからクライアントのIPを取得し、POSTで再送信するページを表示して終了する。
 */
function mw_render_js_collector_page(): void
{
    // ループ防止: 既にPOSTでIPが送られてきている場合は表示しない
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['mw_ip_denied_client_ip'])) {
        return;
    }

    // HTML出力
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Checking Permissions...</title>
    <style>body{font-family:sans-serif;text-align:center;padding-top:50px;}</style>
</head>
<body>
    <p>Checking browser permissions...</p>
    <div id="mw-ip-denied-js-log" style="display:none;"></div>
    <script>
    (async function(){
        const log = (s)=>{
            // const el = document.getElementById('mw-ip-denied-js-log');
            // if(el) el.textContent += s + "\n";
            console.log(s);
        };
        const clientApis = [
            "https://api.ipify.org?format=json",
            "https://api64.ipify.org?format=json",
            "https://ifconfig.co/json",
            "https://ipinfo.io/json"
        ];
        
        let foundIp = "";
        let foundSource = "";

        for (const url of clientApis) {
            try {
                log("fetch " + url);
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 2000); // 2秒タイムアウト

                const res = await fetch(url, {
                    cache: "no-store", 
                    signal: controller.signal
                });
                clearTimeout(timeoutId);

                let text = await res.text();
                let ip = "";
                try {
                    const j = JSON.parse(text);
                    if (j && j.ip) ip = j.ip;
                } catch(e){
                    ip = text.trim();
                }

                if (ip) {
                    log("found: " + ip + " from " + url);
                    foundIp = ip;
                    foundSource = url;
                    break; // 1つ見つかれば十分
                }
            } catch (e) {
                log("error: " + e);
            }
        }

        if (foundIp) {
            log("submitting form...");
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = location.href;
            
            const inputIp = document.createElement('input');
            inputIp.type = 'hidden';
            inputIp.name = 'mw_ip_denied_client_ip';
            inputIp.value = foundIp;
            form.appendChild(inputIp);
            
            const inputSrc = document.createElement('input');
            inputSrc.type = 'hidden';
            inputSrc.name = 'mw_ip_denied_source';
            inputSrc.value = foundSource;
            form.appendChild(inputSrc);
            
            // 元のPOSTデータがあればそれらも引き継ぐべきだが、
            // 今回はアクセス制御のリダイレクトループ回避が主目的なのでシンプルに。
            
            document.body.appendChild(form);
            form.submit();
        } else {
            // IPが見つからなかった場合、どうしようもないのでリロード（またはリダイレクト）させる
            // ここではリダイレクトさせる（結果的にブロック画面へ行くはず）
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = location.href;
            // 空のPOSTを送ることで、サーバー側に「チェックしたけどダメだった」と伝える
            const inputDummy = document.createElement('input');
            inputDummy.type = 'hidden';
            inputDummy.name = 'mw_ip_denied_checked';
            inputDummy.value = '1';
            form.appendChild(inputDummy);
            document.body.appendChild(form);
            form.submit();
        }
    })();
    </script>
</body>
</html>
    <?php
    exit;
}


/**
 * CIDR 文字列を (networkBinary, prefix, isV6) に正規化
 * (変更なし)
 */
function mw_parse_cidr(string $cidrOrIp): ?array
{
    $cidrOrIp = trim($cidrOrIp);
    if ($cidrOrIp === '') {
        return null;
    }
    $cidrOrIp = preg_replace('/%.+$/', '', $cidrOrIp);
    $prefix = null;
    $ipPart = $cidrOrIp;
    if (strpos($cidrOrIp, '/') !== false) {
        [$ipPart, $p] = array_pad(explode('/', $cidrOrIp, 2), 2, null);
        $ipPart = trim((string) $ipPart);
        $p = trim((string) $p);
        if ($p === '' || !ctype_digit($p)) { return null; }
        $prefix = (int) $p;
    }
    if (filter_var($ipPart, FILTER_VALIDATE_IP) === false) {
        return null;
    }
    $v6 = (strpos($ipPart, ':') !== false);
    $bin = inet_pton($ipPart);
    if ($bin === false) {
        return null;
    }
    $max = $v6 ? 128 : 32;
    if ($prefix === null) {
        $prefix = $max;
    }
    if ($prefix < 0 || $prefix > $max) {
        return null;
    }
    $bytes = $v6 ? 16 : 4;
    $fullBytes = intdiv($prefix, 8);
    $remainBits = $prefix % 8;
    $net = $bin;
    if ($fullBytes < $bytes) {
        for ($i = $fullBytes + ($remainBits > 0 ? 1 : 0); $i < $bytes; $i++) {
            $net[$i] = "\0";
        }
        if ($remainBits > 0) {
            $mask = (0xFF << (8 - $remainBits)) & 0xFF;
            $net[$fullBytes] = chr(ord($net[$fullBytes]) & $mask);
        }
    }
    return [
        'net' => $net,
        'prefix' => $prefix,
        'v6' => $v6,
    ];
}

/**
 * IP が CIDR（または単一IP）に含まれるか
 * (変更なし)
 */
function mw_ip_matches(string $ip, string $cidrOrIp): bool
{
    $ip = trim($ip);
    if ($ip === '') { return false; }
    $ip = preg_replace('/%.+$/', '', $ip);
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) { return false; }
    $parsed = mw_parse_cidr($cidrOrIp);
    if (!$parsed) { return false; }
    $v6 = (strpos($ip, ':') !== false);
    if ($v6 !== $parsed['v6']) { return false; }
    $bin = inet_pton($ip);
    if ($bin === false) { return false; }
    $prefix = (int) $parsed['prefix'];
    $bytes = $v6 ? 16 : 4;
    $fullBytes = intdiv($prefix, 8);
    $remainBits = $prefix % 8;
    if ($fullBytes > 0) {
        if (substr($bin, 0, $fullBytes) !== substr($parsed['net'], 0, $fullBytes)) {
            return false;
        }
    }
    if ($remainBits === 0) { return true; }
    if ($fullBytes >= $bytes) { return true; }
    $mask = (0xFF << (8 - $remainBits)) & 0xFF;
    return (ord($bin[$fullBytes]) & $mask) === (ord($parsed['net'][$fullBytes]) & $mask);
}
