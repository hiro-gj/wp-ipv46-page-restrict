<?php
/**
 * get_ip-and-slug_list.php
 *
 * 固定ページ（ページスラッグ）「ip_allowed」の本文から、
 * 「対象とするページスラッグ => 許可するIPアドレス（配列）」を取得する。
 *
 * 記載仕様（本文）:
 *   restricted-page-1 => 203.0.113.10,203.0.113.10/32
 *   restricted-page-2 => 2001:db8::1,2001:db8::/64
 *
 * 対応コメント:
 *   # 行コメント
 *   // 行コメント
 *   [ブロックコメント] 例: / * ... * /
 *   <!-- HTMLコメント -->
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ip_allowed本文（post_content 相当のHTML/テキスト）を解析し、
 * 「対象スラッグ => 許可IP配列」のMapを返す。
 *
 * @param string $content post_content（HTML含む想定）
 * @return array<string, string[]>
 */
function mw_parse_ip_allowed_content(string $content): array
{
    // ビジュアルエディタ対策:
    // - HTMLタグ(<p>,<br>等)を除去して行単位に戻す
    // - `=>` 等のHTMLエンティティをデコードして `=>` を復元する
    $content = (string) preg_replace('/<\s*br\s*\/?\s*>/i', "\n", $content);
    $content = (string) preg_replace('/<\/\s*p\s*>/i', "\n", $content);

    if (function_exists('wp_strip_all_tags')) {
        // 静的解析(Intelephense)対策: 直接呼び出しを避ける
        // 第2引数を true にすると改行が削除され、全行が連結されてしまうため false にする
        $content = (string) call_user_func('wp_strip_all_tags', $content, false);
    } else {
        $content = strip_tags($content);
    }

    $content = html_entity_decode($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');

    // 先頭のBOMを除去（UTF-8 BOM bytes / Unicode BOM）
    // ※UTF-8 BOM(bytes) は 0xEF 0xBB 0xBF
    // 制御文字をソースに直書きせず、hex比較で安全に判定する
    if (strlen($content) >= 3 && bin2hex(substr($content, 0, 3)) === 'efbbbf') {
        $content = substr($content, 3);
    }
    // ※Unicode BOM(U+FEFF)
    $content = (string) preg_replace('/^\x{FEFF}/u', '', $content);

    // Unicodeの「形式文字」(Cf) を除去（LRM/RLM/ZWSP/BOM 等）
    // 先頭行だけ一致しない現象の原因になりやすいため、ここでまとめて落とす
    $content = (string) preg_replace('/\p{Cf}+/u', '', $content);

    // 不可視文字・特殊空白の正規化（先頭行が一致しない問題の対策）
    // - NBSP(U+00A0) / 全角スペース(U+3000) を半角スペースへ
    // - ゼロ幅系（U+200B/200C/200D/2060 等）を除去
    $content = (string) preg_replace('/[\x{00A0}\x{3000}]/u', ' ', $content);
    $content = (string) preg_replace('/[\x{FEFF}\x{200B}\x{200C}\x{200D}\x{2060}]/u', '', $content);

    // 改行を正規化
    $content = str_replace(["\r\n", "\r"], "\n", $content);

    // ブロックコメント /* ... */ を除去
    $content = (string) preg_replace('/\/\*.*?\*\//s', '', $content);

    // HTMLコメント <!-- ... -->（<! -- ... -- > も許容）を除去
    $content = (string) preg_replace('/<\!\s*--.*?--\s*>/s', '', $content);

    // trim() では落ちない NBSP/Unicode BOM/ゼロ幅スペース等も除去して比較ズレを防ぐ
    $trim_unicode = static function (string $s): string {
        // 先頭/末尾から「見えない空白」を除去（BOM/NBSP/ゼロ幅/全角など）
        $out = preg_replace(
            '/^[\s\x{00A0}\x{3000}\x{FEFF}\x{200B}\x{200C}\x{200D}\x{2060}\x{00AD}]+|[\s\x{00A0}\x{3000}\x{FEFF}\x{200B}\x{200C}\x{200D}\x{2060}\x{00AD}]+$/u',
            '',
            $s
        );
        if (!is_string($out)) {
            return '';
        }

        // 念のため、Unicode形式文字(Cf)も端から除去
        $out2 = preg_replace('/^\p{Cf}+|\p{Cf}+$/u', '', $out);
        return is_string($out2) ? $out2 : $out;
    };

    $map = [];

    foreach (explode("\n", $content) as $rawLine) {
        $line = $trim_unicode((string) $rawLine);
        if ($line === '') {
            continue;
        }

        // 行頭コメント行
        if (preg_match('/^\s*(#|\/\/)/', $line)) {
            continue;
        }

        // 行内コメント（//, #）を除去（IPv6表記には影響しない前提）
        $line = preg_replace('/\s*(\/\/|#).*$/', '', $line);
        $line = $trim_unicode((string) $line);
        if ($line === '') {
            continue;
        }

        // "slug => ip,ip/xx" を解析
        $parts = preg_split('/\s*=>\s*/', $line, 2);
        if (!$parts || count($parts) !== 2) {
            continue;
        }

        $target_slug_raw = $trim_unicode((string) $parts[0]);
        $ip_csv = $trim_unicode((string) $parts[1]);

        if ($target_slug_raw === '' || $ip_csv === '') {
            continue;
        }

        // スラッグ表記ゆれ対策:
        // - 先頭/末尾の "/" を許容
        // - パーセントエンコード(%E8%A8%B1%E5%8F%AF... 等)で書かれていても日本語スラッグに寄せる
        $target_slug_raw = $trim_unicode(trim($target_slug_raw, "/ \t\n\r\0"));
        $target_slug_decoded = rawurldecode($target_slug_raw);

        $target_slug_candidates = array_values(array_unique([
            $target_slug_decoded,
            $target_slug_raw,
        ], SORT_STRING));

        $ips = array_values(array_filter(array_map($trim_unicode, explode(',', $ip_csv)), static function ($v) {
            return $v !== '';
        }));

        if (!$ips) {
            continue;
        }

        foreach ($target_slug_candidates as $target_slug) {
            $target_slug = $trim_unicode((string) $target_slug);
            if ($target_slug === '') {
                continue;
            }

            // 同一スラッグが複数行で出た場合はマージ
            if (!isset($map[$target_slug])) {
                $map[$target_slug] = [];
            }

            $map[$target_slug] = array_values(array_unique(array_merge($map[$target_slug], $ips)));
        }
    }

    return $map;
}

/**
 * ip_allowed本文から、アクセス制限対象（スラッグ=>許可IPリスト）を取得する。
 *
 * @param string $config_page_slug 設定用固定ページのスラッグ（既定: ip_allowed）
 * @return array<string, string[]> 例: ['restricted-page-1' => ['203.0.113.10','203.0.113.0/24']]
 */
function mw_get_ip_allowed_map(string $config_page_slug = 'ip_allowed'): array
{
    // Intelephense/ユニットテスト対策: WordPress関数が無い環境では空を返す
    if (!function_exists('get_page_by_path') || !function_exists('get_post')) {
        return [];
    }

    /** @var mixed $page_obj */
    $page_obj = call_user_func('get_page_by_path', $config_page_slug);
    if (!$page_obj) {
        return [];
    }

    /** @var mixed $page */
    $page = call_user_func('get_post', $page_obj);
    if (!$page || empty($page->post_content)) {
        return [];
    }

    return mw_parse_ip_allowed_content((string) $page->post_content);
}
