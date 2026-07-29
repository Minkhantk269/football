<?php
declare(strict_types=1);

header("Content-Type: application/json; charset=utf-8");
header("Access-Control-Allow-Origin: *");
date_default_timezone_set("Asia/Yangon");

require __DIR__ . "/db.php";


// =============================================================================
// CONFIGURATION CLASSES
// =============================================================================

final class Timezone
{
    const MM = "Asia/Yangon";
    const VN = "Asia/Ho_Chi_Minh";
}

final class MatchConfig
{
    const TTL_SEC     = 7200;
    const PRELIVE_SEC = 600;

    const ALWAYS_SHOW_LEAGUES = ["ufc", "one friday fights", "fight night"];

    const REPLACEMENT_LOGO = "https://allsp.org/assets/images/team/689fc7f968c2a1755301881.png";
}

final class FotliveConfig
{
    const VERSION_URL = "https://fotlivepro.com/api/v5/version/check";
    const API_KEY     = "ybvmnasodfuewlkxjsyrekjfiwoygxsj";
    const CTR_KEY     = "25649715971269784561235469874562";
    const CTR_IV      = "2125454156988723";
}

final class ZerohazaarConfig
{
    const EVENTS_URL = "https://hksnjvvahhsvv.site/events.txt";
    const LINKS_BASE = "https://hksnjvvahhsvv.site/";
    const KEY        = "l9K5bT5xC1wP7pK1";
    const IV         = "k5K4nN7oU8hL6l19";
}

final class BurmeseConfig
{
    const PASSWORDS = [
        "bUrMeSeTvx00",
        "HelloFootball@Lovers2025##",
        "BuRmEsETVLite@#1234",
    ];
}

final class BurmaYoteShinConfig
{
    const MATCH_URL = "https://api-server.burmayoteshin.com/api/v1/match?is_highlight=false&page=1";
    const LINK_URL  = "https://api-server.burmayoteshin.com/api/v1/link/get-all?page=1";

    const ACCESS_CODE = "BurmaYoteShin";

    const TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2OWJmZWZmMmM2NDNkNTdhZmZhM2M4ZTEiLCJ1c2VyX25hbWUiOiJNaW5raGFudDM1NiIsImRldmljZV9saW1pdCI6MiwicHJlbWl1bV9leHBpcmVfZGF0ZSI6bnVsbCwiaXNfYmFubmVkIjpmYWxzZSwic2hvd19hZHVsdCI6ZmFsc2UsImRldmljZXMiOlt7InBsYXRmb3JtIjoiYW5kcm9pZCIsImRldmljZV9pZCI6IjBlMjA2MGJlYWFiY2NjZTYiLCJkZXZpY2VfbW9kZWwiOiJSRURNSSBLODAgVWx0cmEgKDI1MDYwUksxNkMpIiwibGFzdF9hY3RpdmUiOiIyMDI2LTAzLTIyVDEzOjM0OjQzLjE4N1oifV0sImNyZWF0ZWRBdCI6IjIwMjYtMDMtMjJUMTM6MzQ6NDIuNTcyWiIsInVwZGF0ZWRBdCI6IjIwMjYtMDMtMjJUMTM6MzQ6NDMuMTg4WiIsIl9fdiI6MSwiaXNfcHJlbWl1bV9hY3RpdmUiOmZhbHNlLCJpZCI6IjY5YmZlZmYyYzY0M2Q1N2FmZmEzYzhlMSIsImxvZ2luX2RldmljZV9pZCI6IjBlMjA2MGJlYWFiY2NjZTYiLCJpYXQiOjE3ODQ1NTQ4MzIsImV4cCI6MTc5NDkyMjgzMn0.l8NiwS-B-kvT_SD7wuZsc0vahV-pinX0yc6roHQ0suI";
}


// =============================================================================
// CRYPTO HELPERS
// =============================================================================

function b64d(string $s): string
{
    $result = base64_decode($s, true);
    if ($result === false) {
        throw new RuntimeException("Invalid base64 string");
    }
    return $result;
}

function pkcs7_unpad(string $data): string
{
    if ($data === "") return $data;
    $pad = ord($data[-1]);
    return ($pad >= 1 && $pad <= 16) ? substr($data, 0, -$pad) : $data;
}

function aes_ctr_decrypt(string $ciphertextB64, string $key, string $iv): string
{
    return pkcs7_unpad(
        openssl_decrypt(b64d($ciphertextB64), "aes-256-ctr", $key, OPENSSL_RAW_DATA, $iv)
    );
}

function aes_cbc_decrypt(string $ciphertextB64, string $key, string $iv): string
{
    return pkcs7_unpad(
        openssl_decrypt(b64d($ciphertextB64), "aes-256-cbc", $key, OPENSSL_RAW_DATA, $iv)
    );
}

function aes128_cbc_decrypt(string $cipherBytes, string $key, string $iv): string
{
    $plain = openssl_decrypt($cipherBytes, "AES-128-CBC", $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
    if ($plain === false) return "";
    $pad = ord($plain[-1]);
    return substr($plain, 0, -$pad);
}

/**
 * Unwrap PHP serialized string format: s:N:"...";
 */
function strip_serialized(string $text): string
{
    if (preg_match('/^s:\d+:"(.*)";$/s', trim($text), $m)) {
        return str_replace(['\\"', "\\\\"], ['"', "\\"], $m[1]);
    }
    return $text;
}

function decrypt_fixed_secret(string $ciphertextB64): string
{
    return trim(aes_ctr_decrypt($ciphertextB64, FotliveConfig::CTR_KEY, FotliveConfig::CTR_IV));
}

function decrypt_api_data(string $dataB64, string $payloadKeyB64): array
{
    $envelope = json_decode(b64d($dataB64), true);
    $key      = b64d($payloadKeyB64);
    $iv       = b64d($envelope["iv"]);
    $plain    = strip_serialized(aes_cbc_decrypt($envelope["value"], $key, $iv));
    return json_decode($plain, true) ?? [];
}

/**
 * Try to decode a value that may be hex-encoded or base64-encoded.
 */
function zerohazaar_try_decode(string $data): string
{
    $data = trim($data);

    if (ctype_xdigit($data) && strlen($data) % 2 === 0) {
        $bin = @hex2bin($data);
        if ($bin !== false) return $bin;
    }

    $b64 = preg_replace("/\s+/", "", $data);
    $pad = strlen($b64) % 4;
    if ($pad) $b64 .= str_repeat("=", 4 - $pad);

    return base64_decode($b64, true) ?: "";
}

function zerohazaar_decrypt(string $encrypted): string
{
    $bytes = zerohazaar_try_decode($encrypted);
    return $bytes === "" ? "" : aes128_cbc_decrypt($bytes, ZerohazaarConfig::KEY, ZerohazaarConfig::IV);
}

/**
 * Derive AES key+IV from password using OpenSSL EVP_BytesToKey (MD5).
 */
function evp_bytes_to_key(string $password, string $salt, int $keyLen, int $ivLen): array
{
    $data = $prev = "";
    while (strlen($data) < $keyLen + $ivLen) {
        $prev  = md5($prev . $password . $salt, true);
        $data .= $prev;
    }
    return [substr($data, 0, $keyLen), substr($data, $keyLen, $ivLen)];
}

function decrypt_burmese_openssl(string $b64, string $password): string
{
    $raw    = base64_decode($b64);
    $salt   = substr($raw, 8, 8);
    $cipher = substr($raw, 16);

    [$key, $iv] = evp_bytes_to_key($password, $salt, 32, 16);

    $decrypted = openssl_decrypt($cipher, "aes-256-cbc", $key, OPENSSL_RAW_DATA, $iv);
    if (!$decrypted) throw new RuntimeException("Decryption failed");
    return $decrypted;
}

/**
 * Extract the CryptoJS-encrypted blob from text, then try each password.
 */
function decrypt_burmese_payload(string $text): string
{
    if (!preg_match("/(U2FsdGVkX1[0-9A-Za-z+\/=]+)/", $text, $m)) {
        return $text;
    }
    foreach (BurmeseConfig::PASSWORDS as $password) {
        try {
            return decrypt_burmese_openssl($m[1], $password);
        } catch (Throwable) {
            // try next password
        }
    }
    return "";
}


// =============================================================================
// HTTP HELPERS
// =============================================================================

/**
 * Fire multiple HTTP requests in parallel using cURL multi.
 *
 * @param  array<string, array{url: string, method?: string, headers?: array, body?: string}> $requests
 * @return array<string, array{0: string|null, 1: string|null}>  [body|null, error|null]
 */
function multi_curl(array $requests, int $timeout = 15): array
{
    $mh      = curl_multi_init();
    $handles = [];

    foreach ($requests as $key => $req) {
        $ch = curl_init($req["url"]);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => min(8, $timeout),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_ENCODING       => "gzip, deflate",
            CURLOPT_HTTPHEADER     => $req["headers"] ?? ["User-Agent: Mozilla/5.0"],
        ]);

        $method = strtoupper($req["method"] ?? "GET");
        if ($method === "POST") {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $req["body"] ?? "");
        } elseif ($method !== "GET") {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        }

        curl_multi_add_handle($mh, $ch);
        $handles[$key] = $ch;
    }

    $running = null;
    do {
        curl_multi_exec($mh, $running);
        curl_multi_select($mh);
    } while ($running > 0);

    $results = [];
    foreach ($handles as $key => $ch) {
        $body   = curl_multi_getcontent($ch);
        $error  = curl_error($ch);
        $code   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $failed = $error || $code < 200 || $code >= 300;

        $results[$key] = $failed
            ? [null, $error ?: "http_{$code}"]
            : [$body,  null];

        curl_multi_remove_handle($mh, $ch);
        curl_close($ch);
    }
    curl_multi_close($mh);

    return $results;
}

function http_get_json(string $url, array $headers = [], int $timeout = 12): ?array
{
    $res = multi_curl([0 => [
        "url"     => $url,
        "headers" => $headers ?: ["User-Agent: Mozilla/5.0"],
    ]], $timeout);

    [$body, $error] = $res[0];
    return (!$error && $body) ? json_decode($body, true) : null;
}

function http_post_json(string $url, array $headers, string $body, int $timeout = 12): ?array
{
    $res = multi_curl([0 => [
        "url"     => $url,
        "method"  => "POST",
        "headers" => $headers,
        "body"    => $body,
    ]], $timeout);

    [$response, $error] = $res[0];
    return (!$error && $response) ? json_decode($response, true) : null;
}


// =============================================================================
// DATE / TIME HELPERS
// =============================================================================

function to_myanmar_time(string $datetime, string $fromTz = "UTC"): string
{
    try {
        $dt = new DateTime($datetime, new DateTimeZone($fromTz));
        $dt->setTimezone(new DateTimeZone(Timezone::MM));
        return $dt->format("Y-m-d H:i:s");
    } catch (Throwable) {
        return "";
    }
}

/**
 * Parse "Month DD HH:MM AM/PM" style string and convert to Myanmar time.
 */
function format_datetime(string $date, string $time): string
{
    $dt = DateTime::createFromFormat("F d Y g:i A", $date . " " . date("Y") . " " . $time);
    if (!$dt) return $date . " " . $time;

    $dt->setTimezone(new DateTimeZone(Timezone::MM));
    return $dt->format("Y-m-d g:i A");
}

/**
 * Parse a Vietnamese API time string like "21:00 - 15.06" and return Myanmar time.
 */
function convert_api_time_to_sql(string $timeStr, int $year = 0): string
{
    $year = $year ?: (int) date("Y");

    if (!preg_match("/(\d{1,2}):(\d{2})\s*-\s*(\d{1,2})\.(\d{1,2})/", $timeStr, $m)) {
        return date("Y-m-d H:i:s");
    }

    $dt = new DateTime(
        sprintf("%d-%d-%d %d:%d:00", $year, (int)$m[4], (int)$m[3], (int)$m[1], (int)$m[2]),
        new DateTimeZone(Timezone::VN)
    );
    $dt->setTimezone(new DateTimeZone(Timezone::MM));
    return $dt->format("Y-m-d H:i:s");
}


// =============================================================================
// MATCH HELPERS
// =============================================================================

/** Normalise a team/league name for fuzzy comparison. */
function norm(string $name): string
{
    return strtolower(trim(str_replace("🏆", "", $name)));
}

/**
 * Returns true if two home/away pairs likely represent the same fixture.
 * Uses similar_text so minor spelling differences still match.
 */
function is_same_fixture(string $h1, string $a1, string $h2, string $a2): bool
{
    similar_text(norm($h1), norm($h2), $homeScore);
    similar_text(norm($a1), norm($a2), $awayScore);
    return $homeScore >= 70 || $awayScore >= 70;
}

/** Append links from $add into $base, skipping exact URL duplicates. */
function merge_links(array $base, array $add, int $priority): array
{
    $existingUrls = array_column($base, "url");

    foreach ($add as $link) {
        if (!is_array($link) || !isset($link["url"])) continue;
        if (in_array($link["url"], $existingUrls, true)) continue;

        $link["priority"] = $priority;
        $base[]           = $link;
        $existingUrls[]   = $link["url"];
    }

    return $base;
}

function sort_links_by_priority(array $links): array
{
    usort($links, fn($a, $b) => ($a["priority"] ?? 99) <=> ($b["priority"] ?? 99));
    return $links;
}


// =============================================================================
// BATCH TRANSLATE (Google Translate unofficial API)
// =============================================================================

function translate_batch(array $texts): array
{
    // Deduplicate and clean input
    $unique = array_values(array_unique(array_filter(
        array_map(fn($t) => trim(html_entity_decode((string)$t, ENT_QUOTES | ENT_HTML5, "UTF-8")), $texts)
    )));

    if (!$unique) return [];

    $finalMap = [];

    foreach (array_chunk($unique, 80) as $chunk) {
        $url = "https://translate.googleapis.com/translate_a/single"
             . "?client=gtx&sl=auto&tl=en&dt=t&q=" . urlencode(implode("\n", $chunk));

        $ctx      = stream_context_create(["http" => ["method" => "GET", "timeout" => 10, "header" => "User-Agent: Mozilla/5.0\r\n"], "ssl" => ["verify_peer" => true]]);
        $response = @file_get_contents($url, false, $ctx);
        $json     = json_decode((string)$response, true);

        if (!isset($json[0]) || !is_array($json[0])) {
            // fallback: keep originals
            foreach ($chunk as $orig) $finalMap[$orig] = $orig;
            continue;
        }

        $translated = preg_split("/\r\n|\n|\r/", implode("", array_column($json[0], 0)));
        foreach ($chunk as $i => $orig) {
            $finalMap[$orig] = trim((string)($translated[$i] ?? $orig)) ?: $orig;
        }
    }

    return $finalMap;
}


// =============================================================================
// SOURCE PARSERS
// =============================================================================

function parse_burmayoteshin(?string $body): array
{
    if (!$body) return [];

    $data = json_decode($body, true);

    if (!isset($data["data"]) || !is_array($data["data"])) {
        return [];
    }

    $matches = [];

    $linkRequests = [];
    $matchMap = [];

    foreach ($data["data"] as $match) {

        if (empty($match["is_free"])) {
            continue;
        }

        $id = $match["_id"] ?? "";

        if (!$id) {
            continue;
        }

        $matchMap[$id] = $match;

        $linkRequests[$id] = [
            "url" => BurmaYoteShinConfig::LINK_URL,

            "method" => "POST",

            "headers" => [
                "User-Agent: Dart/3.9 (dart:io)",
                "Accept: application/json",
                "Content-Type: application/json",
                "access-code: " . BurmaYoteShinConfig::ACCESS_CODE,
                "Authorization: Bearer " . BurmaYoteShinConfig::TOKEN,
            ],

            "body" => json_encode([
                "ref_id" => $id
            ])
        ];
    }

    $linkResponses = multi_curl($linkRequests, 20);

    foreach ($matchMap as $id => $match) {

        $videoLinks = [];

        [$response, $error] = $linkResponses[$id] ?? [null, "missing"];

        if (!$error && $response) {

            $linkData = json_decode($response, true);

            if (isset($linkData["data"]) && is_array($linkData["data"])) {

                foreach ($linkData["data"] as $link) {

                    if (empty($link["url"])) {
                        continue;
                    }

                    $videoLinks[] = [
                        "name"     => $link["name"] ?? "BYT",
                        "url"      => $link["url"],
                        "referer"  => $link["referer"] ?? ""
                    ];
                }
            }
        }

        $date = "";

        if (!empty($match["time"])) {

    try {

        $dt = new DateTime(
            $match["time"],
            new DateTimeZone("UTC")
        );

        $dt->setTimezone(
            new DateTimeZone(Timezone::MM)
        );

        $date = $dt->format(
            "Y-m-d H:i:s"
        );

    } catch (Throwable) {
        $date = "";
    }
}

        $matches[] = [

            "date" => $date,

            "league" => $match["league_name"] ?? "",

            "home" => [
                "name"  => $match["home_team"] ?? "",
                "logo"  => $match["home_logo"] ?? "",
                "score" => "0"
            ],

            "away" => [
                "name"  => $match["away_team"] ?? "",
                "logo"  => $match["away_logo"] ?? "",
                "score" => "0"
            ],

            "video_links" => $videoLinks
        ];
    }

    return $matches;
}

function parse_nieveella(string $body, array $video_tags): array
{
    $data = json_decode($body, true);
    if (!isset($data["data"]["htmls"])) return [];

    // Helper: extract plain UTF-8 text from a DOM node
    $getText = function (?DOMNode $node): string {
        if (!$node) return "";
        $html = $node->ownerDocument->saveHTML($node);
        return html_entity_decode(trim(preg_replace("/<[^>]+>/", " ", $html)), ENT_QUOTES | ENT_HTML5, "UTF-8");
    };

    $raw              = [];
    $textsToTranslate = [];

    foreach ($data["data"]["htmls"] as $html) {
        libxml_use_internal_errors(true);
        $dom = new DOMDocument();
        $dom->loadHTML('<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>' . $html . '</body></html>');
        $xp = new DOMXPath($dom);

        foreach ($xp->query("//div[contains(@class,'grid-matches__item')]") as $node) {
            $league   = $getText($xp->query(".//div[contains(@class,'grid-match__league')]//span", $node)->item(0));
            $homeName = $getText($xp->query(".//div[contains(@class,'team--home-name')]", $node)->item(0));
            $awayName = $getText($xp->query(".//div[contains(@class,'team--away-name')]", $node)->item(0));
            $homeLogo = $xp->query(".//div[contains(@class,'team--home')]//img", $node)->item(0)?->getAttribute("src") ?? "";
            $awayLogo = $xp->query(".//div[contains(@class,'team--away')]//img", $node)->item(0)?->getAttribute("src") ?? "";
            $rawTime  = $getText($xp->query(".//div[contains(@class,'grid-match__date')]", $node)->item(0));
            $pageLink = $xp->query(".//a[contains(@class,'redirectPopup')]", $node)->item(0)?->getAttribute("href") ?? "";

            if ($pageLink) {
                $pageLink = "https://nieveella.com/" . ltrim($pageLink, "/");
            }

            foreach ([$league, $homeName, $awayName] as $t) {
                if ($t !== "") $textsToTranslate[] = trim($t);
            }

            $raw[] = [
                "date"        => convert_api_time_to_sql($rawTime),
                "league"      => trim($league),
                "home"        => ["name" => trim($homeName), "logo" => $homeLogo, "score" => ""],
                "away"        => ["name" => trim($awayName), "logo" => $awayLogo, "score" => ""],
                "video_links" => $pageLink,
            ];
        }
    }

    $tmap = translate_batch($textsToTranslate);

    // Apply translations
    foreach ($raw as &$m) {
        $m["league"]        = $tmap[trim($m["league"])]        ?? $m["league"];
        $m["home"]["name"]  = $tmap[trim($m["home"]["name"])]  ?? $m["home"]["name"];
        $m["away"]["name"]  = $tmap[trim($m["away"]["name"])]  ?? $m["away"]["name"];
        if (trim($m["home"]["name"]) === "You") $m["home"]["name"] = "England";
        if (trim($m["away"]["name"]) === "You") $m["away"]["name"] = "England";
    }

    unset($m);

    // Enrich with Singapore video tags
    foreach ($raw as &$m) {
        $home             = norm($m["home"]["name"]);
        $away             = norm($m["away"]["name"]);
        $m["video_links"] = is_string($m["video_links"]) ? [] : (array)$m["video_links"];

        foreach ($video_tags as $v) {
            if (!is_array($v)) continue;
            $tag = norm((string)($v["tag"] ?? ""));
            if ($tag !== "" && ($tag === $home || $tag === $away)) {
                array_unshift($m["video_links"], $v);
            }
        }
    }
    unset($m);

    return $raw;
}

function parse_burmese(?string $body): array
{
    if (!$body) return [];

    $json = json_decode(decrypt_burmese_payload($body), true);
    if (!is_array($json)) return [];

    $output = [];

    foreach ($json as $league) {
        if (!isset($league["matches"])) continue;
        $leagueName = $league["name"] ?? "";

        foreach ($league["matches"] as $match) {
            $links = [];

            foreach ($match["links"] ?? [] as $link) {
                $name = $link["name"] ?? "";
                // Skip Chinese broadcasters
                if (stripos($name, "soco") !== false || stripos($name, "china") !== false) continue;

                $url = str_replace(["\/", "////"], ["/", "/"], $link["url"] ?? "");
                if (!$url || !str_contains($url, ".mpd")) continue;

                $links[] = [
                    "name"    => $name ?: "BUR",
                    "url"     => $url,
                    "referer" => $link["license_key"] ?? ($link["referrer"] ?? ""),
                ];
            }

            $output[] = [
                "date"        => date("Y-m-d h:i A", $match["start_at"] ?? time()),
                "league"      => $leagueName,
                "home"        => ["name" => $match["home_team"]["name"] ?? "", "logo" => $match["home_team"]["logo_url"] ?? "", "score" => ""],
                "away"        => ["name" => $match["away_team"]["name"] ?? "", "logo" => $match["away_team"]["logo_url"] ?? "", "score" => ""],
                "video_links" => $links,
            ];
        }
    }

    //return $output;
    return filter_expired_matches($output);
}

function parse_devwithai(?string $body): array
{
    //https://socolive.sa.com/
    if (!$body) return [];

    $json = json_decode($body, true);
    if (!isset($json["data"]["matches"])) return [];

    $out = [];

    foreach ($json["data"]["matches"] as $m) {
        $links = $m["livestream"]["links"] ?? [];
        $videoUrl = null;
        foreach ($links as $link) {
            if (
                ($link["commentatorId"] ?? 0) === 100000000000000000 &&
                str_contains($link["url"] ?? "", "master.m3u8")
            ) {
                $videoUrl = $link["url"];
                break; // stop at first match
            }
        }

        if (!$videoUrl) continue;

        $info = $m["info"] ?? [];

        $out[] = [
            "home" => strtolower(trim($info["homeTeam"]["name"] ?? "")),
            "away" => strtolower(trim($info["awayTeam"]["name"] ?? "")),
            "video_links" => [
                [
                    "name"    => "FHD",
                    "url"     => $videoUrl,
                    "referer" => ""
                ]
            ],
        ];
    }

    return $out;
}

function parse_kafei(?string $body): array
{
    if (!$body) return [];

    $data = json_decode($body, true);
    if (empty($data["data"])) return [];

    $getVideoLink = function (array $anchors): string {
        foreach ($anchors as $a) {
            if (($a["category"] ?? 0) == 2) return $a["stream_url"] ?? "";
        }
        return "";
    };

    $textsToTranslate = [];
    $raw              = [];

    foreach ($data["data"] as $match) {
        $videoLink = $getVideoLink($match["archors"] ?? []);
        if (!$videoLink) continue;

        $league = $match["league_name"] ?? "";
        $home   = $match["homeTeam"]["name"] ?? ($match["home_team"] ?? "");
        $away   = $match["awayTeam"]["name"] ?? ($match["away_team"] ?? "");

        foreach ([$league, $home, $away] as $t) {
            if ($t) $textsToTranslate[] = $t;
        }

        $raw[] = compact("match", "videoLink", "league", "home", "away");
    }

    $tmap   = translate_batch($textsToTranslate);
    $result = [];

    foreach ($raw as $r) {
        $match = $r["match"];
        $result[] = [
            "date"        => $match["start_time"] ?? "",
            "league"      => $tmap[$r["league"]] ?? $r["league"],
            "home"        => $tmap[$r["home"]]   ?? $r["home"],
            "away"        => $tmap[$r["away"]]   ?? $r["away"],
            "home_logo"   => $match["homeTeam"]["logo"] ?? ($match["home_team_logo"] ?? ""),
            "away_logo"   => $match["awayTeam"]["logo"] ?? ($match["away_team_logo"] ?? ""),
            "home_score"  => $match["home_score"] ?? 0,
            "away_score"  => $match["away_score"] ?? 0,
            "video_links" => [["name" => "Original", "url" => $r["videoLink"]]],
        ];
    }

    return $result;
}

function parse_zerohazaar(?string $body): array
{
    if (!$body) return [];

    $events = json_decode(zerohazaar_decrypt($body), true);
    if (!is_array($events)) return [];

    $now = new DateTime("now", new DateTimeZone(Timezone::MM));

    $getStatus = function (array $ev) use ($now): string {
        $dt = DateTime::createFromFormat("d/m/Y H:i:s", "{$ev['date']} {$ev['time']}", new DateTimeZone("UTC"));
        if (!$dt) return "UPCOMING";

        $dt->setTimezone(new DateTimeZone(Timezone::MM));
        $endTime = (clone $dt)->modify("+" . MatchConfig::TTL_SEC     . " seconds");
        $preLive = (clone $dt)->modify("-" . MatchConfig::PRELIVE_SEC . " seconds");

        if ($now > $endTime) return "ENDED";
        if ($now < $preLive) return "UPCOMING";
        return $now < $dt ? "PRELIVE" : "LIVE";
    };

    $linkUrls = [];
    $results  = [];

    foreach ($events as $i => $item) {
        $ev = is_array($item["event"] ?? null)
            ? $item["event"]
            : json_decode((string)($item["event"] ?? ""), true);

        if (!$ev) continue;

        $status = $getStatus($ev);
        if ($status === "ENDED") continue;

        $links = $ev["links"] ?? "";
        if ($links && in_array($status, ["LIVE", "PRELIVE"], true)) {
            $linkUrls[$i] = preg_match("/^http/", $links)
                ? $links
                : ZerohazaarConfig::LINKS_BASE . $links;
        }

        $results[$i] = [
            "status"     => $status,
            "league"     => $ev["eventName"] ?? "",
            "home"       => ["name" => $ev["teamAName"] ?? "", "logo" => $ev["teamAFlag"] ?? ""],
            "away"       => ["name" => $ev["teamBName"] ?? "", "logo" => $ev["teamBFlag"] ?? ""],
            "live_links" => [],
        ];
    }

    if ($linkUrls) {
        $reqs      = array_map(fn($url) => ["url" => $url, "headers" => ["User-Agent: Mozilla/5.0"]], $linkUrls);
        $responses = multi_curl($reqs, 20);

        foreach ($responses as $i => [$b, $error]) {
            $results[$i]["live_links"] = ($error || !$b)
                ? [["name" => "error", "url" => "", "tokenApi" => $error]]
                : (json_decode(zerohazaar_decrypt($b), true) ?: []);
        }
    }

    return array_values($results);
}

function parse_fotlive(?string $versionBody): array
{
    if (!$versionBody) return [];

    $ads = json_decode($versionBody, true);
    if (!$ads) return [];

    $apiKey        = decrypt_fixed_secret($ads["mgshine"]);
    $payloadKeyB64 = decrypt_fixed_secret($ads["thuta"]);

    $live    = http_post_json("https://fotlivepro.com/api/cardwidget/live", ["x-api-key: $apiKey", "User-Agent: okhttp/4.9.2"], "");
    $matches = decrypt_api_data($live["data"] ?? "", $payloadKeyB64);
    if (!$matches) return [];

    // Build parallel link-fetch requests
    $linkReqs = [];
    $matchMap = [];

    foreach ($matches as $i => $m) {
        $id = $m["id"] ?? ($m["matchId"] ?? ($m["live_id"] ?? null));
        if (!$id) continue;

        $linkReqs[$i] = [
            "url"     => "https://fotlivepro.com/api/newlinkdata/live/" . rawurlencode((string)$id),
            "headers" => ["x-api-key: $apiKey", "User-Agent: okhttp/4.9.2"],
        ];
        $matchMap[$i] = $m;
    }

    $responses = multi_curl($linkReqs);
    $result    = [];

    foreach ($matchMap as $i => $m) {
        $videoLinks = [];
        [$body, $error] = $responses[$i] ?? [null, "missing"];

        if (!$error && $body) {
            $json = json_decode($body, true);
            if (isset($json["data"])) {
                foreach (decrypt_api_data($json["data"], $payloadKeyB64) as $v) {
                    if (!isset($v["link"])) continue;
                    $keyId   = $v['key_id'] ?? null;
                    $keyData = $v['key_data'] ?? null;
                    $referer = ($keyId || $keyData)? $keyId . ':' .$keyData: '';

                    $videoLinks[] = [
                        "name"    => $v["name"] ?? "FOT",
                        "url"     => $v["link"],
                        "referer" => $referer,
                    ];
                }
            }
        }
        $matchTime = (
            isset($m['time']) &&
            strtolower(trim($m['time'])) === 'live'
        )
            ? ($m['sort_time'] ?? $m['time'])
            : $m['time'];

        $result[] = [
            "date"        => format_datetime($m["date"] ?? "", $matchTime ?? ""),
            "league_name" => trim(str_replace("🏆", "", $m["league_name"] ?? "")),
            "home_name"   => str_replace("🏆", "", $m["home_name"] ?? ""),
            "home_logo"   => $m["home_logo"] ?? "",
            "away_name"   => str_replace("🏆", "", $m["away_name"] ?? ""),
            "away_logo"   => $m["away_logo"] ?? "",
            "video_links" => $videoLinks,
        ];
    }

    return $result;
}

function parse_cumeo_list(?string $body): array
{
    if (!$body) return [];

    $list = json_decode($body, true);
    if (!isset($list["data"]) || !is_array($list["data"])) return [];

    $ids      = [];
    $matchMap = [];

    foreach ($list["data"] as $m) {
        $id = $m["id"] ?? null;
        if (!$id) continue;
        $ids[]         = $id;
        $matchMap[$id] = $m;
    }

    if (!$ids) return [];

    // Fetch live-stream URLs for all matches in parallel
    $liveReqs = [];
    foreach ($ids as $id) {
        $liveReqs[$id] = [
            "url"     => "https://api-cumeo.gvtv1.com/match/{$id}/live",
            "headers" => ["Content-Type: application/json", "User-Agent: Mozilla/5.0"],
        ];
    }
    $liveResponses = multi_curl($liveReqs, 12);

    $result  = [];
    $referer = "https://cumeo2.link/";

    foreach ($ids as $id) {
        $m    = $matchMap[$id];
        [$b]  = $liveResponses[$id] ?? [null];
        $live = ($b ? json_decode($b, true) : null) ?? [];

        $videoLinks = [];
        foreach (["hd_1" => "HD_1", "hd_2" => "HD_2", "hd_3" => "HD_3"] as $key => $label) {
            if (!empty($live[$key])) {
                $videoLinks[] = ["name" => $label, "url" => $live[$key], "referer" => $referer];
            }
        }
        if (!empty($live["source"])) {
            $videoLinks[] = ["name" => "Fast HD", "url" => $live["source"], "referer" => ""];
        }
        if (!$videoLinks && !empty($m["source_live"])) {
            $videoLinks[] = ["name" => "Fast HD", "url" => $m["source_live"], "referer" => ""];
        }

        $result[] = [
            "matchid"     => $id,
            "match_time"  => to_myanmar_time($m["start_date"]),
            "league"      => $m["league"] ?? null,
            "home"        => ["name" => $m["team_1"] ?? "", "logo" => $m["team_1_logo"] ?? "", "score" => $m["team_1_score"] ?? 0],
            "away"        => ["name" => $m["team_2"] ?? "", "logo" => $m["team_2_logo"] ?? "", "score" => $m["team_2_score"] ?? 0],
            "video_links" => $videoLinks,
        ];
    }

    return $result;
}


// =============================================================================
// ZEROHAZAAR LINK NORMALIZER
// =============================================================================

function normalize_zerohazaar_links(array $live_links): array
{
    $out = [];

    foreach ($live_links as $item) {
        if (!is_array($item)) continue;

        $url     = trim((string)($item["url"]     ?? ($item["link"] ?? "")));
        $referer = trim((string)($item["referer"] ?? ($item["api"]  ?? "")));
        if ($url === "") continue;

        $tokenApi = $item["tokenApi"] ?? null;
        if (is_string($tokenApi) && trim($tokenApi) !== "") {
            $decoded  = json_decode($tokenApi, true);
            $tokenApi = is_array($decoded) ? $decoded : $tokenApi;
        }

        $entry = [
            "name" => trim((string)($item["name"] ?? "")) ?: "Zerohazaar",
            "url"  => $url,
        ];
        if ($referer !== "")                                                      $entry["referer"]  = $referer;
        if ($tokenApi !== null && $tokenApi !== "" && $tokenApi !== [])           $entry["tokenApi"] = $tokenApi;

        $out[] = $entry;
    }

    return $out;
}


// =============================================================================
// MERGE ALL SOURCES
// =============================================================================

/**
 * Collect links for a match from all secondary indexes, sorted by priority.
 */
function collect_links(string $home, string $away, array $baseLinks, int $basePri, array $secondaries): array
{
    $links = merge_links([], $baseLinks, $basePri);

    foreach ($secondaries as [$idx, $pri]) {
        foreach ($idx as $row) {
            if (is_same_fixture($home, $away, $row["home"], $row["away"])) {
                $links = merge_links($links, $row["links"], $pri);
            }
        }
    }

    return sort_links_by_priority($links);
}

/**
 * Build a simple lookup index: [["home" => ..., "away" => ..., "links" => [...]], ...]
 */
function build_index(array $src, callable $homeKey, callable $awayKey): array
{
    return array_map(fn($x) => [
        "home"  => norm($homeKey($x)),
        "away"  => norm($awayKey($x)),
        "links" => $x["video_links"] ?? [],
    ], $src);
}

function get_nested(array $arr, array $keys, $default = "") {
    foreach ($keys as $key) {
        if (is_array($arr) && array_key_exists($key, $arr)) {
            $arr = $arr[$key];
        } else {
            return $default;
        }
    }
    return $arr;
}

function merge_all_sources(
    array $soco,
    array $fot,
    array $zerohazaar,
    array $burmese,
    array $dev,
    array $cumeo,
    array $kafei,
    array $byt
): array {

    // Build indexes
    $burIdx = build_index($burmese, fn($x) => get_nested($x, ['home','name']), fn($x) => get_nested($x, ['away','name']));
    $fotIdx = build_index($fot,     fn($x) => get_nested($x, ['home_name']),    fn($x) => get_nested($x, ['away_name']));
    $devIdx = build_index($dev,     fn($x) => get_nested($x, ['home']),         fn($x) => get_nested($x, ['away']));
    $cumIdx = build_index($cumeo,   fn($x) => get_nested($x, ['home','name']), fn($x) => get_nested($x, ['away','name']));
    $kafIdx = build_index($kafei,   fn($x) => get_nested($x, ['home']) ?: get_nested($x, ['home','name']), fn($x) => get_nested($x, ['away']) ?: get_nested($x, ['away','name']));
    $bytIdx = build_index($byt,     fn($x) => get_nested($x, ['home','name']), fn($x) => get_nested($x, ['away','name']));
    $result = [];

    // ── 1. SOCO ──────────────────────────────
    foreach ($soco as $s) {
        $h = norm(get_nested($s, ['home','name']));
        $a = norm(get_nested($s, ['away','name']));

        $s["video_links"] = collect_links($h, $a, (array)($s["video_links"] ?? []), 4, [
            [$burIdx, 2],
            [$cumIdx, 2],
            [$devIdx, 3],
            [$fotIdx, 4],
            [$kafIdx, 1],
            [$bytIdx, 4],
        ]);

        foreach ($zerohazaar as $zev) {
            $zh = norm(get_nested($zev, ['home','name']));
            $za = norm(get_nested($zev, ['away','name']));

            if (str_contains($h, $zh) || str_contains($a, $za)) {
                if (!empty($zev["league"])) $s["league"] = $zev["league"];
                foreach (normalize_zerohazaar_links($zev["live_links"] ?? []) as $link) {
                    $s["video_links"] = merge_links($s["video_links"], [$link], 2);
                }
            }
        }

        $result[] = $s;
    }

    // ── 2. Burmese-only ──────────────────────────────
    foreach ($burmese as $b) {
        $h = norm(get_nested($b, ['home','name']));
        $a = norm(get_nested($b, ['away','name']));

        foreach ($soco as $s) {
            if (is_same_fixture($h, $a, norm(get_nested($s, ['home','name'])), norm(get_nested($s, ['away','name'])))) continue 2;
        }
        
        $b["video_links"] = collect_links($h, $a, $b["video_links"] ?? [], 1, [
            [$cumIdx, 2],
            [$devIdx, 2],
            [$fotIdx, 3],
            [$kafIdx, 4],
            [$bytIdx, 4],
        ]);

        $result[] = $b;
    }

    // ── 3. FOT-only ──────────────────────────────
    foreach ($fot as $f) {
        $h = norm(get_nested($f, ['home_name']));
        $a = norm(get_nested($f, ['away_name']));

        foreach ($soco as $s) {
            if (is_same_fixture($h, $a, norm(get_nested($s, ['home','name'])), norm(get_nested($s, ['away','name'])))) continue 2;
        }
        
        $result[] = [
            "date"        => $f["date"] ?? "",
            "league"      => $f["league_name"] ?? "",
            "home"        => ["name" => $f["home_name"] ?? "", "logo" => $f["home_logo"] ?? "", "score" => "0"],
            "away"        => ["name" => $f["away_name"] ?? "", "logo" => $f["away_logo"] ?? "", "score" => "0"],
            "video_links" => collect_links($h, $a, $f["video_links"] ?? [], 3, [
                [$burIdx, 1],
                [$cumIdx, 2],
                [$devIdx, 2],
                [$kafIdx, 4],
                [$bytIdx, 4],
            ]),
        ];
    }
    
    // ── 4. BURMAYOTESHIN-only ──────────────────────────────
    foreach ($byt as $b) {
        $h = norm(get_nested($c, ['home','name']));
        $a = norm(get_nested($c, ['away','name']));

        foreach ($soco    as $s) { if (is_same_fixture($h, $a, norm(get_nested($s, ['home','name'])), norm(get_nested($s, ['away','name'])))) continue 2; }
        foreach ($fot     as $f) { if (is_same_fixture($h, $a, norm(get_nested($f, ['home_name'])), norm(get_nested($f, ['away_name'])))) continue 2; }
        foreach ($burmese as $b) { if (is_same_fixture($h, $a, norm(get_nested($b, ['home','name'])), norm(get_nested($b, ['away','name'])))) continue 2; }

    $result[] = [

        "date" =>
            $b["date"] ?? "",

        "league" =>
            $b["league"] ?? "",

        "home" => [

            "name" =>
                get_nested($b, ['home','name']),

            "logo" =>
                get_nested($b, ['home','logo']),

            "score" => "0"
        ],

        "away" => [

            "name" =>
                get_nested($b, ['away','name']),

            "logo" =>
                get_nested($b, ['away','logo']),

            "score" => "0"
        ],

        "video_links" =>
            collect_links(
                $h,
                $a,
                $b["video_links"] ?? [],
                4,
                [
                    [$cumIdx, 2],
                    [$devIdx, 3],
                    [$kafIdx, 4],
                ]
            )
    ];
}

    // ── 4. Cumeo-only ──────────────────────────────
    foreach ($cumeo as $c) {
        $h = norm(get_nested($c, ['home','name']));
        $a = norm(get_nested($c, ['away','name']));

        foreach ($soco    as $s) { if (is_same_fixture($h, $a, norm(get_nested($s, ['home','name'])), norm(get_nested($s, ['away','name'])))) continue 2; }
        foreach ($fot     as $f) { if (is_same_fixture($h, $a, norm(get_nested($f, ['home_name'])), norm(get_nested($f, ['away_name'])))) continue 2; }
        foreach ($burmese as $b) { if (is_same_fixture($h, $a, norm(get_nested($b, ['home','name'])), norm(get_nested($b, ['away','name'])))) continue 2; }

        $result[] = [
            "date"        => $c["match_time"] ?? "",
            "league"      => $c["league"]     ?? "",
            "home"        => ["name" => get_nested($c, ['home','name']), "logo" => get_nested($c, ['home','logo']), "score" => get_nested($c, ['home','score'], '0')],
            "away"        => ["name" => get_nested($c, ['away','name']), "logo" => get_nested($c, ['away','logo']), "score" => get_nested($c, ['away','score'], '0')],
            "video_links" => collect_links($h, $a, $c["video_links"] ?? [], 2, [
                [$devIdx, 3],
                [$kafIdx, 4],
            ]),
        ];
    }

    return $result;
}


// =============================================================================
// POST-PROCESSING
// =============================================================================

function fetch_fotmod_scores(): array
{
    $data = http_get_json("https://theredshow.site/football/api/fot.php");
    if (!is_array($data)) return [];

    $map = [];
    foreach ($data as $m) {
        $h = norm($m["home"]["name"] ?? "");
        $a = norm($m["away"]["name"] ?? "");
        if ($h && $a) $map[$h . "||" . $a] = $m;
    }
    return $map;
}

function replace_scores_with_fotmod(array $matches): array
{
    $fotmod = fetch_fotmod_scores();
    if (!$fotmod) return $matches;

    foreach ($matches as &$m) {
        $sh = norm($m["home"]["name"] ?? "");
        $sa = norm($m["away"]["name"] ?? "");

        foreach ($fotmod as $key => $scores) {
            [$fh, $fa] = explode("||", $key);
            similar_text($sh, $fh, $homeMatch);
            similar_text($sa, $fa, $awayMatch);

            if ($homeMatch > 70 || $awayMatch > 70) {
                $m["home"]["score"] = $scores["home"]["score"] ?? "";
                $m["away"]["score"] = $scores["away"]["score"] ?? "";
            }
            if ($homeMatch > 90) $m["home"]["logo"] = $scores["home"]["logo"] ?? $m["home"]["logo"];
            if ($awayMatch > 90) $m["away"]["logo"] = $scores["away"]["logo"] ?? $m["away"]["logo"];
            if ($homeMatch > 70 && $awayMatch > 70) {
                $m["home"]["name"] = $scores["home"]["name"] ?? $m["home"]["name"];
                $m["away"]["name"] = $scores["away"]["name"] ?? $m["away"]["name"];
            }
            if ($homeMatch > 80 && $awayMatch > 80) {
                $m["league"] = $scores["league"] ?? $m["league"];
                break;
            }
        }
    }
    unset($m);

    return $matches;
}

function remove_duplicate_matches(array $matches): array
{
    $out = [];

    foreach ($matches as $m) {
        $h1 = norm($m["home"]["name"] ?? "");
        $a1 = norm($m["away"]["name"] ?? "");

        foreach ($out as $existing) {
            $h2 = norm($existing["home"]["name"] ?? "");
            $a2 = norm($existing["away"]["name"] ?? "");

            $isDuplicate = str_contains($h1, $h2) || str_contains($h2, $h1)
                        || str_contains($a1, $a2) || str_contains($a2, $a1)
                        || str_contains($h1, $a2) || str_contains($a1, $h2);

            if ($isDuplicate) continue 2;
        }

        $out[] = $m;
    }

    return $out;
}

function filter_expired_matches(array $matches): array
{
    return array_values(array_filter($matches, function ($m) {
        if (in_array(strtolower($m["league"] ?? ""), MatchConfig::ALWAYS_SHOW_LEAGUES, true)) {
            return true;
        }
        $timestamp = strtotime($m["date"] ?? "");
        return $timestamp && $timestamp + MatchConfig::TTL_SEC > time();
    }));
}

function fetch_custom_matches(string $path): array
{
    if (!is_file($path)) return [];

    $data = json_decode((string)@file_get_contents($path), true);
    if (!is_array($data)) return [];

    $now = new DateTime("now", new DateTimeZone(Timezone::MM));
    $out = [];

    foreach ($data as $m) {
        if (!is_array($m)) continue;

        $expiry = isset($m["expire_at"])
            ? DateTime::createFromFormat(DateTime::ATOM, $m["expire_at"])
            : null;

        if ($expiry && $now > $expiry) continue;

        $out[] = [
            "date"        => $m["date"]   ?? $now->format("Y-m-d\TH:i:s+06:30"),
            "league"      => $m["league"] ?? "Custom Match",
            "home"        => ["name" => $m["home"]["name"] ?? "", "logo" => $m["home"]["logo"] ?? "", "score" => $m["home"]["score"] ?? ""],
            "away"        => ["name" => $m["away"]["name"] ?? "", "logo" => $m["away"]["logo"] ?? "", "score" => $m["away"]["score"] ?? ""],
            "video_links" => is_array($m["video_links"] ?? null) ? $m["video_links"] : [],
            "is_custom"   => true,
        ];
    }

    return $out;
}

function save_matches(array $matches): void
{
    global $conn;
    if (!$conn) return;

    $conn->set_charset("utf8mb4");
    $conn->query("SET NAMES 'utf8mb4' COLLATE 'utf8mb4_unicode_ci'");
    $conn->query("TRUNCATE TABLE football_matches");

    $stmt = $conn->prepare("
        INSERT INTO football_matches
            (match_date, league, home_name, home_logo, home_score, away_name, away_logo, away_score, video_links)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            league      = VALUES(league),
            home_logo   = VALUES(home_logo),
            home_score  = VALUES(home_score),
            away_logo   = VALUES(away_logo),
            away_score  = VALUES(away_score),
            video_links = VALUES(video_links),
            updated_at  = CURRENT_TIMESTAMP
    ");
    if (!$stmt) return;

    foreach ($matches as $m) {
        $matchDate  = date("Y-m-d H:i:s", strtotime($m["date"] ?? "now"));
        $league     = $m["league"]         ?? "";
        $homeName   = $m["home"]["name"]   ?? "";
        $homeLogo   = $m["home"]["logo"]   ?? "";
        $homeScore  = (string)($m["home"]["score"] ?? "");
        $awayName   = $m["away"]["name"]   ?? "";
        $awayLogo   = $m["away"]["logo"]   ?? "";
        $awayScore  = (string)($m["away"]["score"] ?? "");
        $videoLinks = json_encode($m["video_links"] ?? [], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        $stmt->bind_param("sssssssss", $matchDate, $league, $homeName, $homeLogo, $homeScore, $awayName, $awayLogo, $awayScore, $videoLinks);
        $stmt->execute();
    }

    $stmt->close();
}

function fetch_match_overrides(string $path): array
{
    if (!is_file($path)) return [];
 
    $data = json_decode((string)@file_get_contents($path), true);
    return is_array($data) ? $data : [];
}
 
function apply_match_overrides(array $matches, array $overrides): array
{
    if (!$overrides) return $matches;
 
    foreach ($matches as &$m) {
        $h = norm($m["home"]["name"] ?? "");
        $a = norm($m["away"]["name"] ?? "");
 
        $key = $h . "||" . $a;
        $ov  = $overrides[$key] ?? null;
 
        if (!$ov) {
            foreach ($overrides as $candidate) {
                $oh = norm($candidate["original_home"] ?? "");
                $oa = norm($candidate["original_away"] ?? "");
                if (is_same_fixture($m["home"]["name"] ?? "", $m["away"]["name"] ?? "", $oh, $oa)) {
                    $ov = $candidate;
                    break;
                }
            }
        }
 
        if (!$ov) continue;
 
        if (!empty($ov["league"])) $m["league"] = $ov["league"];
 
        foreach (["home", "away"] as $side) {
            if (!empty($ov[$side]["name"]))             $m[$side]["name"]  = $ov[$side]["name"];
            if (!empty($ov[$side]["logo"]))             $m[$side]["logo"]  = $ov[$side]["logo"];
            if (($ov[$side]["score"] ?? "") !== "")     $m[$side]["score"] = $ov[$side]["score"];
        }
    }
    unset($m);
 
    return $matches;
}

function clean_match_overrides(array $overrides, array $matches, string $path): array
{
    if (!$overrides) return $overrides;

    $keySet = [];
    foreach ($matches as $m) {
        $h = norm($m["home"]["name"] ?? "");
        $a = norm($m["away"]["name"] ?? "");
        $keySet[$h . "||" . $a] = true;
    }

    $cleaned = [];

    foreach ($overrides as $key => $ov) {
        if (!is_array($ov)) continue;

        // 1) Exact key match (e.g. "manchester united||liverpool")
        if (is_string($key) && isset($keySet[$key])) {
            $cleaned[$key] = $ov;
            continue;
        }

        // 2) Fuzzy match via original_home / original_away fields
        $oh = $ov["original_home"] ?? "";
        $oa = $ov["original_away"] ?? "";

        $found = false;
        if ($oh !== "" || $oa !== "") {
            foreach ($matches as $m) {
                if (is_same_fixture($m["home"]["name"] ?? "", $m["away"]["name"] ?? "", $oh, $oa)) {
                    $found = true;
                    break;
                }
            }
        }

        if ($found) {
            $cleaned[$key] = $ov;
        }
    }

    if ($cleaned !== $overrides) {
        @file_put_contents(
            $path,
            json_encode($cleaned, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)
        );
    }

    return $cleaned;
}


// =============================================================================
// MAIN BUILD
// =============================================================================

function build_matches(): array
{
    $yesterday = date("Y-m-d", strtotime("-1 day"));
    $tomorrow  = date("Y-m-d", strtotime("+1 day"));

    // ── Step 1: Fire all external HTTP requests in parallel ───────────────
    $cumeoPayload = json_encode([
        "queries" => [
            ["field" => "start_date", "type" => "gte",   "value" => "2026-01-17T07:08:00.000"],
            ["field" => "is_top",     "type" => "equal", "value" => true],
        ],
        "query_and" => true,
        "limit"     => 10,
        "page"      => 1,
        "order_asc" => "start_date",
    ]);

    $requests = [
        "nieveella"       => ["url" => "https://xoilaczzzzw.tv/sport/football/filter/hot"],
        "burmese"         => ["url" => "https://raw.githubusercontent.com/mm2d3d/lite/refs/heads/main/hub.json"],
        "devwithai"       => ["url" => "https://api-football.devwithai.net/api/matches/query/?fromDate={$yesterday}&toDate={$tomorrow}&statuses=UPCOMING&statuses=LIVE&commentatorAvailable=false&sortMatchTime=asc&returnList=info&returnList=livestream"],
        "kafei"           => ["url" => "https://kafeizhibo.com/api/v1/schedule?type=1&page=1&size=30"],
        "zerohazaar"      => ["url" => ZerohazaarConfig::EVENTS_URL],
        "fotlive_version" => [
            "url"     => FotliveConfig::VERSION_URL,
            "method"  => "POST",
            "headers" => ["x-api-key: " . FotliveConfig::API_KEY, "User-Agent: okhttp/4.9.2"],
        ],
        "cumeo_list" => [
            "url"     => "https://api-cumeo.gvtv1.com/matches/graph",
            "method"  => "POST",
            "headers" => ["Content-Type: application/json", "Accept: application/json", "User-Agent: Mozilla/5.0"],
            "body"    => $cumeoPayload,
        ],
        "burmayoteshin" => [
            "url" => BurmaYoteShinConfig::MATCH_URL,
            "headers" => [
                "Accept: application/json",
                "User-Agent: Mozilla/5.0"
            ]
        ],
    ];

    $raw  = multi_curl($requests);
    $body = fn(string $k): ?string => $raw[$k][0] ?? null;
    $videoTags = json_decode((string)@file_get_contents(__DIR__ . "/api/data/video.json"), true) ?? [];

    $soco    = parse_nieveella($body("nieveella") ?? "", $videoTags);
    $burmese = parse_burmese($body("burmese"));
    $dev     = parse_devwithai($body("devwithai"));
    $kafei   = parse_kafei($body("kafei"));
    $zero    = parse_zerohazaar($body("zerohazaar"));
    $fot     = parse_fotlive($body("fotlive_version"));
    $cumeo   = parse_cumeo_list($body("cumeo_list"));
    $byt     = parse_burmayoteshin($body("burmayoteshin"));
    $custom = fetch_custom_matches(__DIR__ . "/api/admin/data/custom_matches.json");
    $soco   = array_merge($custom, $soco);
    $all = merge_all_sources($soco, $fot, $zero, $burmese, $dev, $cumeo, $kafei,$byt);

    $overrides = fetch_match_overrides(__DIR__ . "/api/admin/data/match_overrides.json");
    $all = apply_match_overrides($all, $overrides);
    $all = replace_scores_with_fotmod($all);
    $all = remove_duplicate_matches($all);
    $all = filter_expired_matches($all);

    save_matches($all);
    return $all;
}


// =============================================================================
// ENTRY POINT
// =============================================================================

$date = isset($_GET["date"]) ? trim($_GET["date"]) : null;

if ($date !== null && $date !== "" && !preg_match('/^\d{8}$/', $date)) {
    http_response_code(400);
    echo json_encode(["error" => "invalid_date", "hint" => "Use ?date=YYYYMMDD e.g. 20260210"], JSON_UNESCAPED_UNICODE);
    exit();
}

try {
    echo json_encode(build_matches(), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(["error" => "server_error", "message" => $e->getMessage()], JSON_UNESCAPED_UNICODE);
}
