import base64
import binascii
import re
import json
import urllib.request
from urllib.parse import urljoin
from datetime import datetime, timezone, timedelta
from Crypto.Cipher import AES

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

def myanmar_tz():
    if ZoneInfo is not None:
        return ZoneInfo("Asia/Yangon")
    return timezone(timedelta(hours=6, minutes=30))

DEFAULT_MATCH_DURATION = timedelta(hours=2)
PRELIVE_WINDOW = timedelta(minutes=10)

EVENTS_URL = "https://zerohazaarop.store/events.txt"
LINKS_BASE_URL = "https://zerohazaarop.store/"

KEY = b"l9K5bT5xC1wP7pK1"
IV  = b"k5K4nN7oU8hL6l19"

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

def is_hex(s):
    s = s.strip()
    return len(s) % 2 == 0 and HEX_RE.fullmatch(s)

def try_decode(data):
    data = data.strip()
    if is_hex(data):
        return binascii.unhexlify(data), "HEX"

    b64 = re.sub(r"\s+", "", data)
    if len(b64) % 4:
        b64 += "=" * (4 - (len(b64) % 4))

    try:
        return base64.b64decode(b64, validate=False), "BASE64"
    except Exception:
        return base64.urlsafe_b64decode(b64), "BASE64_URLSAFE"

def pkcs7_unpad(buf):
    pad = buf[-1]
    return buf[:-pad]

def decrypt_text(enc_text):
    cipher_bytes, fmt = try_decode(enc_text)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted = cipher.decrypt(cipher_bytes)
    return pkcs7_unpad(decrypted).decode("utf-8"), fmt

def fetch_text(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore").strip()

def fetch_and_decrypt_json(url):
    enc = fetch_text(url)
    plain, fmt = decrypt_text(enc)
    try:
        return json.loads(plain), fmt
    except Exception:
        return plain, fmt

def parse_utc(date_str, time_str):
    return datetime.strptime(
        f"{date_str} {time_str}",
        "%d/%m/%Y %H:%M:%S"
    ).replace(tzinfo=timezone.utc)

def get_start_end_mm(event):
    if not event.get("date") or not event.get("time"):
        return None, None

    start_mm = parse_utc(
        event["date"].strip(),
        event["time"].strip()
    ).astimezone(myanmar_tz())

    if event.get("end_time"):
        try:
            end_mm = parse_utc(
                event["date"].strip(),
                event["end_time"].strip()
            ).astimezone(myanmar_tz())
        except Exception:
            end_mm = start_mm + DEFAULT_MATCH_DURATION
    else:
        end_mm = start_mm + DEFAULT_MATCH_DURATION

    return start_mm, end_mm

def get_status(event):
    start_mm, end_mm = get_start_end_mm(event)
    if not start_mm:
        return "UPCOMING"

    now_mm = datetime.now(myanmar_tz())

    if now_mm > end_mm:
        return "ENDED"

    if now_mm < (start_mm - PRELIVE_WINDOW):
        return "UPCOMING"

    if (start_mm - PRELIVE_WINDOW) <= now_mm < start_mm:
        return "PRELIVE"
    
    return "LIVE"

def should_fetch_links(status: str) -> bool:
    return status in ("PRELIVE", "LIVE")

def fmt_ampm(dt):
    return dt.strftime("%d-%m-%Y %I:%M %p")

def normalize_event(item):
    if not isinstance(item, dict):
        return None

    ev = item.get("event")
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except Exception:
            return None

    return ev if isinstance(ev, dict) else None

def build_final_event(event, status, live_links=None):
    start_mm, end_mm = get_start_end_mm(event)

    return {
        "status": status,
        "matchTime": fmt_ampm(start_mm) if start_mm else None,
        "endTime": fmt_ampm(end_mm) if end_mm else None,
        "LeagueName": event.get("eventName", ""),
        "LeagueLogo": event.get("eventLogo", ""),
        "home": {
            "name": event.get("teamAName", ""),
            "logo": event.get("teamAFlag", "")
        },
        "away": {
            "name": event.get("teamBName", ""),
            "logo": event.get("teamBFlag", "")
        },
        "live_links": live_links
    }

def main():
    events, _ = fetch_and_decrypt_json(EVENTS_URL)
    final = []

    for item in events:
        ev = normalize_event(item)
        if not ev:
            continue

        if ev.get("category", "").lower() != "football":
            continue

        status = get_status(ev)

        if status == "ENDED":
            continue

        live_links = []
        if ev.get("links") and should_fetch_links(status):
            try:
                links_path = ev["links"]
                if links_path.startswith("http"):
                    links_url = links_path
                else:
                    links_url = urljoin(LINKS_BASE_URL, links_path)

                live_links, _ = fetch_and_decrypt_json(links_url)
            except Exception as e:
                live_links = {"error": str(e)}

        final.append(build_final_event(ev, status, live_links))

    with open("football_live.json", "w", encoding="utf-8") as f:
        json.dump(final, f, ensure_ascii=False, indent=2)

    print("Done ✅")

if __name__ == "__main__":
    main()
