import json
import socket
import requests
from http.server import BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_SUBDOMAINS_TO_CHECK = 60   # batas biar gak timeout di serverless
CHECK_WORKERS = 20
FETCH_TIMEOUT = 6
CHECK_TIMEOUT = 3

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (SubdomainFinder/1.0)"})


def fetch_hackertarget(domain):
    subs = set()
    try:
        res = session.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=FETCH_TIMEOUT,
        ).text
        for line in res.split("\n"):
            if "," in line:
                subs.add(line.split(",")[0].strip().lower())
    except Exception:
        pass
    return subs


def fetch_crtsh(domain):
    subs = set()
    try:
        res = session.get(
            f"https://crt.sh/?q={domain}&output=json",
            timeout=FETCH_TIMEOUT,
        ).json()
        for entry in res:
            name = entry.get("name_value", "").lower()
            for s in name.split("\n"):
                s = s.strip()
                if domain in s and "*" not in s:
                    subs.add(s)
    except Exception:
        pass
    return subs


def get_subdomains(domain):
    subs = set()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(fetch_hackertarget, domain),
            executor.submit(fetch_crtsh, domain),
        ]
        for f in as_completed(futures):
            subs |= f.result()
    return sorted(subs)


def check_active(url):
    try:
        ip = socket.gethostbyname(url)
    except Exception:
        return None
    try:
        r = session.get(
            f"http://{url}",
            timeout=CHECK_TIMEOUT,
            allow_redirects=True,
        )
        server = r.headers.get("Server", "").lower()
        is_cf = "cloudflare" in server
        return {
            "host": url,
            "ip": ip,
            "status": r.status_code,
            "cloudflare": is_cf,
        }
    except Exception:
        return None


class handler(BaseHTTPRequestHandler):
    def _send_json(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send_json(200, {})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            data = json.loads(raw or b"{}")
            domain = (data.get("domain") or "").strip().lower()
            domain = domain.replace("https://", "").replace("http://", "").strip("/")

            if not domain or "." not in domain:
                self._send_json(400, {"error": "Domain tidak valid"})
                return

            all_subs = get_subdomains(domain)
            if not all_subs:
                self._send_json(200, {
                    "domain": domain,
                    "total_found": 0,
                    "active": [],
                    "truncated": False,
                })
                return

            truncated = len(all_subs) > MAX_SUBDOMAINS_TO_CHECK
            to_check = all_subs[:MAX_SUBDOMAINS_TO_CHECK]

            active = []
            with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as executor:
                for result in executor.map(check_active, to_check):
                    if result:
                        active.append(result)

            self._send_json(200, {
                "domain": domain,
                "total_found": len(all_subs),
                "checked": len(to_check),
                "active": active,
                "truncated": truncated,
            })
        except Exception as e:
            self._send_json(500, {"error": str(e)})
