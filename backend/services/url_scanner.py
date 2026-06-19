import os
import re
import ssl
import socket
import base64
import urllib.parse
import requests
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")

# Suspicious keywords in URLs
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "secure", "verify", "update", "account", "banking", 
    "paypal", "netflix", "appleid", "support", "wallet", "invoice", "claim", 
    "free", "gift", "bonus", "log-in", "sign-in"
]

# Common URL shorteners
SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "adf.ly", 
    "rebrand.ly", "ow.ly", "t.ly", "tiny.cc", "lnk.to"
]

def analyze_url_heuristics(url: str):
    """Analyze URL structure locally for suspicious indicators."""
    # Ensure scheme is present
    parsed_url = url
    if not url.startswith(("http://", "https://")):
        parsed_url = "https://" + url
        
    try:
        parsed = urllib.parse.urlparse(parsed_url)
    except Exception:
        return {
            "is_valid": False,
            "error": "Failed to parse URL",
            "is_ip": False,
            "is_shortened": False,
            "keyword_hits": [],
            "ssl_valid": False,
            "ssl_details": "Unparseable URL"
        }

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # 1. Detect IP-based URL
    # IPv4 regex
    is_ip = False
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, hostname):
        is_ip = True

    # 2. Detect Shortener
    is_shortened = any(hostname.lower() == s or hostname.lower().endswith("." + s) for s in SHORTENERS)

    # 3. Detect Keywords
    hits = []
    combined_path_query = (hostname + path + query).lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in combined_path_query:
            hits.append(kw)

    # 4. Check SSL validity
    ssl_valid, ssl_details = verify_ssl(hostname, parsed.scheme)

    return {
        "is_valid": True,
        "hostname": hostname,
        "is_ip": is_ip,
        "is_shortened": is_shortened,
        "keyword_hits": hits,
        "ssl_valid": ssl_valid,
        "ssl_details": ssl_details
    }

def verify_ssl(hostname: str, scheme: str):
    """Performs a direct SSL socket handshake check on the host."""
    if not hostname:
        return False, "No host to verify"
    if scheme != "https":
        return False, "Insecure HTTP scheme (No SSL)"

    context = ssl.create_default_context()
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True

    try:
        # Resolve address first to set a strict timeout
        addr_info = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        if not addr_info:
            return False, "Host address resolution failed"
        
        # Connect and check certificate
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # Parse issuer
                issuer = dict(x[0] for x in cert.get('issuer', []))
                common_name = issuer.get('commonName', 'Unknown Issuer')
                return True, f"Valid Certificate (Issuer: {common_name})"
    except socket.timeout:
        return False, "Connection timeout during SSL handshake"
    except (ssl.SSLError, socket.error) as e:
        return False, f"SSL verification failed: {str(e)}"
    except Exception as e:
        return False, f"Connection failed: {str(e)}"

def get_virustotal_report(url: str):
    """Fetch URL report from VirusTotal v3 API. Falls back if key is missing."""
    if not VIRUSTOTAL_API_KEY:
        return None  # Triggers mock fallback

    # VT API v3 URL identifier is base64 representation of URL without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        # First, try to get existing report
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}", 
            headers=headers, 
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "source": "VirusTotal Live API"
            }
        elif response.status_code == 404:
            # URL not yet analyzed, submit it for scan
            scan_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls", 
                headers=headers, 
                data={"url": url}, 
                timeout=5
            )
            if scan_resp.status_code == 200:
                return {
                    "harmless": 0,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 0,
                    "source": "VirusTotal Live API (Queued/Submitted)"
                }
    except Exception as e:
        print(f"VirusTotal lookup error: {e}")
    
    return None

def get_urlscan_report(url: str):
    """Perform quick query on URLScan API. Falls back if key is missing."""
    if not URLSCAN_API_KEY:
        return None

    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "url": url,
        "visibility": "public"
    }

    try:
        response = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json=payload,
            timeout=5
        )
        if response.status_code == 200 or response.status_code == 201:
            data = response.json()
            return {
                "scan_id": data.get("uuid"),
                "result_url": data.get("result"),
                "screenshot": f"https://urlscan.io/screenshots/{data.get('uuid')}.png",
                "source": "URLScan Live API"
            }
    except Exception as e:
        print(f"URLScan lookup error: {e}")
        
    return None

def calculate_threat_score(heuristics: dict, vt_report: dict, urlscan_report: dict, is_mock: bool, url: str):
    """Calculates overall threat score (0-100) and status."""
    score = 0

    if heuristics.get("is_ip"):
        score += 20
    if heuristics.get("is_shortened"):
        score += 15
    if not heuristics.get("ssl_valid"):
        score += 25
    
    hits_count = len(heuristics.get("keyword_hits", []))
    score += min(hits_count * 12, 35)

    if vt_report:
        malicious_count = vt_report.get("malicious", 0)
        suspicious_count = vt_report.get("suspicious", 0)
        score += malicious_count * 10
        score += suspicious_count * 5
    elif is_mock:
        # Mock calculation depending on keywords or domain names
        domain = heuristics.get("hostname", "").lower()
        if any(kw in url.lower() for kw in ["phish", "malicious", "paypal-update", "verify-bank", "crypto-gift"]):
            score += 55
        elif any(sh in domain for sh in SHORTENERS) and hits_count > 0:
            score += 40
        
        # Limit base mock additions
        score = max(score, min(hits_count * 15, 45))

    # Cap score
    score = min(max(score, 0), 100)

    if score >= 70:
        status = "Malicious"
    elif score >= 30:
        status = "Suspicious"
    else:
        status = "Safe"

    return score, status

def scan_url(url: str):
    """Primary handler to scan a URL and compile threat metrics."""
    # Ensure scheme
    full_url = url
    if not url.startswith(("http://", "https://")):
        full_url = "https://" + url

    heuristics = analyze_url_heuristics(full_url)
    if not heuristics.get("is_valid"):
        return {
            "url": url,
            "success": False,
            "error": heuristics.get("error", "Invalid URL")
        }

    # API Queries
    vt_report = get_virustotal_report(full_url)
    urlscan_report = get_urlscan_report(full_url)

    is_mock = False
    # If API reports failed/keys missing, create realistic mock data
    if vt_report is None:
        is_mock = True
        domain = heuristics.get("hostname", "").lower()
        # Mock VT based on inputs
        if any(kw in full_url.lower() for kw in ["phish", "malicious", "paypal-update", "verify-bank", "crypto-gift"]):
            vt_report = {"harmless": 5, "malicious": 14, "suspicious": 2, "undetected": 45, "source": "VirusTotal Simulator"}
        elif any(safe in domain for safe in ["google.com", "github.com", "microsoft.com", "wikipedia.org"]):
            vt_report = {"harmless": 68, "malicious": 0, "suspicious": 0, "undetected": 2, "source": "VirusTotal Simulator"}
        else:
            # Default clean/unknown domain
            vt_report = {"harmless": 45, "malicious": 0, "suspicious": 0, "undetected": 25, "source": "VirusTotal Simulator"}

    if urlscan_report is None:
        is_mock = True
        domain = heuristics.get("hostname", "").lower()
        # Mock URLScan
        if any(kw in full_url.lower() for kw in ["phish", "malicious", "paypal-update"]):
            urlscan_report = {
                "scan_id": "mock-phish-scan-uuid-1234",
                "result_url": "https://urlscan.io/result/mock",
                "screenshot": "https://images.unsplash.com/photo-1563986768609-322da13575f3?w=600&auto=format&fit=crop&q=60", # Mock terminal image
                "source": "URLScan Simulator"
            }
        else:
            urlscan_report = {
                "scan_id": "mock-safe-scan-uuid-1234",
                "result_url": "https://urlscan.io/result/mock",
                "screenshot": "https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=600&auto=format&fit=crop&q=60", # Dark abstract
                "source": "URLScan Simulator"
            }

    score, status = calculate_threat_score(heuristics, vt_report, urlscan_report, is_mock, full_url)

    return {
        "url": full_url,
        "success": True,
        "heuristics": heuristics,
        "virustotal": vt_report,
        "urlscan": urlscan_report,
        "threat_score": score,
        "status": status,
        "mode": "Simulation" if is_mock else "Live API",
        "timestamp": str(socket.gethostname()) # Just extra metadata
    }
