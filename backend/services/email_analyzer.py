import os
import re
import email
from email.parser import HeaderParser
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def extract_emails(text: str):
    """Utility to extract email addresses from a string."""
    if not text:
        return []
    return re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)

def extract_ip_addresses(text: str):
    """Utility to extract IPv4 addresses from a text string, filtering out local IPs if possible."""
    if not text:
        return []
    # Standard IPv4 regex
    all_ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    # Filter out common local/loopback IPs
    external_ips = [ip for ip in all_ips if not (
        ip.startswith("127.") or 
        ip.startswith("10.") or 
        ip.startswith("192.168.") or 
        ip.startswith("172.16.") or
        ip.startswith("172.17.") or
        ip.startswith("172.18.") or
        ip.startswith("172.19.") or
        ip.startswith("172.20.") or
        ip.startswith("172.21.") or
        ip.startswith("172.22.") or
        ip.startswith("172.23.") or
        ip.startswith("172.24.") or
        ip.startswith("172.25.") or
        ip.startswith("172.26.") or
        ip.startswith("172.27.") or
        ip.startswith("172.28.") or
        ip.startswith("172.29.") or
        ip.startswith("172.30.") or
        ip.startswith("172.31.") or
        ip == "0.0.0.0"
    )]
    return external_ips if external_ips else all_ips

def parse_auth_results(auth_header: str):
    """Parses Authentication-Results header for spf, dkim, and dmarc outcomes."""
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    if not auth_header:
        return results

    auth_header = auth_header.lower()
    
    # Simple regexes to find dkim=pass, spf=pass, etc.
    for key in ["spf", "dkim", "dmarc"]:
        match = re.search(r'\b' + key + r'=([a-z\-]+)', auth_header)
        if match:
            results[key] = match.group(1)
            
    return results

def get_abuseipdb_reputation(ip: str):
    """Queries AbuseIPDB API for IP threat parameters. Returns mock data if no key."""
    if not ip:
        return None

    if not ABUSEIPDB_API_KEY:
        return None  # Triggers mock fallback

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=5
        )
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "ip": data.get("ipAddress"),
                "abuse_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_public": data.get("isPublic"),
                "source": "AbuseIPDB Live API"
            }
    except Exception as e:
        print(f"AbuseIPDB query error: {e}")
        
    return None

def analyze_relay_chain(received_headers: list):
    """Analyzes SMTP relay path from Received headers."""
    hops = []
    for idx, header in enumerate(reversed(received_headers)):
        # Received headers list details: "from x by y with z; date"
        header_clean = " ".join(header.split())
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', header_clean)
        
        # Try to parse 'from' and 'by'
        from_match = re.search(r'from\s+([^\s\(\)]+)', header_clean, re.IGNORECASE)
        by_match = re.search(r'by\s+([^\s\(\)]+)', header_clean, re.IGNORECASE)
        
        from_node = from_match.group(1) if from_match else "Unknown"
        by_node = by_match.group(1) if by_match else "Unknown"
        hop_ip = ips[0] if ips else "Unknown"

        hops.append({
            "hop": idx + 1,
            "raw": header_clean[:120] + "...",
            "from": from_node,
            "by": by_node,
            "ip": hop_ip
        })
    return hops

def analyze_email_headers(raw_headers: str):
    """Main parsing logic for raw mail headers."""
    if not raw_headers.strip():
        return {
            "success": False,
            "error": "Empty email header input"
        }

    # Parse headers using standard email parser
    parser = HeaderParser()
    msg = parser.parsestr(raw_headers)

    # 1. Extract standard fields
    from_val = msg.get("From", "")
    to_val = msg.get("To", "")
    subject = msg.get("Subject", "")
    reply_to = msg.get("Reply-To", "")
    date_val = msg.get("Date", "")

    # Clean display emails
    from_emails = extract_emails(from_val)
    reply_emails = extract_emails(reply_to)

    sender_email = from_emails[0] if from_emails else "unknown@domain.com"
    reply_email = reply_emails[0] if reply_emails else None

    # 2. Reply-To Mismatch Detection
    mismatch_detected = False
    mismatch_details = "Match"
    if reply_email:
        # Check if domains match (at least)
        sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
        reply_domain = reply_email.split("@")[-1].lower() if "@" in reply_email else ""
        if sender_email.lower() != reply_email.lower():
            mismatch_detected = True
            mismatch_details = f"From email ({sender_email}) does not match Reply-To email ({reply_email})"

    # 3. SPF / DKIM / DMARC authentication checks
    # Extract from Received-SPF or Authentication-Results
    spf_result = "none"
    received_spf = msg.get("Received-SPF", "")
    if received_spf:
        # Received-SPF: pass (google.com: domain of test@example.com...)
        spf_match = re.match(r'^([a-z\-]+)\b', received_spf.strip().lower())
        if spf_match:
            spf_result = spf_match.group(1)

    auth_results_header = msg.get("Authentication-Results", "")
    auth_parsed = parse_auth_results(auth_results_header)

    spf_final = auth_parsed["spf"] if auth_parsed["spf"] != "unknown" else spf_result
    dkim_final = auth_parsed["dkim"]
    dmarc_final = auth_parsed["dmarc"]

    # 4. Extract Sender IP
    # Usually the first received hop ip or SPF client IP
    spf_ip_match = re.search(r'client-ip=([\d\.]+)', received_spf)
    sender_ip = spf_ip_match.group(1) if spf_ip_match else None

    received_headers = msg.get_all("Received", [])
    hops = analyze_relay_chain(received_headers)

    if not sender_ip:
        # If no client IP in SPF, try to find the earliest external IP in the relay hops
        all_hop_ips = []
        for hop in hops:
            if hop["ip"] != "Unknown":
                all_hop_ips.append(hop["ip"])
        
        # Filter external ones
        ext_ips = extract_ip_addresses(" ".join(all_hop_ips))
        if ext_ips:
            sender_ip = ext_ips[0] # The originating external node
        elif all_hop_ips:
            sender_ip = all_hop_ips[-1] # The furthest node down the line (last hop)

    if not sender_ip:
        sender_ip = "127.0.0.1" # Fallback if absolutely no IP found

    # 5. IP Reputation via AbuseIPDB
    ip_rep = get_abuseipdb_reputation(sender_ip)
    is_mock = False
    if ip_rep is None:
        is_mock = True
        # Create realistic mock data depending on IP and sender
        if sender_ip == "127.0.0.1" or sender_ip.startswith("10."):
            ip_rep = {
                "ip": sender_ip,
                "abuse_score": 0,
                "total_reports": 0,
                "country": "US",
                "isp": "Localhost Private Loopback",
                "domain": "local",
                "is_public": False,
                "source": "AbuseIPDB Simulator (Local IP)"
            }
        elif "phish" in sender_email or dmarc_final == "fail" or spf_final == "fail":
            ip_rep = {
                "ip": sender_ip,
                "abuse_score": 85,
                "total_reports": 412,
                "country": "RU",
                "isp": "Hostkey B.V.",
                "domain": "hostkey.com",
                "is_public": True,
                "source": "AbuseIPDB Simulator (Flagged Sender)"
            }
        else:
            ip_rep = {
                "ip": sender_ip,
                "abuse_score": 4,
                "total_reports": 1,
                "country": "US",
                "isp": "Google LLC",
                "domain": "google.com",
                "is_public": True,
                "source": "AbuseIPDB Simulator"
            }

    # 6. Calculate Overall Spoof Risk
    spoof_score = 0
    # Add points for authentication failures
    if spf_final in ["fail", "softfail"]:
        spoof_score += 25
    if dkim_final == "fail":
        spoof_score += 25
    if dmarc_final == "fail":
        spoof_score += 35
    
    # Add points for reply-to mismatch
    if mismatch_detected:
        spoof_score += 30

    # Add points for IP reputation
    abuse_score = ip_rep.get("abuse_score", 0)
    if abuse_score > 50:
        spoof_score += 35
    elif abuse_score > 20:
        spoof_score += 15

    # Check for empty headers/poor authentication setups
    if spf_final == "none" and dkim_final == "none" and dmarc_final == "none":
        spoof_score += 20 # Suspiciously unauthenticated

    spoof_score = min(max(spoof_score, 0), 100)

    if spoof_score >= 70:
        risk_level = "High"
    elif spoof_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "success": True,
        "headers": {
            "from": from_val,
            "to": to_val,
            "subject": subject,
            "date": date_val,
            "reply_to": reply_to
        },
        "auth_results": {
            "spf": spf_final,
            "dkim": dkim_final,
            "dmarc": dmarc_final
        },
        "mismatch": {
            "detected": mismatch_detected,
            "details": mismatch_details
        },
        "sender_ip": sender_ip,
        "ip_reputation": ip_rep,
        "relay_hops": hops,
        "spoof_score": spoof_score,
        "risk_level": risk_level,
        "mode": "Simulation" if is_mock else "Live API"
    }
