import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_ip_reputation(ip: str):
    """Main entry point to check IP details (GeoIP + AbuseIPDB)."""
    # Clean input
    ip = ip.strip()
    if not ip:
        return {"success": False, "error": "IP address is empty"}

    # 1. Geo-location & ISP (via ip-api.com - Free, no keys required)
    geo_data = {}
    try:
        geo_response = requests.get(f"http://ip-api.com/json/{ip}", timeout=4)
        if geo_response.status_code == 200:
            raw_geo = geo_response.json()
            if raw_geo.get("status") == "success":
                geo_data = {
                    "country": raw_geo.get("country"),
                    "country_code": raw_geo.get("countryCode"),
                    "region": raw_geo.get("regionName"),
                    "city": raw_geo.get("city"),
                    "zip": raw_geo.get("zip"),
                    "lat": raw_geo.get("lat"),
                    "lon": raw_geo.get("lon"),
                    "isp": raw_geo.get("isp"),
                    "org": raw_geo.get("org"),
                    "asn": raw_geo.get("as"),
                }
            else:
                # Private IP or query error
                geo_data = {
                    "error": raw_geo.get("message", "IP resolution failed"),
                    "country": "Local / Private Network" if "private" in raw_geo.get("message", "").lower() else "Unknown",
                    "isp": "Local Loopback" if ip in ["127.0.0.1", "localhost"] else "Private Subnet"
                }
    except Exception as e:
        print(f"GeoIP check failed: {e}")
        geo_data = {"error": f"Failed to reach geo provider: {str(e)}"}

    # 2. AbuseIPDB check
    abuse_data = {}
    is_mock = False
    
    if ABUSEIPDB_API_KEY:
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
                timeout=4
            )
            if response.status_code == 200:
                data = response.json().get("data", {})
                abuse_data = {
                    "abuse_score": data.get("abuseConfidenceScore"),
                    "total_reports": data.get("totalReports"),
                    "last_reported_at": data.get("lastReportedAt"),
                    "source": "AbuseIPDB Live API"
                }
        except Exception as e:
            print(f"AbuseIPDB connection failed: {e}")
            abuse_data = {"error": str(e)}

    # Fallback to Mock Data if AbuseIPDB was not queried or failed
    if not abuse_data or "error" in abuse_data:
        is_mock = True
        # If it's a private network, keep score 0
        if "Local" in geo_data.get("country", "") or ip.startswith(("10.", "192.168.", "172.16.", "127.")):
            abuse_data = {
                "abuse_score": 0,
                "total_reports": 0,
                "last_reported_at": None,
                "source": "AbuseIPDB Simulator (Local Network)"
            }
        else:
            # Generate realistic mock parameters based on some hashes of IP
            # E.g. IPs ending in odd digits are suspicious
            ip_sum = sum(int(digit) for digit in ip if digit.isdigit())
            if ip_sum % 4 == 0:  # Malicious simulation
                abuse_data = {
                    "abuse_score": 87,
                    "total_reports": 139,
                    "last_reported_at": "2026-06-18T14:22:10+00:00",
                    "source": "AbuseIPDB Simulator"
                }
            elif ip_sum % 3 == 0:  # Suspicious simulation
                abuse_data = {
                    "abuse_score": 35,
                    "total_reports": 12,
                    "last_reported_at": "2026-06-15T09:12:45+00:00",
                    "source": "AbuseIPDB Simulator"
                }
            else:  # Safe simulation
                abuse_data = {
                    "abuse_score": 0,
                    "total_reports": 0,
                    "last_reported_at": None,
                    "source": "AbuseIPDB Simulator"
                }

    # Compile final metrics
    abuse_score = abuse_data.get("abuse_score", 0)
    if abuse_score >= 50:
        status = "Malicious"
    elif abuse_score >= 15:
        status = "Suspicious"
    else:
        status = "Safe"

    return {
        "ip": ip,
        "success": True,
        "geo": geo_data,
        "reputation": abuse_data,
        "threat_score": abuse_score,
        "status": status,
        "mode": "Simulation" if is_mock else "Live API"
    }
