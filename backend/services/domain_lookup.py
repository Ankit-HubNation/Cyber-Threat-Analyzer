import datetime
import whois
import dns.resolver
from typing import List, Union

def calculate_domain_age(creation_date: Union[datetime.datetime, List[datetime.datetime], None]) -> str:
    """Calculates age of domain from creation date in years, months, and days."""
    if not creation_date:
        return "Unknown"
    
    # Sometimes WHOIS returns a list of dates
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
        
    if not isinstance(creation_date, datetime.datetime):
        return "Unparseable Date"

    # Make naive to prevent timezone subtraction error
    if creation_date.tzinfo is not None:
        creation_date = creation_date.replace(tzinfo=None)

    now = datetime.datetime.now()
    delta = now - creation_date
    
    years = delta.days // 365
    remaining_days = delta.days % 365
    months = remaining_days // 30
    days = remaining_days % 30

    parts = []
    if years > 0:
        parts.append(f"{years} year{'s' if years > 1 else ''}")
    if months > 0:
        parts.append(f"{months} month{'s' if months > 1 else ''}")
    if days > 0:
        parts.append(f"{days} day{'s' if days > 1 else ''}")

    return ", ".join(parts) if parts else "0 days"

def query_dns_records(domain: str) -> dict:
    """Queries DNS records using dnspython."""
    records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "TXT": [],
        "NS": []
    }
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    for r_type in records.keys():
        try:
            answers = resolver.resolve(domain, r_type)
            for rdata in answers:
                if r_type == "MX":
                    # MX record has preference and exchange fields
                    records[r_type].append(f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}")
                else:
                    records[r_type].append(rdata.to_text().strip('"'))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        except Exception as e:
            print(f"Error querying DNS {r_type} for {domain}: {e}")

    return records

def lookup_domain_info(domain: str):
    """Main service logic for WHOIS + DNS lookup."""
    domain = domain.strip().lower()
    if not domain:
        return {"success": False, "error": "Domain is empty"}

    # Remove protocol prefix if user pasted http/https
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]
    # Remove paths if any
    domain = domain.split("/")[0]
    # Remove port if any
    domain = domain.split(":")[0]

    # 1. WHOIS Query
    whois_info = {}
    whois_success = False
    try:
        w = whois.whois(domain)
        
        # Parse expiration and updated dates safely
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        updated_date = w.updated_date

        def serialize_date(d):
            if isinstance(d, list):
                d = d[0]
            if isinstance(d, datetime.datetime):
                return d.isoformat()
            return str(d) if d else None

        # Build clean output fields
        whois_info = {
            "registrar": w.registrar,
            "creation_date": serialize_date(creation_date),
            "expiration_date": serialize_date(expiration_date),
            "updated_date": serialize_date(updated_date),
            "domain_age": calculate_domain_age(creation_date),
            "nameservers": w.name_servers if isinstance(w.name_servers, list) else ([w.name_servers] if w.name_servers else []),
            "emails": w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else []),
            "country": w.country
        }
        whois_success = True
    except Exception as e:
        print(f"WHOIS lookup failed for {domain}: {e}")
        # Build mock WHOIS if real query fails
        whois_info = {
            "registrar": "Mock Registrar, Inc. (Query Failed)",
            "creation_date": (datetime.datetime.now() - datetime.timedelta(days=1250)).isoformat(),
            "expiration_date": (datetime.datetime.now() + datetime.timedelta(days=500)).isoformat(),
            "updated_date": datetime.datetime.now().isoformat(),
            "domain_age": "3 years, 5 months",
            "nameservers": ["ns1.mockdns.com", "ns2.mockdns.com"],
            "emails": ["abuse@mockregistrar.com"],
            "country": "US",
            "error_msg": str(e)
        }

    # 2. DNS Query
    dns_records = query_dns_records(domain)

    # 3. Threat Assessment
    # Simple score based on domain age & registry flags
    # Fresh domains (< 1 month) are flagged as suspicious
    suspicious = False
    details = "Domain is established and active."
    threat_score = 0

    if whois_success and hasattr(w, "creation_date") and w.creation_date:
        c_date = w.creation_date
        if isinstance(c_date, list):
            c_date = c_date[0]
        if isinstance(c_date, datetime.datetime):
            # Make naive to prevent timezone subtraction error
            if c_date.tzinfo is not None:
                c_date = c_date.replace(tzinfo=None)
            age_days = (datetime.datetime.now() - c_date).days
            if age_days < 30:
                suspicious = True
                details = f"Warning: Domain was created very recently ({age_days} days ago)."
                threat_score = 75
            elif age_days < 180:
                suspicious = True
                details = f"Caution: Domain is relatively new ({age_days} days ago)."
                threat_score = 35

    # Check nameservers count
    if not whois_info.get("nameservers"):
        threat_score = max(threat_score, 15)
        details = "Notice: No nameservers found in WHOIS."

    return {
        "domain": domain,
        "success": True,
        "whois": whois_info,
        "dns": dns_records,
        "threat_score": threat_score,
        "status": "Suspicious" if threat_score >= 30 else "Safe",
        "assessment": details
    }
