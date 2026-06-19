import pprint
from services.url_scanner import scan_url
from services.email_analyzer import analyze_email_headers
from services.ip_checker import check_ip_reputation
from services.domain_lookup import lookup_domain_info

def run_tests():
    print("==================================================")
    print("      CYBER THREAT ANALYZER - BACKEND TESTING     ")
    print("==================================================\n")

    # 1. URL Scanner Tests
    print("--- Testing URL Threat Scanner (Safe & Phishing Cases) ---")
    safe_url_res = scan_url("google.com")
    print(f"Safe URL Scan (google.com) - Threat Score: {safe_url_res['threat_score']}, Status: {safe_url_res['status']}")
    
    phish_url_res = scan_url("http://paypal-signin-verify.secure-phish.xyz/login/verify.html")
    print(f"Phish URL Scan (suspicious) - Threat Score: {phish_url_res['threat_score']}, Status: {phish_url_res['status']}")
    print("Heuristics flagged:")
    pprint.pprint(phish_url_res['heuristics'])
    print("\n" + "="*50 + "\n")

    # 2. IP Checker Tests
    print("--- Testing IP Reputation (Public IP: 8.8.8.8) ---")
    ip_res = check_ip_reputation("8.8.8.8")
    print(f"IP Rep Status: {ip_res['status']}, Geo Country: {ip_res['geo'].get('country')}, ISP: {ip_res['geo'].get('isp')}")
    print(f"Abuse score: {ip_res['reputation'].get('abuse_score')}%")
    print("\n" + "="*50 + "\n")

    # 3. Domain Intelligence Lookup
    print("--- Testing Domain Lookup (github.com) ---")
    domain_res = lookup_domain_info("github.com")
    print(f"Domain lookup success: {domain_res['success']}, Age: {domain_res['whois'].get('domain_age')}")
    print("DNS Record types resolved:")
    for record_type, records in domain_res['dns'].items():
        print(f"  {record_type}: {records[:3]} (total {len(records)})")
    print("\n" + "="*50 + "\n")

    # 4. Email Header Analysis
    print("--- Testing Email Header Parser (Mock Spoofed Header) ---")
    fake_header = """Delivered-To: victim@target.com
Received: from mail-issuer.hackerdomain.net (unknown [198.51.100.42])
	by mx.google.com with ESMTPS id abc123xyz
	for <victim@target.com>
	(version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
	Fri, 19 Jun 2026 11:15:30 +0530
Authentication-Results: mx.google.com;
       dkim=fail header.i=@legit-bank.com;
       spf=fail (google.com: domain of support@legit-bank.com does not designate 198.51.100.42 as permitted sender) smtp.mailfrom=support@legit-bank.com;
       dmarc=fail (p=REJECT sp=REJECT) header.from=legit-bank.com
From: "Legit Support Team" <support@legit-bank.com>
To: victim@target.com
Reply-To: phisher-reply@scam-center.ru
Subject: Immediate security action required!
Received-SPF: fail (google.com: domain of support@legit-bank.com does not designate 198.51.100.42 as permitted sender)
"""
    email_res = analyze_email_headers(fake_header)
    print(f"Spoof Analysis status: {email_res['success']}")
    print(f"Calculated Spoof Risk Score: {email_res['spoof_score']} ({email_res['risk_level']} Risk)")
    print(f"Sender IP Extracted: {email_res['sender_ip']}")
    print(f"From vs Reply-To Mismatch Detected: {email_res['mismatch']['detected']}")
    print(f"Mismatch Details: {email_res['mismatch']['details']}")
    print(f"Authentication Checks: SPF={email_res['auth_results']['spf']}, DKIM={email_res['auth_results']['dkim']}, DMARC={email_res['auth_results']['dmarc']}")
    print("Traced Relays:")
    pprint.pprint(email_res['relay_hops'])
    print("\n==================================================")
    print("               TEST RUN COMPLETE                  ")
    print("==================================================")

if __name__ == "__main__":
    run_tests()
