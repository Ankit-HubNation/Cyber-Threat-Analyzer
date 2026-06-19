import os
import re
import requests
from typing import Dict, Any, List
from dotenv import load_dotenv

load_dotenv()

HIBP_API_KEY = os.getenv("HIBP_API_KEY")

# Local database matching the Have I Been Pwned breach structure for simulation
HIBP_BREACH_REGISTRY = [
    {
        "Name": "Canva",
        "Title": "Canva",
        "Domain": "canva.com",
        "BreachDate": "2019-05-24",
        "DataClasses": ["Email addresses", "Passwords", "Usernames", "IP addresses"],
        "Description": "In May 2019, the graphic design tool website Canva suffered a data breach. The incident led to the exposure of 137 million user accounts, including email addresses, usernames, and passwords stored as bcrypt hashes.",
        "LogoPath": "https://haveibeenpwned.com/Content/Images/BreachLogos/Canva.png"
    },
    {
        "Name": "LinkedIn",
        "Title": "LinkedIn",
        "Domain": "linkedin.com",
        "BreachDate": "2016-05-17",
        "DataClasses": ["Email addresses", "Passwords"],
        "Description": "In May 2016, LinkedIn had millions of member passwords leaked on the dark web. The breach originally occurred in 2012, and compromised member email addresses and passwords hashed with SHA-1.",
        "LogoPath": "https://haveibeenpwned.com/Content/Images/BreachLogos/LinkedIn.png"
    },
    {
        "Name": "Adobe",
        "Title": "Adobe",
        "Domain": "adobe.com",
        "BreachDate": "2013-10-04",
        "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
        "Description": "In October 2013, Adobe suffered a massive data security incident. Attackers gained access to customer account details, exposing 152 million username, email, and triple-DES encrypted password records.",
        "LogoPath": "https://haveibeenpwned.com/Content/Images/BreachLogos/Adobe.png"
    },
    {
        "Name": "MySpace",
        "Title": "MySpace",
        "Domain": "myspace.com",
        "BreachDate": "2016-05-31",
        "DataClasses": ["Email addresses", "Passwords", "Usernames"],
        "Description": "In May 2016, a database of 360 million MySpace user credentials was leaked online, exposing historical login details including usernames, email addresses, and SHA-1 passwords.",
        "LogoPath": "https://haveibeenpwned.com/Content/Images/BreachLogos/MySpace.png"
    },
    {
        "Name": "Twitter",
        "Title": "Twitter",
        "Domain": "twitter.com",
        "BreachDate": "2022-07-21",
        "DataClasses": ["Email addresses", "Phone numbers", "Usernames"],
        "Description": "In 2022, a vulnerability in Twitter's API allowed malicious actors to map user email addresses and phone numbers to public usernames. A dataset of 5.4 million records was compiled.",
        "LogoPath": "https://haveibeenpwned.com/Content/Images/BreachLogos/Twitter.png"
    }
]

def validate_email(email: str) -> bool:
    """Validate email formatting via simple regex check."""
    email_regex = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return bool(re.match(email_regex, email.strip()))

def query_hibp_api(email: str) -> Dict[str, Any]:
    """Queries official HIBP v3 endpoint. Requires paid key in .env."""
    if not HIBP_API_KEY:
        return {"success": False, "error": "No HIBP API Key configured", "breaches": []}

    # HIBP v3 URL check
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email.strip()}?truncateResponse=false"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "CyberThreatAnalyzer"
    }

    try:
        response = requests.get(url, headers=headers, timeout=6)
        if response.status_code == 200:
            return {
                "success": True,
                "breaches": response.json(),
                "source": "Have I Been Pwned Live API"
            }
        elif response.status_code == 404:
            # 404 status indicates email is not pwned (clean!)
            return {
                "success": True,
                "breaches": [],
                "source": "Have I Been Pwned Live API"
            }
        elif response.status_code == 401:
            return {"success": False, "error": "Unauthorized: Invalid HIBP API Key", "breaches": []}
        elif response.status_code == 429:
            return {"success": False, "error": "Rate limit exceeded (Too Many Requests)", "breaches": []}
        else:
            return {"success": False, "error": f"API error status: {response.status_code}", "breaches": []}
    except Exception as e:
        print(f"HIBP API connection exception: {e}")
        return {"success": False, "error": f"Network exception: {str(e)}", "breaches": []}

def scan_email_osint(email: str) -> Dict[str, Any]:
    """Orchestrates OSINT data breach check via HIBP or simulation fallback."""
    email = email.strip()
    if not email:
        return {"success": False, "error": "Email address cannot be empty"}

    if not validate_email(email):
        return {"success": False, "error": "Invalid email syntax format"}

    breaches = []
    is_mock = False
    source_name = "Have I Been Pwned Live API"

    if HIBP_API_KEY:
        api_result = query_hibp_api(email)
        if api_result.get("success", False):
            breaches = api_result.get("breaches", [])
            source_name = api_result.get("source")
        else:
            is_mock = True
            source_name = f"HIBP Simulator (Fallback due to: {api_result.get('error')})"
    else:
        is_mock = True
        source_name = "Have I Been Pwned Simulator (No Key)"

    # Handle simulation mode
    if is_mock:
        username, domain = email.split("@")
        domain = domain.lower()

        if email == "admin@corporate.gov":
            # Simulate critical breached profile
            breaches = [HIBP_BREACH_REGISTRY[0], HIBP_BREACH_REGISTRY[1], HIBP_BREACH_REGISTRY[2]]
        elif email == "agent-test@police.gov" or domain in ["police.gov", "fbi.gov"]:
            # Clean profile
            breaches = []
        elif domain in ["gmail.com", "yahoo.com", "hotmail.com"]:
            # Standard common email breaches
            breaches = [HIBP_BREACH_REGISTRY[0], HIBP_BREACH_REGISTRY[4]]
        else:
            # Check length/hash for a realistic odd-even split
            # E.g. email length odd means breached, even means safe
            if len(username) % 2 != 0:
                # Mock a single breach
                breaches = [HIBP_BREACH_REGISTRY[3]]
            else:
                breaches = []

    # Compile data classes (fields compromised)
    data_classes_set = set()
    for b in breaches:
        for dc in b.get("DataClasses", []):
            data_classes_set.add(dc)
    compromised_fields = sorted(list(data_classes_set))

    # Calculate threat score
    score = 0
    breach_count = len(breaches)
    if breach_count > 0:
        score += min(breach_count * 20, 60)
        # Check if fields leaked contain passwords
        for f in compromised_fields:
            if "password" in f.lower():
                score += 25
                break
        for f in compromised_fields:
            if "phone" in f.lower() or "mobile" in f.lower():
                score += 10
                break

    score = min(max(score, 0), 100)

    if score >= 70:
        status = "Malicious"
    elif score >= 20:
        status = "Suspicious"
    else:
        status = "Safe"

    return {
        "email": email,
        "success": True,
        "found_leaks_count": len(breaches),
        "compromised_data_fields": compromised_fields,
        "breaches": breaches,
        "threat_score": score,
        "status": status,
        "mode": "Simulation" if is_mock else "Live API",
        "api_source": source_name
    }
