import ipaddress
import tldextract
import Levenshtein
from urllib.parse import urlparse




CHEAP_EXTENSIONS = ["xyz", "top", "tk", "ml", "pw"]


HIGH_VALUE_TARGETS = [
    "microsoft", "google", "apple", "adobe", "dropbox",
    "docusign", "we-transfer", "rackspace", "godaddy", "cisco",
    "linkedin", "facebook", "instagram", "whatsapp", "twitter",
    "discord", "telegram", "snapchat",
    "amazon", "walmart", "ebay", "alibaba", "target",
    "homedepot", "craigslist" ,"dhl", "fedex", "ups", "usps", "royalmail",
    "paypal", "chase", "wellsfargo", "bankofamerica", "citibank",
    "stripe", "square", "cashapp", "venmo", "americanexpress",
    "netflix", "spotify", "roblox", "steam", "disney","booking", "airbnb", "uber", "lyft",
    "zoom", "slack", "salesforce"
]

FREE_HOSTING_SUFFIXES = [
    "github.io", "pages.dev", "workers.dev", "vercel.app",
    "netlify.app", "web.app", "firebaseapp.com", "s3.amazonaws.com"
]

def live_database_check(test_url: str, live_db_set: set, current_score: int):
    """0(1) Memory lookup for known threats"""
    if live_db_set and test_url in live_db_set:
        return current_score + 100, "URL explicitly found in live threat intelligence database"
    return current_score



def domain_hyphen_check(extracted_url, current_score: int):
    domain_hyphen_count = extracted_url.domain.count("-")
    sub_domain_hyphen_count = extracted_url.subdomain.count("-")
    hyphen_count = domain_hyphen_count + sub_domain_hyphen_count
    if hyphen_count > 5:
        return current_score + 30, f"Suspicious Hyphen Count: {hyphen_count}"
    elif hyphen_count > 3:
        return current_score+15, f"Suspicious Hyphen Count: {hyphen_count}"
    return current_score, None

def sub_domain_period_check(sub_domain: str, current_score: int):
    period_count = sub_domain.count(".")
    if period_count > 2:
        return current_score+10, f"Suspicious Period Count: {period_count}"
    return current_score, None

def tlds_check(extracted_url, current_score: int):
    suffix = extracted_url.suffix
    if suffix in CHEAP_EXTENSIONS:
        return current_score + 25, f"Using Cheap Extensions{suffix}"
    return current_score, None

def tlds_cheap_domain_check(extracted_url, current_score: int):
    suffix = extracted_url.suffix
    if suffix in FREE_HOSTING_SUFFIXES:
        return current_score + 15, f"Using Free Hosting Services{suffix}"
    return current_score, None

def tlds_hiding_check(extracted_url, current_score: int, test_url):
    suffix = extracted_url.suffix
    if suffix in FREE_HOSTING_SUFFIXES:
        parsed_path = urlparse(test_url).path.lower()
        sub_domain = extracted_url.subdomain.lower()

        for target in HIGH_VALUE_TARGETS:
            if target in parsed_path or target in sub_domain:
                return current_score + 45, f"Target brand: {target} spoofed on free host {suffix}"
    return current_score, None


def ip_address_check(test_url: str, current_score: int):
    host_target = test_url if "//" in test_url else f"//{test_url}"
    hostname = urlparse(host_target).hostname

    try:
        ip_object = ipaddress.ip_address(hostname)

        if ip_object.is_loopback:
            return current_score, None

        return current_score+45, f"Ip Address is given instead of Domain/Subdomain: {hostname}"

    except ValueError:
        return current_score, None


def homoglyph_check(extracted_url, current_score: int):
    safe_fqdn = extracted_url.fqdn.encode('idna').decode('utf-8')
    if "xn--" in safe_fqdn:
        return current_score+65, "Using Foreign Alphabet Characters mimicking English Character"
    return current_score, None

def typosquatting_check(extracted_url, current_score: int):
    for domain_name in HIGH_VALUE_TARGETS:
        if extracted_url.domain == domain_name:
            continue
        raw_distance = Levenshtein.distance(extracted_url.domain, domain_name)
        max_len = max(len(extracted_url.domain), len(domain_name))

        if max_len == 0:
            return current_score, None

        normalized_distance = raw_distance/max_len

        if normalized_distance < 0.22:
            return current_score + 45, f"Typo_squatting: '{extracted_url.domain}' mimics '{domain_name}' (NLD : {normalized_distance:.2f})"
    return current_score, None

def subdomain_spoofing(current_score: int, domain: str, sub_domain: str):
    word_list = sub_domain.replace("-", ".").split(".")
    for brands_domain in HIGH_VALUE_TARGETS:
        if brands_domain == domain:
            continue


        for word in word_list:
            if brands_domain == word:
                return current_score+30, f" Subdomain spoofing: '{brands_domain}' found in subdomain."
    return current_score, None

def protocol(test_url, current_score: int):
    parsed_url = urlparse(test_url)
    if parsed_url.scheme == "http":
        return current_score+10, f"Using http as Protocol"
    return current_score, None

def symbol_obfuscation(test_url, current_score: int):
    if "@" in test_url:
        return current_score+65, f"Using @ inside the URL trying to hide the data"
    return current_score, None



def testing_url(test_url, live_fishing_db: set = None):
    risk_score, flag = live_database_check(test_url, live_fishing_db)
    if flag:
        return {
            "final_score" : risk_score,
            "threat_reasons" : [flag]
        }

    extracted_url = tldextract.extract(test_url)
    domain = extracted_url.domain
    sub_domain = extracted_url.subdomain
    risk_score = 0
    detected_threats = []

    risk_score, flag = sub_domain_period_check(sub_domain, risk_score)
    if flag:
        detected_threats.append(flag)

    risk_score, flag = domain_hyphen_check(extracted_url, risk_score)
    if flag:
        detected_threats.append(flag)

    risk_score, flag = tlds_check(extracted_url, risk_score)
    if flag:
        detected_threats.append(flag)

    risk_score, flag = ip_address_check(test_url, risk_score)
    if flag:
        detected_threats.append(flag)

    risk_score, flag = homoglyph_check(extracted_url, risk_score)
    if flag:
        detected_threats.append(flag)

    risk_score, flag = typosquatting_check(extracted_url, risk_score)
    if flag:
        detected_threats.append(flag)

    risk_score, flag = subdomain_spoofing(risk_score, domain, sub_domain)
    if flag:
        detected_threats.append(flag)

    risk_score, flag = protocol(test_url, risk_score)
    if flag:
        detected_threats.append(flag)

    risk_score, flag = symbol_obfuscation(test_url, risk_score)
    if flag:
        detected_threats.append(flag)

    risk_score, flag = tlds_hiding_check(extracted_url, risk_score, test_url)
    if flag:
        detected_threats.append(flag)

    risk_score, flag = tlds_cheap_domain_check(extracted_url, risk_score)
    if flag:
        detected_threats.append(flag)

    risk_score = min(risk_score, 100)

    return {
        "final_score" : risk_score,
        "threat_reasons" : detected_threats
    }

