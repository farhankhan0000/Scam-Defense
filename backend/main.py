import tldextract
import Levenshtein
from urllib.parse import urlparse
import ipaddress



test_url = "https://secure-account-verification-update-now.com/login"
extracted_url = tldextract.extract(test_url)
parsed_url = urlparse(test_url)


risk_score = 0


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

def domain_hyphen_check(extracted_url: str, current_score: int):
    if extracted_url.domain.count("-") > 2:
        return False
    return True

def tlds_check(extracted_url: str, current_score: int):
    suffix = extracted_url.suffix
    for extensions in CHEAP_EXTENSIONS:
        if suffix == extensions:
            return False

    return True

def ip_address_check(test_url: str, current_score: int):
    hostname = urlparse(test_url).hostname

    try:
        ip_object = ipaddress.ip_address(hostname)

        if ip_object.is_loopback:
            return current_score

        return current_score+45

    except ValueError:
        return current_score


def homoglyph_check(current_score: int):
    safe_domain = extracted_url.domain.encode('idna').decode('utf-8')
    if safe_domain.startswith("xn--"):
        return current_score+50
    return current_score

def typosquatting_check(current_score: int):
    for domain_name in HIGH_VALUE_TARGETS:
        raw_distance = Levenshtein.distance(extracted_url.domain, domain_name)
        max_len = max(len(extracted_url.domain), len(domain_name))

        normalized_distance = raw_distance/max_len

        if normalized_distance < 0.22:
            print(f"Typo_squatting: '{extracted_url.domain}' mimics '{domain_name}' (NLD : {normalized_distance:.2f})")
            return current_score + 35
        return current_score

def subdomain_spoofing(current_score: int):
    for brands_domain in HIGH_VALUE_TARGETS:
        if brands_domain in extracted_url.subdomain:
            return False
    return True

def protocol(current_score: int):
    if parsed_url.scheme == "http":
        return False
    return True

def symbol_obfuscation(current_score: int):
    if "@" in test_url:
        return current_score+50
    return current_score



def testing_url():
    if not symbol_obfuscation():
        print("the url is ignoring the given domain and treating it as a subdomain")

    if not protocol():
        print("the url is not legitimate")

    if not subdomain_spoofing():
        print("the url is scam")

    if not homoglyph_check():
        print("the url is not using standard english")

    if not typosquatting_check():
        print("the url is fake one")

    if not ip_address_check(test_url):
        print("the url has raw ip address therefore its a scam")

    if not tlds_check(extracted_url):
        print("the url is a cheap one so its a scam")

    if not domain_hyphen_check(extracted_url):
        print("the domain contains alot of hyphen so its a scam")

testing_url()