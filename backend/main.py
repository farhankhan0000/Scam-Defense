import tldextract
import Levenshtein
from urllib.parse import urlparse
import ipaddress



test_url = "https://secure-account-verification-update-now.com/login"
extracted_url = tldextract.extract(test_url)
parsed_url = urlparse(test_url)




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

def tlds_check(extracted_url: str):
    suffix = extracted_url.suffix
    for extensions in CHEAP_EXTENSIONS:
        if suffix == extensions:
            return False

    return True

def ip_address_check(test_url: str):
    hostname = urlparse(test_url).hostname

    try:
        ip_object = ipaddress.ip_address(hostname)

        if ip_object.is_loopback:
            return True

        return False

    except ValueError:
        return True


def homoglyph_check():
    safe_domain = extracted_url.domain.encode('idna').decode('utf-8')
    if safe_domain.startswith("xn--"):
        return False
    return True

def typosquatting_check():
    for domain_name in HIGH_VALUE_TARGETS:
        distance = Levenshtein.distance(extracted_url.domain, domain_name)
        if distance in [1,2]:
            return False
    return True

def subdomain_spoofing():
    for brands_domain in HIGH_VALUE_TARGETS:
        if brands_domain in extracted_url.subdomain:
            return False
    return True

def protocol():
    if parsed_url.scheme == "http":
        return False
    return True

def symbol_obfuscation():
    if "@" in test_url:
        return False
    return True



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



testing_url()