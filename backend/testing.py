from fastapi import APIRouter, Depends
from pydantic import BaseModel
import ipaddress
import tldextract
import Levenshtein
from urllib.parse import urlparse
from database import get_db
from sqlalchemy.orm import Session

router = APIRouter(
    prefix="/scam",
    tags=["Scam detector"]
)

class URLRequest(BaseModel):
    test_url: str

@router.post("/")
def get_risk_score(request_data: URLRequest):
    return testing_url(request_data.test_url)



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



def domain_hyphen_check(extracted_url, current_score: int):
    hyphen_count = extracted_url.domain.count("-")
    if hyphen_count > 2:
        print(f"Suspicious Hyphen Count: {hyphen_count}")
        return current_score+10
    return current_score

def sub_domain_period_check(sub_domain: str, current_score: int):
    period_count = sub_domain.count(".")
    if period_count > 2:
        print(f"Suspicious Period Count: {period_count}")
        return current_score+10
    return current_score

def tlds_check(extracted_url, current_score: int):
    suffix = extracted_url.suffix
    for extensions in CHEAP_EXTENSIONS:
        if suffix == extensions:
            print(f"Using Cheap Extension: {suffix}")
            return current_score + 15
    return current_score

def ip_address_check(test_url: str, current_score: int):
    hostname = urlparse(test_url).hostname

    try:
        ip_object = ipaddress.ip_address(hostname)

        if ip_object.is_loopback:
            return current_score

        return current_score+45

    except ValueError:
        return current_score


def homoglyph_check(extracted_url, current_score: int):
    safe_domain = extracted_url.domain.encode('idna').decode('utf-8')
    if safe_domain.startswith("xn--"):
        return current_score+50
    return current_score

def typosquatting_check(extracted_url, current_score: int):
    for domain_name in HIGH_VALUE_TARGETS:
        if extracted_url.domain == domain_name:
            continue
        raw_distance = Levenshtein.distance(extracted_url.domain, domain_name)
        max_len = max(len(extracted_url.domain), len(domain_name))

        normalized_distance = raw_distance/max_len

        if normalized_distance < 0.22:
            print(f"Typo_squatting: '{extracted_url.domain}' mimics '{domain_name}' (NLD : {normalized_distance:.2f})")
            return current_score + 35
    return current_score

def subdomain_spoofing(current_score: int, domain: str, sub_domain: str):
    word_list = sub_domain.replace("-", ".").split(".")
    for brands_domain in HIGH_VALUE_TARGETS:
        if brands_domain == domain:
            continue


        for word in word_list:
            if brands_domain == word:
                print(f" Subdomain spoofing: '{brands_domain}' found in subdomain.")
                return current_score+30
    return current_score

def protocol(parsed_url, current_score: int):
    if parsed_url.scheme == "http":
        return current_score+10
    return current_score

def symbol_obfuscation(test_url, current_score: int):
    if "@" in test_url:
        return current_score+50
    return current_score



def testing_url(test_url):
    extracted_url = tldextract.extract(test_url)
    parsed_url = urlparse(test_url)
    domain = extracted_url.domain
    sub_domain = extracted_url.subdomain
    risk_score = 0

    risk_score = domain_hyphen_check(extracted_url, risk_score)
    risk_score = tlds_check(extracted_url, risk_score)
    risk_score = ip_address_check(test_url, risk_score)
    risk_score = homoglyph_check(extracted_url, risk_score)
    risk_score = typosquatting_check(extracted_url, risk_score)
    risk_score = subdomain_spoofing(risk_score, domain, sub_domain)
    risk_score = protocol(parsed_url, risk_score)
    risk_score = symbol_obfuscation(test_url, risk_score)

    return risk_score