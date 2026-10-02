import tldextract
from urllib.parse import urlparse



test_url = "https://www.google.com@hacker-domain.xyz/login"
extracted_url = tldextract.extract(test_url)
parsed_url = urlparse(test_url)

print(parsed_url.scheme)

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

testing_url()