import tldextract



test_url = "https://www.google.com@hacker-domain.xyz/login"
extracted_url = tldextract.extract(test_url)

def symbol_obfuscation():
    if "@" in test_url:
        return False
    return True

def testing_url():
    if not symbol_obfuscation():
        print("the url is ignoring the given domain and treating it as a subdomain")

testing_url()