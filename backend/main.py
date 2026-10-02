

def symbol_obfuscation(url: str):
    if "@" in url:
        print("the url is ignoring the given domain and treating it as a subdomain")
        return False
    return True

