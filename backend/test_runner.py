import requests


print("Fetching live Scam URLs...")
response = requests.get("https://openphish.com/feed.txt")
scam_urls = response.text.splitlines()[:10]

grey_zone_targets = [
    "http://secure-billing-update.vercel.app",
    "https://www.netflix-login-portal.xyz",
    "https://account-verify-support-portal.github.io",
    "http://www.apple.com.secure-update.top"
]

# for url in scam_urls:
#     try:
#         res = requests.post(
#             "http://127.0.0.1:8000/scam",
#             json={"test_url" : url}
#         )
#         print(f"Target {url}")
#         print(f"API Response: {res.json()}\n")
#
#     except requests.exceptions.ConnectionError:
#         print("Error: Make sure Your FastAPI server is running")
#         break


for url in grey_zone_targets:
    try:
        res = requests.post(
            "http://127.0.0.1:8000/scam",
            json={"test_url" : url}
        )
        print(f"Target {url}")
        print(f"API Response: {res.json()}\n")

    except requests.exceptions.ConnectionError:
        print("Error: Make sure Your FastAPI server is running")
        break