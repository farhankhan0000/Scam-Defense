import requests


print("Fetching live Scam URLs...")
response = requests.get("https://openphish.com/feed.txt")
scam_urls = response.text.splitlines()[:10]

for url in scam_urls:
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

