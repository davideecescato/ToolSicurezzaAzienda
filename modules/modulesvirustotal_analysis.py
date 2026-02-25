import requests
import os

def analyze_virustotal(domain):
    headers = {
        "x-apikey": os.getenv("VT_API_KEY")
    }
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        r = requests.get(url, headers=headers, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}