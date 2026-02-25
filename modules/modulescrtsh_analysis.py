import requests

def analyze_crtsh(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return r.json()
        else:
            return {"error": f"Status code {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}