import requests

# CAMBIATO DA analyze_headers A check_headers
def check_headers(domain):
    try:
        # Aggiungiamo verify=False per evitare errori con certificati self-signed
        r = requests.get(f"https://{domain}", timeout=5, verify=False)
        headers = r.headers
        return {
            "HSTS": headers.get("Strict-Transport-Security"),
            "CSP": headers.get("Content-Security-Policy"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options")
        }
    except Exception as e:
        return {"error": str(e)}