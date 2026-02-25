import requests

def check_headers(domain):
    results = {"HTTPS_Redirect": False, "SRI_Check": False, "Cookie_Security": True, "Cache_History": None}
    try:
        # 1. Redirect HTTP -> HTTPS
        try:
            r_http = requests.get(f"http://{domain}", timeout=5, allow_redirects=True)
            results["HTTPS_Redirect"] = r_http.url.startswith("https://")
        except: pass

        # 2. Analisi Headers su HTTPS
        r = requests.get(f"https://{domain}", timeout=5, verify=False)
        results["SRI_Check"] = "integrity=" in r.text.lower()
        results["Cache_History"] = r.headers.get("Cache-Control")
        results["HSTS"] = r.headers.get("Strict-Transport-Security")
        results["X-Frame-Options"] = r.headers.get("X-Frame-Options")

        # 3. Cookie (Secure & HttpOnly)
        if not r.cookies:
            results["Cookie_Security"] = "Nessun Cookie"
        else:
            for cookie in r.cookies:
                if not cookie.secure:
                    results["Cookie_Security"] = False
                    break
        return results
    except:
        return results