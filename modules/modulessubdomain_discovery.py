import socket
from concurrent.futures import ThreadPoolExecutor

def check_subdomain(domain, sub):
    target = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(target)
        return {"subdomain": target, "ip": ip}
    except socket.gaierror:
        return None

def discover_subdomains(domain):
    # Lista rapida di sottodomini comuni
    common_subs = ['www', 'mail', 'remote', 'blog', 'test', 'dev', 'api', 'vpn', 'cloud', 'shop']
    found = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = [executor.submit(check_subdomain, domain, sub) for sub in common_subs]
        for f in results:
            res = f.result()
            if res:
                found.append(res)
    return found