import ssl
import socket
from datetime import datetime

def check_tls(domain):
    results = {
        "is_valid": False,
        "sni_supported": False,
        "days_to_expire": 0,
        "issuer": "N/D"
    }
    try:
        context = ssl.create_default_context()
        
        # Test con SNI (Standard)
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                results["sni_supported"] = True # Se arriviamo qui, SNI funziona
                
                # Calcolo scadenza
                exp_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                results["days_to_expire"] = (exp_date - datetime.now()).days
                results["is_valid"] = results["days_to_expire"] > 0
                results["issuer"] = dict(x[0] for x in cert['issuer']).get('organizationName', 'N/D')
                results["version"] = ssock.version()
        
        return results
    except Exception as e:
        return {"error": str(e), "is_valid": False, "sni_supported": False}