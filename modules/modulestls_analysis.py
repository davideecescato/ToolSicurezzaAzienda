import ssl
import socket

def analyze_tls(domain):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": cert.get("issuer"),
                    "notAfter": cert.get("notAfter"),
                    "version": ssock.version()
                }
    except Exception as e:
        return {"error": str(e)}