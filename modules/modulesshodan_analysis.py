import shodan
import socket
import os

def get_shodan_data(domain):
    try:
        api = shodan.Shodan(os.getenv("SHODAN_API_KEY"))
        ip_address = socket.gethostbyname(domain)
        host = api.host(ip_address)
        
        return {
            "ip": ip_address,
            "organizzazione": host.get('org', 'N/D'),
            "citta": host.get('city', 'N/D'),
            "isp": host.get('isp', 'N/D'),
            "ports": host.get('ports', []),
            "os": host.get('os', 'N/D')
        }
    except Exception as e:
        try:
            return {"ip": socket.gethostbyname(domain), "ports": [], "organizzazione": "N/D (Non in Shodan)"}
        except:
            return {"ip": "N/D", "ports": [], "organizzazione": "Errore DNS"}