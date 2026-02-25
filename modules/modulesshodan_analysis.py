import shodan
import socket
import os
from dotenv import load_dotenv

# Carichiamo l'API KEY dal file .env
load_dotenv()

# ABBIAMO CAMBIATO IL NOME DA analyze_shodan A get_shodan_data
def get_shodan_data(domain):
    try:
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            return {"error": "API Key Shodan non trovata"}
            
        api = shodan.Shodan(api_key)
        ip = socket.gethostbyname(domain)
        host = api.host(ip)
        return host
    except Exception as e:
        return {"error": str(e)}