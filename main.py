import json
from dotenv import load_dotenv 
from modules.modulesdns_analysis import check_dns
from modules.modulesshodan_analysis import get_shodan_data
from modules.modulesweb_headers_analysis import check_headers
from modules.modulesscoring import calculate_score
from modules.modulesreport_generator import generate_pdf

load_dotenv() # Carica l'API Key dal file .env

def start_audit(target_domain):
    print(f"--- Analisi avviata per: {target_domain} ---")
    
    # 1. Analisi DNS
    dns_results = check_dns(target_domain)
    
    # 2. Web Headers
    header_results = check_headers(target_domain)
    
    # 3. Shodan (usiamo un IP di esempio o risolviamo il dominio)
    # Per semplicità qui usiamo l'analisi Shodan sul dominio
    shodan_results = get_shodan_data(target_domain)
    
    # 4. Calcolo Punteggio
    final_score, alerts = calculate_score(dns_results, header_results, shodan_results)
    
    # Report Finale
    report_data = {
        "domain": target_domain,
        "dns": dns_results,
        "headers": header_results,
        "shodan": shodan_results,
        "score": final_score,
        "alerts": alerts
    }
    
    # Export JSON e PDF
    with open("results.json", "w") as f:
        json.dump(report_data, f, indent=4)
    
    generate_pdf(report_data)
    print(f"Analisi completata. Score: {final_score}/100")

if __name__ == "__main__":
    domain = input("Inserisci il dominio da analizzare (es. google.com): ")
    start_audit(domain)