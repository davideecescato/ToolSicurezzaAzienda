import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv 

from modules.modulesdns_analysis import check_dns
from modules.modulesshodan_analysis import get_shodan_data
from modules.modulesweb_headers_analysis import check_headers
from modules.modulesscoring import calculate_score
from modules.modulesreport_generator import generate_pdf
from modules.moduleshistory_manager import save_analysis_history
from modules.modulestls_analysis import check_tls 
# --- AGGIUNTA 1: Import del modulo Sottodomini ---
from modules.modulessubdomain_discovery import discover_subdomains 

load_dotenv()

class Theme:
    CYAN, GREEN, YELLOW, RED, MAGENTA = '\033[96m', '\033[92m', '\033[93m', '\033[91m', '\033[95m'
    BOLD, RESET, UNDERLINE = '\033[1m', '\033[0m', '\033[4m'
    SCAN, SHIELD, GLOBE, LOCK, SUCCESS, PORT = "🔍", "🛡️", "🌐", "🔒", "✅", "🔌"

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Theme.CYAN}{Theme.BOLD}╔" + "═"*60 + "╗")
    print(f"║ {Theme.MAGENTA}⚡ CYBER-SENTINEL V5.0 - SECURITY AUDIT SUITE{Theme.CYAN} ⚡ ║")
    print(f"╚" + "═"*60 + f"╝{Theme.RESET}")

def loading(text):
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    for i in range(10):
        sys.stdout.write(f"\r{Theme.YELLOW}{chars[i % len(chars)]}{Theme.RESET} {text}...")
        sys.stdout.flush()
        time.sleep(0.08)
    print(f"\r{Theme.GREEN}{Theme.SUCCESS}{Theme.RESET} {text} completato!")

def start_audit(target_domain):
    domain = target_domain.strip().lower().replace("https://", "").replace("http://", "").split('/')[0]
    print_banner()
    print(f"{Theme.CYAN}{Theme.BOLD}{Theme.SCAN} TARGET IDENTIFICATO: {Theme.UNDERLINE}{domain}{Theme.RESET}\n")

    with ThreadPoolExecutor(max_workers=5) as executor: # Aumentato a 5 workers per gestire i sottodomini
        loading("Analisi Record DNS")
        f_dns = executor.submit(check_dns, domain)
        loading("Scansione Headers Web")
        f_web = executor.submit(check_headers, domain)
        loading("Query Database Shodan")
        f_sho = executor.submit(get_shodan_data, domain)
        loading("Analisi Certificato TLS/SNI")
        f_tls = executor.submit(check_tls, domain)
        # --- AGGIUNTA 2: Esecuzione ricerca sottodomini ---
        loading("Ricerca Sottodomini Comuni")
        f_sub = executor.submit(discover_subdomains, domain)

        dns_res, web_res, sho_res, tls_res, sub_res = f_dns.result(), f_web.result(), f_sho.result(), f_tls.result(), f_sub.result()

    score, alerts = calculate_score(dns_res, web_res, sho_res)

    # DASHBOARD
    print(f"\n{Theme.BOLD}{Theme.MAGENTA}📊 RISULTATI SCANSIONE{Theme.RESET}")
    print(f"{Theme.CYAN}━"*50 + f"{Theme.RESET}")

    # Infrastruttura & Porte
    ip = sho_res.get('ip', 'N/D')
    ports = sho_res.get('ports', [])
    print(f"{Theme.GLOBE} {Theme.BOLD}Infrastruttura & Rete:{Theme.RESET}")
    print(f"   ├─ Indirizzo IP:   {Theme.GREEN}{ip}{Theme.RESET}")
    print(f"   ├─ Provider:       {sho_res.get('organizzazione', 'N/D')}")
    
    # --- AGGIUNTA 3: Visualizzazione Sottodomini ---
    sub_count = len(sub_res) if sub_res else 0
    print(f"   ├─ Sottodomini:    {Theme.CYAN}{sub_count} rilevati{Theme.RESET}")
    if sub_res:
        for s in sub_res[:3]: # Mostriamo i primi 3 per non intasare il terminale
            print(f"   │  • {s['subdomain']} ({s['ip']})")
    
    str_ports = f"{Theme.YELLOW}" + ", ".join(map(str, ports)) + f"{Theme.RESET}" if ports else f"{Theme.RED}Nessuna{Theme.RESET}"
    print(f"   └─ Porte Aperte:   {Theme.PORT} {str_ports}")

    # Sicurezza Web
    print(f"\n{Theme.LOCK} {Theme.BOLD}Security Web & TLS:{Theme.RESET}")
    redirect = f"{Theme.GREEN}SÌ{Theme.RESET}" if web_res.get("HTTPS_Redirect") else f"{Theme.RED}NO{Theme.RESET}"
    sri = f"{Theme.GREEN}OK{Theme.RESET}" if web_res.get("SRI_Check") else f"{Theme.RED}MANCANTE{Theme.RESET}"
    sni_status = f"{Theme.GREEN}SUPPORTO OK{Theme.RESET}" if tls_res.get("sni_supported") else f"{Theme.RED}NON RILEVATO{Theme.RESET}"
    
    print(f"   ├─ HTTPS Redirect: {redirect}")
    print(f"   ├─ SRI Integrity:  {sri}")
    print(f"   ├─ SNI Support:    {sni_status}")
    print(f"   └─ Cookie Sec:     {Theme.YELLOW}{web_res.get('Cookie_Security', 'N/D')}{Theme.RESET}")

    # Score
    print(f"\n{Theme.BOLD}--- [ {Theme.SHIELD} VALUTAZIONE FINALE ] ---{Theme.RESET}")
    c = Theme.GREEN if score > 75 else Theme.YELLOW if score > 50 else Theme.RED
    print(f" SCORE: {c}{Theme.BOLD}{score}/100{Theme.RESET} | AVVISI: {Theme.RED}{len(alerts)}{Theme.RESET}")
    for a in alerts[:4]: print(f" {Theme.RED}•{Theme.RESET} {a}")
    
    print(f"{Theme.CYAN}━"*50 + f"{Theme.RESET}")

    # Aggiornato report_data per includere TLS e Sottodomini
    report_data = {
        "domain": domain, 
        "dns": dns_res, 
        "headers": web_res, 
        "shodan": sho_res, 
        "tls": tls_res, 
        "subdomains": sub_res, # Aggiunto qui
        "score": score, 
        "alerts": alerts
    }
    
    generate_pdf(report_data)
    print(f"\n{Theme.GREEN}{Theme.SUCCESS} Analisi terminata. Report salvato in /output.{Theme.RESET}\n")

    save_analysis_history(domain, report_data)

if __name__ == "__main__":
    if os.name == 'nt': os.system('color')
    try:
        user_input = input(f"{Theme.BOLD}{Theme.SCAN} Inserisci dominio: {Theme.RESET}")
        if user_input: start_audit(user_input)
    except KeyboardInterrupt: print(f"\n{Theme.YELLOW}🔌 Uscita...{Theme.RESET}")