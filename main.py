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

    with ThreadPoolExecutor(max_workers=3) as executor:
        loading("Analisi Record DNS")
        f_dns = executor.submit(check_dns, domain)
        loading("Scansione Headers Web")
        f_web = executor.submit(check_headers, domain)
        loading("Query Database Shodan")
        f_sho = executor.submit(get_shodan_data, domain)

        dns_res, web_res, sho_res = f_dns.result(), f_web.result(), f_sho.result()

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
    str_ports = f"{Theme.YELLOW}" + ", ".join(map(str, ports)) + f"{Theme.RESET}" if ports else f"{Theme.RED}Nessuna{Theme.RESET}"
    print(f"   └─ Porte Aperte:   {Theme.PORT} {str_ports}")

    # Sicurezza Web
    print(f"\n{Theme.LOCK} {Theme.BOLD}Security Web:{Theme.RESET}")
    redirect = f"{Theme.GREEN}SÌ{Theme.RESET}" if web_res.get("HTTPS_Redirect") else f"{Theme.RED}NO{Theme.RESET}"
    sri = f"{Theme.GREEN}OK{Theme.RESET}" if web_res.get("SRI_Check") else f"{Theme.RED}MANCANTE{Theme.RESET}"
    print(f"   ├─ HTTPS Redirect: {redirect}")
    print(f"   ├─ SRI Integrity:  {sri}")
    print(f"   └─ Cookie Sec:     {Theme.YELLOW}{web_res.get('Cookie_Security', 'N/D')}{Theme.RESET}")

    # Score
    print(f"\n{Theme.BOLD}--- [ {Theme.SHIELD} VALUTAZIONE FINALE ] ---{Theme.RESET}")
    c = Theme.GREEN if score > 75 else Theme.YELLOW if score > 50 else Theme.RED
    print(f" SCORE: {c}{Theme.BOLD}{score}/100{Theme.RESET} | AVVISI: {Theme.RED}{len(alerts)}{Theme.RESET}")
    for a in alerts[:4]: print(f" {Theme.RED}•{Theme.RESET} {a}")
    
    print(f"{Theme.CYAN}━"*50 + f"{Theme.RESET}")

    report_data = {"domain": domain, "dns": dns_res, "headers": web_res, "shodan": sho_res, "score": score, "alerts": alerts}
    generate_pdf(report_data)
    print(f"\n{Theme.GREEN}{Theme.SUCCESS} Analisi terminata. Report salvato in /output.{Theme.RESET}\n")

if __name__ == "__main__":
    if os.name == 'nt': os.system('color')
    try:
        user_input = input(f"{Theme.BOLD}{Theme.SCAN} Inserisci dominio: {Theme.RESET}")
        if user_input: start_audit(user_input)
    except KeyboardInterrupt: print(f"\n{Theme.YELLOW}🔌 Uscita...{Theme.RESET}")