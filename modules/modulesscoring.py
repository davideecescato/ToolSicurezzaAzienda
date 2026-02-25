def calculate_score(dns_results, header_results, shodan_results):
    score = 100
    alerts = []

    # 1. Controllo DNS
    if dns_results.get("spf") == "Non trovato" or dns_results.get("spf") == "Mancante":
        score -= 20
        alerts.append("CRITICO: SPF mancante (rischio spoofing email).")
    
    if dns_results.get("dmarc") == "Non trovato" or dns_results.get("dmarc") == "Mancante":
        score -= 10
        alerts.append("MEDIO: DMARC mancante.")

    # 2. Controllo Web Headers
    # Se HSTS o X-Frame-Options sono None (mancanti), abbassiamo il punteggio
    if not header_results.get("HSTS"):
        score -= 10
        alerts.append("BASSO: HSTS non abilitato (rischio attacchi Man-in-the-Middle).")
    
    if not header_results.get("X-Frame-Options"):
        score -= 5
        alerts.append("BASSO: X-Frame-Options mancante (rischio Clickjacking).")

    # 3. Controllo Shodan
    # Se shodan_results è una lista di porte o un dizionario con errori
    if isinstance(shodan_results, list):
        for match in shodan_results:
            port = match.get('port')
            if port in [21, 23, 3389, 445]: # Porte pericolose
                score -= 20
                alerts.append(f"ALTO: Rilevata porta pericolosa aperta: {port}")
    elif isinstance(shodan_results, dict) and "error" not in shodan_results:
        # Se Shodan restituisce l'oggetto host direttamente
        for port in shodan_results.get('ports', []):
            if port in [21, 23, 3389, 445]:
                score -= 20
                alerts.append(f"ALTO: Porta critica {port} aperta.")

    # Assicuriamoci che lo score non vada sotto zero
    final_score = max(0, score)
    
    return final_score, alerts