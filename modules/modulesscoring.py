def calculate_score(dns_results, header_results, shodan_results):
    score = 100
    alerts = []

    # DNS
    if dns_results.get("spf") in ["Non trovato", "Mancante"]:
        score -= 20
        alerts.append("CRITICO: SPF mancante (rischio spoofing email).")

    # Web
    if not header_results.get("HTTPS_Redirect"):
        score -= 15
        alerts.append("ALTO: Il sito non reindirizza su HTTPS.")
    if not header_results.get("SRI_Check"):
        score -= 5
        alerts.append("BASSO: SRI non rilevato negli script esterni.")
    if not header_results.get("X-Frame-Options"):
        score -= 5
        alerts.append("BASSO: X-Frame-Options mancante (Clickjacking).")

    # Shodan (Porte Pericolose)
    ports = shodan_results.get("ports", [])
    danger = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP"}
    for p in ports:
        if p in danger:
            score -= 20
            alerts.append(f"CRITICO: Porta {p} ({danger[p]}) esposta su internet!")

    return max(0, score), alerts