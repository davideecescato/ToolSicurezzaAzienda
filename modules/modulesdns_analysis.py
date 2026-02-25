import dns.resolver

def check_dns(domain):
    results = {"spf": "Mancante", "dmarc": "Mancante", "cnames": []}
    
    try:
        # Risoluzione record TXT per SPF
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if "v=spf1" in str(rdata):
                results["spf"] = str(rdata)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass

    try:
        # Risoluzione record TXT per DMARC
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in dmarc_answers:
            if "v=DMARC1" in str(rdata):
                results["dmarc"] = str(rdata)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass

    return results