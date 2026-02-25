import os
import json
from datetime import datetime


def save_analysis_history(domain, data):

    # Crea la cartella "history" se non esiste già
    os.makedirs("history", exist_ok=True)

    # Genera timestamp nel formato YYYYMMDD_HHMMSS
    # Serve per evitare sovrascritture e tracciare quando è stata fatta l’analisi
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Costruisce il nome file usando dominio + timestamp
    # I punti nel dominio vengono sostituiti con "_" per sicurezza
    filename = f"history/{domain.replace('.', '_')}_{timestamp}.json"

    # Salva i dati dell’analisi in formato JSON con indentazione leggibile
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

    # Stampa a console il percorso del file salvato
    print("Storico salvato in:", filename)