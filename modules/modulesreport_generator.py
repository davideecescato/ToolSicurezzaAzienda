from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import os
from datetime import datetime

def generate_pdf(data):
    # 1. Definiamo il percorso della cartella output
    output_dir = r"C:\Users\ITS-Utente43\Desktop\ToolSicurezzaAzienda\output"
    
    # 2. Creiamo la cartella se non esiste
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"[*] Cartella {output_dir} creata.")

    # 3. Creiamo un nome file mnemonico: Report_google.com_20240520_1530.pdf
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    domain_name = data['domain'].replace(".", "_")
    filename = f"Report_{domain_name}_{timestamp}.pdf"
    
    # Percorso completo per il salvataggio
    full_path = os.path.join(output_dir, filename)
    
    # 4. Generazione del PDF
    doc = SimpleDocTemplate(full_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Contenuto del PDF
    elements.append(Paragraph(f"Analisi di Sicurezza: {data['domain']}", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Data Analisi: {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles['Normal']))
    elements.append(Paragraph(f"Punteggio Finale: {data['score']}/100", styles['Heading2']))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Vulnerabilità e Criticità Rilevate:", styles['Heading3']))
    for alert in data['alerts']:
        elements.append(Paragraph(f"• {alert}", styles['Normal']))
    
    try:
        doc.build(elements)
        print(f"\n[OK] Report salvato con successo in: {full_path}")
    except Exception as e:
        print(f"[!] Errore critico durante il salvataggio del PDF: {e}")