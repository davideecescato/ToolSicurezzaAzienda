from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
import os
from datetime import datetime

def generate_pdf(data):
    # 1. Configurazione Percorsi
    output_dir = r"C:\Users\ITS-Utente43\Desktop\ToolSicurezzaAzienda\output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    domain_name = data['domain'].replace(".", "_")
    filename = f"Audit_{domain_name}_{timestamp}.pdf"
    full_path = os.path.join(output_dir, filename)

    # 2. Setup Documento
    doc = SimpleDocTemplate(full_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # --- INTESTAZIONE ---
    elements.append(Paragraph(f"Security Audit Report: {data['domain']}", styles['Title']))
    elements.append(Paragraph(f"Data Analisi: {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles['Normal']))
    elements.append(Spacer(1, 20))

    # --- SEZIONE SCORE (Con Colore Dinamico) ---
    score = data['score']
    score_color = colors.green if score > 80 else colors.orange if score > 50 else colors.red
    elements.append(Paragraph(f"PUNTEGGIO FINALE: <font color='{score_color}' size='16'>{score}/100</font>", styles['Heading2']))
    elements.append(Spacer(1, 15))

    # --- SEZIONE INFRASTRUTTURA (Dati Shodan) ---
    elements.append(Paragraph("Dettagli Infrastruttura (Shodan):", styles['Heading3']))
    sh = data.get('shodan', {})
    
    # Creiamo una tabella per i dati Shodan se disponibili
    if isinstance(sh, dict) and "ip" in sh:
        sh_info = [
            ["Indirizzo IP", sh.get('ip', 'N/D')],
            ["Organizzazione", sh.get('organizzazione', 'N/D')],
            ["Località", f"{sh.get('citta', 'N/D')} ({sh.get('isp', 'N/D')})"],
            ["Porte Aperte", ", ".join(map(str, sh.get('ports', [])))]
        ]
        t_sh = Table(sh_info, colWidths=[120, 330])
        t_sh.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('BACKGROUND', (0,0), (0,-1), colors.whitesmoke),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        elements.append(t_sh)
    else:
        elements.append(Paragraph("Nessun dato Shodan disponibile.", styles['Italic']))
    
    elements.append(Spacer(1, 20))

    # --- SEZIONE VULNERABILITÀ (Tabella Alerts) ---
    elements.append(Paragraph("Criticità e Raccomandazioni:", styles['Heading3']))
    
    if data['alerts']:
        alert_data = [["Gravità", "Descrizione Analitica"]]
        for alert in data['alerts']:
            # Cerchiamo di capire la gravità dal testo (es: "ALTO: ...")
            severity = alert.split(":")[0] if ":" in alert else "INFO"
            msg = alert.split(":", 1)[1].strip() if ":" in alert else alert
            alert_data.append([severity, msg])

        t_alerts = Table(alert_data, colWidths=[80, 370])
        t_alerts.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(t_alerts)
    else:
        elements.append(Paragraph("✅ Nessuna vulnerabilità rilevata.", styles['Normal']))

    # --- SEZIONE DETTAGLI WEB (Cookie, SRI, ecc) ---
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("Configurazioni Web Avanzate:", styles['Heading3']))
    wh = data.get('headers', {})
    web_info = [
        ["HTTPS Redirect", "SÌ" if wh.get("HTTPS_Redirect") else "NO"],
        ["Cookie Security", "OK" if wh.get("Cookie_Security") else "DEBOLE"],
        ["SRI Integrity", "PRESENTE" if wh.get("SRI_Check") else "MANCANTE"],
        ["HSTS Policy", "ABILITATA" if wh.get("HSTS") else "DISABILITATA"]
    ]
    t_web = Table(web_info, colWidths=[150, 300])
    t_web.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 0.5, colors.grey), ('PADDING', (0,0), (-1,-1), 5)]))
    elements.append(t_web)

    # 4. Generazione Finale
    try:
        doc.build(elements)
        print(f"\n[OK] Report professionale generato in: {full_path}")
    except Exception as e:
        print(f"[!] Errore critico nella generazione PDF: {e}")