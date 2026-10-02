import os
import re

# Sökvägar baserade på projektroten
DATA_DIR = "data"
OUTPUT_DIR = "output"
REPORT_PATH = os.path.join(OUTPUT_DIR, "security_report.txt")

def load_suspicious_ips(filepath):
    """Läser in lista över misstänkta IP-adresser."""
    suspicious = set()
    if not os.path.exists(filepath):
        return suspicious
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()
            if ip and not ip.startswith("#"):
                suspicious.add(ip)
    return suspicious

def parse_auth_log(filepath):
    """Analyserar auth.log efter misslyckade inloggningar och IP-adresser."""
    failed_logins = 0
    extracted_ips = set()
    corrupt_lines = 0

    if not os.path.exists(filepath):
        return failed_logins, extracted_ips, corrupt_lines

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            # Formatfel: Raden har för få ord för att vara en giltig loggrad
            if len(line.split()) < 4:
                corrupt_lines += 1
                continue

            # Räkna mönster
            if "Failed password" in line or "AUTHENTICATION_FAILURE" in line:
                failed_logins += 1

            # Extrahera IP med Regex
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            if ip_match:
                extracted_ips.add(ip_match.group(0))

    return failed_logins, extracted_ips, corrupt_lines

def parse_access_log(filepath):
    """Analyserar access.log efter käll-IPs och HTTP 401/403-svar."""
    extracted_ips = set()
    http_errors = 0
    corrupt_lines = 0

    if not os.path.exists(filepath):
        return extracted_ips, http_errors, corrupt_lines

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 4:
                corrupt_lines += 1
                continue

            ip = parts[0]
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                extracted_ips.add(ip)

            if " 401 " in line or " 403 " in line:
                http_errors += 1

    return extracted_ips, http_errors, corrupt_lines

def generate_report():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    suspicious_ips = load_suspicious_ips(os.path.join(DATA_DIR, "suspicious_ips.txt"))
    failed_logins, auth_ips, auth_corrupt = parse_auth_log(os.path.join(DATA_DIR, "auth.log"))
    web_ips, http_errors, web_corrupt = parse_access_log(os.path.join(DATA_DIR, "access.log"))

    all_observed_ips = sorted(list(auth_ips.union(web_ips)))
    matched_ips = sorted(list(set(all_observed_ips).intersection(suspicious_ips)))

    report_content = f"""========================================
ITSX26 - AUTOMATED SECURITY REPORT
========================================
Datakällor analyserade:
- data/auth.log
- data/access.log
- data/suspicious_ips.txt

Mönster och Statistik:
- Misslyckade autentiseringsförsök (auth.log): {failed_logins}
- HTTP 401/403 Felkoder (access.log): {http_errors}
- Totalt antal korrupta/överhoppade rader: {auth_corrupt + web_corrupt}

IP-Analys:
- Unika observerade IP-adresser: {len(all_observed_ips)} ({', '.join(all_observed_ips)})
- Träffar mot indikatorlista (suspicious_ips.txt): {len(matched_ips)}
- Matched IPs: {', '.join(matched_ips) if matched_ips else 'Inga'}

Begränsning:
Detta skript identifierar endast enkel mönstermatchning. En träff mot 
indikatorlistan innebär inte en bekräftad incident, utan kräver vidare manuell verifiering.
========================================
"""

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"Rapport genererad i: {REPORT_PATH}")

if __name__ == "__main__":
    generate_report()