# Security Automation Report - Week 39 (ITSX26)

## Syfte
Automatisera den första analysen av autentiserings- och webbloggar genom att extrahera IP-adresser, räkna misslyckade försök samt jämföra mot en IOC-lista utan att draga förhastade slutsatser.

## Datasetval
* **Dataset:** Dataset A (Basic)
* **Filer:** `data/auth.log`, `data/access.log`, `data/suspicious_ips.txt`

## Miljö & Körinstruktioner
* **Python-version:** Python 3.10+
* **Körning:** Körs från projektroten med följande kommando:
  ```bash
  python src/security_report.py