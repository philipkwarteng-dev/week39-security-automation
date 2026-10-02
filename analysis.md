# Säkerhetsanalys - Vecka 39 (ITSX26)

## 1. Rådata
* **Filer:** `data/auth.log`, `data/access.log` samt `data/suspicious_ips.txt`.
* **Användning:** Skriptet `security_report.py` läser loggfiler rad för rad utan att modifiera ursprungskällan.

## 2. Observation
Programmet identifierade:
* Totalt **3** misslyckade inloggningsförsök i `auth.log`.
* IP-adressen `192.168.1.50` observerades i loggarna och matchade en post i `suspicious_ips.txt`.
* Skriptet identifierade och hoppade över **2** korrupta rader på grund av formatfel.

## 3. Slutsats
IP-adressen `192.168.1.50` uppvisar misslyckade inloggningsförsök och förekommer på en indikatorlista. Det finns underlag för att granska adressen närmare.

## 4. Osäkerhet
Data och skript kan **inte** fastställa om detta är ett intrångsförsök eller om användaren knappade fel lösenord. Skriptet analyserar inte händelsesekvenser eller sessionstillstånd över tid.

## 5. Alternativ förklaring
* **Legitim användare:** En behörig användare som skrivit fel lösenord.
* **Gammal IOC-lista:** IP-adressen kan vara en dynamisk adress som tidigare tillhört en elakartad aktör men nu tilldelats en legitim användare.

## 6. Säkerhetsbetydelse
Resultatet fungerar som ett underlag för prioritering i SOC. Istället för att blockera IP-adressen direkt bör analytikern kontrollera om adressen lyckades logga in senare eller nådde känsliga resurser.
