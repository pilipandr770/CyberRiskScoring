"""
Evergreen blog topic definitions — 60 NIS2 / Cybersecurity topics.

Each topic is a dict with:
  title         — German article title (H1 / SEO title base)
  category_slug — URL-friendly category label for tagging
  tags          — list of tag names (max 5)
  keywords      — target SEO keywords string
  nis2_ref      — relevant BSIG paragraph(s)
  outline       — brief outline hints for the AI writer
"""

EVERGREEN_TOPICS: list[dict] = [

    # ── NIS2 Grundlagen (12) ──────────────────────────────────────────────────
    {
        'title': 'NIS2-Betroffenheitsprüfung 2025: Fällt Ihr Unternehmen unter die Richtlinie?',
        'category_slug': 'nis2-grundlagen',
        'tags': ['NIS2', 'Betroffenheit', 'BSIG', 'KMU'],
        'keywords': 'NIS2 Betroffenheitsprüfung Unternehmen Deutschland 2025',
        'nis2_ref': '§3 NIS2UmsuCG',
        'outline': 'Sektoren (Anlage 1 & 2), Größenkriterien (50+ MA, 10 Mio. €), '
                   'wesentliche vs. wichtige Einrichtungen, interaktiver Selbsttest, '
                   'Konsequenzen bei Nichterfüllung (Bußgeld §65 BSIG)',
    },
    {
        'title': 'Die 10 Pflichtmaßnahmen nach §30 BSIG im Detail erklärt',
        'category_slug': 'nis2-grundlagen',
        'tags': ['NIS2', '§30 BSIG', 'Pflichtmaßnahmen', 'ISMS'],
        'keywords': 'NIS2 Pflichtmaßnahmen §30 BSIG Unternehmen Überblick',
        'nis2_ref': '§30 Abs. 2 BSIG',
        'outline': 'Alle 10 Nrn. §30 Abs. 2 einzeln erläutert, Umsetzungsaufwand je Maßnahme, '
                   'Priorisierungsempfehlung für KMU, Checkliste zum Download',
    },
    {
        'title': 'BSI-Registrierungspflicht: Schritt-für-Schritt-Anleitung 2025',
        'category_slug': 'nis2-grundlagen',
        'tags': ['BSI', 'Registrierung', 'NIS2', 'Meldepflicht'],
        'keywords': 'BSI Registrierung NIS2 Pflicht Anleitung Portal',
        'nis2_ref': '§33 BSIG',
        'outline': 'Wer muss sich registrieren (§33), Fristen, BSI-Portal Schritt für Schritt, '
                   'benötigte Angaben, häufige Fehler, nach der Registrierung',
    },
    {
        'title': 'NIS2 vs. ISO 27001: Was ist der Unterschied und was brauche ich?',
        'category_slug': 'nis2-grundlagen',
        'tags': ['NIS2', 'ISO 27001', 'ISMS', 'Zertifizierung'],
        'keywords': 'NIS2 ISO 27001 Unterschied Vergleich Deutschland',
        'nis2_ref': '§30 BSIG',
        'outline': 'Gemeinsamkeiten/Unterschiede als Tabelle, ISO 27001 als NIS2-Nachweis (§39), '
                   'Kosten-Nutzen-Analyse KMU, empfohlener Weg ohne Zertifizierung',
    },
    {
        'title': 'NIS2-Bußgelder: Was droht bei Nicht-Compliance (bis zu 10 Mio. €)',
        'category_slug': 'nis2-grundlagen',
        'tags': ['NIS2', 'Bußgeld', 'Compliance', 'BSIG'],
        'keywords': 'NIS2 Bußgeld Strafe Nicht-Compliance Deutschland',
        'nis2_ref': '§65 BSIG',
        'outline': 'Bußgeldrahmen (10 Mio. € / 2% Jahresumsatz), Fallbeispiele aus EU, '
                   'Aufsichtsbehörden in Deutschland, Haftung der Geschäftsleitung §38, '
                   'Durchsetzungszeitplan',
    },
    {
        'title': 'Geschäftsleiterhaftung nach §38 BSIG: Was Führungskräfte wissen müssen',
        'category_slug': 'nis2-grundlagen',
        'tags': ['§38 BSIG', 'Haftung', 'Geschäftsführung', 'NIS2'],
        'keywords': 'Geschäftsführer Haftung NIS2 §38 BSIG persönlich',
        'nis2_ref': '§38 BSIG',
        'outline': 'Persönliche Haftung der GL, Schulungspflicht (§38 Abs. 3), '
                   'Regress des Unternehmens, praktische Maßnahmen zur Haftungsminimierung',
    },
    {
        'title': 'NIS2-Umsetzungsgesetz (NIS2UmsuCG): Die wichtigsten Änderungen auf einen Blick',
        'category_slug': 'nis2-grundlagen',
        'tags': ['NIS2UmsuCG', 'NIS2', 'BSIG', 'Gesetz'],
        'keywords': 'NIS2UmsuCG Änderungen Deutschland BSIG Überblick',
        'nis2_ref': 'NIS2UmsuCG',
        'outline': 'In-Kraft-Treten 6. Dez 2025, wesentlichste Änderungen vs. KRITIS-alt, '
                   'neue Sektoren, verschärfte Bußgelder, Zeitplan für Unternehmen',
    },
    {
        'title': 'Lieferkettensicherheit nach NIS2: Anforderungen an Ihre Lieferanten',
        'category_slug': 'nis2-grundlagen',
        'tags': ['Lieferkette', 'Supply Chain', 'NIS2', '§30 BSIG'],
        'keywords': 'NIS2 Lieferkettensicherheit Lieferanten Anforderungen',
        'nis2_ref': '§30 Abs. 2 Nr. 4 BSIG',
        'outline': 'Was §30 Nr. 4 fordert, Risikoklassifizierung Lieferanten, '
                   'Vertragsklauseln, AVV DSGVO Art. 28, Lieferanten-Fragebögen, Monitoring',
    },
    {
        'title': 'NIS2 für KMU: Umsetzung mit kleinem Budget und Team',
        'category_slug': 'nis2-grundlagen',
        'tags': ['KMU', 'NIS2', 'Umsetzung', 'Budget'],
        'keywords': 'NIS2 KMU Umsetzung kleines Unternehmen günstig',
        'nis2_ref': '§30 BSIG',
        'outline': 'Realistischer 6-Monats-Plan, kostenlose BSI-Tools, Priorisierung '
                   'der 10 Maßnahmen, externe Unterstützung vs. intern, Kosten-Überblick',
    },
    {
        'title': 'IT-Sicherheitsleitlinie erstellen: Vorlage und Anleitung für NIS2',
        'category_slug': 'nis2-grundlagen',
        'tags': ['IT-Sicherheitsleitlinie', 'ISMS', 'NIS2', 'Vorlage'],
        'keywords': 'IT-Sicherheitsleitlinie erstellen Vorlage NIS2',
        'nis2_ref': '§30 Abs. 2 Nr. 1 BSIG',
        'outline': 'Pflichtinhalte laut BSI 200-1, Struktur (10 Kapitel), '
                   'wer unterschreibt, Überprüfungsintervall, häufige Fehler',
    },
    {
        'title': 'Incident-Response-Plan nach NIS2: Aufbau und Meldepflichten §32 BSIG',
        'category_slug': 'nis2-grundlagen',
        'tags': ['Incident Response', '§32 BSIG', 'Meldepflicht', 'NIS2'],
        'keywords': 'Incident Response Plan NIS2 §32 BSIG Meldepflicht 24h',
        'nis2_ref': '§32 BSIG',
        'outline': '24h Frühwarnung, 72h Zwischenmeldung, 30 Tage Abschlussbericht, '
                   'BSI-Meldeformular, IRT-Aufbau, Playbooks je Incident-Typ',
    },
    {
        'title': 'NIS2 Risikoanalyse: Methodik und praktisches Beispiel',
        'category_slug': 'nis2-grundlagen',
        'tags': ['Risikoanalyse', 'BSI 200-3', 'NIS2', 'ISMS'],
        'keywords': 'NIS2 Risikoanalyse Methodik BSI Beispiel',
        'nis2_ref': '§30 Abs. 2 Nr. 1 BSIG, BSI 200-3',
        'outline': 'Methodik BSI 200-3, Schutzbedarfsfeststellung, Risikomatrix, '
                   'Top-10-Risiken je Branche, Restrisiken, Überprüfungszyklen',
    },

    # ── Angriffe & Bedrohungen (18) ───────────────────────────────────────────
    {
        'title': 'Ransomware 2025: Neue Varianten, Angriffswege und Schutzmaßnahmen',
        'category_slug': 'cyberangriffe',
        'tags': ['Ransomware', 'Malware', 'Cybersicherheit', 'Schutz'],
        'keywords': 'Ransomware 2025 neu Schutz Deutschland Angriff',
        'nis2_ref': '§30 Abs. 2 Nr. 2, 3 BSIG',
        'outline': 'LockBit 3.0, Cl0p, BlackCat — neue Taktiken, Doppelte Erpressung, '
                   'RaaS-Modell, Angriffsvektoren, Sofortmaßnahmen, Backup-Strategie, '
                   'NIS2-konforme Meldepflicht',
    },
    {
        'title': 'Phishing 2025: KI-gestützte Angriffe und wie man sie erkennt',
        'category_slug': 'cyberangriffe',
        'tags': ['Phishing', 'Social Engineering', 'KI', 'E-Mail-Sicherheit'],
        'keywords': 'Phishing 2025 KI erkennen schützen Deutschland',
        'nis2_ref': '§30 Abs. 2 Nr. 7 BSIG',
        'outline': 'Spear-Phishing, Vishing, Smishing, GPT-generierte Mails, '
                   'Deepfake-Audio, technische Schutzmaßnahmen (SPF/DKIM/DMARC), '
                   'Mitarbeiterschulung',
    },
    {
        'title': 'Business Email Compromise (BEC): Der teuerste Cyberbetrug der Welt',
        'category_slug': 'cyberangriffe',
        'tags': ['BEC', 'CEO-Fraud', 'Phishing', 'Finanzbetrug'],
        'keywords': 'Business Email Compromise BEC CEO Fraud Deutschland',
        'nis2_ref': '§30 Abs. 2 Nr. 7 BSIG',
        'outline': 'Was ist BEC, Zahlen (FBI IC3 2024), Angriffsmuster (Fake-Rechnung, '
                   'CEO-Fraud, Anwaltsbetrug), Schutzmaßnahmen (4-Augen, Rückruf-Pflicht)',
    },
    {
        'title': 'Supply-Chain-Angriffe: SolarWinds, XZ Utils und was Sie daraus lernen',
        'category_slug': 'cyberangriffe',
        'tags': ['Supply Chain', 'Softwaresicherheit', 'NIS2', 'APT'],
        'keywords': 'Supply Chain Angriff Schutz Deutschland NIS2 2025',
        'nis2_ref': '§30 Abs. 2 Nr. 4 BSIG',
        'outline': 'Fallstudien (SolarWinds, XZ Utils, 3CX), Angriffsmuster, '
                   'SBOM (Software Bill of Materials), Lieferanten-Sicherheitsanforderungen',
    },
    {
        'title': 'DDoS-Angriffe 2025: Rekorde und Abwehrstrategien',
        'category_slug': 'cyberangriffe',
        'tags': ['DDoS', 'Verfügbarkeit', 'Netzwerksicherheit', 'Schutz'],
        'keywords': 'DDoS Angriff 2025 Schutz Abwehr Deutschland',
        'nis2_ref': '§30 Abs. 2 Nr. 3 BSIG',
        'outline': 'Rekord-Angriffe 2024/25, Motivationen (Hacktivismus, Erpressung), '
                   'Layer 3/4/7 Angriffe, Cloud-Scrubbing, On-Prem-Abwehr, BCP-Integration',
    },
    {
        'title': 'Zero-Day-Exploits: Was tun, wenn kein Patch existiert?',
        'category_slug': 'cyberangriffe',
        'tags': ['Zero-Day', 'Patch-Management', 'Schwachstellen', 'NIS2'],
        'keywords': 'Zero-Day Exploit Schutz Maßnahmen kein Patch',
        'nis2_ref': '§30 Abs. 2 Nr. 5 BSIG',
        'outline': 'Was ist ein Zero-Day, bekannte Beispiele 2024/25, Compensating Controls, '
                   'Threat Intelligence, Vendor-Kommunikation, BSI-Warnmeldungen abonnieren',
    },
    {
        'title': 'Insider-Bedrohungen: Wenn der Angreifer im eigenen Unternehmen sitzt',
        'category_slug': 'cyberangriffe',
        'tags': ['Insider Threat', 'Zugriffskontrolle', 'NIS2', 'Datenschutz'],
        'keywords': 'Insider Threat Bedrohung innen Mitarbeiter Schutz',
        'nis2_ref': '§30 Abs. 2 Nr. 9 BSIG',
        'outline': 'Typen (böswillig, fahrlässig, kompromittiert), Statistiken, '
                   'Erkennung (UBA/UEBA), Least Privilege, Offboarding-Prozess',
    },
    {
        'title': 'Man-in-the-Middle-Angriffe: Erkennen und verhindern',
        'category_slug': 'cyberangriffe',
        'tags': ['MitM', 'Verschlüsselung', 'TLS', 'Netzwerksicherheit'],
        'keywords': 'Man in the Middle Angriff Schutz TLS Zertifikat',
        'nis2_ref': '§30 Abs. 2 Nr. 8 BSIG',
        'outline': 'Techniken (ARP Spoofing, SSL Stripping, Rogue AP), Schutzmaßnahmen '
                   '(TLS 1.3, HSTS, Zertifikat-Pinning, DNSSEC), WLAN-Sicherheit',
    },
    {
        'title': 'Social Engineering: Die gefährlichste Angriffstechnik 2025',
        'category_slug': 'cyberangriffe',
        'tags': ['Social Engineering', 'Phishing', 'Awareness', 'Schulung'],
        'keywords': 'Social Engineering Angriff Arten Schutz Mitarbeiter',
        'nis2_ref': '§30 Abs. 2 Nr. 7 BSIG',
        'outline': 'Phishing, Pretexting, Quid Pro Quo, Tailgating, Deepfakes, '
                   'psychologische Mechanismen, Awareness-Training, Meldeprozess',
    },
    {
        'title': 'Credential Stuffing und Passwort-Angriffe: Schutz ohne MFA ist unzureichend',
        'category_slug': 'cyberangriffe',
        'tags': ['Passwort', 'MFA', 'Credential Stuffing', 'IAM'],
        'keywords': 'Credential Stuffing Passwort Angriff MFA Schutz',
        'nis2_ref': '§30 Abs. 2 Nr. 10 BSIG',
        'outline': 'Credential Stuffing, Brute Force, Password Spraying, '
                   'Have I Been Pwned, Passwort-Manager, MFA-Pflicht, FIDO2',
    },
    {
        'title': 'APT-Gruppen und staatlich gesponserte Angriffe auf deutsche Unternehmen',
        'category_slug': 'cyberangriffe',
        'tags': ['APT', 'Staatliche Angreifer', 'Spionage', 'NIS2'],
        'keywords': 'APT staatliche Angriffe Deutschland Spionage 2025',
        'nis2_ref': '§30 BSIG',
        'outline': 'Was sind APTs, bekannte Gruppen (Cozy Bear, Sandworm, APT10), '
                   'Ziele in Deutschland, TTPs (MITRE ATT&CK), Erkennung, BSI-Lageberichte',
    },
    {
        'title': 'Schwachstellen in OT/ICS-Systemen: Das unterschätzte Risiko in der Produktion',
        'category_slug': 'cyberangriffe',
        'tags': ['OT-Sicherheit', 'ICS', 'Produktion', 'NIS2'],
        'keywords': 'OT ICS Sicherheit Schwachstellen Produktion NIS2',
        'nis2_ref': '§30 BSIG, Anlage 1 Sektor Produktion',
        'outline': 'IT/OT-Konvergenz, typische Schwachstellen (veraltete Protokolle, '
                   'keine Patches), Netzwerksegmentierung, IEC 62443, NIS2-Pflichten Produktion',
    },
    {
        'title': 'Deepfake-Angriffe auf Unternehmen: Was jetzt möglich ist',
        'category_slug': 'cyberangriffe',
        'tags': ['Deepfake', 'KI', 'Social Engineering', 'Betrug'],
        'keywords': 'Deepfake Angriff Unternehmen Betrug Schutz 2025',
        'nis2_ref': '§30 Abs. 2 Nr. 7 BSIG',
        'outline': 'Deepfake-Audio CEO-Fraud (Fallbeispiele), Video-Deepfakes, '
                   'Erkennungstools, Verifikationsprozesse, Out-of-Band-Bestätigung',
    },
    {
        'title': 'Cloud-Fehlkonfigurationen: Die häufigste Ursache für Datenpannen',
        'category_slug': 'cyberangriffe',
        'tags': ['Cloud-Sicherheit', 'Fehlkonfiguration', 'AWS', 'DSGVO'],
        'keywords': 'Cloud Fehlkonfiguration Datenpanne S3 Azure Schutz',
        'nis2_ref': '§30 Abs. 2 Nr. 1 BSIG',
        'outline': 'Top-Fehlkonfigurationen (offene S3-Buckets, fehlende MFA, '
                   'überprivilegierte IAM-Rollen), CSPM-Tools, Cloud Security Posture, '
                   'Shared Responsibility',
    },
    {
        'title': 'Ransomware-as-a-Service (RaaS): Wie Kriminelle professionell werden',
        'category_slug': 'cyberangriffe',
        'tags': ['Ransomware', 'RaaS', 'Cyberkriminalität', 'NIS2'],
        'keywords': 'Ransomware as a Service RaaS Cyberkriminalität Modell',
        'nis2_ref': '§30 Abs. 2 Nr. 2, 3 BSIG',
        'outline': 'RaaS-Geschäftsmodell, bekannte Plattformen, Affiliate-System, '
                   'Initial Access Brokers, Verteidigung, Cyber-Versicherung',
    },
    {
        'title': 'QR-Code-Phishing (Quishing): Neue Bedrohung für mobile Nutzer',
        'category_slug': 'cyberangriffe',
        'tags': ['Quishing', 'QR-Code', 'Phishing', 'Mobile'],
        'keywords': 'QR Code Phishing Quishing Betrug schützen',
        'nis2_ref': '§30 Abs. 2 Nr. 7 BSIG',
        'outline': 'Was ist Quishing, Angriffsmethode, reale Beispiele 2024/25, '
                   'E-Mail-Filter-Umgehung, Schulungsmaßnahmen, technische Abwehr',
    },
    {
        'title': 'DSGVO-Datenpannen richtig melden: 72-Stunden-Frist und Praxis',
        'category_slug': 'cyberangriffe',
        'tags': ['DSGVO', 'Datenpanne', 'Meldepflicht', 'NIS2'],
        'keywords': 'DSGVO Datenpanne melden 72 Stunden Frist Behörde',
        'nis2_ref': 'DSGVO Art. 33, §32 BSIG',
        'outline': 'Was ist eine Datenpanne (Art. 4 Nr. 12), wann melden, '
                   'wie melden (Aufsichtsbehörde + Betroffene), NIS2-Doppeltes Melden, '
                   'Dokumentation, Bußgeldrisiko',
    },
    {
        'title': 'Schwachstellenmanagement: CVE-Prozess, CVSS und Patch-Prioritäten',
        'category_slug': 'cyberangriffe',
        'tags': ['Schwachstellenmanagement', 'CVE', 'CVSS', 'Patch-Management'],
        'keywords': 'Schwachstellenmanagement CVE CVSS Patch Priorität NIS2',
        'nis2_ref': '§30 Abs. 2 Nr. 5 BSIG',
        'outline': 'CVE-Lebenszyklus, CVSS v3.1 Score verstehen, '
                   'BSI CERT-Bund Meldungen, Patch-Zeitfenster (72h / 30d / 90d), '
                   'Ausnahmen / Kompensationsmaßnahmen',
    },

    # ── Technische Maßnahmen (15) ─────────────────────────────────────────────
    {
        'title': 'Multi-Faktor-Authentifizierung (MFA): Welche Methode ist die sicherste?',
        'category_slug': 'technische-massnahmen',
        'tags': ['MFA', 'FIDO2', 'TOTP', 'Authentifizierung'],
        'keywords': 'MFA Multi-Faktor-Authentifizierung sicherste Methode FIDO2',
        'nis2_ref': '§30 Abs. 2 Nr. 10 BSIG',
        'outline': 'Vergleich: SMS vs. TOTP vs. FIDO2/WebAuthn, Sicherheitsranking, '
                   'Implementierung je System, Notfall-Prozedur, Kosten, NIS2-Pflicht',
    },
    {
        'title': 'Zero Trust Architecture: Von der Theorie zur NIS2-konformen Praxis',
        'category_slug': 'technische-massnahmen',
        'tags': ['Zero Trust', 'Netzwerksicherheit', 'IAM', 'NIS2'],
        'keywords': 'Zero Trust Architecture NIS2 Umsetzung Deutschland',
        'nis2_ref': '§30 Abs. 2 Nr. 9 BSIG',
        'outline': '"Never trust, always verify", Kernprinzipien, '
                   'Umsetzungsschritte (Identität → Gerät → Netzwerk → Anwendung), '
                   'Microsoft / Google-Ansätze, Budget für KMU',
    },
    {
        'title': 'Endpoint Detection & Response (EDR): Mehr als nur Antivirus',
        'category_slug': 'technische-massnahmen',
        'tags': ['EDR', 'Endpoint-Sicherheit', 'NIS2', 'SIEM'],
        'keywords': 'EDR Endpoint Detection Response Vergleich NIS2',
        'nis2_ref': '§30 Abs. 2 Nr. 2 BSIG',
        'outline': 'EDR vs. AV vs. XDR, Marktvergleich (CrowdStrike, SentinelOne, '
                   'Microsoft Defender), Deployment, Alert-Management, SOC-Integration',
    },
    {
        'title': 'SIEM & Log-Management: Sicherheitsereignisse zentral überwachen',
        'category_slug': 'technische-massnahmen',
        'tags': ['SIEM', 'Log-Management', 'Monitoring', 'NIS2'],
        'keywords': 'SIEM Log-Management Sicherheit Überwachung NIS2',
        'nis2_ref': '§30 Abs. 2 Nr. 2 BSIG',
        'outline': 'Was ist ein SIEM, Use Cases, Log-Quellen, Retention-Anforderungen, '
                   'Open Source (Wazuh, ELK) vs. kommerziell, NIS2-Relevanz',
    },
    {
        'title': 'Backup nach 3-2-1-Regel: Schutz vor Ransomware und Datenverlust',
        'category_slug': 'technische-massnahmen',
        'tags': ['Backup', '3-2-1-Regel', 'Ransomware', 'BCP'],
        'keywords': 'Backup 3-2-1-Regel Ransomware Schutz NIS2 BCP',
        'nis2_ref': '§30 Abs. 2 Nr. 3 BSIG',
        'outline': '3-2-1 + 1 (air-gapped), Backup-Typen (voll/inkrementell/differentiell), '
                   'Restore-Tests (quartalsweise), Backup-Verschlüsselung, Cloud-Backup',
    },
    {
        'title': 'Netzwerksegmentierung: Wie Sie Angreifer am Querbewegen hindern',
        'category_slug': 'technische-massnahmen',
        'tags': ['Netzwerksegmentierung', 'Firewall', 'Zero Trust', 'Lateral Movement'],
        'keywords': 'Netzwerksegmentierung Lateral Movement verhindern NIS2',
        'nis2_ref': '§30 Abs. 2 Nr. 2 BSIG',
        'outline': 'Lateral Movement, VLANs, Mikrosegmentierung, DMZ, '
                   'Firewall-Regeln (Whitelist vs. Blacklist), Überprüfung',
    },
    {
        'title': 'Kryptographie-Konzept nach BSI TR-02102: Welche Algorithmen sind noch sicher?',
        'category_slug': 'technische-massnahmen',
        'tags': ['Kryptographie', 'BSI TR-02102', 'TLS', 'Verschlüsselung'],
        'keywords': 'Kryptographie BSI TR-02102 sichere Algorithmen TLS 2025',
        'nis2_ref': '§30 Abs. 2 Nr. 8 BSIG, BSI TR-02102',
        'outline': 'AES-256, RSA-4096, ECDSA-384, SHA-256+, TLS 1.3, '
                   'verbotene Algorithmen (MD5, SHA-1, DES, RC4), Schlüsselmanagement, '
                   'Post-Quantum-Kryptographie Ausblick',
    },
    {
        'title': 'Privileged Access Management (PAM): Admin-Konten sicher verwalten',
        'category_slug': 'technische-massnahmen',
        'tags': ['PAM', 'IAM', 'Admin-Sicherheit', 'NIS2'],
        'keywords': 'Privileged Access Management PAM Admin NIS2 Sicherheit',
        'nis2_ref': '§30 Abs. 2 Nr. 9 BSIG',
        'outline': 'Warum PAM, JIT-Access, Session Recording, Passwort-Vault, '
                   'Marktlösungen (CyberArk, HashiCorp, Teleport), KMU-Budget',
    },
    {
        'title': 'Penetrationstests: Was sie kosten, was sie bringen, wann sie Pflicht sind',
        'category_slug': 'technische-massnahmen',
        'tags': ['Penetrationstest', 'NIS2', 'Schwachstellenscan', 'Sicherheitstest'],
        'keywords': 'Penetrationstest Kosten Pflicht NIS2 wann',
        'nis2_ref': '§30 Abs. 2 Nr. 5 BSIG',
        'outline': 'Arten (Black/Grey/White Box, externes/internes Pentest), '
                   'Scope, Kosten (5k–50k €), Bericht-Interpretation, Frequenz, '
                   'BSI-Zertifizierung Pentester (BSI-IS)',
    },
    {
        'title': 'E-Mail-Sicherheit: SPF, DKIM, DMARC und BIMI richtig konfigurieren',
        'category_slug': 'technische-massnahmen',
        'tags': ['E-Mail-Sicherheit', 'SPF', 'DKIM', 'DMARC'],
        'keywords': 'E-Mail Sicherheit SPF DKIM DMARC NIS2 Konfiguration',
        'nis2_ref': '§30 Abs. 2 Nr. 8, 10 BSIG',
        'outline': 'SPF (Sender Policy Framework), DKIM (DomainKeys), '
                   'DMARC (p=reject), BIMI für Markenvertrauen, '
                   'MTA-STS, schritt-für-Schritt DNS-Konfiguration',
    },
    {
        'title': 'Schwachstellenscanner: Nessus, OpenVAS & Co. im Vergleich',
        'category_slug': 'technische-massnahmen',
        'tags': ['Schwachstellenscan', 'Nessus', 'OpenVAS', 'NIS2'],
        'keywords': 'Schwachstellenscanner Vergleich Nessus OpenVAS NIS2',
        'nis2_ref': '§30 Abs. 2 Nr. 5 BSIG',
        'outline': 'Produktvergleich, Funktionsumfang, Kosten, Deployment, '
                   'Scan-Frequenz, Ergebnis-Interpretation, Integration in Patch-Prozess',
    },
    {
        'title': 'Mobile Device Management (MDM): BYOD-Sicherheit für NIS2-Compliance',
        'category_slug': 'technische-massnahmen',
        'tags': ['MDM', 'BYOD', 'Mobile', 'NIS2'],
        'keywords': 'MDM BYOD Mobile Device Management NIS2 Compliance',
        'nis2_ref': '§30 Abs. 2 Nr. 2 BSIG',
        'outline': 'BYOD-Risiken, MDM vs. MAM, Microsoft Intune, Jamf, '
                   'Remote Wipe, Containerisierung, Policy-Anforderungen',
    },
    {
        'title': 'Sichere Softwareentwicklung (DevSecOps): Security by Design für NIS2',
        'category_slug': 'technische-massnahmen',
        'tags': ['DevSecOps', 'Softwaresicherheit', 'SAST', 'NIS2'],
        'keywords': 'DevSecOps sichere Softwareentwicklung NIS2 SAST',
        'nis2_ref': '§30 Abs. 2 Nr. 5 BSIG',
        'outline': 'Security in CI/CD Pipeline, SAST/DAST, Dependency-Scanning, '
                   'Secret Detection, Container-Scanning, SBOM, NIS2-Anforderungen',
    },
    {
        'title': 'DNSSEC und DNS-Sicherheit: Unterschätzte Angriffsfläche',
        'category_slug': 'technische-massnahmen',
        'tags': ['DNSSEC', 'DNS', 'Netzwerksicherheit', 'Kryptographie'],
        'keywords': 'DNSSEC DNS Sicherheit konfigurieren NIS2',
        'nis2_ref': '§30 Abs. 2 Nr. 8 BSIG',
        'outline': 'DNS-Hijacking, Cache Poisoning, DNSSEC-Funktionsweise, '
                   'DoH/DoT, Konfigurationsanleitung, Monitoring',
    },
    {
        'title': 'Security Awareness Training: So gestalten Sie wirkungsvolle Schulungen',
        'category_slug': 'technische-massnahmen',
        'tags': ['Security Awareness', 'Schulung', '§30 BSIG', 'Phishing-Simulation'],
        'keywords': 'Security Awareness Training Schulung NIS2 §30 BSIG',
        'nis2_ref': '§30 Abs. 2 Nr. 7 BSIG',
        'outline': 'Was wirksame Schulungen auszeichnet, Phishing-Simulationen, '
                   'Gamification, Frequenz (jährlich + anlassbezogen), '
                   'Nachweis-Dokumentation §39 BSIG',
    },

    # ── Cloud & Moderne Infrastruktur (8) ─────────────────────────────────────
    {
        'title': 'Cloud-Sicherheit nach NIS2: Microsoft Azure, AWS und Google Cloud im Vergleich',
        'category_slug': 'cloud-sicherheit',
        'tags': ['Cloud-Sicherheit', 'AWS', 'Azure', 'NIS2'],
        'keywords': 'Cloud Sicherheit NIS2 AWS Azure Google Vergleich',
        'nis2_ref': '§30 Abs. 2 Nr. 1 BSIG',
        'outline': 'Shared Responsibility Model, Compliance-Features der Provider, '
                   'DSGVO-konforme Cloud (EU-Datenspeicherung), Shadow IT, '
                   'Cloud Security Posture Management',
    },
    {
        'title': 'Microsoft 365 Sicherheit: Sicherheitseinstellungen für NIS2-Compliance',
        'category_slug': 'cloud-sicherheit',
        'tags': ['Microsoft 365', 'Cloud-Sicherheit', 'NIS2', 'Exchange'],
        'keywords': 'Microsoft 365 Sicherheit NIS2 Einstellungen Compliance',
        'nis2_ref': '§30 BSIG',
        'outline': 'Conditional Access, MFA-Enforcement, Defender for O365, '
                   'DLP-Policies, Purview, Audit Logging, Admin-Center-Checkliste',
    },
    {
        'title': 'Homeoffice-Sicherheit: VPN, Endgeräte und sichere Kommunikation',
        'category_slug': 'cloud-sicherheit',
        'tags': ['Homeoffice', 'VPN', 'Remote Work', 'NIS2'],
        'keywords': 'Homeoffice Sicherheit VPN NIS2 Remote Work',
        'nis2_ref': '§30 Abs. 2 Nr. 9, 10 BSIG',
        'outline': 'VPN-Anforderungen (Split Tunnel, Always-On), Endgeräte-Sicherheit, '
                   'BYOD vs. Firmengerät, sichere Video-Konferenz, '
                   'Richtlinie für Homeoffice',
    },
    {
        'title': 'Kubernetes und Container-Sicherheit: NIS2-Anforderungen für DevOps-Teams',
        'category_slug': 'cloud-sicherheit',
        'tags': ['Kubernetes', 'Container', 'DevSecOps', 'Cloud-Sicherheit'],
        'keywords': 'Kubernetes Container Sicherheit NIS2 DevOps',
        'nis2_ref': '§30 Abs. 2 Nr. 5 BSIG',
        'outline': 'Container-Image-Scanning, RBAC in K8s, Network Policies, '
                   'Secrets Management (Vault), Runtime Security (Falco)',
    },
    {
        'title': 'SaaS-Sicherheit: Wie Sie Cloud-Anwendungen NIS2-konform einsetzen',
        'category_slug': 'cloud-sicherheit',
        'tags': ['SaaS', 'Cloud-Sicherheit', 'DSGVO', 'NIS2'],
        'keywords': 'SaaS Sicherheit NIS2 DSGVO Cloud-Anwendung',
        'nis2_ref': '§30 Abs. 2 Nr. 4 BSIG',
        'outline': 'SaaS-Inventar (CASB), Datenspeicherung EU, AVV-Abschluss, '
                   'SSO/MFA für SaaS, Offboarding-Prozess, Shadow IT',
    },
    {
        'title': 'Backup in der Cloud: Was Sie über DSGVO-konforme Datensicherung wissen müssen',
        'category_slug': 'cloud-sicherheit',
        'tags': ['Backup', 'Cloud', 'DSGVO', 'NIS2'],
        'keywords': 'Backup Cloud DSGVO NIS2 Datensicherung konform',
        'nis2_ref': '§30 Abs. 2 Nr. 3 BSIG',
        'outline': 'Anbieterauswahl (EU-Datenzentrum), Verschlüsselung, '
                   'Zugriffsrechte, Restore-Tests, Kosten, Empfehlungen',
    },
    {
        'title': 'Identity and Access Management (IAM): Grundlage jeder NIS2-Compliance',
        'category_slug': 'cloud-sicherheit',
        'tags': ['IAM', 'Zugriffsmanagement', 'NIS2', 'Zero Trust'],
        'keywords': 'IAM Identity Access Management NIS2 Grundlage',
        'nis2_ref': '§30 Abs. 2 Nr. 9 BSIG',
        'outline': 'IAM-Grundsätze (Least Privilege, Need-to-Know), '
                   'Lösungen (Azure AD, Okta, Keycloak), Lifecycle Management, '
                   'Rezertifizierung, Privileged Identity Management',
    },
    {
        'title': 'API-Sicherheit: Unterschätzte Angriffsfläche in modernen Unternehmen',
        'category_slug': 'cloud-sicherheit',
        'tags': ['API-Sicherheit', 'REST', 'OAuth', 'DevSecOps'],
        'keywords': 'API Sicherheit OWASP Top 10 REST OAuth 2.0',
        'nis2_ref': '§30 Abs. 2 Nr. 5 BSIG',
        'outline': 'OWASP API Security Top 10, OAuth 2.0 / OpenID Connect, '
                   'Rate Limiting, API Gateway, Authentifizierung (mTLS, API-Keys)',
    },

    # ── Compliance & Recht (7) ────────────────────────────────────────────────
    {
        'title': 'Cyber-Versicherung 2025: Was deckt sie ab und lohnt sie sich?',
        'category_slug': 'compliance-recht',
        'tags': ['Cyber-Versicherung', 'NIS2', 'Risikomanagement', 'Versicherung'],
        'keywords': 'Cyber-Versicherung 2025 lohnt NIS2 Deckung',
        'nis2_ref': '§30 BSIG',
        'outline': 'Was deckt Cyber-Versicherung (BI, Forensik, Lösegeld), '
                   'was ist ausgeschlossen, Anforderungen der Versicherer (MFA, Backup), '
                   'Kosten, Top-Anbieter Deutschland',
    },
    {
        'title': 'IT-Forensik nach einem Cyberangriff: Was zu tun ist (und was nicht)',
        'category_slug': 'compliance-recht',
        'tags': ['IT-Forensik', 'Incident Response', 'Beweissicherung', 'NIS2'],
        'keywords': 'IT-Forensik Cyberangriff Beweissicherung Vorgehen',
        'nis2_ref': '§32 BSIG',
        'outline': 'Erste Stunden (nicht überschreiben!), Beweissicherung (RAM-Dump, '
                   'Disk-Image), externe Forensiker, BSI-Meldung, strafrechtliche Anzeige, '
                   'Versicherungsbenachrichtigung',
    },
    {
        'title': 'DSGVO und NIS2: Wo sich die Pflichten überschneiden',
        'category_slug': 'compliance-recht',
        'tags': ['DSGVO', 'NIS2', 'Datenschutz', 'Compliance'],
        'keywords': 'DSGVO NIS2 Überschneidung Pflichten Deutschland',
        'nis2_ref': '§30 BSIG, DSGVO Art. 32',
        'outline': 'Gemeinsame Anforderungen (Art. 32 DSGVO ≈ §30 BSIG), '
                   'Doppeltes Melden (BSI + Datenschutzbehörde), AVV, '
                   'unterschiedliche Bußgelder, CISO/DSB-Synergien',
    },
    {
        'title': 'NIS2-Nachweis gegenüber Kunden und Behörden: Was gilt als Nachweis (§39 BSIG)',
        'category_slug': 'compliance-recht',
        'tags': ['§39 BSIG', 'Nachweis', 'Audit', 'NIS2'],
        'keywords': 'NIS2 Nachweis §39 BSIG Audit Behörde',
        'nis2_ref': '§39 BSIG',
        'outline': 'Wann Nachweis gefordert, akzeptierte Nachweisformen '
                   '(ISO 27001, BSI-Audit, Selbsterklärung), Fristen, '
                   'Konsequenzen bei fehlendem Nachweis',
    },
    {
        'title': 'Business Continuity Management (BCM) nach BSI 100-4: Praxisleitfaden',
        'category_slug': 'compliance-recht',
        'tags': ['BCM', 'BSI 100-4', 'BCP', 'NIS2'],
        'keywords': 'Business Continuity Management BSI 100-4 NIS2 Praxis',
        'nis2_ref': '§30 Abs. 2 Nr. 3 BSIG',
        'outline': 'BIA (Business Impact Analysis), RTO/RPO je Prozess, '
                   'Krisenorganisation, Kommunikationsplan, Test-Typen, '
                   'Aktualisierungsintervall',
    },
    {
        'title': 'NIS2 und Datenschutz im Homeoffice: Rechte und Pflichten der Mitarbeiter',
        'category_slug': 'compliance-recht',
        'tags': ['Homeoffice', 'DSGVO', 'Datenschutz', 'NIS2'],
        'keywords': 'Homeoffice Datenschutz DSGVO Pflichten Mitarbeiter NIS2',
        'nis2_ref': '§30 BSIG, DSGVO',
        'outline': 'Datenschutz-Anforderungen Homeoffice, Bildschirmsperre, '
                   'Aktenvernichtung, Familienmitglieder, VPN-Pflicht, '
                   'Betriebsvereinbarung',
    },
    {
        'title': 'IT-Compliance-Roadmap 2025–2026: Schritt-für-Schritt-Plan für NIS2',
        'category_slug': 'compliance-recht',
        'tags': ['Roadmap', 'NIS2', 'Compliance', 'Umsetzungsplan'],
        'keywords': 'NIS2 Roadmap Umsetzungsplan 2025 2026 Schritte',
        'nis2_ref': '§30 BSIG',
        'outline': 'Phasen (Q1: Assessment, Q2: Dokumentation, Q3: Technik, Q4: Nachweis), '
                   'Meilensteine, Quick Wins, langfristige Maßnahmen, Budget-Planung',
    },
]
