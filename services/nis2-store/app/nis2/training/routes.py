"""
Security Awareness Training — Routes (§30 Abs. 2 Nr. 7 BSIG)

Workflow:
  1. Admin creates training with Markdown content + audience list
  2. System sends personalised email with unique token link to each recipient
  3. Recipient opens link → reads lecture → clicks "Bestätigen"
  4. Acknowledgment (name, timestamp, IP) stored → audit trail for regulator
  5. Admin sees report: who confirmed, who hasn't, exportable for BSI audit
"""

import json
import logging
import secrets
import smtplib
from datetime import UTC, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import (abort, current_app, flash, redirect, render_template,
                   request, url_for)
from services.security_helpers import require_plan
from flask_login import current_user, login_required

from app.extensions import db
from ..models import SecurityTraining, TrainingAcknowledgment, TRAINING_TOPICS

logger = logging.getLogger(__name__)

# Default lecture content per topic (Markdown)
DEFAULT_CONTENT = {
    'phishing': """## Phishing & Social Engineering — Pflichtunterweisung

### Was ist Phishing?
Phishing ist der Versuch, über gefälschte E-Mails oder Webseiten sensible Daten zu stehlen.
Angreifer geben sich als Bank, IT-Abteilung oder Vorgesetzter aus.

### Erkennungsmerkmale
- Unbekannter Absender oder leicht abgewandelte Domain (z.B. `microsof t.com`)
- Druck und Dringlichkeit („Ihr Konto wird gesperrt!")
- Links, die auf fremde Domains zeigen (vor dem Klicken hovern!)
- Anhänge von unbekannten Absendern
- Grammatik- und Rechtschreibfehler

### Ihre Pflichten
1. Verdächtige E-Mails **nicht öffnen oder klicken** — an IT-Sicherheit melden
2. Phishing-Versuche über das interne Meldeformular dokumentieren
3. Zugangsdaten **niemals** per E-Mail übermitteln
4. Bei Unsicherheit: Absender telefonisch verifizieren

### Rechtsgrundlage
§30 Abs. 2 Nr. 7 BSIG verpflichtet NIS2-Einrichtungen zur regelmäßigen Schulung aller Mitarbeiter.
Diese Unterweisung ist Teil Ihres Compliance-Programms.""",

    'passwords': """## Sichere Passwörter & Mehrfaktor-Authentifizierung

### Warum sichere Passwörter?
80% aller Datenpannen entstehen durch schwache oder gestohlene Passwörter (Verizon DBIR 2025).

### BSI-Empfehlungen für Passwörter
- Mindestlänge: **12 Zeichen** (empfohlen: 16+)
- Kombination: Groß-/Kleinbuchstaben, Zahlen, Sonderzeichen
- **Keine** Wörter aus dem Wörterbuch
- **Kein** Wiederverwenden von Passwörtern
- Passwort-Manager verwenden (z.B. Bitwarden, KeePass)

### Mehrfaktor-Authentifizierung (MFA)
MFA schützt Accounts auch bei gestohlenem Passwort. Aktivieren Sie MFA für:
- E-Mail-Konto
- VPN-Zugang
- Cloud-Dienste (Microsoft 365, Google Workspace)
- Bankkonto und kritische Systeme

### Passwörter niemals
- Per E-Mail oder Chat teilen
- Auf Notizzetteln aufschreiben
- An Kollegen weitergeben

### Rechtsgrundlage
§30 Abs. 2 Nr. 10 BSIG (MFA) und Nr. 7 (Schulung).""",

    'general': """## Grundlagen der Cybersicherheit — Pflichtunterweisung

### Ihre Rolle in der Cybersicherheit
Jeder Mitarbeiter ist Teil der Sicherheitskette. 95% aller erfolgreichen Angriffe nutzen menschliche Fehler aus (IBM Security Report 2025).

### Die 5 wichtigsten Regeln
1. **Phishing erkennen**: Unbekannte Links und Anhänge nicht öffnen
2. **Passwörter schützen**: Starke, einzigartige Passwörter + MFA aktivieren
3. **Updates installieren**: Betriebssystem und Software aktuell halten
4. **Verdächtiges melden**: Ungewöhnliches sofort der IT-Abteilung melden
5. **Geräte sichern**: Computer beim Verlassen sperren (Win+L / Cmd+Ctrl+Q)

### Was tun bei einem Vorfall?
1. Betroffenes Gerät **sofort vom Netzwerk trennen** (Kabel ziehen / WLAN aus)
2. **Nicht versuchen**, das Problem selbst zu lösen
3. IT-Sicherheit unter der internen Notfallnummer informieren
4. Nichts löschen — Beweise sichern

### Ihre Pflicht nach NIS2
Als Mitarbeiter einer NIS2-regulierten Organisation sind Sie verpflichtet:
- Diese Schulung vollständig zu lesen
- Sicherheitsvorfälle unverzüglich zu melden
- Die interne Sicherheitsrichtlinie einzuhalten

### Rechtsgrundlage
§30 Abs. 2 Nr. 7 BSIG — Schulungen zur Cyberhygiene.""",
}

DEFAULT_CONTENT['ransomware'] = """## Ransomware & Malware — Pflichtunterweisung

### Was ist Ransomware?
Ransomware ist Schadsoftware, die Ihre Dateien verschlüsselt und Lösegeld fordert.
Angriffe kosteten deutsche Unternehmen 2024 durchschnittlich **1,1 Mio. €** — inklusive Ausfallzeiten,
Wiederherstellung und Reputationsschaden (BSI Lagebericht 2024).

### Wie gelangt Ransomware ins Unternehmen?
1. **Phishing-E-Mails** mit infizierten Anhängen (PDF, Word, ZIP)
2. **Kompromittierte Websites** (Drive-by-Download)
3. **RDP / VPN-Schwachstellen** — Angreifer nutzen schwache Passwörter
4. **Infizierte USB-Sticks** oder externe Laufwerke
5. **Software-Downloads** aus unseriösen Quellen

### Warnsignale eines laufenden Angriffs
- Ungewöhnlich hohe CPU- / Festplatten-Auslastung
- Dateien können nicht geöffnet werden oder haben unbekannte Endungen (.locked, .crypt)
- Verschlüsselungshinweis erscheint auf dem Bildschirm (README.txt, DECRYPT.html)
- Netzwerklaufwerke sind plötzlich nicht mehr erreichbar

### Sofortmaßnahmen bei Verdacht
1. **Gerät sofort vom Netzwerk trennen** (Ethernet-Kabel ziehen, WLAN deaktivieren)
2. Gerät **nicht ausschalten** — Forensikdaten können im RAM liegen
3. Sofort die **IT-Sicherheit / Notfallnummer** informieren
4. **Kein Lösegeld zahlen** ohne Rücksprache mit der Geschäftsleitung und BSI
5. BSI-Meldepflicht prüfen (§32 BSIG: Frühwarnung innerhalb 24h)

### Schutzmaßnahmen (Ihr Beitrag)
- Keine unbekannten USB-Sticks anschließen
- Software nur aus genehmigten Quellen installieren
- Verdächtige E-Mails nicht öffnen — an IT melden
- Regelmäßige Backups sichern Ihre Daten auch ohne Lösegeld

### Rechtsgrundlage
§30 Abs. 2 Nr. 2 BSIG (Incident Response), Nr. 7 (Schulung), §32 BSIG (BSI-Meldepflicht)."""

DEFAULT_CONTENT['data_protection'] = """## Datenschutz & DSGVO — Pflichtunterweisung

### Warum Datenschutz?
Als NIS2-Einrichtung verarbeiten Sie personenbezogene Daten (DSGVO Art. 4).
Datenschutzverletzungen können zu **Bußgeldern bis 20 Mio. € oder 4 % des Jahresumsatzes**
führen — zusätzlich zu NIS2-Sanktionen.

### Was sind personenbezogene Daten?
Alle Informationen, die eine natürliche Person direkt oder indirekt identifizierbar machen:
- Name, Adresse, E-Mail, Telefonnummer
- IP-Adressen, Cookie-IDs, Standortdaten
- Gesundheitsdaten, Bankverbindungen (besonders schützenswert)
- Mitarbeiterdaten (Gehalt, Krankheit, Leistungsbeurteilung)

### Ihre Pflichten im Arbeitsalltag
| Situation | Richtig | Falsch |
|---|---|---|
| Kundendaten weitergeben | Nur mit Erlaubnis / Vertrag | Per WhatsApp an Kollegen |
| E-Mails mit personenbezogenen Daten | Verschlüsseln (S/MIME) | Unverschlüsselt senden |
| Daten nicht mehr benötigt | Sicher löschen (Schredder / sicheres Löschen) | In Papierkorb legen |
| Anfrage auf Datenlöschung | An Datenschutzbeauftragten weiterleiten | Selbst entscheiden |
| Datenpanne entdeckt | Sofort IT-Sicherheit informieren | Erst mal abwarten |

### DSGVO Art. 33 — Meldepflicht bei Datenpannen
Bei einer Datenschutzverletzung (unbefugter Zugriff, Verlust, Diebstahl) gilt:
- Intern melden: **sofort** an IT-Sicherheit / Datenschutzbeauftragten
- Behörde informieren: Datenschutzbehörde innerhalb **72 Stunden**
- Betroffene informieren: Wenn hohes Risiko für die Person besteht

### Verzeichnis von Verarbeitungstätigkeiten (VVT)
Jede Datenverarbeitung muss dokumentiert sein. Sprechen Sie mit dem Datenschutzbeauftragten,
wenn Sie neue Prozesse mit personenbezogenen Daten einführen wollen.

### Rechtsgrundlage
DSGVO Art. 5, 13, 32, 33 | §30 Abs. 2 Nr. 7 BSIG (Schulungspflicht)."""

DEFAULT_CONTENT['remote_work'] = """## Sicheres Homeoffice & VPN — Pflichtunterweisung

### Homeoffice-Risiken
Im Homeoffice fehlen Schutzmechanismen des Firmennetzwerks (Firewall, IDS, NAC).
Das macht Remote-Arbeitsplätze zu einem bevorzugten Angriffsziel.

### Grundregeln im Homeoffice

**Netzwerk & Verbindung**
- Immer über das **Firmen-VPN** arbeiten — kein direkter Internetzugang zu Firmensystemen
- Nur das **eigene (gesicherte) WLAN** verwenden — kein öffentliches WLAN (Café, Bahn, Hotel)
- Wenn öffentliches WLAN unvermeidbar: zusätzlich VPN aktiv lassen
- Router-Passwort geändert? Standard-Passwörter sind bekannte Angriffsziele

**Geräte**
- Nur **vom Unternehmen genehmigte Geräte** für Arbeit verwenden
- Kein Mischen von privaten und beruflichen Aktivitäten auf einem Gerät
- Betriebssystem und Software aktuell halten (automatische Updates aktivieren)
- Bildschirm sperren beim Verlassen — auch im eigenen Zuhause (Kinder, Besuch)

**Daten & Dokumente**
- Keine Firmendaten auf privaten Cloud-Diensten (Dropbox, iCloud, Google Drive)
- Ausgedruckte Dokumente sicher aufbewahren und schreddern
- Vertrauliche Meetings: Tür schließen, kein Mithören durch Dritte

**Videokonferenzen**
- Hintergrund prüfen (keine vertraulichen Infos sichtbar)
- Unbeteiligte Personen nicht im Bild
- Genehmigtes Tool verwenden (Teams, Webex — kein privates Zoom ohne Freigabe)

### Was tun bei Sicherheitsproblemen im Homeoffice?
1. IT-Sicherheit / Helpdesk kontaktieren (Nummer im Intranet)
2. Gerät vom Netzwerk trennen wenn Infekt vermutet wird
3. Vorfall dokumentieren

### Rechtsgrundlage
§30 Abs. 2 Nr. 7, 10 BSIG | BSI-Empfehlungen für Homeoffice (BSI-Leitfaden)."""

DEFAULT_CONTENT['social_media'] = """## Social Media & OSINT-Risiken — Pflichtunterweisung

### Social Media als Angriffsfläche
Angreifer nutzen öffentlich verfügbare Informationen (OSINT — Open Source Intelligence),
um gezielte Angriffe zu planen. **LinkedIn, Xing, Facebook, Instagram** sind Goldminen für:
- Organigramme (wer ist wofür zuständig?)
- Technologie-Stack (welche Systeme werden genutzt?)
- Mitarbeiter-Namen für Phishing-Angriffe ("Ihr Kollege Hans Meier bat mich...")
- Urlaubszeiten für gezielte Angriffe bei geringer Besetzung

### Vishing & Pretexting
"Vishing" = Voice-Phishing per Telefon. Angreifer rufen an als:
- IT-Support ("Ich brauche Ihr Passwort zur Fehlersuche")
- BSI-Mitarbeiter ("NIS2-Prüfung — senden Sie uns Ihre Zugangsdaten")
- Vorgesetzter (Stimme gefälscht per AI-Deepfake)

**Regel**: Kein legitimes Unternehmen oder Behörde fragt telefonisch nach Passwörtern.

### Was Sie im Umgang mit Social Media beachten müssen

**Beruflich**
- Keine Infos über interne Systeme, Projekte oder Kunden posten
- Keine Fotos aus dem Büro mit sichtbaren Bildschirmen / Whiteboards
- Keine Organigramme oder Prozessdiagramme öffentlich teilen
- Job-Ausschreibungen verraten Technologien — prüfen Sie, was nötig ist

**Privat (mit Auswirkung auf die Firma)**
- Eindeutige Assoziation mit dem Arbeitgeber = erhöhte Angriffsfläche
- Urlaubsankündigungen = Information für Angreifer

### Vorfälle melden
Social Engineering-Versuche (Anrufe, Nachrichten, ungewöhnliche Kontaktanfragen)
gehören an die IT-Sicherheit gemeldet — auch wenn nichts passiert ist.
Diese Informationen helfen, gezielte Angriffskampagnen zu erkennen.

### Rechtsgrundlage
§30 Abs. 2 Nr. 7 BSIG | BSI-Grundschutz ORP.3 (Sensibilisierung und Schulung)."""

DEFAULT_CONTENT['incident'] = """## Vorfallmeldung & Notfallprozesse — Pflichtunterweisung

### Was ist ein Sicherheitsvorfall?
Ein Sicherheitsvorfall (Incident) ist jedes Ereignis, das die **Vertraulichkeit, Integrität
oder Verfügbarkeit** von IT-Systemen oder Daten beeinträchtigt oder beeinträchtigen könnte:

| Schweregrad | Beispiele |
|---|---|
| **Kritisch** | Ransomware, Datenleck mit personenbezogenen Daten, Totalausfall kritischer Systeme |
| **Hoch** | Unauthorisierter Zugriff auf Systeme, Datei-Exfiltration entdeckt |
| **Mittel** | Phishing-Mail geöffnet + Link geklickt, verdächtige Anmeldung |
| **Niedrig** | Spam-Kampagne, Passwort-Reset ohne Eigeninitiative |

### Ihr Meldeweg — Was tun bei einem Vorfall?

**Schritt 1 — Sofortmaßnahme (erste 5 Minuten)**
- Ruhe bewahren, nicht selbst versuchen zu "reparieren"
- Gerät vom Netzwerk trennen, wenn Infekt vermutet wird
- Alles dokumentieren: Was haben Sie gesehen? Wann? Welches Gerät?

**Schritt 2 — Melden (erste 30 Minuten)**
- **Interne Notfallnummer** anrufen (im Intranet / Aushang)
- E-Mail an it-security@[ihr-unternehmen].de mit Kurzbeurteilung
- Vorgesetzten informieren

**Schritt 3 — Nicht tun**
- Gerät nicht ausschalten (Forensik-Beweise gehen verloren)
- Keine Dateien löschen oder verschieben
- Keine Screenshots teilen (Datenschutz)
- Nicht mit Dritten über den Vorfall sprechen (interne Kommunikation zuerst)

### BSI-Meldepflichten nach §32 BSIG (für Ihre IT-Abteilung)
Als NIS2-Einrichtung gelten gesetzliche Fristen nach Entdeckung eines erheblichen Vorfalls:
- **24 Stunden**: Frühwarnung an BSI
- **72 Stunden**: Erste Meldung mit Bewertung
- **30 Tage**: Abschlussbericht

**Sie als Mitarbeiter müssen sofort intern melden** — die IT-Sicherheit übernimmt die BSI-Kommunikation.

### Rechtsgrundlage
§30 Abs. 2 Nr. 2 BSIG (Incident Response) | §32 BSIG (BSI-Meldepflicht) | §30 Nr. 7 (Schulung)."""

DEFAULT_CONTENT['access_control'] = """## Zugangskontrolle & Berechtigungen — Pflichtunterweisung

### Warum Zugangskontrolle?
Das **Prinzip der minimalen Rechte** (Least Privilege) besagt: Jeder Mitarbeiter erhält nur
die Zugriffsrechte, die er für seine Arbeit tatsächlich braucht — nicht mehr.

Insider-Bedrohungen (absichtlich oder versehentlich) verursachen **34 % aller Datenpannen**
(Verizon DBIR 2024). Zu weit gefasste Rechte verstärken jeden Schaden.

### Ihre Zugriffsrechte — Grundregeln

**Anfordern und Freigeben**
- Neue Zugriffsrechte immer über das offizielle Berechtigungsformular anfordern
- Genehmigung durch Vorgesetzten erforderlich — kein informelles "Kurz mal einloggen"
- Temporäre Zugriffsrechte nach Ende des Projekts zurückgeben

**Konten & Passwörter**
- **Keine Account-Weitergabe** — jede Person hat ihr eigenes Konto
- Vertretungsregelungen über HR/IT einrichten — nicht über Passwort-Weitergabe
- Verdächtige Anmeldungen (ungewöhnliche Zeiten, Orte) sofort melden

**Privilegierte Konten (Admin)**
- Admin-Rechte nur für konkrete Aufgaben verwenden — danach abmelden
- Kein Surfen oder E-Mails lesen mit Admin-Account
- Jede Admin-Aktion ist protokolliert

**Beim Ausscheiden von Kollegen**
- IT-Sicherheit sofort informieren — Zugangsrechte werden deaktiviert
- Gemeinsam genutzte Passwörter (falls unvermeidbar) sofort ändern

### Zugriffsüberprüfungen
Mindestens **einmal jährlich** überprüft die IT-Abteilung alle Berechtigungen.
Wenn Sie von einer solchen Prüfung kontaktiert werden — antworten Sie zeitnah.
Nicht mehr benötigte Zugriffsrechte werden entfernt.

### MFA — Pflicht für kritische Systeme
- Remote Access (VPN, RDP): MFA immer aktiv
- Cloud-Dienste (Microsoft 365, Google): MFA aktivieren
- Finanz- und HR-Systeme: MFA Pflicht

### Rechtsgrundlage
§30 Abs. 2 Nr. 9 BSIG (Zugangskontrolle) | Nr. 10 (MFA) | Nr. 7 (Schulung)."""

DEFAULT_CONTENT['cloud_security'] = """## Cloud-Sicherheit — Pflichtunterweisung

### Cloud-Nutzung im Unternehmen
Cloud-Dienste bieten Flexibilität, schaffen aber neue Risiken.
Als NIS2-Einrichtung sind wir für die **Sicherheit unserer Cloud-Umgebung mitverantwortlich**
(Shared Responsibility Model).

### Was ist das Shared Responsibility Model?
| Bereich | Cloud-Anbieter | Ihr Unternehmen |
|---|---|---|
| Physische Infrastruktur | ✅ Verantwortung | — |
| Netzwerk / Hypervisor | ✅ Verantwortung | — |
| Betriebssystem (IaaS) | Teilweise | ✅ Verantwortung |
| Anwendungen | — | ✅ Verantwortung |
| **Daten & Identitäten** | — | ✅ **Vollständig Ihre Verantwortung** |

**Fazit**: Datenverlust durch Fehlkonfiguration oder gestohlene Zugangsdaten liegt bei Ihnen.

### Häufige Cloud-Sicherheitsfehler (die Sie vermeiden können)

**Shadow IT — Verbotene Cloud-Nutzung**
- Keine privaten Konten für Firmendaten verwenden (iCloud, Google Drive privat)
- Keine nicht genehmigten SaaS-Tools für Projektarbeit (Trello privat, Notion privat)
- Neue Cloud-Dienste immer über IT-Sicherheit freigeben lassen

**Zugangsdaten schützen**
- Cloud-Zugangsdaten nie in Code-Repositories (GitHub!) einchecken
- API-Keys und Secrets in Passwort-Manager oder Secret Manager speichern
- MFA für alle Cloud-Dienste aktivieren

**Fehlkonfigurationen**
- Keine öffentlichen S3-Buckets / Blob-Storage ohne explizite Freigabe
- Shared-Links für Dokumente: Zeitlimit setzen und nur an konkrete Empfänger

### Genehmigte Cloud-Dienste (Beispiele)
Nutzen Sie **nur** die von der IT freigegebenen Dienste. Im Zweifelsfall fragen Sie nach.

### Datenspeicherort (DSGVO)
EU-Datenschutzrecht erfordert, dass personenbezogene Daten bevorzugt in der EU gespeichert werden.
Prüfen Sie bei neuen Diensten, wo Daten verarbeitet werden (Datenschutzerklärung des Anbieters).

### Rechtsgrundlage
§30 Abs. 2 Nr. 4 BSIG (Supply Chain / Cloud-Anbieter) | Nr. 7 (Schulung) | DSGVO Art. 28 (AVV)."""


def register_training_routes(bp):

    # ── List ──────────────────────────────────────────────────────
    @bp.route('/training/')
    @login_required
    @require_plan("professional")
    def training_list():
        trainings = SecurityTraining.query.filter_by(user_id=current_user.id)\
            .order_by(SecurityTraining.created_at.desc()).all()
        return render_template('nis2/training/list.html',
                               trainings=trainings,
                               topics=dict(TRAINING_TOPICS))

    # ── Create ────────────────────────────────────────────────────
    @bp.route('/training/create', methods=['GET', 'POST'])
    @login_required
    @require_plan("professional")
    def training_create():
        if request.method == 'POST':
            topic = request.form.get('topic', 'general')
            title = request.form.get('title', '').strip()
            content_md = request.form.get('content_md', '').strip()
            summary = request.form.get('summary', '').strip()
            due_date_str = request.form.get('due_date', '')

            # Parse audience: one per line — "Name <email>" or just "email"
            raw_audience = request.form.get('audience', '')
            audience = _parse_audience(raw_audience)

            if not title:
                flash('Bitte einen Titel angeben.', 'danger')
                return redirect(url_for('nis2.training_create'))
            if not content_md:
                flash('Inhalt darf nicht leer sein.', 'danger')
                return redirect(url_for('nis2.training_create'))

            due_date = None
            if due_date_str:
                try:
                    due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
                except ValueError:
                    pass

            training = SecurityTraining(
                user_id=current_user.id,
                title=title,
                topic=topic,
                content_md=content_md,
                summary=summary or None,
                due_date=due_date,
                status='draft',
            )
            training.set_audience(audience)
            db.session.add(training)
            db.session.commit()

            flash('Schulung erstellt.', 'success')
            return redirect(url_for('nis2.training_detail', training_id=training.id))

        # Pre-fill content based on topic param
        prefill_topic = request.args.get('topic', 'general')
        prefill_content = DEFAULT_CONTENT.get(prefill_topic, DEFAULT_CONTENT['general'])

        # Load TeamGuard members as audience suggestions
        team_members = _get_team_members()

        return render_template('nis2/training/create.html',
                               topics=TRAINING_TOPICS,
                               prefill_content=prefill_content,
                               prefill_topic=prefill_topic,
                               team_members=team_members)

    # ── Detail / management view ──────────────────────────────────
    @bp.route('/training/<int:training_id>')
    @login_required
    @require_plan("professional")
    def training_detail(training_id):
        training = SecurityTraining.query.filter_by(
            id=training_id, user_id=current_user.id
        ).first_or_404()
        acks = TrainingAcknowledgment.query.filter_by(training_id=training.id)\
            .order_by(TrainingAcknowledgment.sent_at.asc()).all()
        return render_template('nis2/training/detail.html',
                               training=training,
                               acks=acks,
                               topics=dict(TRAINING_TOPICS))

    # ── §38 BSIG: GF-Bestätigung (Verantwortliche/r liest zuerst) ──
    @bp.route('/training/<int:training_id>/gf-acknowledge', methods=['POST'])
    @login_required
    @require_plan("professional")
    def training_gf_acknowledge(training_id):
        training = SecurityTraining.query.filter_by(
            id=training_id, user_id=current_user.id
        ).first_or_404()

        if training.gf_acknowledged:
            flash('Sie haben diese Schulung bereits als Verantwortliche/r bestätigt.', 'info')
            return redirect(url_for('nis2.training_detail', training_id=training_id))

        gf_name = request.form.get('gf_name', '').strip()
        if not gf_name:
            flash('Bitte geben Sie Ihren vollständigen Namen als Verantwortliche/r ein.', 'danger')
            return redirect(url_for('nis2.training_detail', training_id=training_id))

        ip = (request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
              or request.remote_addr or '')

        training.gf_acknowledged = True
        training.gf_acknowledged_at = datetime.now(UTC)
        training.gf_acknowledged_name = gf_name
        training.gf_acknowledged_ip = ip[:45]
        db.session.commit()

        flash(
            f'Bestätigung durch {gf_name} gespeichert (§38 BSIG). '
            'Sie können die Schulung jetzt an Ihre Mitarbeiter versenden.',
            'success',
        )
        return redirect(url_for('nis2.training_detail', training_id=training_id))

    # ── Send to audience ──────────────────────────────────────────
    @bp.route('/training/<int:training_id>/send', methods=['POST'])
    @login_required
    @require_plan("professional")
    def training_send(training_id):
        training = SecurityTraining.query.filter_by(
            id=training_id, user_id=current_user.id
        ).first_or_404()

        # §38 BSIG: GF muss die Schulung selbst zuerst bestätigt haben
        if not training.gf_acknowledged:
            flash(
                '§38 BSIG: Sie müssen die Schulung zunächst selbst lesen und als '
                'Verantwortliche/r bestätigen, bevor sie an Mitarbeiter versendet werden kann.',
                'warning',
            )
            return redirect(url_for('nis2.training_detail', training_id=training_id))

        audience = training.get_audience()
        if not audience:
            flash('Keine Empfänger angegeben.', 'warning')
            return redirect(url_for('nis2.training_detail', training_id=training_id))

        sent_count = 0
        error_count = 0

        for person in audience:
            name = person.get('name', '')
            email = person.get('email', '')
            if not email:
                continue

            # Check if already sent to this email
            existing = TrainingAcknowledgment.query.filter_by(
                training_id=training_id, recipient_email=email
            ).first()
            if existing:
                continue  # Skip re-send

            token = secrets.token_urlsafe(32)
            ack = TrainingAcknowledgment(
                training_id=training_id,
                recipient_name=name or email,
                recipient_email=email,
                token=token,
            )
            db.session.add(ack)
            db.session.flush()  # get ID

            ok = _send_training_email(training, name or email, email, token)
            if ok:
                sent_count += 1
            else:
                error_count += 1

        training.status = 'sent'
        training.sent_at = datetime.now(UTC)
        db.session.commit()

        if sent_count:
            flash(f'Schulung an {sent_count} Empfänger versendet.', 'success')
        if error_count:
            flash(f'{error_count} E-Mails konnten nicht zugestellt werden (SMTP-Fehler).', 'warning')

        return redirect(url_for('nis2.training_detail', training_id=training_id))

    # ── Resend to single recipient ────────────────────────────────
    @bp.route('/training/<int:training_id>/resend/<int:ack_id>', methods=['POST'])
    @login_required
    @require_plan("professional")
    def training_resend(training_id, ack_id):
        training = SecurityTraining.query.filter_by(
            id=training_id, user_id=current_user.id
        ).first_or_404()
        ack = TrainingAcknowledgment.query.filter_by(
            id=ack_id, training_id=training_id
        ).first_or_404()

        ok = _send_training_email(
            training, ack.recipient_name, ack.recipient_email, ack.token
        )
        if ok:
            flash(f'Erinnerung an {ack.recipient_email} gesendet.', 'success')
        else:
            flash('E-Mail-Versand fehlgeschlagen — SMTP prüfen.', 'danger')
        return redirect(url_for('nis2.training_detail', training_id=training_id))

    # ── Admin-Override: mark ack as confirmed (for in-person training) ──
    @bp.route('/training/<int:training_id>/ack/<int:ack_id>/admin-confirm', methods=['POST'])
    @login_required
    @require_plan("professional")
    def training_admin_confirm(training_id, ack_id):
        training = SecurityTraining.query.filter_by(
            id=training_id, user_id=current_user.id
        ).first_or_404()
        ack = TrainingAcknowledgment.query.filter_by(
            id=ack_id, training_id=training_id
        ).first_or_404()

        if ack.acknowledged:
            flash('Bereits bestätigt.', 'info')
            return redirect(url_for('nis2.training_detail', training_id=training_id))

        ack.acknowledged = True
        ack.acknowledged_at = datetime.now(UTC)
        ack.confirmed_name = f'Admin-Bestätigung ({current_user.email})'
        db.session.commit()
        flash(f'Bestätigung für {ack.recipient_name} manuell gesetzt.', 'success')
        return redirect(url_for('nis2.training_detail', training_id=training_id))

    # ── Acknowledgment page (public — no login required) ──────────
    @bp.route('/training/ack/<token>', methods=['GET', 'POST'])
    def training_ack(token):
        ack = TrainingAcknowledgment.query.filter_by(token=token).first_or_404()
        training = SecurityTraining.query.get_or_404(ack.training_id)

        # Record first open
        if not ack.opened_at:
            ack.opened_at = datetime.now(UTC)
            db.session.commit()

        if request.method == 'POST':
            if ack.acknowledged:
                flash('Sie haben diese Schulung bereits bestätigt.', 'info')
                return render_template('nis2/training/ack.html',
                                       ack=ack, training=training, already_done=True)

            confirmed_name = request.form.get('confirmed_name', '').strip()
            if not confirmed_name:
                flash('Bitte geben Sie Ihren vollständigen Namen ein.', 'danger')
                return render_template('nis2/training/ack.html',
                                       ack=ack, training=training)

            # Get real IP (behind proxy)
            ip = (request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
                  or request.remote_addr or '')
            # Limit to 45 chars (IPv6 max)
            ip = ip[:45]

            ack.acknowledged = True
            ack.acknowledged_at = datetime.now(UTC)
            ack.confirmed_name = confirmed_name
            ack.ip_address = ip
            db.session.commit()

            return render_template('nis2/training/ack_done.html',
                                   ack=ack, training=training)

        return render_template('nis2/training/ack.html',
                               ack=ack, training=training)

    # ── Certificate download (public) ─────────────────────────────
    @bp.route('/training/ack/<token>/certificate')
    def training_certificate(token):
        from flask import make_response
        ack = TrainingAcknowledgment.query.filter_by(
            token=token, acknowledged=True
        ).first_or_404()
        training = SecurityTraining.query.get_or_404(ack.training_id)
        html = render_template('nis2/training/certificate.html',
                               ack=ack, training=training)
        safe_name = ack.confirmed_name.replace(' ', '_').replace('/', '_')
        filename = f'zertifikat_{safe_name}_{training.id}.html'
        response = make_response(html)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    # ── Compliance report (for auditor / BSI) ─────────────────────
    @bp.route('/training/<int:training_id>/report')
    @login_required
    @require_plan("professional")
    def training_report(training_id):
        training = SecurityTraining.query.filter_by(
            id=training_id, user_id=current_user.id
        ).first_or_404()
        acks = TrainingAcknowledgment.query.filter_by(training_id=training.id)\
            .order_by(TrainingAcknowledgment.acknowledged.desc(),
                      TrainingAcknowledgment.acknowledged_at.asc()).all()
        return render_template('nis2/training/report.html',
                               training=training,
                               acks=acks,
                               now=datetime.now(UTC),
                               topics=dict(TRAINING_TOPICS))

    # ── Delete (draft only) ───────────────────────────────────────
    @bp.route('/training/<int:training_id>/delete', methods=['POST'])
    @login_required
    @require_plan("professional")
    def training_delete(training_id):
        training = SecurityTraining.query.filter_by(
            id=training_id, user_id=current_user.id
        ).first_or_404()
        if training.status != 'draft':
            flash('Nur Entwürfe können gelöscht werden.', 'warning')
            return redirect(url_for('nis2.training_detail', training_id=training_id))
        db.session.delete(training)
        db.session.commit()
        flash('Schulung gelöscht.', 'success')
        return redirect(url_for('nis2.training_list'))


# ── Helpers ───────────────────────────────────────────────────────

def _get_team_members():
    """Return TeamGuard members for the current user, if any."""
    try:
        from app.teamguard.models import TeamMember
        return TeamMember.query.filter_by(
            owner_user_id=current_user.id, is_active=True
        ).order_by(TeamMember.full_name).all()
    except Exception:
        return []


def _parse_audience(raw: str) -> list:
    """
    Parse textarea input into list of {name, email}.
    Supports formats:
      - max@example.com
      - Max Mustermann <max@example.com>
      - max@example.com; Max Mustermann
    One entry per line.
    """
    import re
    result = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # "Name <email>" format
        m = re.match(r'^(.+?)\s*<([^>]+)>\s*$', line)
        if m:
            result.append({'name': m.group(1).strip(), 'email': m.group(2).strip().lower()})
            continue
        # "email; Name" format
        if ';' in line:
            parts = [p.strip() for p in line.split(';', 1)]
            email = parts[0].lower()
            name = parts[1] if len(parts) > 1 else ''
            result.append({'name': name, 'email': email})
            continue
        # Just email
        if '@' in line:
            result.append({'name': '', 'email': line.lower()})
    return result


def _send_training_email(training: SecurityTraining,
                          recipient_name: str,
                          recipient_email: str,
                          token: str) -> bool:
    """Send acknowledgment link email via SMTP."""
    try:
        smtp_server = current_app.config.get('MAIL_SERVER')
        smtp_port = int(current_app.config.get('MAIL_PORT', 587))
        smtp_user = current_app.config.get('MAIL_USERNAME')
        smtp_pass = current_app.config.get('MAIL_PASSWORD')
        mail_sender = current_app.config.get('MAIL_DEFAULT_SENDER', smtp_user)

        if not all([smtp_server, smtp_user, smtp_pass, mail_sender]):
            logger.warning('Training email: SMTP not configured — skipping')
            return False

        ack_url = url_for('nis2.training_ack', token=token, _external=True)
        due_str = training.due_date.strftime('%d.%m.%Y') if training.due_date else '–'

        subject = f'[Pflichtschulung] {training.title}'

        text_body = (
            f'Hallo {recipient_name},\n\n'
            f'Sie werden gebeten, die folgende Pflichtschulung bis {due_str} zu lesen '
            f'und Ihre Kenntnisnahme zu bestätigen:\n\n'
            f'📋 {training.title}\n\n'
            f'Bitte klicken Sie auf den folgenden Link:\n{ack_url}\n\n'
            f'Nach dem Lesen bestätigen Sie mit Ihrem Namen — es dauert ca. 3-5 Minuten.\n\n'
            f'Mit freundlichen Grüßen\nIhr Sicherheitsteam'
        )
        html_body = f"""
<html><body style="font-family:Arial,sans-serif;max-width:600px;margin:auto;color:#333">
<div style="background:#1a56db;padding:20px;border-radius:8px 8px 0 0">
  <h2 style="color:white;margin:0">🛡️ Pflichtschulung: Cybersicherheit</h2>
</div>
<div style="padding:24px;background:#f9fafb;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px">
  <p>Hallo <strong>{recipient_name}</strong>,</p>
  <p>Sie werden gebeten, folgende <strong>Pflichtunterweisung</strong> bis
     <strong>{due_str}</strong> zu lesen und zu bestätigen:</p>
  <div style="background:white;border-left:4px solid #1a56db;padding:12px 16px;margin:16px 0;border-radius:4px">
    <strong>📋 {training.title}</strong>
  </div>
  <p>Nach dem Lesen geben Sie bitte Ihren Namen als Bestätigung ein.
     Das dauert ca. 3–5 Minuten.</p>
  <div style="text-align:center;margin:24px 0">
    <a href="{ack_url}"
       style="background:#1a56db;color:white;padding:14px 28px;border-radius:6px;
              text-decoration:none;font-weight:bold;font-size:16px">
      📖 Schulung lesen &amp; bestätigen
    </a>
  </div>
  <p style="font-size:12px;color:#6b7280">
    Dieser Link ist personalisiert und gilt nur für {recipient_email}.<br>
    Grundlage: §30 Abs. 2 Nr. 7 BSIG (NIS2-Richtlinie).
  </p>
</div>
</body></html>"""

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = mail_sender
        msg['To'] = recipient_email
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return True

    except Exception as e:
        logger.error(f'Training email send failed to {recipient_email}: {e}', exc_info=True)
        return False
