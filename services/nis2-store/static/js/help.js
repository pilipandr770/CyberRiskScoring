/**
 * NIS2 Compliance Platform — Contextual Help System
 * Detects current page via data-page attribute and renders
 * page-specific German help content in a Bootstrap Offcanvas.
 */

const HELP_CONTENT = {

  'nis2.dashboard': {
    title: 'Dashboard — Compliance-Übersicht',
    sections: [
      {
        heading: 'Was zeigt der Compliance-Score?',
        body: `<p>Der <strong>Compliance-Score</strong> (0–100%) gibt an, wie vollständig Ihre NIS2-Maßnahmen umgesetzt sind. Er berechnet sich aus dem Durchschnitt aller 10 Sicherheitsmaßnahmen gemäß §30 BSIG.</p>
<ul>
  <li><span class="badge bg-success">80–100%</span> — Gut: Die meisten Pflichten erfüllt</li>
  <li><span class="badge bg-warning text-dark">50–79%</span> — Teilweise: Handlungsbedarf</li>
  <li><span class="badge bg-danger">0–49%</span> — Kritisch: Sofortmaßnahmen nötig</li>
</ul>`
      },
      {
        heading: 'Was sind die §30 BSIG-Maßnahmen?',
        body: `<p>Das <strong>BSIG §30</strong> (BSI-Gesetz) schreibt 10 technische und organisatorische Maßnahmen vor, die Unternehmen ab einer gewissen Größe umsetzen müssen:</p>
<ol style="font-size:.85rem;">
  <li>Risikoanalyse & Informationssicherheitsrichtlinien</li>
  <li>Bewältigung von Sicherheitsvorfällen</li>
  <li>Business Continuity & Krisenmanagement</li>
  <li>Sicherheit der Lieferkette</li>
  <li>Sicherheit bei Erwerb, Entwicklung & Wartung</li>
  <li>Schwachstellenmanagement & Offenlegung</li>
  <li>Bewertung der Wirksamkeit von Maßnahmen</li>
  <li>Cyberhygiene & Schulungen</li>
  <li>Kryptografie & Verschlüsselung</li>
  <li>Zugriffskontrolle & Asset-Management</li>
</ol>`
      },
      {
        heading: 'Wie verbessere ich meinen Score?',
        body: `<p>Die Karte <strong>„Nächste Schritte"</strong> zeigt priorisierte Aufgaben. Generell gilt:</p>
<ul>
  <li>Fehlende ISMS-Dokumente erstellen</li>
  <li>Risikoregister befüllen und Maßnahmen dokumentieren</li>
  <li>Schulungen für Mitarbeiter anlegen und versenden</li>
  <li>IT-Assets inventarisieren</li>
  <li>Lieferanten erfassen und bewerten</li>
</ul>`
      },
      {
        heading: 'Schlüsselbegriffe',
        body: `<dl class="row" style="font-size:.82rem;">
  <dt class="col-5">NIS2</dt><dd class="col-7">EU-Richtlinie zur Netzwerk- und Informationssicherheit (2022/2555)</dd>
  <dt class="col-5">BSIG</dt><dd class="col-7">BSI-Gesetz — deutsches Umsetzungsgesetz der NIS2-Richtlinie</dd>
  <dt class="col-5">BSI</dt><dd class="col-7">Bundesamt für Sicherheit in der Informationstechnik</dd>
  <dt class="col-5">ISMS</dt><dd class="col-7">Informationssicherheits-Managementsystem (z.B. nach ISO 27001)</dd>
</dl>`
      }
    ]
  },

  'nis2.bsi_registration_landing': {
    title: 'BSI-Registrierung',
    sections: [
      {
        heading: 'Wer muss sich beim BSI registrieren?',
        body: `<p>Unternehmen, die als <strong>wichtige</strong> oder <strong>besonders wichtige Einrichtung</strong> gemäß NIS2 eingestuft sind, müssen sich beim BSI registrieren. Dazu gehören typischerweise:</p>
<ul>
  <li>Unternehmen ab 50 Mitarbeitern oder €10 Mio. Jahresumsatz in kritischen Sektoren</li>
  <li>Sektoren: Energie, Verkehr, Gesundheit, Wasser, Digitale Infrastruktur, Finanzen u.a.</li>
</ul>`
      },
      {
        heading: 'Was ist die Registrierungsfrist?',
        body: `<p>Die Registrierung beim BSI muss <strong>spätestens 3 Monate</strong> nach Feststellung der Einrichtungseigenschaft erfolgen. Das NIS2UmsuCG (Umsetzungsgesetz) ist seit Oktober 2024 in Kraft.</p>
<p>Nutzen Sie das BSI-MUK-Portal: <a href="https://muk.bsi.bund.de" target="_blank" class="text-primary">muk.bsi.bund.de</a></p>`
      },
      {
        heading: 'Wie funktioniert der Registrierungs-Assistent?',
        body: `<p>Der Assistent führt Sie in mehreren Schritten durch die Selbsteinschätzung:</p>
<ol>
  <li>Branchenzuordnung (Sektor/Teilsektor)</li>
  <li>Größenklasse (Mitarbeiter, Umsatz)</li>
  <li>Einrichtungstyp (wichtig/besonders wichtig)</li>
  <li>Exportfunktion für das BSI-Portal</li>
</ol>`
      }
    ]
  },

  'nis2.isms_overview': {
    title: 'ISMS-Dokumente',
    sections: [
      {
        heading: 'Was ist ein ISMS?',
        body: `<p>Ein <strong>Informationssicherheits-Managementsystem (ISMS)</strong> ist ein systematischer Ansatz zur Verwaltung sensibler Unternehmensdaten. Es umfasst Richtlinien, Prozesse und Kontrollen zum Schutz der Informationssicherheit — typischerweise nach <strong>ISO/IEC 27001</strong>.</p>`
      },
      {
        heading: 'Welche Dokumente sind Pflicht?',
        body: `<p>NIS2 / §30 BSIG erfordert dokumentierte Nachweise für alle Sicherheitsmaßnahmen. Typische Pflichtdokumente:</p>
<ul style="font-size:.85rem;">
  <li>Informationssicherheitsrichtlinie (IS-Policy)</li>
  <li>Risikobeurteilung und -behandlungsplan</li>
  <li>Notfall- und Business-Continuity-Plan</li>
  <li>Schulungs- und Awareness-Konzept</li>
  <li>Patch-Management-Richtlinie</li>
  <li>Zugriffskontrollkonzept</li>
  <li>Incident-Response-Plan</li>
</ul>`
      },
      {
        heading: 'Wie funktioniert die KI-Generierung?',
        body: `<p>Die Plattform nutzt <strong>Mistral AI</strong> — ein KI-Modell aus der EU (Frankreich) mit Datenverarbeitung ausschließlich in Europa — um auf Basis Ihrer Unternehmensdaten (Branche, Größe, Risikolage) passgenaue ISMS-Dokumente zu erstellen. Das Interview-Verfahren sammelt alle nötigen Informationen — die KI erstellt dann rechtssichere Texte auf Deutsch.</p>`
      }
    ]
  },

  'nis2.risk_list': {
    title: 'Risikoregister',
    sections: [
      {
        heading: 'Was ist das Risikoregister?',
        body: `<p>Das <strong>Risikoregister</strong> ist die zentrale Dokumentation aller identifizierten IT-Sicherheitsrisiken. §30 Abs. 1 BSIG schreibt eine regelmäßige Risikoanalyse vor — das Register ist der Nachweis dafür.</p>`
      },
      {
        heading: 'Wie wird der Risikoscore berechnet?',
        body: `<p>Der Score ergibt sich aus: <strong>Wahrscheinlichkeit × Auswirkung</strong> (je 1–5):</p>
<table class="table table-sm" style="font-size:.8rem;">
  <thead><tr><th>Score</th><th>Bewertung</th><th>Farbe</th></tr></thead>
  <tbody>
    <tr><td>1–4</td><td>Niedrig</td><td><span class="badge bg-success">grün</span></td></tr>
    <tr><td>5–9</td><td>Mittel</td><td><span class="badge bg-warning text-dark">gelb</span></td></tr>
    <tr><td>10–16</td><td>Hoch</td><td><span class="badge bg-danger">orange</span></td></tr>
    <tr><td>17–25</td><td>Kritisch</td><td><span class="badge bg-danger">rot</span></td></tr>
  </tbody>
</table>`
      },
      {
        heading: 'Was sind Risikobehandlungsoptionen?',
        body: `<p>Für jedes Risiko wählen Sie eine Behandlungsstrategie:</p>
<dl class="row" style="font-size:.83rem;">
  <dt class="col-4">Akzeptieren</dt><dd class="col-8">Risiko bewusst in Kauf nehmen (dokumentieren)</dd>
  <dt class="col-4">Behandeln</dt><dd class="col-8">Maßnahmen umsetzen, um Wahrscheinlichkeit/Auswirkung zu reduzieren</dd>
  <dt class="col-4">Übertragen</dt><dd class="col-8">An Dritte auslagern (z.B. Cyber-Versicherung)</dd>
  <dt class="col-4">Vermeiden</dt><dd class="col-8">Risikoursache ganz beseitigen</dd>
</dl>`
      },
      {
        heading: 'Wie lese ich die Risikomatrix?',
        body: `<p>Die 5×5-Matrix zeigt die Verteilung aller Risiken nach Wahrscheinlichkeit (Y-Achse) und Auswirkung (X-Achse). Je weiter oben rechts, desto kritischer. Klicken Sie auf eine Zelle, um die darin enthaltenen Risiken zu sehen.</p>`
      }
    ]
  },

  'nis2.incidents_list': {
    title: 'Incident Response',
    sections: [
      {
        heading: 'Was ist die Meldepflicht nach §32 BSIG?',
        body: `<p>Bei erheblichen Sicherheitsvorfällen müssen betroffene Unternehmen das BSI in mehreren Stufen benachrichtigen:</p>
<ul>
  <li><strong>24 Stunden:</strong> Frühwarnung — erste Meldung an das BSI</li>
  <li><strong>72 Stunden:</strong> Zwischenmeldung — erste Bewertung</li>
  <li><strong>30 Tage:</strong> Abschlussbericht — vollständige Analyse</li>
</ul>
<p class="text-danger small">Verstöße können Bußgelder bis zu €10 Mio. oder 2% des Jahresumsatzes nach sich ziehen.</p>`
      },
      {
        heading: 'Was gilt als „erheblicher Vorfall"?',
        body: `<p>Ein Vorfall ist erheblich (§31 BSIG), wenn er:</p>
<ul style="font-size:.85rem;">
  <li>Erhebliche Betriebsstörungen verursacht hat oder verursachen kann</li>
  <li>Andere Personen oder Unternehmen erheblich beeinträchtigt</li>
  <li>Finanziellen Verlust für Betroffene verursacht</li>
</ul>`
      },
      {
        heading: 'Wie nutze ich den KI-Assistenten?',
        body: `<p>Bei jedem Vorfall können Sie per Klick einen <strong>BSI-Meldungsentwurf</strong> per KI generieren lassen. Die KI analysiert Ihre Vorfallsdaten und erstellt einen formalgerechten Meldungstext, den Sie prüfen, anpassen und als „eingereicht" markieren können.</p>`
      },
      {
        heading: 'Was ist DSGVO Art. 33?',
        body: `<p>Bei Datenschutzverletzungen (z.B. Datenleck) gilt zusätzlich die <strong>72-Stunden-Meldepflicht</strong> an die zuständige Datenschutz-Aufsichtsbehörde (Landesdatenschutzbehörde). Aktivieren Sie beim Vorfall die Option „DSGVO-relevant".</p>`
      }
    ]
  },

  'nis2.supply_chain_dashboard': {
    title: 'Lieferkettensicherheit',
    sections: [
      {
        heading: 'Warum ist die Lieferkette relevant?',
        body: `<p>§30 Abs. 2 Nr. 4 BSIG verpflichtet Unternehmen zur <strong>Absicherung der Lieferkette</strong>. Viele erfolgreiche Cyberangriffe erfolgen über unsichere Zulieferer (z.B. SolarWinds, NotPetya). Sie müssen die Sicherheitsstandards Ihrer wichtigen Lieferanten bewerten und dokumentieren.</p>`
      },
      {
        heading: 'Was ist ein AVV?',
        body: `<p>Ein <strong>Auftragsverarbeitungsvertrag (AVV)</strong> ist bei Lieferanten, die personenbezogene Daten verarbeiten, nach DSGVO Art. 28 Pflicht. Die Plattform hilft Ihnen zu verfolgen, bei welchen Lieferanten ein AVV noch aussteht.</p>`
      },
      {
        heading: 'Wie werden Lieferanten bewertet?',
        body: `<p>Jeder Lieferant erhält ein <strong>Risikolevel</strong> basierend auf:</p>
<ul style="font-size:.85rem;">
  <li>Kritikalität für Ihre Geschäftsprozesse</li>
  <li>Art der übermittelten Daten</li>
  <li>Vorhandensein von ISO 27001 / SOC2-Zertifizierungen</li>
  <li>Ergebnis des Sicherheitsfragebogens</li>
</ul>`
      }
    ]
  },

  'nis2.dsgvo_list': {
    title: 'DSGVO Art. 30 — Verarbeitungsverzeichnis',
    sections: [
      {
        heading: 'Was ist das Verarbeitungsverzeichnis?',
        body: `<p>Das <strong>Verarbeitungsverzeichnis</strong> (auch: Verzeichnis der Verarbeitungstätigkeiten) ist nach <strong>DSGVO Art. 30</strong> für Unternehmen ab 250 Mitarbeitern Pflicht — für kleinere Unternehmen bei risikoreichen Verarbeitungen. Es dokumentiert alle Vorgänge, bei denen personenbezogene Daten verarbeitet werden.</p>`
      },
      {
        heading: 'Was muss dokumentiert werden?',
        body: `<p>Für jede Verarbeitungstätigkeit müssen Sie angeben:</p>
<ul style="font-size:.85rem;">
  <li>Zweck der Verarbeitung (z.B. Gehaltsabrechnung)</li>
  <li>Kategorien betroffener Personen</li>
  <li>Kategorien personenbezogener Daten</li>
  <li>Empfänger der Daten (intern/extern)</li>
  <li>Speicherdauer</li>
  <li>Technische und organisatorische Maßnahmen (TOMs)</li>
  <li>Drittlandübermittlung (falls vorhanden)</li>
</ul>`
      },
      {
        heading: 'Was ist eine DSFA?',
        body: `<p>Eine <strong>Datenschutz-Folgenabschätzung (DSFA)</strong> ist nach DSGVO Art. 35 bei besonders risikoreichen Verarbeitungen Pflicht (z.B. Profiling, Gesundheitsdaten, Videoüberwachung). Die Plattform markiert solche Einträge automatisch.</p>`
      }
    ]
  },

  'nis2.training_list': {
    title: 'Sicherheitsschulungen',
    sections: [
      {
        heading: 'Warum sind Schulungen Pflicht?',
        body: `<p>§30 Abs. 3 BSIG schreibt vor, dass Mitarbeiter regelmäßig in Cybersicherheit geschult werden müssen. Menschliches Fehlverhalten ist die häufigste Ursache für Sicherheitsvorfälle. Die Teilnahme muss <strong>dokumentiert und nachweisbar</strong> sein.</p>`
      },
      {
        heading: 'Wie funktioniert der Schulungsworkflow?',
        body: `<ol style="font-size:.85rem;">
  <li>Schulung erstellen (Thema, Inhalt, Zielgruppe)</li>
  <li>Per E-Mail an Mitarbeiter versenden — jeder erhält einen einzigartigen Link</li>
  <li>Mitarbeiter lesen Inhalt und bestätigen per Unterschrift/Klick</li>
  <li>Die Plattform protokolliert Datum, IP und Bestätigung</li>
  <li>Export als PDF-Nachweis für Audits</li>
</ol>`
      },
      {
        heading: 'Welche Themen sind empfohlen?',
        body: `<ul style="font-size:.85rem;">
  <li>Phishing & Social Engineering</li>
  <li>Sichere Passwörter & MFA</li>
  <li>DSGVO-Grundlagen & Datenschutz am Arbeitsplatz</li>
  <li>Incident Reporting (Was tue ich bei einem Vorfall?)</li>
  <li>Mobile Device & Homeoffice-Sicherheit</li>
  <li>Clean Desk Policy</li>
</ul>`
      }
    ]
  },

  'nis2.monitoring_dashboard': {
    title: 'Security Monitoring',
    sections: [
      {
        heading: 'Was wird überwacht?',
        body: `<p>Das <strong>Continuous Monitoring</strong> prüft Ihre öffentlich erreichbaren Domains/IPs regelmäßig auf Schwachstellen:</p>
<ul style="font-size:.85rem;">
  <li>TLS/SSL-Zertifikat (Gültigkeit, Protokollversion)</li>
  <li>HTTP Security Headers (CSP, HSTS, X-Frame-Options…)</li>
  <li>Offene Ports und exponierte Dienste</li>
  <li>Bekannte CVE-Schwachstellen</li>
  <li>DNS-Konfiguration (SPF, DMARC, DNSSEC)</li>
</ul>`
      },
      {
        heading: 'Was bedeutet der Score?',
        body: `<p>Der <strong>Sicherheitsscore (0–100)</strong> bewertet den aktuellen Zustand eines Ziels. Er basiert auf CVSS-Bewertungen gefundener Schwachstellen:</p>
<ul>
  <li><span class="badge bg-success">80–100</span> Gut gesichert</li>
  <li><span class="badge bg-warning text-dark">50–79</span> Verbesserungsbedarf</li>
  <li><span class="badge bg-danger">0–49</span> Kritische Lücken</li>
</ul>`
      },
      {
        heading: 'Was ist CVSS?',
        body: `<p>Das <strong>Common Vulnerability Scoring System (CVSS)</strong> ist ein Branchenstandard zur Bewertung von Sicherheitslücken (0.0–10.0). Je höher der Wert, desto kritischer die Schwachstelle. CVSS 7.0+ gilt als „hoch", 9.0+ als „kritisch".</p>`
      }
    ]
  },

  'nis2.site_audit_index': {
    title: 'Site-Audit',
    sections: [
      {
        heading: 'Was prüft der Site-Audit?',
        body: `<p>Der <strong>Site-Audit</strong> führt eine automatisierte Sicherheitsprüfung Ihrer Website durch und bewertet:</p>
<ul style="font-size:.85rem;">
  <li>SSL/TLS-Konfiguration und Zertifikat</li>
  <li>HTTP Security Headers (HSTS, CSP, X-Content-Type-Options…)</li>
  <li>Sicherheitsrelevante Cookie-Attribute (Secure, HttpOnly, SameSite)</li>
  <li>Offene Redirect-Schwachstellen</li>
  <li>Veraltete JavaScript-Bibliotheken</li>
</ul>`
      },
      {
        heading: 'Welche Headers sind Pflicht?',
        body: `<dl class="row" style="font-size:.8rem;">
  <dt class="col-5">HSTS</dt><dd class="col-7">Erzwingt HTTPS-Verbindungen</dd>
  <dt class="col-5">CSP</dt><dd class="col-7">Verhindert XSS-Angriffe</dd>
  <dt class="col-5">X-Frame-Options</dt><dd class="col-7">Verhindert Clickjacking</dd>
  <dt class="col-5">X-Content-Type</dt><dd class="col-7">Verhindert MIME-Sniffing</dd>
  <dt class="col-5">Referrer-Policy</dt><dd class="col-7">Kontrolliert Referrer-Header</dd>
</dl>`
      },
      {
        heading: 'Was tue ich mit den Ergebnissen?',
        body: `<p>Jeder Befund enthält eine <strong>Handlungsempfehlung</strong> mit konkreten Schritten zur Behebung. Die Ergebnisse können als PDF-Bericht exportiert und für Audits oder Behörden verwendet werden.</p>`
      }
    ]
  },

  'nis2.asset_list': {
    title: 'IT-Asset-Management',
    sections: [
      {
        heading: 'Warum ein IT-Asset-Inventar?',
        body: `<p>§30 Abs. 2 Nr. 10 BSIG fordert ein <strong>IT-Asset-Management</strong>. Sie können nur schützen, was Sie kennen. Das Inventar dokumentiert alle IT-Systeme, auf die Sicherheitsmaßnahmen angewendet werden müssen.</p>`
      },
      {
        heading: 'Was gehört ins Inventar?',
        body: `<ul style="font-size:.85rem;">
  <li>Server (physisch und virtuell)</li>
  <li>Netzwerkgeräte (Router, Firewalls, Switches)</li>
  <li>Endgeräte (Laptops, PCs, Smartphones)</li>
  <li>Cloud-Dienste und SaaS-Applikationen</li>
  <li>Industrielle Steuerungssysteme (OT/ICS) — falls relevant</li>
  <li>Software und Lizenzen</li>
</ul>`
      },
      {
        heading: 'Welche Felder sind wichtig?',
        body: `<dl class="row" style="font-size:.83rem;">
  <dt class="col-5">Kritikalität</dt><dd class="col-7">Wie wichtig ist das Asset für den Geschäftsbetrieb?</dd>
  <dt class="col-5">Verantwortlicher</dt><dd class="col-7">Wer ist für Sicherheit und Wartung zuständig?</dd>
  <dt class="col-5">Patch-Status</dt><dd class="col-7">Ist die Software aktuell? Wann zuletzt gepatcht?</dd>
  <dt class="col-5">Standort</dt><dd class="col-7">Physisch oder Cloud (wichtig für DSGVO)</dd>
</dl>`
      }
    ]
  },

  'nis2.fristen': {
    title: 'Fristenkalender',
    sections: [
      {
        heading: 'Welche Fristen gelten nach NIS2?',
        body: `<p>Das NIS2-Umsetzungsgesetz (NIS2UmsuCG) legt verbindliche Fristen fest:</p>
<ul style="font-size:.85rem;">
  <li><strong>Sofort:</strong> Erstregistrierung beim BSI nach Feststellung der Einrichtungseigenschaft (3 Monate)</li>
  <li><strong>24 Stunden:</strong> Frühwarnung bei erheblichem Vorfall</li>
  <li><strong>72 Stunden:</strong> Zwischenmeldung + DSGVO-Meldung</li>
  <li><strong>30 Tage:</strong> Abschlussbericht Sicherheitsvorfall</li>
  <li><strong>Jährlich:</strong> Erneuerung von ISMS-Dokumenten, Schulungen, Risikoreviews</li>
</ul>`
      },
      {
        heading: 'Was sind die Bußgelder bei Verstößen?',
        body: `<p>Bei Verstößen gegen NIS2 / BSIG drohen empfindliche Sanktionen:</p>
<ul style="font-size:.85rem;">
  <li>Besonders wichtige Einrichtungen: bis zu <strong>€10 Mio.</strong> oder <strong>2% des weltweiten Jahresumsatzes</strong></li>
  <li>Wichtige Einrichtungen: bis zu <strong>€7 Mio.</strong> oder <strong>1,4% des Jahresumsatzes</strong></li>
  <li>Geschäftsführer können <strong>persönlich haftbar</strong> gemacht werden</li>
</ul>`
      },
      {
        heading: 'Wie nutze ich den Fristenkalender?',
        body: `<p>Der Kalender aggregiert automatisch alle laufenden Fristen aus:</p>
<ul style="font-size:.85rem;">
  <li>Offenen Sicherheitsvorfällen (BSI-Meldepflichten)</li>
  <li>Anstehenden ISMS-Dokumentenreviews</li>
  <li>Lieferantenüberprüfungen</li>
  <li>Schulungs-Wiederholungsintervallen</li>
</ul>`
      }
    ]
  },

  'nis2.compliance_report': {
    title: '§39 Compliance-Bericht',
    sections: [
      {
        heading: 'Was ist der §39-Bericht?',
        body: `<p>§39 BSIG verpflichtet Geschäftsführer und Vorstände, die Umsetzung der Sicherheitsmaßnahmen <strong>jährlich zu dokumentieren und zu genehmigen</strong>. Der Compliance-Bericht dient als dieser Nachweis — auch gegenüber dem BSI bei Prüfungen.</p>`
      },
      {
        heading: 'Was enthält der Bericht?',
        body: `<ul style="font-size:.85rem;">
  <li>Aktueller Compliance-Score und Trend</li>
  <li>Umsetzungsstand aller 10 §30-Maßnahmen</li>
  <li>Übersicht offener und abgeschlossener Vorfälle</li>
  <li>Risikoregister-Zusammenfassung</li>
  <li>Schulungsnachweis (Abdeckungsquote)</li>
  <li>Lieferketten-Bewertungsübersicht</li>
</ul>`
      },
      {
        heading: 'Wer muss den Bericht genehmigen?',
        body: `<p>Nach §38 BSIG tragen <strong>Geschäftsführer und Vorstände persönlich</strong> die Verantwortung für die Umsetzung der NIS2-Maßnahmen. Sie müssen den Bericht formal genehmigen und sind bei Verstößen persönlich haftbar. Die Unterschrift im System dokumentiert diese Genehmigung.</p>`
      }
    ]
  }

};

function buildHelpHTML(page) {
  const data = HELP_CONTENT[page];
  if (!data) {
    return `<div class="p-4 text-muted">
      <i class="bi bi-info-circle me-2"></i>
      Für diese Seite ist noch kein Hilfetext verfügbar.
    </div>`;
  }

  const items = data.sections.map((s, i) => `
    <div class="accordion-item border-0 border-bottom">
      <h2 class="accordion-header">
        <button class="accordion-button ${i > 0 ? 'collapsed' : ''} py-3"
          type="button" data-bs-toggle="collapse"
          data-bs-target="#helpSection${i}" style="font-size:.88rem;font-weight:600;">
          ${s.heading}
        </button>
      </h2>
      <div id="helpSection${i}" class="accordion-collapse collapse ${i === 0 ? 'show' : ''}">
        <div class="accordion-body" style="font-size:.84rem;line-height:1.6;">
          ${s.body}
        </div>
      </div>
    </div>
  `).join('');

  return `
    <div class="px-3 pt-3 pb-2">
      <h6 class="text-primary mb-0" style="font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;">
        <i class="bi bi-map me-1"></i>Hilfe zu
      </h6>
      <div class="fw-600" style="font-size:.95rem;">${data.title}</div>
    </div>
    <div class="accordion accordion-flush" id="helpAccordion">
      ${items}
    </div>
    <div class="p-3 text-center" style="border-top:1px solid #f0f0f0;">
      <small class="text-muted">
        <i class="bi bi-envelope me-1"></i>
        Fragen? <a href="mailto:info@andrii-it.de" class="text-primary">info@andrii-it.de</a>
      </small>
    </div>
  `;
}

function initHelp() {
  const main = document.querySelector('main[data-page]');
  if (!main) return;

  const page = main.dataset.page;
  const body = document.getElementById('helpOffcanvasBody');
  if (body) {
    body.innerHTML = buildHelpHTML(page);
  }

  // Pulse the FAB once for first-time visitors on a page
  const seenKey = 'help_seen_' + page;
  if (!localStorage.getItem(seenKey)) {
    const fab = document.getElementById('helpFab');
    if (fab) {
      fab.classList.add('help-fab-pulse');
      setTimeout(() => fab.classList.remove('help-fab-pulse'), 3000);
    }
    document.getElementById('helpOffcanvas')?.addEventListener('show.bs.offcanvas', () => {
      localStorage.setItem(seenKey, '1');
      const fab = document.getElementById('helpFab');
      if (fab) fab.classList.remove('help-fab-pulse');
    }, { once: true });
  }
}

document.addEventListener('DOMContentLoaded', initHelp);
