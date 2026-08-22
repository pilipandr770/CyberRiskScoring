import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/data/risk_scanner.db")
SESSION_SECRET = os.getenv("SESSION_SECRET", "dev-only-change-me")

# Secure by default (cookie only sent by the browser over https) since
# production always sits behind Traefik/Cloudflare TLS. Local docker-compose
# dev (plain http://localhost:8000) must explicitly opt out via .env — see
# .env.example.
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
SESSION_MAX_AGE_SECONDS = int(os.getenv("SESSION_MAX_AGE_SECONDS", str(8 * 3600)))

# Login brute-force throttling (slowapi, keyed by client IP).
LOGIN_RATE_LIMIT = os.getenv("LOGIN_RATE_LIMIT", "10/minute")

# Machine API — replaces the old external "black box" pentesting microservice
# that Module 3 (nis2.store) used to call. Same request/response contract
# (POST /api/audit, GET /api/audit/{id}, .../findings) so their existing
# client code is a drop-in URL swap, not a rewrite.
M3_API_KEY = os.getenv("M3_API_KEY", "")

# Outbound — called when an underwriter accepts a decision, to provision the
# client's account on the post-contract platform. Optional: if unset, the
# decision is still recorded, just not auto-provisioned (logged instead).
M3_PROVISIONING_WEBHOOK_URL = os.getenv("M3_PROVISIONING_WEBHOOK_URL", "")
M3_PROVISIONING_API_KEY = os.getenv("M3_PROVISIONING_API_KEY", "")

# Placeholder single-tenant branding — becomes a per-insurer DB field once
# multi-tenancy is built; one env var is enough for this MVP's one insurer.
INSURER_NAME = os.getenv("INSURER_NAME", "Ihre Cyber-Versicherung")

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "claude-sonnet-4-6")

# Reserved for future passive-recon enrichment (VirusTotal passive DNS,
# URLScan lookup, OTX threat intel, IPinfo ASN/geo) — mirrors BB_Assist's
# Phase 1 passive chain. Not wired into the pipeline yet; the app works
# fine without them, per the free-tier framing they were given under.
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")

# Local CVE cache — sparse-cloned from cvelistV5 (CVE JSON 5.0 records) and
# refreshed periodically, so CPE/product-version matching doesn't depend on
# NVD's live rate-limited API for every lookup. See scoring/cve_dataset.py.
CVE_CSV_REMOTE_URL = os.getenv("CVE_CSV_REMOTE_URL", "https://github.com/CVEProject/cvelistV5")
CVE_CSV_REFRESH_HOURS = int(os.getenv("CVE_CSV_REFRESH_HOURS", "24"))
CVE_CVELIST_YEARS_BACK = int(os.getenv("CVE_CVELIST_YEARS_BACK", "8"))
CVE_CVELIST_MAX_ROWS = int(os.getenv("CVE_CVELIST_MAX_ROWS", "20000"))
CVE_CACHE_REPO_DIR = os.path.join(BASE_DIR, "data", "cvelistV5_sparse")
CVE_CACHE_CSV = os.path.join(BASE_DIR, "data", "cve_cache.csv")

# Generic-layer benchmark constants (documented assumptions — see M2 report appendix).
# Recalibrate once real claims data is available.
BASE_LOSS_EUR = 83_000  # BSI Lagebericht average German cyber-damage benchmark

INDUSTRY_FACTOR = {
    "retail": 1.1,
    "healthcare": 1.3,
    "finance": 1.4,
    "manufacturing": 1.0,
    "it_software": 1.2,
    "logistics": 1.1,
    "other": 1.0,
}

# Saturating-multiplier curve parameters (raw_score -> risk multiplier).
MULTIPLIER_MAX = 4.0
MULTIPLIER_K = 15.0
MULTIPLIER_FLOOR_CLEAN = 0.85  # applied when raw_score is ~0 (clean scan discount)

# DSGVO fine is computed via the real DSK-Bußgeldkonzept (2019) — see
# scoring/dsk_bussgeld.py. Confirmed current as of 2026-08-21: no updated
# version has been published; it only lapses once the EDPB/EDSA issues its
# own binding fine-calculation guidelines, which hasn't happened. Important
# legal caveat (must stay visible in the report, not just here): German
# courts are NOT bound by this model and have adjusted/rejected DPA fines
# based on it, especially for larger companies where it tends to overshoot
# — treat the output as a DPA-internal calculation aid / starting point,
# not a guaranteed fine.
#
# NIS2UmsuCG (Germany's NIS2 transposition) entered into force 2025-12-06 —
# confirmed real, current law as of 2026-08-21, not a draft. Fine caps use
# whichever is HIGHER of the percentage or the fixed euro cap, same pattern
# as DSGVO Art. 83. Applicability threshold: NIS2 generally only applies to
# companies with >=50 employees OR >€10M annual turnover, AND operating in
# a regulated sector (§28 BSIG) — most Kleinst-/kleine-GmbH clients in this
# product's actual target segment fall below this threshold entirely, so
# the exposure should read "not applicable" for them, not just a smaller
# number. Sector regulation isn't checked yet (no NACE->NIS2-sector mapping
# built) — size threshold is checked, sector applicability is flagged as
# still requiring review.
NIS2_FINE_PCT = {
    "wichtige": (0.014, 7_000_000),      # 1.4% or €7M, whichever is higher
    "wesentliche": (0.02, 10_000_000),   # 2.0% or €10M, whichever is higher
}
NIS2_SIZE_THRESHOLD_TURNOVER_EUR = 10_000_000
NIS2_SIZE_THRESHOLD_EMPLOYEE_BANDS = {"50-249", "250+"}

# Cyber-extortion (ransom) sublimit estimate — % of turnover, documented IR-
# industry benchmark (e.g. Coveware case reporting), not a legal figure.
RANSOM_PCT_OF_TURNOVER = (0.01, 0.03)
RANSOM_FLOOR_EUR = 5_000
RANSOM_CEILING_EUR = 2_000_000

# Premium = expected_damage / target loss ratio. Anchored to GDV's published
# German cyber insurance Schaden-Kosten-Quote: 64.7% (2020), 123.7% (2021,
# crisis year — excluded as unsustainable), 77.7% (2022), 97% (2023).
# Confirmed 2026-08-21, source: GDV market statistics / "Cyberversicherer
# kehren in die Gewinnzone zurück". Target range brackets the two healthiest
# realized years rather than repricing last year's volatile actual.
PREMIUM_TARGET_LOSS_RATIO = (0.55, 0.75)

# Exposure-class weights for the risk-multiplier categorization table.
CATEGORY_WEIGHTS = {
    "iot_ot_cve": 1.6,          # camera/POS/NVR with a matched CVE
    "iot_ot_panel": 1.0,        # exposed admin panel, no CVE matched yet
    "internet_facing_data": 1.5,
    "internet_facing_generic": 1.0,
    "misconfig": 0.8,
    "internal_passive": 0.4,
}

# Nuclei tag filter — inverted from BB_Assist's bug-bounty filter. BB_Assist
# skips ssl/headers/cors/cookies/tech/misconfig as "noise nobody pays out
# for"; for risk scoring those are exactly the hygiene/regulatory-gap signal
# we want. Deliberately excludes exploit-oriented tags (rce/sqli/xss/ssrf/
# lfi/idor/auth-bypass/ssti/xxe) — stays inside the non-destructive boundary
# even with full client authorization to scan.
# "cve" is deliberately left out here even though it's a detection-only tag:
# it alone covers most of nuclei-templates' ~13.5k files, which turns one
# scan into a 10+ minute run against a single host. CVE coverage still
# happens — via the local cve_dataset cache on product/version banners,
# which is fast because it's a local lookup, not a live request per template.
# Nuclei's job here is what it's actually fast at: live hygiene/config checks.
NUCLEI_TAGS = "ssl,tls,headers,cors,cookies,misconfig,exposed-panel,default-login,token-disclosure,tech"
NUCLEI_SEVERITIES = "info,low,medium,high,critical"
NUCLEI_TIMEOUT_SECONDS = int(os.getenv("NUCLEI_TIMEOUT_SECONDS", "300"))
NUCLEI_RATE_LIMIT = int(os.getenv("NUCLEI_RATE_LIMIT", "150"))

# Server-header values known to be third-party CDN/WAF/reverse-proxy edges
# (Cloudflare, CloudFront, Akamai, Fastly, Sucuri, Incapsula/Imperva) rather
# than the client's own origin server. These banners carry no version and
# the client can't patch them (the vendor manages and patches their own
# edge) — matching them against the CVE cache by bare product name produced
# false positives (e.g. "Server: cloudflare" substring-matching unrelated
# CVEs from completely different Cloudflare-branded products). See
# pipeline.py's _findings_from_recon.
THIRD_PARTY_EDGE_SERVER_BANNERS = {
    "cloudflare", "cloudflare-nginx",
    "cloudfront",
    "akamaighost", "akamai",
    "fastly", "fastly-varnish",
    "sucuri/cloudproxy",
    "imperva", "incapsula",
}

# Keyword patterns used to classify Shodan products into the IoT/OT/POS bucket.
IOT_OT_KEYWORDS = [
    "hikvision", "dahua", "axis", "ip camera", "ipcamera", "dvr", "nvr",
    "webcam", "camera",
    "pos terminal", "point of sale", "verifone", "ingenico", "kasse", "kassensystem",
]
