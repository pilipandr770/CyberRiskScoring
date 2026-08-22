# CyberRiskScoring

A cyber-risk scoring and underwriting toolkit built for **regional and mid-size German cyber insurers** — the segment the established players (Kovrr, CyberCube) don't really serve, since they focus on the top five insurers. It's not a rating-only service like BitSight/SecurityScorecard either: it runs a real, non-destructive technical scan of a prospective policyholder's infrastructure, turns that into a regulator-grounded (DSGVO/NIS2) underwriting report, and — once a policy is issued — hands the client off into a compliance/monitoring platform they keep using for the life of the contract.

The product makes recommendations only. An underwriter or actuary at the insurer signs off on every price and every decision; nothing here binds the insurer automatically.

## Architecture

Three independent, Dockerized services sharing one docker-compose stack:

| Module | Service | What it does |
|---|---|---|
| 1. Cyber Resilience Assessment | [`services/risk-scanner`](services/risk-scanner) | Passive recon (DNS/CT-logs) + active non-destructive scanning (subfinder, dnsx, httpx, nuclei, nmap, Shodan) + a local CVE cache enriched with EPSS/KEV. Outputs structured findings, not a price. |
| 2. Underwriting Report | same app, `app/scoring/` | Turns Module 1's findings into a risk multiplier, an expected-damage figure, a DSGVO fine estimate (real DSK-Bußgeldkonzept methodology), a NIS2 fine estimate (NIS2UmsuCG, in force since 2025-12-06), and a premium range anchored to GDV's published loss-ratio data. Generates a client report (remediation-focused, no pricing) and an agent/underwriter report (full pricing + a fillable AVB-Cyber-shaped insurance contract draft), both exportable as PDF. |
| 3. Post-Contract Platform | [`services/nis2-store`](services/nis2-store) | Once an underwriter accepts a decision, the client is automatically provisioned an account here — NIS2/DSGVO/BSI-A5 compliance dashboard, continuous re-scanning, ISMS document generation, incident response drafting, supply-chain tracking, security training. Access is insurer-gated only; there's no public self-signup. |

The hand-off between modules is a webhook: Module 2's underwriter-decision step calls Module 3's provisioning endpoint, which creates the client's account and seeds it with the Module 1 scan that was already done — no re-entering data, no second scan needed on day one.

## Repository layout

```
services/
  risk-scanner/     Module 1 + 2 — FastAPI, SQLite
  nis2-store/        Module 3 — Flask, PostgreSQL
docker-compose.yml   Both services + Postgres, one stack
.env.example         risk-scanner config template
.env.nis2store.example   nis2-store config template
```

`reference/` (gitignored) holds prior-art source material this project was built from or against — not part of the shipped product.

## Quick start (local dev)

```bash
cp .env.example .env
cp .env.nis2store.example .env.nis2store
# fill in at least SHODAN_API_KEY / ANTHROPIC_API_KEY in .env — the app
# still runs without them, with reduced scan coverage
docker compose up -d --build
```

- risk-scanner: http://localhost:8000
- nis2-store: http://localhost:5000

Seed a risk-scanner agent login:

```bash
docker compose exec risk-scanner python seed_agent.py <username> <password>
```

nis2-store has no public registration — accounts are created only by the M2→M3 provisioning webhook (i.e. by accepting a decision in risk-scanner) or manually via its admin tooling.

## Configuration

All configuration is environment-variable driven — see `.env.example` and `.env.nis2store.example` for the full list, with inline comments explaining each one. Notable groups:

- **Scanning**: `SHODAN_API_KEY`, `ANTHROPIC_API_KEY`, nuclei tag/rate-limit tuning, local CVE-cache settings.
- **M1↔M3 machine API**: `M3_API_KEY` (inbound, nis2-store → risk-scanner), `M3_PROVISIONING_WEBHOOK_URL` / `M3_PROVISIONING_API_KEY` (outbound, risk-scanner → nis2-store on decision acceptance).
- **Session/security**: `SESSION_SECRET`, `SESSION_COOKIE_SECURE` (defaults to secure; set `false` for local http dev), `LOGIN_RATE_LIMIT`.
- **Deployment**: `RISK_SCANNER_TRAEFIK_ENABLE` / `RISK_SCANNER_DOMAIN`, `NIS2_STORE_TRAEFIK_ENABLE` / `NIS2_STORE_DOMAIN` — inert by default, only meaningful on a host that already runs Traefik with a Cloudflare-DNS-challenge (`cfdns`) cert resolver.

## Security posture

- CSRF tokens on every cookie-authenticated form in risk-scanner (login, intake, decision, contract-PDF export).
- Rate-limited login (`slowapi`, IP-aware behind Cloudflare/Traefik via `CF-Connecting-IP`).
- `Secure` + `HttpOnly` + `SameSite=Lax` session cookies, HSTS/`X-Content-Type-Options`/`X-Frame-Options` response headers.
- risk-scanner's machine API (`/api/*`) is not reachable on the public Traefik route at all — nis2-store talks to it over the internal docker network only; a `403` guard blocks any public request to that path prefix.
- nis2-store already carried Flask-WTF CSRF protection and Flask-Limiter rate limiting from its original codebase.

## Scanning boundary

Active scanning is strictly non-destructive: version/CVE fingerprinting and configuration/hygiene checks, never exploitation or PoC attempts, and never anything against third-party suppliers' own infrastructure — only assets the client itself owns and has consented to have scanned.

## CI

`.github/workflows/ci.yml` runs on every push/PR to `main`: Python syntax check for both services, the nis2-store pytest suite (in-memory SQLite, no external services needed), and a Docker build validation for both service images.

## Status

Actively developed; deployed to production for a pilot insurer. See commit history for the detailed build log — regulatory figures (DSK-Bußgeldkonzept, NIS2UmsuCG, GDV loss-ratio benchmarks) are sourced from the actual published methodologies, not invented, with citations and caveats kept in the code comments where the numbers are computed.
