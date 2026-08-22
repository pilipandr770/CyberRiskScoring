"""Orchestrates the full M1 scan: recon -> Shodan (Tier 1) -> CVE enrichment
-> risk-multiplier -> report. This is the single entry point the intake
router calls after a client assessment is submitted."""

import json

from app.config import BASE_LOSS_EUR, THIRD_PARTY_EDGE_SERVER_BANNERS
from app.scoring import (
    client_report_generator, cve_dataset, cve_enrich, cvss_calc, nmap_scan,
    nuclei_scan, passive_recon, regulatory_check, report_generator,
    risk_formula, shodan_client,
)


async def _matched_cve_findings(product: str, version: str | None, category: str, key_prefix: str) -> list[dict]:
    """Look up a product/version in the local CVE cache and turn any hits
    into findings, enriched with EPSS/KEV. Returns [] if the cache isn't
    populated yet or nothing matches — callers fall back accordingly."""
    matches = cve_dataset.match(product, version)
    if not matches:
        return []
    cve_ids = [m["cve_id"] for m in matches]
    enriched = await cve_enrich.enrich_cves(cve_ids)
    findings = []
    for m in matches:
        info = enriched.get(m["cve_id"], {"epss": 0.0, "kev": False})
        cvss = cvss_calc.score_from_number(m.get("cvss_score"))
        cvss_score = cvss[0] if cvss else 7.0
        findings.append({
            "key": f"{key_prefix}:{m['cve_id']}",
            "source": "cve_cache",
            "product": product,
            "cve": m["cve_id"],
            "cvss": cvss_score,
            "epss": info.get("epss", 0.0),
            "kev": info.get("kev", False),
            "category": category,
        })
    return findings


async def _findings_from_shodan(shodan_hosts: list[dict]) -> list[dict]:
    findings = []
    all_cves = []
    unmatched_services = []  # (ip, svc) — Shodan gave a product but no CVE list
    for host in shodan_hosts:
        for svc in host.get("services", []):
            if svc.get("cves"):
                for cve in svc["cves"]:
                    all_cves.append((host["ip"], svc, cve))
            elif svc.get("product"):
                unmatched_services.append((host["ip"], svc))

    cve_ids = list({c for _, _, c in all_cves})
    enriched = await cve_enrich.enrich_cves(cve_ids)

    for ip, svc, cve in all_cves:
        info = enriched.get(cve, {"epss": 0.0, "kev": False})
        # Shodan sometimes hands us a real per-CVE cvss score (preserved in
        # cve_scores by shodan_client); fall back to a conservative 7.0/High
        # only when it genuinely didn't provide one.
        cvss_score = (svc.get("cve_scores") or {}).get(cve) or 7.0
        category = "iot_ot_cve" if svc.get("is_iot_ot") else "internet_facing_data"
        findings.append({
            "key": f"{ip}:{svc.get('port')}:{cve}",
            "source": "shodan",
            "product": svc.get("product") or f"service on port {svc.get('port')}",
            "cve": cve,
            "cvss": cvss_score,
            "epss": info.get("epss", 0.0),
            "kev": info.get("kev", False),
            "category": category,
        })

    # For services Shodan didn't already tag with a CVE, try the local
    # CVE-cache before falling back to a bare "exposed panel" finding.
    for ip, svc in unmatched_services:
        category = "iot_ot_cve" if svc.get("is_iot_ot") else "internet_facing_data"
        matched = await _matched_cve_findings(svc["product"], svc.get("version"), category, f"{ip}:{svc.get('port')}")
        if matched:
            findings.extend(matched)
        elif svc.get("is_iot_ot"):
            findings.append({
                "key": f"{ip}:{svc.get('port')}:panel",
                "source": "shodan",
                "product": svc.get("product") or "IoT/OT device",
                "cve": None,
                "cvss": 5.0,
                "epss": 0.0,
                "kev": False,
                "category": "iot_ot_panel",
            })

    return findings


async def _findings_from_recon(recon: dict) -> list[dict]:
    """Tier 0 signal: missing HTTPS/HSTS as misconfig findings, plus a local
    CVE-cache lookup on whatever the `Server` header reveals (e.g.
    "nginx/1.18.0")."""
    findings = []
    for probe in recon.get("probes", []):
        if not probe.get("reachable"):
            continue
        if not probe.get("https"):
            findings.append({
                "key": f"{probe['host']}:no-https",
                "source": "recon",
                "product": probe["host"],
                "cve": None,
                "cvss": 5.3,
                "epss": 0.0,
                "kev": False,
                "category": "misconfig",
            })
        elif not probe.get("has_hsts"):
            findings.append({
                "key": f"{probe['host']}:no-hsts",
                "source": "recon",
                "product": probe["host"],
                "cve": None,
                "cvss": 3.1,
                "epss": 0.0,
                "kev": False,
                "category": "misconfig",
            })

        server = probe.get("server")
        if server and server.lower().strip() not in THIRD_PARTY_EDGE_SERVER_BANNERS:
            matched = await _matched_cve_findings(server, None, "internet_facing_generic", probe["host"])
            findings.extend(matched)

    urls = [
        f"{'https' if p.get('https') else 'http'}://{p['host']}"
        for p in recon.get("probes", []) if p.get("reachable")
    ]
    findings.extend(await nuclei_scan.scan_urls(urls))
    return findings


async def _findings_from_nmap(nmap_hosts: list[dict]) -> list[dict]:
    """Tier 1 supplement to Shodan — nmap's own version-detection scan,
    matched against the local CVE cache the same way as every other
    product/version source in this pipeline."""
    findings = []
    for host in nmap_hosts:
        for svc in host.get("services", []):
            product = " ".join(p for p in (svc.get("product"), svc.get("version")) if p).strip()
            if not product:
                continue
            key_prefix = f"{host['ip']}:{svc.get('port')}"
            matched = await _matched_cve_findings(product, svc.get("version"), "internet_facing_data", key_prefix)
            findings.extend(matched)
    return findings


def _dedupe_by_cve(findings: list[dict]) -> list[dict]:
    """Shodan, nmap, and nuclei can each independently surface the same
    real CVE on the same host (e.g. version-detected two ways). Same CVE
    anywhere in one scan is treated as one finding, keeping whichever copy
    has the higher CVSS — avoids double-counting it in the score and
    showing the same weakness twice in the report."""
    best_by_cve: dict[str, dict] = {}
    no_cve = []
    for f in findings:
        cve = f.get("cve")
        if not cve:
            no_cve.append(f)
            continue
        existing = best_by_cve.get(cve)
        if existing is None or (f.get("cvss") or 0) > (existing.get("cvss") or 0):
            best_by_cve[cve] = f
    return list(best_by_cve.values()) + no_cve


async def run_scan(assessment) -> dict:
    """assessment: ClientAssessment ORM row. Returns everything needed to
    populate a ScanResult row."""
    recon = await passive_recon.run_tier0(assessment.domain)

    tier = "Tier 0"
    shodan_findings: list[dict] = []
    nmap_findings: list[dict] = []
    if assessment.office_ip:
        tier = "Tier 1"
        shodan_hosts = await shodan_client.lookup_range(assessment.office_ip)
        shodan_findings = await _findings_from_shodan(shodan_hosts)
        nmap_hosts = await nmap_scan.scan_range(assessment.office_ip)
        nmap_findings = await _findings_from_nmap(nmap_hosts)

    recon_findings = await _findings_from_recon(recon)
    all_findings = _dedupe_by_cve(shodan_findings + nmap_findings + recon_findings)

    formal_check = await regulatory_check.check_formal_requirements(assessment.domain)

    reg_points = risk_formula.compliance_gap_points(assessment)
    agg = risk_formula.aggregate_raw_score(all_findings, reg_points)
    multiplier = risk_formula.raw_score_to_multiplier(agg["raw_score"])
    agg["multiplier"] = multiplier

    damage = risk_formula.expected_damage(assessment.industry, multiplier)
    fine = risk_formula.fine_exposure(
        assessment.annual_turnover_eur, all_findings, formal_check["has_violation"], assessment.employee_band
    )
    ransom = risk_formula.ransom_exposure(assessment.annual_turnover_eur)
    premium = risk_formula.premium_range(damage)
    tier_label = risk_formula.risk_tier_label(multiplier)

    scoring = {"raw_score_info": agg}

    report_md = await report_generator.build_report(
        company_name=assessment.company_name,
        domain=assessment.domain,
        industry=assessment.industry,
        tier=tier,
        findings=all_findings,
        scoring=scoring,
        damage=damage,
        fine=fine,
        ransom=ransom,
        premium=premium,
        risk_tier=tier_label,
        recon=recon,
        formal_check=formal_check,
    )

    client_report_md = await client_report_generator.build_client_report(
        company_name=assessment.company_name,
        domain=assessment.domain,
        tier=tier,
        findings=all_findings,
        risk_tier=tier_label,
        formal_check=formal_check,
    )

    return {
        "tier": tier,
        "raw_findings_json": json.dumps(
            {"recon": recon, "findings": all_findings, "formal_check": formal_check}, default=str
        ),
        "raw_score": agg["raw_score"],
        "multiplier": multiplier,
        "expected_damage_eur": damage,
        "fine_range_low_eur": fine.get("low"),
        "fine_range_high_eur": fine.get("high"),
        "fine_estimate_eur": fine.get("estimate"),
        "premium_range_low_eur": premium[0],
        "premium_range_high_eur": premium[1],
        "risk_tier": tier_label,
        "report_markdown": report_md,
        "client_report_markdown": client_report_md,
    }
