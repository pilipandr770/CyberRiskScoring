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
            # The banner/search string we matched against — kept separately
            "queried_product": product,
            # ...from what the CVE record actually says it affects. These can
            # differ (loose substring match), and collapsing them into one
            # "product" field used to launder a wrong attribution into
            # fluent report prose with no way to tell it happened.
            "product": m.get("product") or product,
            "matched_vendor": m.get("vendor") or "",
            "cve": m["cve_id"],
            "cvss": cvss_score,
            "epss": info.get("epss", 0.0),
            "kev": info.get("kev", False),
            "category": category,
            "description": m.get("description") or "",
            "version_verified": m.get("version_verified", "no_version_given"),
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
        # only when it genuinely didn't provide one. `or 7.0` would also
        # replace a real score of 0.0 (falsy) — use an explicit None check.
        _real_score = (svc.get("cve_scores") or {}).get(cve)
        cvss_score = _real_score if _real_score is not None else 7.0
        category = "iot_ot_cve" if svc.get("is_iot_ot") else "internet_facing_data"
        # Shodan already gives us a trusted CVE ID directly (not a fuzzy
        # product-name match) — look up its real description by that exact
        # ID so the report doesn't have to describe it from the ID alone.
        cached = cve_dataset.get_by_cve_id(cve)
        findings.append({
            "key": f"{ip}:{svc.get('port')}:{cve}",
            "source": "shodan",
            "product": svc.get("product") or f"service on port {svc.get('port')}",
            "cve": cve,
            "cvss": cvss_score,
            "epss": info.get("epss", 0.0),
            "kev": info.get("kev", False),
            "category": category,
            "description": (cached or {}).get("description") or "",
            "version_verified": "n/a",
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


def _collect_data_quality_warnings(
    shodan_hosts: list[dict], nmap_hosts: list[dict], cve_cache_ready: bool
) -> list[str]:
    """A failed data source (revoked/rate-limited Shodan key, nmap error, an
    empty CVE cache) must never be silently indistinguishable from "this
    infrastructure is clean" — that's the single most misleading thing this
    report could do to an underwriter. Surface every real failure by name;
    "no Shodan data for this host" is excluded because it's a normal,
    non-failure outcome (the host just isn't indexed)."""
    warnings = []
    for h in shodan_hosts:
        err = h.get("error")
        if err and err != "no Shodan data for this host":
            warnings.append(f"Shodan-Abfrage für {h['ip']} nicht erfolgreich: {err}")
    for h in nmap_hosts:
        err = h.get("error")
        if err:
            warnings.append(f"nmap-Scan für {h['ip']} nicht erfolgreich: {err}")
    if not cve_cache_ready:
        warnings.append(
            "Lokaler CVE-Cache ist nicht verfügbar (Erstbefüllung läuft noch oder "
            "letzter Refresh fehlgeschlagen) — der CVE-Abgleich für erkannte "
            "Produkt-/Versions-Banner wurde für diesen Scan übersprungen."
        )
    return warnings


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
    shodan_hosts: list[dict] = []
    nmap_hosts: list[dict] = []
    if assessment.office_ip:
        tier = "Tier 1"
        shodan_hosts = await shodan_client.lookup_range(assessment.office_ip)
        shodan_findings = await _findings_from_shodan(shodan_hosts)
        nmap_hosts = await nmap_scan.scan_range(assessment.office_ip)
        nmap_findings = await _findings_from_nmap(nmap_hosts)

    recon_findings = await _findings_from_recon(recon)
    all_findings = _dedupe_by_cve(shodan_findings + nmap_findings + recon_findings)

    data_quality_warnings = _collect_data_quality_warnings(
        shodan_hosts, nmap_hosts, cve_dataset.cache_status().get("ready", False)
    )

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

    # Decompose the one aggregate damage figure back onto individual
    # findings (proportional to each finding's own contribution to
    # raw_score) so the report can say "this finding accounts for
    # approximately €X of the total" instead of only a company-wide number.
    damage_shares = risk_formula.finding_damage_shares(all_findings, agg["raw_score"], damage)
    for f in all_findings:
        share = damage_shares.get(f["key"], {"damage_share_eur": 0.0, "counted_in_score": False})
        f["damage_share_eur"] = share["damage_share_eur"]
        f["counted_in_score"] = share["counted_in_score"]

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
        data_quality_warnings=data_quality_warnings,
    )

    client_report_md = await client_report_generator.build_client_report(
        company_name=assessment.company_name,
        domain=assessment.domain,
        tier=tier,
        findings=all_findings,
        risk_tier=tier_label,
        formal_check=formal_check,
        data_quality_warnings=data_quality_warnings,
    )

    return {
        "tier": tier,
        "raw_findings_json": json.dumps(
            {
                "recon": recon, "findings": all_findings, "formal_check": formal_check,
                "data_quality_warnings": data_quality_warnings,
            },
            default=str,
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
