"""Build a NIST/CVSS-aligned scan report with narrative and after-action steps."""

SEVERITY_WEIGHT = {
    "high": 2.0,
    "medium": 1.0,
    "low": 0.4,
    "info": 0.0,
}

NIST_RATING = (
    (1, 3, "Low"),
    (4, 6, "Medium"),
    (7, 8, "High"),
    (9, 10, "Critical"),
)


def finding(tool, severity, title, detail, evidence=""):
    return {
        "tool": tool,
        "severity": severity,
        "title": title,
        "detail": detail,
        "evidence": evidence,
    }


def _counts(findings):
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        severity = item.get("severity", "info")
        if severity in counts:
            counts[severity] += 1
    return counts


def _tool_outcomes(tool_results):
    passed = []
    failed = []
    info = []
    used = []
    for result in tool_results:
        name = result.get("tool", "unknown")
        used.append(name)
        status = (result.get("status") or "").lower()
        entry = {"tool": name, "status": status, "finding_count": len(result.get("findings") or [])}
        if status == "pass":
            passed.append(entry)
        elif status == "fail":
            failed.append(entry)
        else:
            info.append(entry)
    return {"used": used, "passed": passed, "failed": failed, "info": info}


def nist_score(findings, matched_cves=None):
    """NIST/CVSS-inspired risk score on a 1-10 scale (10 = highest risk)."""
    matched_cves = matched_cves or []
    score = 1.0
    for item in findings:
        score += SEVERITY_WEIGHT.get(item.get("severity", "info"), 0.0)
    for item in matched_cves:
        sources = item.get("sources") or []
        cvss = item.get("cvss_score")
        if isinstance(cvss, (int, float)):
            score += min(float(cvss), 10.0) / 10.0
        elif len(sources) >= 2:
            score += 1.5
        else:
            score += 1.0
    score = max(1, min(10, round(score)))
    rating = "Low"
    for low, high, label in NIST_RATING:
        if low <= score <= high:
            rating = label
            break
    return {"score": score, "scale": "1-10", "standard": "NIST_CVSS_aligned", "rating": rating}


def _explain_score(score_info, counts, outcomes, matched_cves, cross_check):
    score = score_info["score"]
    rating = score_info["rating"]
    failed = outcomes["failed"]
    passed = outcomes["passed"]
    parts = [
        f"The NIST/CVSS-aligned risk score is {score}/10 ({rating}). "
        f"Higher scores mean higher assessed risk.",
        f"The scan used {len(outcomes['used'])} arsenal tools: "
        f"{len(passed)} passed, {len(failed)} failed, and {len(outcomes['info'])} were informational.",
        f"Finding severity counts were high={counts['high']}, medium={counts['medium']}, "
        f"low={counts['low']}, info={counts['info']}.",
    ]
    if matched_cves:
        confirmed = [
            item["cve_id"]
            for item in matched_cves
            if len(item.get("sources") or []) >= 2
        ]
        parts.append(
            f"{len(matched_cves)} CVE(s) matched the target stack fingerprints. "
            f"{len(confirmed)} were cross-checked by more than one source"
            + (f" ({', '.join(confirmed[:5])})." if confirmed else ".")
        )
    else:
        parts.append("No CVE identifiers matched the observed stack fingerprints during this scan.")
    if cross_check:
        parts.append(
            "CVE feeds consulted: "
            + ", ".join(sorted((cross_check.get("by_source") or {}).keys()) or ["none"])
            + f". Multi-source confirmations in the feed set: "
            f"{cross_check.get('confirmed_by_multiple_sources', 0)}."
        )
    if failed:
        titles = ", ".join(item["tool"] for item in failed[:6])
        parts.append(f"Failed checks that raised the score: {titles}.")
    if passed:
        parts.append(
            f"Controls that passed and limited the score include: "
            f"{', '.join(item['tool'] for item in passed[:6])}."
        )
    return " ".join(parts)


def after_action_report(findings, matched_cves, outcomes, cve_knowledge=None):
    """Prioritized next steps to harden the application."""
    from ai.cve_knowledge import defense_for_cve, load_cve_entry

    steps = []
    seen = set()
    cve_knowledge = cve_knowledge or {}

    def add(priority, title, detail):
        key = (priority, title)
        if key in seen:
            return
        seen.add(key)
        steps.append({"priority": priority, "title": title, "detail": detail})

    for item in findings:
        severity = item.get("severity", "info")
        if severity not in {"high", "medium"}:
            continue
        priority = "P1" if severity == "high" else "P2"
        add(
            priority,
            item.get("title") or "Remediate finding",
            item.get("detail") or "Review and fix this finding.",
        )

    for item in matched_cves or []:
        cve_id = item.get("cve_id") or ""
        sources = ", ".join(item.get("sources") or [])
        cvss = item.get("cvss_score")
        cvss_text = f" NIST CVSS base score {cvss}." if cvss is not None else ""
        local = cve_knowledge.get(cve_id) or load_cve_entry(cve_id) or {}
        defense = local.get("defend_against") or defense_for_cve(cve_id)
        if defense:
            detail = (
                f"{defense} Sources: {sources or 'local knowledge'}.{cvss_text}"
            )
        else:
            detail = (
                f"Review {item.get('product') or item.get('vendor') or 'the affected component'} "
                f"against {cve_id} (sources: {sources}).{cvss_text} "
                f"{(item.get('description') or '')[:180]}"
            )
        add(
            "P1" if (cvss or 0) >= 7 or "cisa_kev" in (item.get("sources") or []) else "P2",
            f"Address {cve_id}",
            detail,
        )

    if outcomes.get("failed"):
        add(
            "P2",
            "Re-run failed arsenal checks after fixes",
            "After patching, re-scan with the same council tools that failed: "
            + ", ".join(item["tool"] for item in outcomes["failed"][:8])
            + ".",
        )

    add(
        "P3",
        "Keep dependency and CVE monitoring continuous",
        "Track CISA KEV, NIST NVD, and OSV regularly, pin dependencies, and apply security updates promptly.",
    )
    add(
        "P3",
        "Harden baseline web controls",
        "Confirm HTTPS, CSP, secure session cookies, CSRF protections, and least-privilege access on every public route.",
    )

    order = {"P1": 0, "P2": 1, "P3": 2}
    steps.sort(key=lambda item: order.get(item["priority"], 9))
    return {
        "summary": (
            f"{sum(1 for item in steps if item['priority'] == 'P1')} urgent, "
            f"{sum(1 for item in steps if item['priority'] == 'P2')} important, and "
            f"{sum(1 for item in steps if item['priority'] == 'P3')} ongoing next steps."
        ),
        "next_steps": steps,
    }


def build_report(tool_results, cves=None, council=None):
    findings = []
    for result in tool_results:
        findings.extend(result.get("findings", []))

    cves = cves or {}
    matched = list(cves.get("matched") or [])
    tried = list(cves.get("items") or matched)
    cross_check = cves.get("cross_check") or {}
    council = council or {}
    counts = _counts(findings)
    outcomes = _tool_outcomes(tool_results)
    score_info = nist_score(findings, matched)
    narrative = _explain_score(score_info, counts, outcomes, matched, cross_check)
    knowledge_map = cves.get("local_knowledge") or {}
    aar = after_action_report(findings, matched, outcomes, cve_knowledge=knowledge_map)

    return {
        "summary": {
            "tool_count": len(tool_results),
            "finding_count": len(findings),
            "severity": counts,
            "matched_cve_count": len(matched),
            "cves_tried_count": len(tried),
            "council_rounds": len(council.get("debate") or []),
            "nist_score": score_info["score"],
            "nist_rating": score_info["rating"],
            "score_standard": score_info["standard"],
            "local_cve_knowledge_count": (
                len(knowledge_map) if knowledge_map else cves.get("local_cve_count", 0)
            ),
        },
        "nist": {
            **score_info,
            "explanation": narrative,
            "passed": outcomes["passed"],
            "failed": outcomes["failed"],
            "informational": outcomes["info"],
            "tools_used": outcomes["used"],
        },
        "cves": {
            "matched": matched,
            "tried": tried,
            "sources": cves.get("sources") or [],
            "cross_check": cross_check,
            "fetched_at": cves.get("fetched_at"),
            "local_knowledge": list(knowledge_map.values()) if isinstance(knowledge_map, dict) else knowledge_map,
        },
        "after_action_report": aar,
        "tools": tool_results,
        "findings": findings,
        "council": council,
        "narrative": narrative,
    }
