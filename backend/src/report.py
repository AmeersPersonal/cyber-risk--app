"""Build scan findings and the final report."""


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


def build_report(tool_results, cves=None, council=None):
    findings = []
    for result in tool_results:
        findings.extend(result.get("findings", []))

    matched = list((cves or {}).get("matched") or [])
    council = council or {}
    return {
        "summary": {
            "tool_count": len(tool_results),
            "finding_count": len(findings),
            "severity": _counts(findings),
            "matched_cve_count": len(matched),
            "council_rounds": len(council.get("debate") or []),
        },
        "cves": matched,
        "tools": tool_results,
        "findings": findings,
        "council": council,
    }
