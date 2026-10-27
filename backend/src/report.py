"""Build a NIST/CVSS-aligned scan report with narrative and after-action steps.

`render_pdf` turns that report into a downloadable PDF document.
"""

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


def _unique_findings(findings):
    unique = []
    seen = set()
    for item in findings:
        key = (
            item.get("severity", "info"),
            item.get("title", ""),
            item.get("evidence", ""),
            item.get("detail", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def nist_score(findings, matched_cves=None):
    """Risk score on a 1-10 scale.

    The label is confirmed_cvss only when a version-matched CVE carries a
    numeric CVSS value. Every other scan is marked heuristic.
    """
    matched_cves = matched_cves or []
    score = 1.0
    for item in findings:
        score += SEVERITY_WEIGHT.get(item.get("severity", "info"), 0.0)
    confirmed_scores = [
        min(float(item["cvss_score"]), 10.0)
        for item in matched_cves
        if item.get("version_confirmed") and isinstance(item.get("cvss_score"), (int, float))
    ]
    if confirmed_scores:
        score = max(score, max(confirmed_scores))
        standard = "confirmed_cvss"
    else:
        for item in matched_cves:
            if item.get("version_confirmed"):
                score += 1.0
        standard = "heuristic"
    score = max(1, min(10, round(score)))
    rating = "Low"
    for low, high, label in NIST_RATING:
        if low <= score <= high:
            rating = label
            break
    return {"score": score, "scale": "1-10", "standard": standard, "rating": rating}


def _explain_score(score_info, counts, outcomes, matched_cves, cross_check):
    score = score_info["score"]
    rating = score_info["rating"]
    failed = outcomes["failed"]
    passed = outcomes["passed"]
    if score_info.get("standard") == "confirmed_cvss":
        lead = (
            f"The risk score is {score}/10 ({rating}). "
            f"It is driven by CVSS on version-confirmed CVEs, plus finding severity."
        )
    else:
        lead = (
            f"The risk score is {score}/10 ({rating}). "
            f"This score is a heuristic based on finding severity."
        )
    parts = [
        lead,
        f"The scan used {len(outcomes['used'])} checks: "
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
            f"{len(matched_cves)} CVE(s) matched an installed package version. "
            f"{len(confirmed)} were cross-checked by more than one source"
            + (f" ({', '.join(confirmed[:5])})." if confirmed else ".")
        )
    else:
        parts.append("No CVE matched an installed package version during this scan.")
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
    seen_tools = set()
    unique_results = []
    for result in tool_results:
        name = result.get("tool")
        if name in seen_tools:
            continue
        seen_tools.add(name)
        unique_results.append(result)
        findings.extend(result.get("findings", []))
    findings = _unique_findings(findings)
    tool_results = unique_results

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


PAGE_WIDTH = 612
PAGE_HEIGHT = 792
PAGE_MARGIN = 54
PAGE_BOTTOM = 64


def _pdf_escape(text):
    cleaned = []
    for char in str(text):
        code = ord(char)
        if char in "\\()":
            cleaned.append("\\" + char)
        elif char in "\n\r\t":
            cleaned.append(" ")
        elif 32 <= code <= 126:
            cleaned.append(char)
        else:
            cleaned.append("?")
    return "".join(cleaned)


def _wrap_text(text, width):
    words = " ".join(str(text).split()).split(" ")
    if not words or words == [""]:
        return [""]
    lines = []
    current = ""
    for word in words:
        while len(word) > width:
            if current:
                lines.append(current)
                current = ""
            lines.append(word[:width])
            word = word[width:]
        candidate = word if not current else f"{current} {word}"
        if len(candidate) <= width:
            current = candidate
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def _text_width(size):
    return max(40, int(480 / (size * 0.52)))


def _add_block(lines, text, size=11, bold=False):
    for part in _wrap_text(text, _text_width(size)):
        lines.append((part, size, bold))


def _report_lines(report):
    report = report or {}
    summary = report.get("summary") or {}
    nist = report.get("nist") or {}
    target = report.get("target") or {}
    lines = []

    def add(text, size=11, bold=False):
        _add_block(lines, text, size, bold)

    def blank():
        lines.append(("", 8, False))

    add("Cyber Risk Scan Report", 18, True)
    blank()
    company = target.get("company") or target.get("url") or "unspecified target"
    add(f"Target: {company}", 12, True)
    if target.get("url"):
        add(f"URL: {target['url']}")
    if target.get("kind"):
        add(f"Scan type: {target['kind']}")
    blank()

    score = summary.get("nist_score", nist.get("score", "n/a"))
    rating = summary.get("nist_rating", nist.get("rating", "n/a"))
    standard = summary.get("score_standard", nist.get("standard", "heuristic"))
    label = "Confirmed CVSS score" if standard == "confirmed_cvss" else "Heuristic risk score"
    add(f"{label}: {score}/10 ({rating})", 14, True)
    blank()
    add("Score explanation", 13, True)
    add(report.get("narrative") or nist.get("explanation") or "No narrative.")
    blank()

    severity = summary.get("severity") or {}
    findings = report.get("findings") or []
    add("Findings", 13, True)
    add(
        f"Total findings: {summary.get('finding_count', len(findings))}. "
        f"High {severity.get('high', 0)}, medium {severity.get('medium', 0)}, "
        f"low {severity.get('low', 0)}, info {severity.get('info', 0)}."
    )
    if findings:
        for item in findings:
            add(
                f"[{item.get('severity', 'info')}] {item.get('title', 'Finding')} "
                f"({item.get('tool', 'tool')})",
                11,
                True,
            )
            if item.get("detail"):
                add(item["detail"])
            if item.get("evidence"):
                add(f"Evidence: {item['evidence']}")
    else:
        add("No findings recorded.")
    blank()

    add("Tools", 13, True)
    for bucket, label in (
        ("failed", "Failed"),
        ("passed", "Passed"),
        ("informational", "Informational"),
    ):
        names = ", ".join(
            item.get("tool", "unknown") for item in (nist.get(bucket) or [])
        ) or "none"
        add(f"{label}: {names}")
    blank()

    add("CVEs", 13, True)
    matched = (report.get("cves") or {}).get("matched") or []
    if matched:
        for item in matched:
            cvss = item.get("cvss_score")
            cvss_text = f", CVSS {cvss}" if cvss is not None else ""
            sources = ", ".join(item.get("sources") or []) or "unknown source"
            add(f"{item.get('cve_id', 'CVE')}{cvss_text} ({sources})", 11, True)
            if item.get("description"):
                add(str(item["description"])[:400])
    else:
        add("No matched CVEs.")
    blank()

    aar = report.get("after_action_report") or {}
    add("After-action report", 13, True)
    if aar.get("summary"):
        add(aar["summary"])
    steps = aar.get("next_steps") or []
    if steps:
        for step in steps:
            add(
                f"{step.get('priority', 'P3')}: {step.get('title', 'Next step')}",
                11,
                True,
            )
            if step.get("detail"):
                add(step["detail"])
    else:
        add("No after-action steps recorded.")
    return lines


def _paginate(lines):
    pages = []
    current = []
    y = PAGE_HEIGHT - PAGE_MARGIN
    for text, size, bold in lines:
        step = size + 4
        if y - step < PAGE_BOTTOM:
            pages.append(current)
            current = []
            y = PAGE_HEIGHT - PAGE_MARGIN
        current.append((text, size, bold, y - size))
        y -= step
    if current:
        pages.append(current)
    return pages or [[]]


def _page_stream(lines, page_index, page_count):
    chunks = ["BT"]
    for text, size, bold, y in lines:
        font = "F2" if bold else "F1"
        chunks.append(f"/{font} {size} Tf")
        chunks.append(f"1 0 0 1 {PAGE_MARGIN} {y} Tm")
        chunks.append(f"({_pdf_escape(text)}) Tj")
    chunks.append("/F1 9 Tf")
    chunks.append(f"1 0 0 1 {PAGE_MARGIN} 36 Tm")
    chunks.append(f"(Page {page_index} of {page_count}) Tj")
    chunks.append("ET")
    return "\n".join(chunks).encode("ascii")


def _pdf_document(pages):
    page_count = len(pages)
    kids = " ".join(f"{5 + index * 2} 0 R" for index in range(page_count))
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {page_count} >>".encode("ascii"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
    ]
    for index, lines in enumerate(pages):
        content_id = 6 + index * 2
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
                f"/Contents {content_id} 0 R "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>"
            ).encode("ascii")
        )
        stream = _page_stream(lines, index + 1, page_count)
        objects.append(
            f"<< /Length {len(stream)} >>\nstream\n".encode("ascii")
            + stream
            + b"\nendstream"
        )

    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii"))
        output.extend(body)
        output.extend(b"\nendobj\n")
    xref_at = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_at}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(output)


def render_pdf(report):
    """Render a scan report as a PDF byte string suitable for download."""
    if not isinstance(report, dict):
        raise TypeError("report must be a dict")
    return _pdf_document(_paginate(_report_lines(report)))
