import {
  AlertTriangle,
  BookOpen,
  Check,
  CheckCircle2,
  ChevronDown,
  Clipboard,
  Download,
  Info,
  ListChecks,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Wrench,
  XCircle,
} from "lucide-react";
import { useEffect, useState } from "react";
import type { AgentId, Finding, Report } from "../types";
import { getFallbackReport } from "../services/api";
import { getReportFromCookie } from "../utils/cookies";

interface Props {
  repository: string;
  enabled?: AgentId[];
  reportId?: string;
  report?: Report | null;
  onNew: () => void;
}

export default function ReportView({
  repository,
  enabled = [],
  reportId,
  report: propReport,
  onNew,
}: Props) {
  // Retrieve report from prop, cookie, or sample fallback
  const [report, setReport] = useState<Report>(() => {
    if (propReport) return propReport;
    const fromCookie = getReportFromCookie(reportId);
    return fromCookie || getFallbackReport(repository);
  });

  const [closedSections, setClosedSections] = useState<string[]>([]);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [resolved, setResolved] = useState(false);
  const [activeTab, setActiveTab] = useState<"findings" | "tools" | "cves" | "council">("findings");
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  // Keep report in sync when reportId or prop changes
  useEffect(() => {
    if (propReport) {
      setReport(propReport);
      return;
    }
    const fromCookie = getReportFromCookie(reportId);
    if (fromCookie) {
      setReport(fromCookie);
    } else {
      setReport(getFallbackReport(repository));
    }
  }, [reportId, repository, propReport]);

  const toggleSection = (key: string) => {
    setClosedSections((prev) =>
      prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key],
    );
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  function exportReport() {
    const summaryText = `================================================================================
AEGIS SECURITY ANALYSIS REPORT
Target: ${report.target.url}
Scan Date: ${new Date(report.timestamp).toLocaleString()}
NIST Risk Score: ${report.nist.score}/10 (${report.nist.rating})
Standard: ${report.summary.score_standard}
================================================================================

EXECUTIVE SUMMARY
-----------------
${report.narrative || report.nist.explanation}

FINDINGS SUMMARY
----------------
Total Findings: ${report.summary.finding_count}
Critical: ${report.summary.severity.critical || 0}
High:     ${report.summary.severity.high || 0}
Medium:   ${report.summary.severity.medium || 0}
Low:      ${report.summary.severity.low || 0}
Info:     ${report.summary.severity.info || 0}

Tools Evaluated: ${report.summary.tool_count} (${report.nist.passed.length} passed, ${report.nist.failed.length} failed, ${report.nist.informational.length} informational)

AFTER ACTION REPORT - NEXT STEPS
--------------------------------
${report.after_action_report.summary}
${report.after_action_report.next_steps.map((s) => `[${s.priority}] ${s.title}\n   ${s.detail}`).join("\n\n")}

DETAILED FINDINGS
-----------------
${report.findings
  .map(
    (f, i) =>
      `#${i + 1} [${f.severity.toUpperCase()}] ${f.title} (Tool: ${f.tool})
Detail: ${f.detail}
Evidence: ${f.evidence || "N/A"}`
  )
  .join("\n\n")}

ARSENAL TOOLS STATUS
--------------------
${report.tools.map((t) => `• ${t.tool}: ${t.status.toUpperCase()} (${t.findings?.length || 0} findings)`).join("\n")}

CVE KNOWLEDGE BASE & DEFENSE TIPS
---------------------------------
${report.cves.local_knowledge.map((c) => `[${c.cve_name}]\nHow it works: ${c.how_it_works}\nDefend: ${c.defend_against}`).join("\n\n")}
`;

    const blob = new Blob([summaryText], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegis-report-${report.target.url.replace(/[^a-zA-Z0-9]/g, "_")}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Filter findings based on user selection
  const filteredFindings = report.findings.filter((f) => {
    if (severityFilter === "all") return true;
    return f.severity.toLowerCase() === severityFilter.toLowerCase();
  });

  // Group findings by severity
  const criticalAndHigh = report.findings.filter(
    (f) => f.severity.toLowerCase() === "critical" || f.severity.toLowerCase() === "high",
  );
  const mediumFindings = report.findings.filter((f) => f.severity.toLowerCase() === "medium");
  const lowFindings = report.findings.filter((f) => f.severity.toLowerCase() === "low");
  const infoFindings = report.findings.filter((f) => f.severity.toLowerCase() === "info");

  const scoreColor =
    report.nist.score >= 8
      ? "text-red-600"
      : report.nist.score >= 5
        ? "text-amber-600"
        : "text-emerald-700";

  const scoreBg =
    report.nist.score >= 8
      ? "bg-red-50 text-red-700 border-red-200"
      : report.nist.score >= 5
        ? "bg-amber-50 text-amber-800 border-amber-200"
        : "bg-emerald-50 text-emerald-800 border-emerald-200";

  return (
    <div className="content-page report-page pb-16">
      {/* ── Page Heading ── */}
      <div className="page-heading">
        <div className="min-w-0 pr-4">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-emerald-800 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
              Security Scan Report
            </span>
            <span className="text-[11px] text-gray-700">
              {new Date(report.timestamp).toLocaleDateString(undefined, {
                month: "short",
                day: "numeric",
                year: "numeric",
                hour: "2-digit",
                minute: "2-digit",
              })}
            </span>
          </div>
          <h1 className="truncate text-xl md:text-2xl font-bold text-gray-900" title={report.target.url}>
            {report.target.url}
          </h1>
          <p className="text-sm text-gray-700 mt-1 line-clamp-2">
            {report.narrative || report.nist.explanation}
          </p>
        </div>
        <div className="flex flex-col items-end gap-2 shrink-0">
          <span className={`status-badge border ${scoreBg}`}>
            <span
              className={`w-2 h-2 rounded-full ${
                report.nist.score >= 8
                  ? "bg-red-500"
                  : report.nist.score >= 5
                    ? "bg-amber-500"
                    : "bg-emerald-500"
              }`}
            />
            NIST {report.nist.rating} Risk ({report.nist.score}/10)
          </span>
          {enabled.length > 0 && (
            <span className="text-[11px] text-gray-700">
              {enabled.length} agent models configured
            </span>
          )}
        </div>
      </div>

      {/* ── Report Actions / Tools ── */}
      <div className="report-tools flex items-center justify-between border-b border-gray-200 pb-3 mb-5">
        <div className="flex items-center gap-1.5 overflow-x-auto text-xs">
          <button
            onClick={() => setActiveTab("findings")}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === "findings"
                ? "bg-emerald-800 text-white shadow-sm"
                : "bg-gray-100 text-gray-700 hover:bg-gray-200"
            }`}
          >
            <ShieldAlert size={13} />
            Findings ({report.findings.length})
          </button>
          <button
            onClick={() => setActiveTab("tools")}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === "tools"
                ? "bg-emerald-800 text-white shadow-sm"
                : "bg-gray-100 text-gray-700 hover:bg-gray-200"
            }`}
          >
            <Wrench size={13} />
            Arsenal Tools ({report.summary.tool_count})
          </button>
          <button
            onClick={() => setActiveTab("cves")}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === "cves"
                ? "bg-emerald-800 text-white shadow-sm"
                : "bg-gray-100 text-gray-700 hover:bg-gray-200"
            }`}
          >
            <BookOpen size={13} />
            CVE Intel ({report.cves.local_knowledge.length})
          </button>
          {report.council?.debate && report.council.debate.length > 0 && (
            <button
              onClick={() => setActiveTab("council")}
              className={`px-3 py-1.5 rounded-md font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === "council"
                  ? "bg-emerald-800 text-white shadow-sm"
                  : "bg-gray-100 text-gray-700 hover:bg-gray-200"
              }`}
            >
              <Radio size={13} />
              Council Debate ({report.summary.council_rounds} rounds)
            </button>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={exportReport}
            className="flex items-center gap-1.5 bg-white border border-gray-300 hover:bg-gray-50 text-gray-700 px-3 py-1.5 rounded text-xs font-medium shadow-xs"
            title="Export full report as text file"
          >
            <Download size={13} />
            Export report
          </button>
          <button
            onClick={onNew}
            className="flex items-center gap-1.5 bg-emerald-800 hover:bg-emerald-900 text-white px-3 py-1.5 rounded text-xs font-semibold shadow-xs"
          >
            + New scan
          </button>
        </div>
      </div>

      {/* ── Key Metrics Overview Cards ── */}
      <div className="metrics grid grid-cols-1 md:grid-cols-4 gap-3 mb-5">
        {/* Metric 1: NIST Risk Score */}
        <div className="metric bg-white border border-gray-200 rounded-lg p-3 shadow-xs">
          <div className="flex items-center justify-between text-xs text-gray-700 font-medium">
            <span>NIST Risk Score</span>
            <span className="text-[10px] text-gray-600 bg-gray-100 px-1.5 py-0.5 rounded">
              {report.summary.score_standard}
            </span>
          </div>
          <div className="flex items-baseline gap-2 mt-1">
            <strong className={`text-2xl font-bold ${scoreColor}`}>
              {report.nist.score}
            </strong>
            <span className="text-xs text-gray-700">/ 10 ({report.nist.rating})</span>
          </div>
          <span className="meter mt-2 bg-gray-100 h-1.5 rounded-full overflow-hidden block">
            <span
              className={`h-full block rounded-full ${
                report.nist.score >= 8
                  ? "bg-red-500"
                  : report.nist.score >= 5
                    ? "bg-amber-500"
                    : "bg-emerald-600"
              }`}
              style={{ width: `${(report.nist.score / 10) * 100}%` }}
            />
          </span>
          <small className="text-[11px] text-gray-700 mt-1 block">
            Scale: {report.nist.scale}
          </small>
        </div>

        {/* Metric 2: Vulnerability Findings */}
        <div className="metric bg-white border border-gray-200 rounded-lg p-3 shadow-xs">
          <div className="text-xs text-gray-700 font-medium">Vulnerabilities</div>
          <div className="flex items-baseline gap-2 mt-1">
            <strong className="text-2xl font-bold text-gray-900">
              {report.summary.finding_count}
            </strong>
            <span className="text-xs text-gray-700">findings surfaced</span>
          </div>
          <div className="flex items-center gap-1.5 mt-2 flex-wrap">
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-100 text-red-800 font-medium">
              {report.summary.severity.critical || 0} Critical
            </span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-100 text-amber-800 font-medium">
              {report.summary.severity.medium} Med
            </span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-yellow-100 text-yellow-800 font-medium">
              {report.summary.severity.low} Low
            </span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-100 text-blue-800 font-medium">
              {report.summary.severity.info} Info
            </span>
          </div>
        </div>

        {/* Metric 3: Security Arsenal Tools */}
        <div className="metric bg-white border border-gray-200 rounded-lg p-3 shadow-xs">
          <div className="text-xs text-gray-700 font-medium">Arsenal Controls</div>
          <div className="flex items-baseline gap-2 mt-1">
            <strong className="text-2xl font-bold text-gray-900">
              {report.summary.tool_count}
            </strong>
            <span className="text-xs text-gray-700">security checks run</span>
          </div>
          <div className="flex items-center gap-2 mt-2 text-[11px] text-gray-700">
            <span className="flex items-center gap-1 text-emerald-800 font-medium">
              <CheckCircle2 size={12} /> {report.nist.passed.length} passed
            </span>
            <span className="flex items-center gap-1 text-red-700 font-medium">
              <XCircle size={12} /> {report.nist.failed.length} failed
            </span>
            <span className="flex items-center gap-1 text-gray-700 font-medium">
              <Info size={12} /> {report.nist.informational.length} info
            </span>
          </div>
        </div>

        {/* Metric 4: Council & Intelligence */}
        <div className="metric bg-white border border-gray-200 rounded-lg p-3 shadow-xs">
          <div className="text-xs text-gray-700 font-medium">Threat Intelligence</div>
          <div className="flex items-baseline gap-2 mt-1">
            <strong className="text-2xl font-bold text-gray-900">
              {report.summary.local_cve_knowledge_count || report.cves.local_knowledge.length}
            </strong>
            <span className="text-xs text-gray-700">CVE profiles analyzed</span>
          </div>
          <div className="text-[11px] text-gray-700 mt-2 truncate">
            {report.council?.intel?.fingerprints && report.council.intel.fingerprints.length > 0 ? (
              <span className="text-gray-700">
                Fingerprint: <b>{report.council.intel.fingerprints.join(", ")}</b>
              </span>
            ) : (
              <span>CISA KEV, NIST & OSV monitored</span>
            )}
          </div>
        </div>
      </div>

      {/* ── After-Action Report (Remediation / Next Steps) ── */}
      {report.after_action_report && (
        <section className="bg-emerald-50/50 border border-emerald-200 rounded-lg p-4 mb-6 shadow-xs">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <ListChecks size={16} className="text-emerald-700" />
              <h2 className="text-sm font-semibold text-emerald-950">
                After-Action Remediation Plan
              </h2>
            </div>
            <span className="text-xs text-emerald-800 font-medium">
              {report.after_action_report.summary}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 mt-3">
            {report.after_action_report.next_steps.map((step, idx) => (
              <div
                key={idx}
                className="bg-white border border-emerald-100 rounded-md p-2.5 flex items-start gap-2.5 shadow-2xs"
              >
                <span
                  className={`text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0 ${
                    step.priority === "P1"
                      ? "bg-red-100 text-red-800"
                      : step.priority === "P2"
                        ? "bg-amber-100 text-amber-800"
                        : "bg-blue-100 text-blue-800"
                  }`}
                >
                  {step.priority}
                </span>
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-gray-900 leading-tight">
                    {step.title}
                  </div>
                  <div className="text-[11px] text-gray-700 mt-0.5 leading-snug">
                    {step.detail}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── TAB 1: Detailed Findings View ── */}
      {activeTab === "findings" && (
        <div className="space-y-4">
          {/* Severity filter bar */}
          <div className="flex items-center justify-between bg-gray-50 p-2 rounded-lg border border-gray-200 flex-wrap gap-2 text-xs">
            <div className="flex items-center gap-1">
              <span className="text-gray-700 font-medium mr-2">Filter by severity:</span>
              {(
                [
                  { id: "all", label: `All (${report.findings.length})` },
                  { id: "medium", label: `Medium (${mediumFindings.length})` },
                  { id: "low", label: `Low (${lowFindings.length})` },
                  { id: "info", label: `Info (${infoFindings.length})` },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setSeverityFilter(tab.id)}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                    severityFilter === tab.id
                      ? "bg-white text-gray-900 shadow-2xs font-semibold border border-gray-200"
                      : "text-gray-700 hover:text-gray-900"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <span className="text-xs text-gray-700">
              Showing {filteredFindings.length} of {report.findings.length} findings
            </span>
          </div>

          {/* Critical / High Section */}
          {criticalAndHigh.length > 0 && (severityFilter === "all" || severityFilter === "critical" || severityFilter === "high") && (
            <section className="report-section border-red-200 bg-red-50/20">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle size={16} className="text-red-600" />
                <h2 className="text-sm font-semibold text-red-900 m-0">
                  Critical & High Severity ({criticalAndHigh.length})
                </h2>
              </div>
              {criticalAndHigh.map((f, i) => renderFindingCard(f, `crit-${i}`))}
            </section>
          )}

          {/* Medium Section */}
          {mediumFindings.length > 0 && (severityFilter === "all" || severityFilter === "medium") && (
            <section className="report-section border-amber-200 bg-amber-50/10">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle size={16} className="text-amber-600" />
                <h2 className="text-sm font-semibold text-amber-900 m-0">
                  Medium Severity ({mediumFindings.length})
                </h2>
              </div>
              {mediumFindings.map((f, i) => renderFindingCard(f, `med-${i}`))}
            </section>
          )}

          {/* Low Section */}
          {lowFindings.length > 0 && (severityFilter === "all" || severityFilter === "low") && (
            <section className="report-section border-yellow-200 bg-yellow-50/10">
              <div className="flex items-center gap-2 mb-3">
                <Info size={16} className="text-yellow-600" />
                <h2 className="text-sm font-semibold text-yellow-900 m-0">
                  Low Severity ({lowFindings.length})
                </h2>
              </div>
              {lowFindings.map((f, i) => renderFindingCard(f, `low-${i}`))}
            </section>
          )}

          {/* Informational Section */}
          {infoFindings.length > 0 && (severityFilter === "all" || severityFilter === "info") && (
            <section className="report-section border-gray-200">
              <div className="flex items-center gap-2 mb-3">
                <Info size={16} className="text-blue-500" />
                <h2 className="text-sm font-semibold text-gray-800 m-0">
                  Informational & Passed Checks ({infoFindings.length})
                </h2>
              </div>
              {infoFindings.map((f, i) => renderFindingCard(f, `info-${i}`))}
            </section>
          )}
        </div>
      )}

      {/* ── TAB 2: Arsenal Tools Status ── */}
      {activeTab === "tools" && (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-xs">
            <h3 className="text-sm font-semibold text-gray-900 mb-1">
              Arsenal Security Tools Evaluation
            </h3>
            <p className="text-xs text-gray-700 mb-4">
              Results from all 13 specialized security scanners executed during this analysis.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {report.tools.map((t, idx) => {
                const isFail = t.status === "fail";
                const isPass = t.status === "pass";
                return (
                  <div
                    key={idx}
                    className={`border rounded-lg p-3 transition-shadow ${
                      isFail
                        ? "border-red-200 bg-red-50/20"
                        : isPass
                          ? "border-emerald-200 bg-emerald-50/20"
                          : "border-gray-200 bg-gray-50/30"
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-semibold text-xs text-gray-900 font-mono">
                        {t.tool.replace(/_/g, " ")}
                      </span>
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${
                          isFail
                            ? "bg-red-100 text-red-800"
                            : isPass
                              ? "bg-emerald-100 text-emerald-800"
                              : "bg-blue-100 text-blue-800"
                        }`}
                      >
                        {t.status}
                      </span>
                    </div>

                    <div className="text-xs text-gray-700">
                      {t.findings && t.findings.length > 0 ? (
                        <div className="space-y-1 mt-1">
                          {t.findings.map((f, fi) => (
                            <div key={fi} className="text-[11px] text-gray-700 leading-tight">
                              • <b>{f.title}</b>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <span className="text-[11px] text-gray-600">
                          {isPass ? "✓ No issues detected" : "Informational check"}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 3: CVE Intelligence ── */}
      {activeTab === "cves" && (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-xs">
            <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
              <div>
                <h3 className="text-sm font-semibold text-gray-900">
                  CVE Knowledge Base & Vulnerability Defense
                </h3>
                <p className="text-xs text-gray-700">
                  Known vulnerability defense catalog checked against the target profile.
                </p>
              </div>
              <span className="text-xs text-gray-700 bg-gray-100 px-2.5 py-1 rounded">
                Feed sources: {report.cves.sources?.join(", ") || "CISA KEV"}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
              {report.cves.local_knowledge.map((cve, idx) => (
                <div
                  key={idx}
                  className="border border-gray-200 rounded-lg p-3.5 bg-gray-50/50 hover:bg-white transition-colors"
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-bold text-xs text-emerald-900 font-mono">
                      {cve.cve_name}
                    </span>
                    <span className="text-[10px] text-gray-600 bg-gray-200 px-1.5 py-0.5 rounded">
                      Profiled
                    </span>
                  </div>
                  <div className="text-xs text-gray-800 font-medium mb-2 leading-relaxed">
                    {cve.how_it_works}
                  </div>
                  <div className="bg-emerald-50/60 border border-emerald-100 rounded p-2 text-[11px] text-emerald-950 leading-relaxed">
                    <strong className="text-emerald-900">Defense: </strong>
                    {cve.defend_against}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 4: Multi-Agent Council Debate ── */}
      {activeTab === "council" && report.council && (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 rounded-lg p-4 shadow-xs">
            <div className="flex items-center justify-between mb-2">
              <div>
                <h3 className="text-sm font-semibold text-gray-900">
                  Multi-Agent Threat Council Debate
                </h3>
                <p className="text-xs text-gray-700">
                  Deliberation logs from AI agent personas prioritizing attack surfaces and defenses.
                </p>
              </div>
              <span className="text-xs bg-emerald-50 text-emerald-800 font-medium px-2 py-1 rounded border border-emerald-200">
                Engine: {report.council.engines?.council || "parallel-threat-council"}
              </span>
            </div>

            {/* Rounds */}
            <div className="space-y-3 mt-4">
              {report.council.debate?.map((roundItem) => (
                <div
                  key={roundItem.round}
                  className="border border-gray-200 rounded-lg p-3 bg-gray-50/30"
                >
                  <div className="flex items-center justify-between mb-2 pb-2 border-b border-gray-200">
                    <span className="font-bold text-xs text-gray-900 flex items-center gap-1.5">
                      <Radio size={13} className="text-emerald-700" />
                      Debate Round #{roundItem.round}
                    </span>
                    <div className="flex items-center gap-2">
                      {roundItem.scout?.intent && (
                        <span className="text-[11px] text-gray-700">
                          Scout intent: <b>{roundItem.scout.intent.primary}</b> ({(roundItem.scout.intent.confidence * 100).toFixed(0)}%)
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Proposals */}
                  <div className="space-y-2 mt-2">
                    {roundItem.proposals.map((prop, pi) => (
                      <div
                        key={pi}
                        className="bg-white border border-gray-200 rounded p-2.5 text-xs"
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-semibold text-gray-900 flex items-center gap-1.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-700" />
                            {prop.agent} <span className="text-gray-600 font-normal">({prop.role})</span>
                          </span>
                          <span className="text-[10px] text-gray-700 bg-gray-100 px-1.5 py-0.5 rounded">
                            Votes: {prop.votes.join(", ")}
                          </span>
                        </div>
                        <p className="text-gray-700 text-[11px] leading-relaxed m-0 mt-1">
                          {prop.argument}
                        </p>
                      </div>
                    ))}
                  </div>

                  {/* Chosen Tools */}
                  {roundItem.chosen_tools && (
                    <div className="mt-2.5 pt-2 border-t border-gray-200 text-[11px] text-gray-700 flex items-center gap-2">
                      <span className="font-semibold text-gray-900">Chosen checks:</span>
                      <div className="flex gap-1 flex-wrap">
                        {roundItem.chosen_tools.map((ct) => (
                          <span key={ct} className="bg-emerald-100 text-emerald-900 px-1.5 py-0.5 rounded font-mono text-[10px]">
                            {ct}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Review & Disclaimer Actions ── */}
      <div className="mt-6 flex flex-col sm:flex-row items-center justify-between gap-3 pt-4 border-t border-gray-200">
        <div className="ai-disclaimer text-xs text-gray-600 m-0">
          <ShieldCheck size={14} className="text-emerald-700 inline mr-1" />
          AI analysis results should be verified before making production changes.
        </div>
        <button
          className={`resolve-btn px-4 py-2 text-xs font-semibold rounded shadow-xs transition-colors flex items-center gap-1.5 ${
            resolved
              ? "bg-emerald-700 text-white border-transparent"
              : "bg-white text-gray-700 border-gray-300 hover:bg-gray-50"
          }`}
          onClick={() => setResolved(!resolved)}
        >
          {resolved ? <Check size={14} /> : null}
          {resolved ? "Marked as reviewed" : "Mark findings reviewed"}
        </button>
      </div>
    </div>
  );

  // Helper to render individual finding accordion card
  function renderFindingCard(f: Finding, key: string) {
    const isClosed = closedSections.includes(key);
    const isCritical = f.severity === "critical" || f.severity === "high";
    const isMedium = f.severity === "medium";
    const isLow = f.severity === "low";

    const badgeColor = isCritical
      ? "bg-red-100 text-red-800 border-red-200"
      : isMedium
        ? "bg-amber-100 text-amber-800 border-amber-200"
        : isLow
          ? "bg-yellow-100 text-yellow-800 border-yellow-200"
          : "bg-blue-100 text-blue-800 border-blue-200";

    return (
      <div className="finding bg-white border border-gray-200 rounded-lg p-3.5 mb-2.5 shadow-2xs" key={key}>
        <button
          className="finding-title flex items-center justify-between w-full text-left"
          onClick={() => toggleSection(key)}
          aria-expanded={!isClosed}
        >
          <div className="flex items-center gap-2.5 flex-wrap min-w-0 pr-2">
            <span
              className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase border ${badgeColor}`}
            >
              {f.severity}
            </span>
            <span className="text-[11px] font-mono text-gray-700 bg-gray-100 px-1.5 py-0.5 rounded">
              {f.tool}
            </span>
            <strong className="text-xs md:text-sm font-semibold text-gray-900 truncate">
              {f.title}
            </strong>
          </div>
          <ChevronDown
            size={16}
            className={`text-gray-600 transition-transform shrink-0 ${
              isClosed ? "" : "rotate-180"
            }`}
          />
        </button>

        {!isClosed && (
          <div className="mt-3 pt-3 border-t border-gray-100 space-y-2">
            {f.detail && (
              <div>
                <strong className="text-xs text-gray-900 block font-semibold mb-0.5">
                  Recommendation / Detail:
                </strong>
                <p className="text-xs text-gray-700 m-0 leading-relaxed">
                  {f.detail}
                </p>
              </div>
            )}

            {f.evidence && (
              <div className="mt-2">
                <div className="flex items-center justify-between text-[11px] text-gray-700 font-medium mb-1">
                  <span>Evidence / Target context:</span>
                  <button
                    onClick={() => copyToClipboard(f.evidence, key)}
                    className="flex items-center gap-1 text-[11px] text-emerald-800 hover:text-emerald-900 font-medium"
                    aria-label="Copy evidence"
                  >
                    {copiedKey === key ? (
                      <>
                        <Check size={11} /> Copied!
                      </>
                    ) : (
                      <>
                        <Clipboard size={11} /> Copy
                      </>
                    )}
                  </button>
                </div>
                <div className="code-shell bg-gray-900 text-gray-100 rounded-md p-2.5 text-xs font-mono overflow-x-auto relative">
                  <pre className="m-0 text-emerald-400 whitespace-pre-wrap break-all text-[11px]">
                    <code>{f.evidence}</code>
                  </pre>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    );
  }
}
