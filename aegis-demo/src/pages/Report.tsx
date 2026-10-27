import { AlertTriangle, CheckCircle2, ShieldCheck } from "lucide-react";
import type { Finding, Report, Severity } from "../types";

interface Props {
  report: Report;
}

const severityStyles: Record<Severity, string> = {
  critical: "bg-red-100 text-red-800",
  high: "bg-orange-100 text-orange-800",
  medium: "bg-amber-100 text-amber-800",
  low: "bg-blue-100 text-blue-800",
  info: "bg-slate-100 text-slate-700",
};

function getSeverityStyle(severity: string) {
  return severityStyles[severity as Severity] ?? severityStyles.info;
}

function formatLabel(value: string) {
  return value
    .split(/[_\s]+/)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className="finding">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h3 className="m-0 text-sm font-semibold text-slate-900">
          {finding.title}
        </h3>
        <span
          className={`rounded-full px-2 py-1 text-[10px] font-semibold uppercase ${getSeverityStyle(finding.severity)}`}
        >
          {finding.severity}
        </span>
      </div>
      <p>{finding.detail}</p>
      {finding.evidence && (
        <p className="break-all text-xs text-slate-500">
          <strong>Evidence:</strong> {finding.evidence}
        </p>
      )}
      <div className="finding-subtitle">
        Check: {formatLabel(finding.tool)}
      </div>
    </article>
  );
}

export default function ReportView({ report }: Props) {
  const severity = report.summary.severity;
  const findings = report.findings ?? [];
  const formattedDate = new Date(report.timestamp);
  const timestamp = Number.isNaN(formattedDate.getTime())
    ? report.timestamp
    : formattedDate.toLocaleString();

  return (
    <div className="content-page report-page">
      <header className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="mb-1 text-xs font-medium uppercase tracking-wide text-emerald-700">
            Security scan report
          </p>
          <h1 className="m-0 break-all text-2xl font-semibold text-slate-900">
            {report.target.url}
          </h1>
          <p className="mt-2 text-xs text-slate-500">Completed {timestamp}</p>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-3 py-1.5 text-xs font-medium text-emerald-800">
          <ShieldCheck size={14} />
          {report.summary.nist_rating} risk
        </span>
      </header>

      <section className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <div className="rounded-lg border border-slate-200 bg-white p-4">
          <p className="m-0 text-xs text-slate-500">Risk score</p>
          <p className="mb-0 mt-2 text-2xl font-semibold text-slate-900">
            {report.summary.nist_score}
            <span className="text-sm font-normal text-slate-500"> / 10</span>
          </p>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-4">
          <p className="m-0 text-xs text-slate-500">Findings</p>
          <p className="mb-0 mt-2 text-2xl font-semibold text-slate-900">
            {report.summary.finding_count}
          </p>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-4">
          <p className="m-0 text-xs text-slate-500">Checks run</p>
          <p className="mb-0 mt-2 text-2xl font-semibold text-slate-900">
            {report.summary.tool_count}
          </p>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-4">
          <p className="m-0 text-xs text-slate-500">Matched CVEs</p>
          <p className="mb-0 mt-2 text-2xl font-semibold text-slate-900">
            {report.summary.matched_cve_count}
          </p>
        </div>
      </section>

      <section className="report-section">
        <h2 className="flex items-center gap-2">
          <AlertTriangle size={16} />
          Findings
        </h2>
        <div className="mb-3 flex flex-wrap gap-2">
          {(["critical", "high", "medium", "low", "info"] as const).map(
            (level) => (
              <span
                key={level}
                className={`rounded-full px-2 py-1 text-[10px] font-semibold uppercase ${getSeverityStyle(level)}`}
              >
                {level}: {severity[level] ?? 0}
              </span>
            ),
          )}
        </div>
        {findings.length ? (
          findings.map((finding, index) => (
            <FindingCard
              key={`${finding.tool}-${finding.title}-${index}`}
              finding={finding}
            />
          ))
        ) : (
          <p className="m-0 text-sm text-slate-600">No findings were reported.</p>
        )}
      </section>

      <section className="report-section">
        <h2 className="flex items-center gap-2">
          <CheckCircle2 size={16} />
          Recommended next steps
        </h2>
        {report.after_action_report.next_steps.length ? (
          <ol className="m-0 list-decimal space-y-3 pl-5">
            {report.after_action_report.next_steps.map((step, index) => (
              <li key={`${step.priority}-${step.title}-${index}`} className="pl-1">
                <div className="flex flex-wrap items-center gap-2">
                  <strong className="text-sm text-slate-900">{step.title}</strong>
                  <span className="rounded bg-slate-200 px-1.5 py-0.5 text-[10px] font-semibold text-slate-700">
                    {step.priority}
                  </span>
                </div>
                <p className="mb-0 mt-1 text-sm text-slate-600">{step.detail}</p>
              </li>
            ))}
          </ol>
        ) : (
          <p className="m-0 text-sm text-slate-600">
            No next steps were included in this report.
          </p>
        )}
      </section>
    </div>
  );
}