import type { Report, ToolCheck, Finding, Severity } from "../types";
import { saveReportToCookie } from "../utils/cookies";
import sampleJson from "../data/sample.json";

/**
 * Base URL for the security scanner backend API.
 * Defaults to environment variables or local fallback.
 */
export const API_URL: string =
  (import.meta.env.VITE_API_URL as string) ||
  (import.meta.env.API_URL as string) ||
  (typeof window !== "undefined" && (window as any).API_URL) ||
  "/";

/**
 * Creates a unique identifier.
 */
function generateId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return "rep_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

/**
 * Deep clone helper.
 */
function clone<T>(val: T): T {
  return JSON.parse(JSON.stringify(val));
}

/**
 * Generates a complete fallback Report object using sample.json,
 * customized with the user's requested target URL and current timestamp.
 */
export function getFallbackReport(_requestedUrl: string): Report {
  const base = clone(sampleJson as unknown as Report);
  const cleanUrl = base.target?.url || "https://example.invalid/";
  const id = generateId();
  const now = new Date().toISOString();

  const report: Report = {
    ...base,
    id,
    timestamp: now,
    createdGroup: "Today",
    target: {
      ...base.target,
      url: cleanUrl,
      company: cleanUrl,
    },
    findings: base.findings || [],
    tools: base.tools || [],
    narrative: "Synthetic demo report only. No repository was scanned.",
  };

  return report;
}

/**
 * TypeScript parser that validates, parses, and fills in any missing/empty
 * information from sample.json to construct a robust, fully-typed Report object.
 */
export function parseReport(apiOutput: unknown, requestedUrl: string): Report {
  const fallback = getFallbackReport(requestedUrl);

  if (!apiOutput || typeof apiOutput !== "object") {
    return fallback;
  }

  const raw = apiOutput as Record<string, any>;
  const cleanUrl = requestedUrl.trim() || raw.target?.url || fallback.target.url;

  // Helper to safely extract tool checks
  const sanitizeToolChecks = (arr: unknown, fallbackArr: ToolCheck[]): ToolCheck[] => {
    if (!Array.isArray(arr)) return fallbackArr;
    return arr.map((item) => ({
      tool: String(item.tool || "unknown_tool"),
      status: String(item.status || "info"),
      finding_count: typeof item.finding_count === "number" ? item.finding_count : undefined,
      findings: Array.isArray(item.findings) ? item.findings : undefined,
    }));
  };

  // Helper to safely extract findings
  const sanitizeFindings = (arr: unknown, fallbackArr: Finding[]): Finding[] => {
    if (!Array.isArray(arr)) return fallbackArr;
    return arr.map((item) => ({
      tool: String(item.tool || "general"),
      severity: (item.severity || "info") as Severity,
      title: String(item.title || "Untitled finding"),
      detail: String(item.detail || ""),
      evidence: String(item.evidence || ""),
    }));
  };

  const parsedReport: Report = {
    id: raw.id || generateId(),
    timestamp: raw.timestamp || new Date().toISOString(),
    createdGroup: "Today",
    target: {
      kind: raw.target?.kind || "url",
      url: cleanUrl,
      file_count: typeof raw.target?.file_count === "number" ? raw.target.file_count : fallback.target.file_count,
      company: raw.target?.company || cleanUrl,
    },
    summary: {
      tool_count: typeof raw.summary?.tool_count === "number" ? raw.summary.tool_count : fallback.summary.tool_count,
      finding_count: typeof raw.summary?.finding_count === "number" ? raw.summary.finding_count : fallback.summary.finding_count,
      severity: {
        critical: raw.summary?.severity?.critical ?? fallback.summary.severity.critical ?? 0,
        high: raw.summary?.severity?.high ?? fallback.summary.severity.high ?? 0,
        medium: raw.summary?.severity?.medium ?? fallback.summary.severity.medium ?? 0,
        low: raw.summary?.severity?.low ?? fallback.summary.severity.low ?? 0,
        info: raw.summary?.severity?.info ?? fallback.summary.severity.info ?? 0,
      },
      matched_cve_count: typeof raw.summary?.matched_cve_count === "number" ? raw.summary.matched_cve_count : fallback.summary.matched_cve_count,
      cves_tried_count: typeof raw.summary?.cves_tried_count === "number" ? raw.summary.cves_tried_count : fallback.summary.cves_tried_count,
      council_rounds: typeof raw.summary?.council_rounds === "number" ? raw.summary.council_rounds : fallback.summary.council_rounds,
      nist_score: typeof raw.summary?.nist_score === "number" ? raw.summary.nist_score : fallback.summary.nist_score,
      nist_rating: raw.summary?.nist_rating || fallback.summary.nist_rating,
      score_standard: raw.summary?.score_standard || fallback.summary.score_standard,
      local_cve_knowledge_count: typeof raw.summary?.local_cve_knowledge_count === "number" ? raw.summary.local_cve_knowledge_count : fallback.summary.local_cve_knowledge_count,
    },
    nist: {
      score: typeof raw.nist?.score === "number" ? raw.nist.score : fallback.nist.score,
      scale: raw.nist?.scale || fallback.nist.scale,
      standard: raw.nist?.standard || fallback.nist.standard,
      rating: raw.nist?.rating || fallback.nist.rating,
      explanation: raw.nist?.explanation || fallback.nist.explanation,
      passed: sanitizeToolChecks(raw.nist?.passed, fallback.nist.passed),
      failed: sanitizeToolChecks(raw.nist?.failed, fallback.nist.failed),
      informational: sanitizeToolChecks(raw.nist?.informational, fallback.nist.informational),
      tools_used: Array.isArray(raw.nist?.tools_used) ? raw.nist.tools_used : fallback.nist.tools_used,
    },
    cves: {
      matched: Array.isArray(raw.cves?.matched) ? raw.cves.matched : fallback.cves.matched,
      tried: Array.isArray(raw.cves?.tried) ? raw.cves.tried : fallback.cves.tried,
      sources: Array.isArray(raw.cves?.sources) ? raw.cves.sources : fallback.cves.sources,
      cross_check: raw.cves?.cross_check || fallback.cves.cross_check,
      fetched_at: raw.cves?.fetched_at || fallback.cves.fetched_at,
      local_knowledge: Array.isArray(raw.cves?.local_knowledge)
        ? raw.cves.local_knowledge
        : fallback.cves.local_knowledge,
    },
    after_action_report: {
      summary: raw.after_action_report?.summary || fallback.after_action_report.summary,
      next_steps: Array.isArray(raw.after_action_report?.next_steps)
        ? raw.after_action_report.next_steps
        : fallback.after_action_report.next_steps,
    },
    tools: sanitizeToolChecks(raw.tools, fallback.tools),
    findings: sanitizeFindings(raw.findings, fallback.findings),
    council: raw.council || fallback.council,
    narrative: raw.narrative || fallback.narrative,
  };

  return parsedReport;
}

/** Sends the repository and one-scan GitHub credential to the ownership-checked API. */
export async function scanGitHubRepository(
  repository: string,
  token: string,
): Promise<Report> {
  const endpoint = `${API_URL.replace(/\/$/, "")}/scan/github`;
  const controller = new AbortController();
  const timeoutMs = 180000;
  const timeoutId = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ repository }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      throw new Error(
        typeof payload?.detail === "string"
          ? payload.detail
          : `Scan API returned HTTP ${response.status}.`,
      );
    }

    const data = await response.json();
    const report = parseReport(data, repository);
    saveReportToCookie(report);
    return report;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("The repository scan timed out. Please try again.");
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

