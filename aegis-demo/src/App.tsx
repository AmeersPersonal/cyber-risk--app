import { useEffect, useRef, useState } from "react";
import Sidebar from "./components/Sidebar";
import Login from "./pages/Login";
import Setup from "./pages/Setup";
import Processing from "./pages/Processing";
import ReportView from "./pages/Report";
import type { Analysis, Report } from "./types";
import { scanGitHubRepository } from "./services/api";
import {
  getReportFromCookie,
  getReportsFromCookies,
  setActiveReportCookie,
} from "./utils/cookies";

function getSaved(): Analysis[] {
  try {
    const raw = localStorage.getItem("aegis-analyses");
    if (!raw) return [];
    const reportSummaries = getReportsFromCookies();
    return (JSON.parse(raw) as Analysis[]).map((analysis) => {
      if (
        typeof analysis.findingCount === "number" &&
        analysis.severityCounts &&
        analysis.reportId
      ) {
        return analysis;
      }

      const savedSummary = reportSummaries.find(
        (summary) => summary.id === analysis.reportId,
      );
      if (savedSummary) {
        return {
          ...analysis,
          findingCount: savedSummary.findingCount,
          severityCounts: savedSummary.severityCounts,
        };
      }

      const savedReport = analysis.reportId
        ? getReportFromCookie(analysis.reportId)
        : null;
      if (!savedReport || savedReport.id !== analysis.reportId) return analysis;

      return {
        ...analysis,
        findingCount: savedReport.summary.finding_count,
        severityCounts: savedReport.summary.severity,
      };
    });
  } catch {
    return [];
  }
}

export default function App() {
  const [loggedIn, setLoggedIn] = useState(
    () => localStorage.getItem("aegis-login") === "yes",
  );
  const [analyses, setAnalyses] = useState<Analysis[]>(getSaved);
  const [activeId, setActiveId] = useState<string | null>(null);
  const activeIdRef = useRef(activeId);
  activeIdRef.current = activeId;
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [scanError, setScanError] = useState("");

  useEffect(
    () => localStorage.setItem("aegis-analyses", JSON.stringify(analyses)),
    [analyses],
  );

  function login() {
    localStorage.setItem("aegis-login", "yes");
    setLoggedIn(true);
  }

  function logout() {
    localStorage.removeItem("aegis-login");
    setLoggedIn(false);
  }

  async function start(repository: string, token: string) {
    const nextId = crypto.randomUUID();
    const next: Analysis = {
      id: nextId,
      repository,
      status: "running",
      created: "Today",
      stage: "processing",
      enabled: [],
      context: "",
    };

    setScanError("");
    setReport(null);
    setAnalyses((prev) => [next, ...prev]);
    activeIdRef.current = nextId;
    setActiveId(nextId);
    setProcessingId(nextId);

    try {
      const result = await scanGitHubRepository(repository, token);
      setActiveReportCookie(result.id);
      setAnalyses((prev) =>
        prev.map((a) =>
          a.id === nextId
            ? {
                ...a,
                stage: "report",
                reportId: result.id,
                findingCount: result.summary.finding_count,
                severityCounts: result.summary.severity,
                status: result.summary.nist_score >= 5 ? "warning" : "complete",
              }
            : a,
        ),
      );
      if (activeIdRef.current === nextId) setReport(result);
    } catch (error) {
      setAnalyses((prev) => prev.filter((analysis) => analysis.id !== nextId));
      if (activeIdRef.current === nextId) {
        activeIdRef.current = null;
        setActiveId(null);
        setScanError(
            error instanceof Error
              ? error.message
              : "The scan could not be completed.",
        );
      }
    } finally {
      setProcessingId((current) => (current === nextId ? null : current));
    }
  }

  function select(id: string) {
    const selected = analyses.find((analysis) => analysis.id === id);
    const selectedReport = getReportFromCookie(selected?.reportId ?? id);
    activeIdRef.current = id;
    setActiveId(id);
    setReport(selectedReport);
    setScanError("");
    if (selectedReport) setActiveReportCookie(selectedReport.id);
  }

  if (!loggedIn) return <Login onLogin={login} />;

  return (
    <div className="app-shell">
      <Sidebar
        analyses={analyses}
        activeId={activeId}
        onSelect={select}
        onNew={() => {
          activeIdRef.current = null;
          setActiveId(null);
          setReport(null);
          setScanError("");
        }}
        onLogout={logout}
      />
      <div className="main-column">
        <main className="main-area">
          {processingId !== null && processingId === activeId ? (
            <Processing />
          ) : report ? (
            <ReportView report={report} />
          ) : (
            <Setup onStart={start} error={scanError} />
          )}
        </main>
      </div>
    </div>
  );
}
