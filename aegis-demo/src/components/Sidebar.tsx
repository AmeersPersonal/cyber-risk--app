import {
  BookOpen,
  ChevronDown,
  CircleCheck,
  CircleDot,
  Clock3,
  FileText,
  Menu,
  Plus,
  Search,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";
import type { Analysis } from "../types";

interface Props {
  analyses: Analysis[];
  activeId: string | null;
  onSelect: (id: string) => void;
  onNew: () => void;
  onLogout: () => void;
}

interface SidebarItem {
  id: string;
  repository: string;
  status: "running" | "complete" | "warning";
  created: "Today" | "Yesterday" | "Previous 7 days";
  subtitle: string;
}

function getAnalysisSubtitle(analysis: Analysis) {
  if (typeof analysis.findingCount !== "number") {
    return "Summary unavailable";
  }
  if (analysis.findingCount === 0) return "No findings";

  const counts = analysis.severityCounts ?? {};
  const critical = counts.critical ?? 0;
  const warnings = (counts.high ?? 0) + (counts.medium ?? 0) + (counts.low ?? 0);
  return `${critical} critical, ${warnings} warnings · ${analysis.findingCount} findings`;
}

export default function Sidebar({
  analyses,
  activeId,
  onSelect,
  onNew,
  onLogout,
}: Props) {
  const [search, setSearch] = useState("");
  const [collapsed, setCollapsed] = useState(false);
  const items: SidebarItem[] = analyses
    .filter((analysis) => analysis.stage === "report" && analysis.reportId)
    .map((analysis) => ({
      id: analysis.id,
      repository: analysis.repository,
      status: analysis.status,
      created: (analysis.created as any) || "Today",
      subtitle: getAnalysisSubtitle(analysis),
    }));

  const filtered = items.filter((item) =>
    item.repository.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <aside className={`sidebar ${collapsed ? "sidebar-collapsed" : ""}`}>
      <div className="brand">
        {!collapsed && (
          <div className="flex flex-row gap-2 justify-center items-baseline">
            <ShieldCheck size={19} strokeWidth={1.8} className="text-emerald-700" />
            <b> aegis</b>
          </div>
        )}
        <button
          className="icon-button ml-auto flex justify-center items-center p-0 gap-0"
          aria-label="Toggle sidebar"
          onClick={() => setCollapsed(!collapsed)}
        >
          <Menu size={12} />
        </button>
      </div>
      {!collapsed && (
        <>
          <div className="sidebar-actions">
            <button className="sidebar-btn" onClick={onNew}>
              <Plus size={14} />
              New analysis <span className="ml-auto muted">⌘ K</span>
            </button>
            <div className="sidebar-search">
              <Search size={14} />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search analyses"
                aria-label="Search analyses"
              />
            </div>
          </div>
          <div className="history scrollbars">
            {(["Today", "Yesterday", "Previous 7 days"] as const).map(
              (group) => {
                const groupItems = filtered.filter((a) => a.created === group);
                if (groupItems.length === 0) return null;

                return (
                  <section key={group}>
                    <div className="section-label flex items-center justify-between">
                      <span>{group}</span>
                    </div>
                    {groupItems.map((a) => (
                      <button
                        key={a.id}
                        className={`history-entry ${activeId === a.id ? "history-active" : ""}`}
                        onClick={() => onSelect(a.id)}
                        title={a.repository}
                      >
                        <span className="history-icon">
                          {a.status === "running" ? (
                            <CircleDot size={15} />
                          ) : a.status === "warning" ? (
                            <Clock3 size={15} />
                          ) : (
                            <FileText size={15} />
                          )}
                        </span>
                        <span className="history-copy">
                          <strong className="flex items-center gap-1.5">
                            <span className="truncate">{a.repository}</span>
                          </strong>
                          <small
                            className={
                              a.status === "warning"
                                ? "text-red-600"
                                : a.status === "running"
                                  ? "text-emerald-700"
                                  : ""
                            }
                          >
                            {a.subtitle}
                          </small>
                        </span>
                      </button>
                    ))}
                  </section>
                );
              },
            )}
            {filtered.length === 0 && (
              <p className="p-3 muted text-[12.5px]">No matching analyses.</p>
            )}
          </div>
          <div className="sidebar-bottom">
            <button
              className="footer-link"
              onClick={() =>
                window.open(
                  "https://github.com",
                  "_blank",
                  "noopener,noreferrer",
                )
              }
            >
              <BookOpen size={15} />
              Help & documentation
            </button>
            <button className="profile" onClick={onLogout}>
              <span className="avatar">JL</span>
              <span className="profile-text">
                <strong>Jamie Lee</strong>
                <small>Active workspace</small>
              </span>
              <ChevronDown size={14} />
            </button>
          </div>
        </>
      )}
      {collapsed && (
        <div className="mt-5 flex flex-col items-center gap-4">
          <button aria-label="New analysis" onClick={onNew}>
            <Plus size={18} />
          </button>
          <button aria-label="History" onClick={() => setCollapsed(false)}>
            <Clock3 size={18} />
          </button>
          <button aria-label="Log out" onClick={onLogout}>
            <CircleCheck size={18} />
          </button>
        </div>
      )}
    </aside>
  );
}
