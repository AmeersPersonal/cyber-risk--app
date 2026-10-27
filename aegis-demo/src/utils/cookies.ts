import type { Report, ReportSummary } from "../types";

const CHUNK_SIZE = 3500;
const COOKIE_DAYS = 30;

/**
 * Low-level helper to get a raw cookie string by name.
 */
function getRawCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(
    new RegExp("(?:^|; )" + name.replace(/([.$?*|{}()[\]\\/+^])/g, "\\$1") + "=([^;]*)")
  );
  return match ? decodeURIComponent(match[1]) : null;
}

/**
 * Low-level helper to set a single raw cookie string.
 */
function setRawCookie(name: string, value: string, days = COOKIE_DAYS): void {
  if (typeof document === "undefined") return;
  const expires = new Date(Date.now() + days * 864e5).toUTCString();
  document.cookie = `${name}=${encodeURIComponent(value)}; expires=${expires}; path=/; SameSite=Lax`;
}

/**
 * Low-level helper to delete a raw cookie.
 */
function deleteRawCookie(name: string): void {
  if (typeof document === "undefined") return;
  document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; SameSite=Lax`;
}

/**
 * Gets a cookie value by name, handling transparent reassembly if chunked.
 */
export function getCookie(name: string): string | null {
  // Check if this cookie was stored in chunks
  const chunkCountStr = getRawCookie(`${name}__chunks`);
  if (chunkCountStr) {
    const chunkCount = parseInt(chunkCountStr, 10);
    if (!isNaN(chunkCount) && chunkCount > 0) {
      let full = "";
      for (let i = 0; i < chunkCount; i++) {
        const piece = getRawCookie(`${name}__${i}`);
        if (piece === null) {
          // If a chunk is missing, fallback to single raw cookie
          return getRawCookie(name);
        }
        full += piece;
      }
      return full;
    }
  }
  return getRawCookie(name);
}

/**
 * Sets a cookie with automatic chunking if the value exceeds standard browser limits.
 */
export function setCookie(name: string, value: string, days = COOKIE_DAYS): void {
  // If value is small, write directly
  if (value.length <= CHUNK_SIZE) {
    // Clean up any old chunks first
    const oldChunkCountStr = getRawCookie(`${name}__chunks`);
    if (oldChunkCountStr) {
      const oldChunkCount = parseInt(oldChunkCountStr, 10);
      for (let i = 0; i < oldChunkCount; i++) {
        deleteRawCookie(`${name}__${i}`);
      }
      deleteRawCookie(`${name}__chunks`);
    }
    setRawCookie(name, value, days);
    return;
  }

  // Chunking for values > CHUNK_SIZE
  const chunks: string[] = [];
  for (let i = 0; i < value.length; i += CHUNK_SIZE) {
    chunks.push(value.slice(i, i + CHUNK_SIZE));
  }

  // Delete previous direct cookie if existed
  deleteRawCookie(name);

  // Set number of chunks
  setRawCookie(`${name}__chunks`, chunks.length.toString(), days);

  // Set each chunk
  for (let i = 0; i < chunks.length; i++) {
    setRawCookie(`${name}__${i}`, chunks[i], days);
  }
}

/**
 * Deletes a cookie and any associated chunks.
 */
export function deleteCookie(name: string): void {
  const chunkCountStr = getRawCookie(`${name}__chunks`);
  if (chunkCountStr) {
    const chunkCount = parseInt(chunkCountStr, 10);
    for (let i = 0; i < chunkCount; i++) {
      deleteRawCookie(`${name}__${i}`);
    }
    deleteRawCookie(`${name}__chunks`);
  }
  deleteRawCookie(name);
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* High-Level Report Cookie Operations                                       */
/* ─────────────────────────────────────────────────────────────────────────── */

const REPORTS_INDEX_COOKIE = "aegis_reports_list";
const ACTIVE_REPORT_COOKIE = "aegis_active_report_id";

/**
 * Fetches the list of all API report summaries stored in cookies.
 */
export function getReportsFromCookies(): ReportSummary[] {
  try {
    const raw = getCookie(REPORTS_INDEX_COOKIE);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed as ReportSummary[];
      }
    }
  } catch (err) {
    console.warn("Failed to parse reports list from cookie:", err);
  }

  // Fallback to localStorage if cookie is empty
  try {
    if (typeof localStorage !== "undefined") {
      const local = localStorage.getItem(REPORTS_INDEX_COOKIE);
      if (local) {
        const parsed = JSON.parse(local);
        if (Array.isArray(parsed)) return parsed as ReportSummary[];
      }
    }
  } catch {
    // Ignore
  }

  return [];
}

/**
 * Saves a report to a cookie, updates the index cookie, and marks it active.
 */
export function saveReportToCookie(report: Report): void {
  try {
    const jsonStr = JSON.stringify(report);

    // 1. Store the full report in cookie by its unique ID
    setCookie(`aegis_report_${report.id}`, jsonStr);

    // 2. Also update generic "report" cookie for easy single-report access
    setCookie("report", jsonStr);

    // 3. Mark as currently active report
    setCookie(ACTIVE_REPORT_COOKIE, report.id);

    // 4. Update the summary index cookie
    const currentList = getReportsFromCookies();
    const summary: ReportSummary = {
      id: report.id,
      url: report.target.url,
      status: report.summary.nist_score >= 8 ? "warning" : report.summary.nist_score >= 5 ? "warning" : "complete",
      nistScore: report.summary.nist_score,
      nistRating: report.summary.nist_rating,
      findingCount: report.summary.finding_count,
      severityCounts: { ...report.summary.severity },
      timestamp: report.timestamp,
      createdGroup: report.createdGroup,
    };

    const existingIndex = currentList.findIndex((item) => item.id === report.id);
    let updatedList: ReportSummary[];
    if (existingIndex >= 0) {
      updatedList = [...currentList];
      updatedList[existingIndex] = summary;
    } else {
      updatedList = [summary, ...currentList];
    }

    setCookie(REPORTS_INDEX_COOKIE, JSON.stringify(updatedList));

    // Mirror to localStorage as backup
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(`aegis_report_${report.id}`, jsonStr);
      localStorage.setItem("report", jsonStr);
      localStorage.setItem(REPORTS_INDEX_COOKIE, JSON.stringify(updatedList));
      localStorage.setItem(ACTIVE_REPORT_COOKIE, report.id);
    }

    // Dispatch event so other components (e.g. Sidebar) can react immediately
    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("aegis:report_saved", { detail: { id: report.id } }));
    }
  } catch (err) {
    console.error("Error saving report to cookie:", err);
  }
}

/**
 * Retrieves a Report object from cookies by its ID, or the active/latest report.
 */
export function getReportFromCookie(id?: string): Report | null {
  const targetId = id || getCookie(ACTIVE_REPORT_COOKIE);

  if (targetId) {
    const raw = getCookie(`aegis_report_${targetId}`);
    if (raw) {
      try {
        return JSON.parse(raw) as Report;
      } catch (err) {
        console.warn(`Failed to parse report ${targetId} from cookie:`, err);
      }
    }
  }

  // Try standard "report" cookie
  const generic = getCookie("report");
  if (generic) {
    try {
      return JSON.parse(generic) as Report;
    } catch {
      // Ignore
    }
  }

  // Fallback to localStorage if cookies were dropped or not yet populated
  if (typeof localStorage !== "undefined") {
    try {
      if (targetId) {
        const local = localStorage.getItem(`aegis_report_${targetId}`);
        if (local) return JSON.parse(local) as Report;
      }
      const genericLocal = localStorage.getItem("report");
      if (genericLocal) return JSON.parse(genericLocal) as Report;
    } catch {
      // Ignore
    }
  }

  return null;
}

/**
 * Sets the active report ID in the cookie.
 */
export function setActiveReportCookie(id: string): void {
  setCookie(ACTIVE_REPORT_COOKIE, id);
}

/**
 * Gets the active report ID from the cookie.
 */
export function getActiveReportIdFromCookie(): string | null {
  return getCookie(ACTIVE_REPORT_COOKIE);
}

