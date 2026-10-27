export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  tool: string;
  severity: Severity | string;
  title: string;
  detail: string;
  evidence: string;
}

export interface ToolCheck {
  tool: string;
  status: "pass" | "fail" | "info" | string;
  finding_count?: number;
  findings?: Finding[];
}

export interface LocalCVEKnowledge {
  cve_name: string;
  how_it_works: string;
  defend_against: string;
}

export interface NextStep {
  priority: "P1" | "P2" | "P3" | string;
  title: string;
  detail: string;
}

export interface SummaryData {
  tool_count: number;
  finding_count: number;
  severity: {
    critical?: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  matched_cve_count: number;
  cves_tried_count: number;
  council_rounds: number;
  nist_score: number;
  nist_rating: string;
  score_standard: string;
  local_cve_knowledge_count: number;
}

export interface NistData {
  score: number;
  scale: string;
  standard: string;
  rating: string;
  explanation: string;
  passed: ToolCheck[];
  failed: ToolCheck[];
  informational: ToolCheck[];
  tools_used: string[];
}

export interface CveData {
  matched: Array<{
    cve_id?: string;
    description?: string;
    severity?: string;
    score?: number;
    remediation?: string;
  }>;
  tried: string[];
  sources: string[];
  cross_check: {
    total: number;
    confirmed_by_multiple_sources: number;
    single_source: number;
    by_source: Record<string, unknown>;
    confirmed_ids: string[];
  };
  fetched_at: string;
  local_knowledge: LocalCVEKnowledge[];
}

export interface AfterActionReport {
  summary: string;
  next_steps: NextStep[];
}

export interface CouncilProposal {
  agent: string;
  role: string;
  argument: string;
  votes: string[];
  source?: string;
}

export interface CouncilDebateRound {
  round: number;
  proposals: CouncilProposal[];
  votes: Array<[string, number]>;
  scout?: {
    intent?: { primary: string; confidence: number };
    risk?: { level: string; flags: string[] };
    candidates?: Array<{ intent: string; score: number }>;
  };
  chosen_tools?: string[];
}

export interface CouncilMemory {
  id: string;
  kind: string;
  text: string;
  meta?: Record<string, unknown>;
  created_at: string;
}

export interface CouncilData {
  debate?: CouncilDebateRound[];
  memory?: CouncilMemory[];
  intel?: {
    source?: string;
    company?: string;
    rows?: Array<{ note: string; fingerprints: string[] }>;
    fingerprints?: string[];
  };
  engines?: Record<string, string>;
}

export interface TargetData {
  kind: string;
  url: string;
  file_count?: number;
  company?: string;
}

/**
 * Report represents the complete parsed response from the backend scan API.
 * It is stored in cookies and used across Report.tsx, Sidebar.tsx, and App.tsx.
 */
export interface Report {
  id: string;
  timestamp: string;
  createdGroup: "Today" | "Yesterday" | "Previous 7 days";
  target: TargetData;
  summary: SummaryData;
  nist: NistData;
  cves: CveData;
  after_action_report: AfterActionReport;
  tools: ToolCheck[];
  findings: Finding[];
  council?: CouncilData;
  narrative: string;
}

export interface ReportSummary {
  id: string;
  url: string;
  status: "complete" | "warning" | "running";
  nistScore: number;
  nistRating: string;
  findingCount: number;
  severityCounts: {
    critical?: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  timestamp: string;
  createdGroup: "Today" | "Yesterday" | "Previous 7 days";
}

