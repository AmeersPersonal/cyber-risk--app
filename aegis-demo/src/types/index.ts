import type { Severity } from "./report";

export type Stage = "setup" | "processing" | "report";
export type AgentId = string;
export interface Agent {
  id: AgentId;
  name: string;
  description: string;
  model: string;
}
export interface Analysis {
  id: string;
  repository: string;
  status: "running" | "complete" | "warning";
  created: string;
  stage: Stage;
  enabled: AgentId[];
  context: string;
  reportId?: string;
  findingCount?: number;
  severityCounts?: Partial<Record<Severity, number>>;
}
export * from "./report";
