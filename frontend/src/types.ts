export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type AlertStatus = "open" | "in_progress" | "resolved" | "dismissed";
export type RuleKind = "match" | "threshold" | "cardinality" | "sequence";

export interface User {
  id: number;
  username: string;
  role: "admin" | "analyst";
  created_at: string;
}

export interface SiemEvent {
  id: number;
  timestamp: string;
  ingested_at: string;
  source: string;
  category: string;
  action: string;
  severity: Severity;
  host: string | null;
  username: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  message: string;
  extra: Record<string, unknown>;
  raw: string | null;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface Rule {
  id: number;
  slug: string;
  name: string;
  description: string;
  kind: RuleKind;
  severity: Severity;
  enabled: boolean;
  builtin: boolean;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  definition: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  alert_count: number;
}

export interface Alert {
  id: number;
  rule_id: number | null;
  title: string;
  summary: string;
  severity: Severity;
  status: AlertStatus;
  entity: string;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  hit_count: number;
  event_count: number;
  first_seen: string;
  last_seen: string;
  assignee: string | null;
  created_at: string;
  updated_at: string;
}

export interface Note {
  id: number;
  author: string;
  body: string;
  created_at: string;
}

export interface AlertDetail extends Alert {
  events: SiemEvent[];
  notes: Note[];
  rule: Rule | null;
}

export interface IngestResult {
  accepted: number;
  alerts_created: number;
  alerts_updated: number;
  alert_ids: number[];
  parsers: Record<string, number>;
}

export interface SimulationResult extends IngestResult {
  scenario: string;
  attacker_ip: string;
  target_host: string;
}

export interface Scenario {
  slug: string;
  name: string;
  description: string;
  tactics: string[];
  techniques: string[];
  default_target: string;
  expected_rules: string[];
}

export interface SimHost {
  name: string;
  ip: string;
  os: string;
  role: string;
}

export interface NamedCount {
  name: string;
  count: number;
}

export interface Overview {
  range: { hours: number; since: string; bucket_seconds: number };
  totals: {
    events: number;
    events_all_time: number;
    events_per_minute: number;
    alerts: number;
    open_alerts: number;
    open_critical: number;
    open_high: number;
  };
  timeline: { t: string; events: number; alerts: number }[];
  alerts_by_severity: NamedCount[];
  alerts_by_status: Record<string, number>;
  events_by_category: NamedCount[];
  events_by_source: NamedCount[];
  top_sources: { ip: string; events: number; flagged: boolean }[];
  top_hosts: NamedCount[];
  mitre: { tactic: string; technique: string; count: number }[];
  recent_alerts: Alert[];
  engine: {
    rules_enabled: number;
    tracked_entities: number;
    live_clients: number;
    noise_enabled: boolean;
  };
}

export interface LiveMessage {
  type: "hello" | "event" | "alert" | "alert_updated" | "ingest" | "purged";
  data: unknown;
}
