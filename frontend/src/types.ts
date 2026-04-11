export interface GapEntry {
  type: "GAP" | "REVERSED" | string;
  gap_start: string;
  gap_end: string;
  duration_sec: number;
  duration_human: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "REVERSED" | string;
  start_line: number;
  end_line: number;
}

export interface ThreatActor {
  ip: string;
  risk_tags: string[];
  hits: number;
  failed_attempts?: number;
  span_human: string;
  last_active: string;
  off_hours_ratio?: string;
}

export interface SystemInfo {
  os: string;
  ver: string;
  arch: string;
  host: string;
  cpu: string;
  ts: string;
}

export interface FileInfo {
  filename: string;
  path: string;
  size_bytes: number;
  modified_at: string;
  extension: string;
}

export interface PerformanceInfo {
  time: number;
  lps: number;
}

export interface StatsInfo {
  log_type: string;
  total_lines: number;
  parsed_lines: number;
  skipped_lines: number;
  log_span_sec: number;
  obfuscation_count?: number;
}

export interface ForensicReport {
  gaps: GapEntry[];
  threats: ThreatActor[];
  system_info: SystemInfo;
  file_info?: FileInfo;
  performance: PerformanceInfo;
  stats: StatsInfo;
  risk_score?: number;
  threshold_seconds?: number;
  analysis_source?: string;
  analysis_generated_at?: string;
  server_timestamp?: string;
  error?: string;
}
