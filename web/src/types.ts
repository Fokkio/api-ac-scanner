export interface Finding {
  type: "source" | "domain";
  rule_id: string;
  file?: string;
  line?: number;
  url?: string;
  message: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  cvss: number;
  owasp: string;
  owasp_name: string;
  guidance: string;
  code?: string;
  severity_color: string;
}

export interface ScanRecord {
  id: string;
  kind: "source" | "domain";
  target: string;
  createdAt: string;
  findings: Finding[];
  status: "done" | "error";
  error?: string;
}

export interface FixPreview {
  scanId: string;
  ruleId: string;
  file: string;
  line: number;
  original: string;
  fixed: string;
  changes: string[];
}
