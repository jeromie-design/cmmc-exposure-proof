export type Confidence = "Confirmed" | "Likely" | "Needs Validation";

export type AssetCategory =
  | "Authentication Surface"
  | "Admin / Management Surface"
  | "Remote Access Surface"
  | "General Web Presence"
  | "Unknown / Needs Review";

export interface CMMCConcern {
  family: string;        // e.g. "AC", "IA", "SC"
  familyName: string;    // e.g. "Access Control"
  summary: string;
  rationale: string;
}

export interface Finding {
  asset: string;
  category: AssetCategory;
  url: string;
  title: string | null;
  statusCode: number | null;
  headers: Record<string, string>;
  missingHeaders: string[];
  evidence: string[];
  confidence: Confidence;
  cmmcConcerns: CMMCConcern[];
  summary: string;
  tlsInfo?: {
    issuer: string;
    validFrom: string;
    validTo: string;
    protocol: string;
  } | null;
}

export interface ScanResult {
  domain: string;
  inputType: "domain" | "company_name";
  originalInput: string;
  scanTimestamp: string;
  durationMs: number;
  subdomainsDiscovered: number;
  assetsProbed: number;
  findings: Finding[];
  redFlags: string[];
  nextSteps: string[];
  executiveSummary: string;
  cmmcMappingSummary: CMMCConcern[];
}
