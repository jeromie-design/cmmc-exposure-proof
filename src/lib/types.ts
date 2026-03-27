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

// Email security (SPF/DKIM/DMARC)
export interface EmailSecurity {
  spf: { found: boolean; record: string | null; issues: string[] };
  dkim: { found: boolean; selector: string | null; issues: string[] };
  dmarc: { found: boolean; record: string | null; policy: string | null; issues: string[] };
  overallRating: "Good" | "Partial" | "Weak" | "Missing";
  summary: string;
}

// HIBP breach data
export interface BreachInfo {
  totalBreaches: number;
  breaches: { name: string; date: string; dataClasses: string[]; pwnCount: number }[];
  summary: string;
}

// WHOIS / domain info
export interface DomainInfo {
  registrar: string | null;
  creationDate: string | null;
  expirationDate: string | null;
  registrantOrg: string | null;
  registrantCountry: string | null;
  privacyProtection: boolean;
  dnssec: boolean;
  nameservers: string[];
  issues: string[];
  summary: string;
}

// Lead capture
export interface LeadInfo {
  name: string;
  email: string;
  company: string;
  title?: string;
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
  emailSecurity?: EmailSecurity;
  breachInfo?: BreachInfo;
  domainInfo?: DomainInfo;
}
