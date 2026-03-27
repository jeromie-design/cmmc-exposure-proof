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

// GitHub exposure
export interface GitHubExposure {
  orgFound: boolean;
  orgName: string | null;
  orgProfile: { publicRepos: number; avatarUrl: string; description: string | null } | null;
  repos: { name: string; fullName: string; url: string; description: string | null; language: string | null; stars: number; forks: number; updatedAt: string; isForked: boolean; topics: string[]; concerns: string[] }[];
  codeFindings: { type: string; file: string; repo: string; repoUrl: string; snippet: string; confidence: string; description: string }[];
  summary: string;
  cmmcConcerns: { family: string; familyName: string; summary: string; rationale: string }[];
}

// SSL/TLS analysis
export interface TLSAnalysis {
  grade: "A" | "B" | "C" | "D" | "F" | "N/A";
  protocol: string | null;
  certIssuer: string | null;
  certExpiry: string | null;
  certDaysLeft: number | null;
  hasHSTS: boolean;
  hstsMaxAge: number | null;
  issues: string[];
  fipsCompliant: boolean;
  summary: string;
}

// Cookie security
export interface CookieSecurity {
  totalCookies: number;
  insecureCookies: { name: string; issues: string[] }[];
  summary: string;
}

// Server disclosure
export interface ServerDisclosure {
  serverHeader: string | null;
  poweredBy: string | null;
  detectedSoftware: { name: string; version: string | null; outdated: boolean; cve?: string }[];
  issues: string[];
  summary: string;
}

// CORS analysis
export interface CORSAnalysis {
  hasWildcard: boolean;
  allowCredentials: boolean;
  origins: string | null;
  issues: string[];
  summary: string;
}

// Robots.txt / sitemap exposure
export interface RobotsExposure {
  found: boolean;
  disallowedPaths: string[];
  sitemapUrls: string[];
  sensitivePathsExposed: string[];
  issues: string[];
  summary: string;
}

// Directory listing
export interface DirectoryListing {
  found: boolean;
  urls: string[];
  summary: string;
}

// Infrastructure checks (aggregated per scan)
export interface InfrastructureChecks {
  tlsAnalysis: TLSAnalysis[];
  cookieSecurity: CookieSecurity;
  serverDisclosure: ServerDisclosure;
  corsIssues: CORSAnalysis;
  robotsExposure: RobotsExposure;
  directoryListings: DirectoryListing;
  overallGrade: string;
  totalNewIssues: number;
  cmmcConcerns: CMMCConcern[];
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
  githubExposure?: GitHubExposure;
  infrastructureChecks?: InfrastructureChecks;
}
