import { AssetCategory, CMMCConcern, EmailSecurity, BreachInfo, DomainInfo, GitHubExposure } from "./types";

// CMMC Level 2 practice family mappings based on asset category and finding type
const FAMILY_DETAILS: Record<string, string> = {
  AC: "Access Control",
  IA: "Identification & Authentication",
  SC: "System & Communications Protection",
  AU: "Audit & Accountability",
  CM: "Configuration Management",
  MP: "Media Protection",
  PE: "Physical & Environmental Protection",
  SI: "System & Information Integrity",
  RA: "Risk Assessment",
  CA: "Security Assessment",
};

export function mapConcerns(
  category: AssetCategory,
  missingHeaders: string[],
  hasLogin: boolean,
  tlsIssues: boolean
): CMMCConcern[] {
  const concerns: CMMCConcern[] = [];

  // Authentication surfaces
  if (category === "Authentication Surface" || hasLogin) {
    concerns.push({
      family: "IA",
      familyName: FAMILY_DETAILS.IA,
      summary: "Externally accessible authentication surface detected",
      rationale:
        "Public-facing login portals may create assessor scrutiny around multi-factor authentication enforcement, credential management practices, and authenticator lifecycle controls (IA.L2-3.5.3, IA.L2-3.5.4).",
    });
    concerns.push({
      family: "AC",
      familyName: FAMILY_DETAILS.AC,
      summary: "Access enforcement on public-facing portal",
      rationale:
        "Assessors may question how access to this system is restricted, whether session controls are adequate, and how least-privilege principles apply to externally accessible services (AC.L2-3.1.1, AC.L2-3.1.5).",
    });
  }

  // Admin / management surfaces
  if (category === "Admin / Management Surface") {
    concerns.push({
      family: "AC",
      familyName: FAMILY_DETAILS.AC,
      summary: "Administrative interface exposed to the public internet",
      rationale:
        "Externally reachable admin portals could contribute to questions around remote access management, privilege escalation risk, and the principle of least privilege (AC.L2-3.1.12, AC.L2-3.1.5).",
    });
    concerns.push({
      family: "CM",
      familyName: FAMILY_DETAILS.CM,
      summary: "Configuration management of exposed management interfaces",
      rationale:
        "Assessors may ask whether externally exposed administrative services are documented, baselined, and subject to change control (CM.L2-3.4.1, CM.L2-3.4.2).",
    });
    concerns.push({
      family: "AU",
      familyName: FAMILY_DETAILS.AU,
      summary: "Audit logging for externally accessible administrative functions",
      rationale:
        "This may create scrutiny around whether administrative actions on publicly exposed management interfaces are logged, reviewed, and retained (AU.L2-3.3.1, AU.L2-3.3.2).",
    });
  }

  // Remote access surfaces
  if (category === "Remote Access Surface") {
    concerns.push({
      family: "AC",
      familyName: FAMILY_DETAILS.AC,
      summary: "Remote access entry point identified",
      rationale:
        "This could contribute to questions around remote access authorization, monitoring, and enforcement of connection requirements (AC.L2-3.1.12, AC.L2-3.1.14).",
    });
    concerns.push({
      family: "IA",
      familyName: FAMILY_DETAILS.IA,
      summary: "Authentication requirements for remote access",
      rationale:
        "Assessors will likely evaluate whether multi-factor authentication is enforced for all remote access sessions to organizational systems (IA.L2-3.5.3).",
    });
  }

  // TLS issues
  if (tlsIssues) {
    concerns.push({
      family: "SC",
      familyName: FAMILY_DETAILS.SC,
      summary: "Transport layer protection concern",
      rationale:
        "This is relevant to practices around cryptographic protection of CUI in transit and the use of validated cryptographic mechanisms (SC.L2-3.13.8, SC.L2-3.13.11).",
    });
  }

  // Missing security headers
  if (missingHeaders.length > 0) {
    concerns.push({
      family: "SC",
      familyName: FAMILY_DETAILS.SC,
      summary: "Security header configuration gaps on public-facing assets",
      rationale:
        `Missing headers (${missingHeaders.join(", ")}) may create assessor scrutiny around boundary protection and system hardening practices (SC.L2-3.13.1, SC.L2-3.13.2).`,
    });
    concerns.push({
      family: "CM",
      familyName: FAMILY_DETAILS.CM,
      summary: "Baseline configuration of public-facing web services",
      rationale:
        "Incomplete security header configuration could indicate questions around whether systems are configured per organizational security baselines (CM.L2-3.4.1, CM.L2-3.4.2).",
    });
  }

  // SI concern for any public-facing asset
  if (category !== "General Web Presence") {
    concerns.push({
      family: "SI",
      familyName: FAMILY_DETAILS.SI,
      summary: "Monitoring and protection of public-facing services",
      rationale:
        "Assessors may evaluate whether this externally accessible service is monitored for indicators of compromise and protected against known threats (SI.L2-3.14.6, SI.L2-3.14.7).",
    });
  }

  // Risk assessment concern for all
  concerns.push({
    family: "RA",
    familyName: FAMILY_DETAILS.RA,
    summary: "External attack surface in organizational risk assessment",
    rationale:
      "This asset should be included in periodic vulnerability scanning and organizational risk assessments (RA.L2-3.11.2, RA.L2-3.11.3).",
  });

  return concerns;
}

// Generate assessor red flag questions based on findings
export function generateRedFlags(
  hasAuthSurfaces: boolean,
  hasAdminSurfaces: boolean,
  hasRemoteAccess: boolean,
  hasMissingHeaders: boolean,
  hasTlsIssues: boolean,
  subdomainCount: number,
  emailSecurity?: EmailSecurity,
  breachInfo?: BreachInfo,
  githubExposure?: GitHubExposure
): string[] {
  const flags: string[] = [];

  if (hasAuthSurfaces) {
    flags.push(
      "How is multi-factor authentication enforced on externally accessible authentication portals?"
    );
  }
  if (hasAdminSurfaces) {
    flags.push(
      "How are public-facing administrative interfaces restricted, monitored, and documented in your System Security Plan?"
    );
  }
  if (hasRemoteAccess) {
    flags.push(
      "What controls govern remote access sessions, and how is session activity logged and reviewed?"
    );
  }
  if (hasMissingHeaders) {
    flags.push(
      "What is the organizational baseline configuration for security headers on public-facing web services?"
    );
  }
  if (hasTlsIssues) {
    flags.push(
      "What evidence demonstrates that validated cryptographic mechanisms protect data in transit across all public-facing services?"
    );
  }
  if (subdomainCount > 5) {
    flags.push(
      "What evidence demonstrates regular review of publicly accessible systems and services for unauthorized or undocumented assets?"
    );
  }

  if (emailSecurity && emailSecurity.overallRating !== "Good") {
    flags.push(
      "What controls are in place to prevent email spoofing and phishing targeting the organization's domain?"
    );
  }
  if (breachInfo && breachInfo.totalBreaches > 0) {
    flags.push(
      "What incident response and credential rotation procedures were executed following known data breaches involving organizational accounts?"
    );
  }
  if (githubExposure && githubExposure.codeFindings.length > 0) {
    flags.push(
      "What controls prevent sensitive configuration data, credentials, or internal references from being committed to public code repositories?"
    );
  }
  if (githubExposure && githubExposure.repos.some((r) => r.concerns.length > 0)) {
    flags.push(
      "Are public repositories reviewed for inadvertent exposure of infrastructure details, deployment configurations, or internal tooling?"
    );
  }

  // Always add a general one
  flags.push(
    "Are all externally discoverable assets documented in the organization's system boundary definition and SSP?"
  );

  return flags.slice(0, 7);
}

export function generateNextSteps(
  findings: { category: AssetCategory; missingHeaders: string[] }[],
  emailSecurity?: EmailSecurity,
  breachInfo?: BreachInfo,
  domainInfo?: DomainInfo,
  githubExposure?: GitHubExposure
): string[] {
  const steps: string[] = [
    "Validate ownership and intended exposure of all discovered public-facing assets.",
  ];

  const hasAuth = findings.some(
    (f) => f.category === "Authentication Surface" || f.category === "Remote Access Surface"
  );
  const hasAdmin = findings.some((f) => f.category === "Admin / Management Surface");
  const hasMissing = findings.some((f) => f.missingHeaders.length > 0);

  if (hasAuth) {
    steps.push("Confirm multi-factor authentication and access restrictions on all externally accessible login portals.");
  }
  if (hasAdmin) {
    steps.push("Review whether exposed administrative portals are documented in your SSP and subject to access controls.");
  }
  if (hasMissing) {
    steps.push("Establish and enforce a security header baseline for all public-facing web services.");
  }
  if (emailSecurity && emailSecurity.overallRating !== "Good") {
    steps.push("Implement or strengthen email authentication controls (SPF, DKIM, DMARC) to prevent domain spoofing.");
  }
  if (breachInfo && breachInfo.totalBreaches > 0) {
    steps.push("Review credential rotation and incident response posture in light of known breach exposure.");
  }
  if (domainInfo && domainInfo.issues.length > 0) {
    steps.push("Address domain infrastructure concerns including DNSSEC, registration privacy, and DNS redundancy.");
  }
  if (githubExposure && githubExposure.codeFindings.length > 0) {
    steps.push("Audit public code repositories for exposed credentials, configuration files, and internal infrastructure references.");
  }
  if (githubExposure && githubExposure.repos.some((r) => r.concerns.length > 0)) {
    steps.push("Review flagged public repositories for inadvertent exposure of internal tooling or infrastructure details.");
  }
  steps.push("Verify monitoring and logging coverage for all public-facing services.");
  steps.push("Conduct a boundary review to ensure all public assets are within the defined CMMC assessment scope.");

  return steps;
}
