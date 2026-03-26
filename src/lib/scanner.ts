import { Finding, AssetCategory, Confidence, ScanResult } from "./types";
import { mapConcerns, generateRedFlags, generateNextSteps } from "./cmmc";

// ---- Subdomain discovery via crt.sh ----

interface CrtEntry {
  name_value: string;
  not_before: string;
  not_after: string;
  issuer_name: string;
}

// Common subdomain prefixes to check when crt.sh is unavailable
const COMMON_PREFIXES = [
  "www", "mail", "remote", "vpn", "sso", "login", "portal", "admin",
  "webmail", "owa", "outlook", "autodiscover", "app", "apps", "api",
  "dev", "staging", "test", "intranet", "extranet", "gateway",
  "citrix", "rdp", "rdweb", "connect", "access", "myapps",
  "hr", "helpdesk", "support", "jira", "confluence", "wiki",
  "git", "gitlab", "github", "jenkins", "ci", "cd",
  "cloud", "sharepoint", "teams", "crm", "erp",
];

async function discoverSubdomains(domain: string): Promise<string[]> {
  const hostnames = new Set<string>();
  hostnames.add(domain);

  // Try crt.sh with a reasonable timeout
  const crtUrl = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json&deduplicate=Y`;
  let crtSuccess = false;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const res = await fetch(crtUrl, {
      signal: controller.signal,
      headers: { "User-Agent": "CMMCExposureProof/1.0 (security-assessment)" },
    });
    clearTimeout(timeout);

    if (res.ok) {
      const entries: CrtEntry[] = await res.json();
      for (const entry of entries) {
        const names = entry.name_value.split("\n");
        for (const name of names) {
          const cleaned = name.trim().toLowerCase().replace(/^\*\./, "");
          if (cleaned.endsWith(domain) && !cleaned.includes("*") && cleaned.length < 200) {
            hostnames.add(cleaned);
          }
        }
      }
      crtSuccess = hostnames.size > 1;
    }
  } catch {
    // crt.sh timeout or failure
  }

  // If crt.sh returned few results, supplement with common prefix probing
  if (!crtSuccess || hostnames.size < 5) {
    for (const prefix of COMMON_PREFIXES) {
      hostnames.add(`${prefix}.${domain}`);
    }
  }

  return Array.from(hostnames);
}

// ---- Asset classification ----

const AUTH_KEYWORDS = ["login", "signin", "sign-in", "auth", "sso", "saml", "oauth", "cas", "adfs", "okta", "onelogin"];
const ADMIN_KEYWORDS = ["admin", "manage", "console", "dashboard", "panel", "cpanel", "webmin", "phpmyadmin"];
const REMOTE_KEYWORDS = ["vpn", "remote", "rdp", "citrix", "rdweb", "gateway", "anyconnect", "pulse", "globalprotect", "f5"];
const SKIP_KEYWORDS = ["mail", "email", "mx", "autodiscover", "smtp", "imap", "pop", "spf", "dkim", "dmarc", "_"];

function classifyAsset(hostname: string, title: string | null): AssetCategory {
  const h = hostname.toLowerCase();
  const t = (title || "").toLowerCase();
  const combined = `${h} ${t}`;

  if (AUTH_KEYWORDS.some((k) => combined.includes(k))) return "Authentication Surface";
  if (ADMIN_KEYWORDS.some((k) => combined.includes(k))) return "Admin / Management Surface";
  if (REMOTE_KEYWORDS.some((k) => combined.includes(k))) return "Remote Access Surface";

  // Check title for login indicators
  if (t.includes("log in") || t.includes("sign in") || t.includes("password")) {
    return "Authentication Surface";
  }

  return "General Web Presence";
}

function shouldSkip(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return SKIP_KEYWORDS.some((k) => h.startsWith(k + ".") || h.includes("." + k + "."));
}

function prioritizeSubdomains(subdomains: string[], domain: string): string[] {
  // Score each subdomain for interest
  const scored = subdomains
    .filter((s) => !shouldSkip(s))
    .map((s) => {
      let score = 0;
      const lower = s.toLowerCase();
      if (AUTH_KEYWORDS.some((k) => lower.includes(k))) score += 10;
      if (ADMIN_KEYWORDS.some((k) => lower.includes(k))) score += 10;
      if (REMOTE_KEYWORDS.some((k) => lower.includes(k))) score += 10;
      if (lower === domain) score += 5; // base domain is always interesting
      if (lower.startsWith("www.")) score += 3;
      if (lower.includes("portal")) score += 8;
      if (lower.includes("app")) score += 4;
      if (lower.includes("api")) score += 2;
      return { hostname: s, score };
    });

  scored.sort((a, b) => b.score - a.score);

  // Take top 20 to keep probing fast
  return scored.slice(0, 20).map((s) => s.hostname);
}

// ---- Security header checks ----

const EXPECTED_HEADERS = [
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
  "content-security-policy",
  "x-xss-protection",
  "referrer-policy",
  "permissions-policy",
];

function checkMissingHeaders(headers: Record<string, string>): string[] {
  const present = new Set(Object.keys(headers).map((h) => h.toLowerCase()));
  return EXPECTED_HEADERS.filter((h) => !present.has(h));
}

// ---- HTTP probe ----

function extractTitle(html: string): string | null {
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? match[1].trim().slice(0, 200) : null;
}

function detectLoginPage(html: string): boolean {
  const lower = html.toLowerCase();
  const indicators = [
    'type="password"',
    'name="password"',
    "sign in",
    "log in",
    "login",
    "username",
    "forgot password",
    "forgot your password",
    "enter your credentials",
  ];
  let hits = 0;
  for (const ind of indicators) {
    if (lower.includes(ind)) hits++;
  }
  return hits >= 2;
}

interface ProbeResult {
  hostname: string;
  url: string;
  statusCode: number | null;
  title: string | null;
  headers: Record<string, string>;
  hasLogin: boolean;
  error?: string;
}

async function probeHost(hostname: string): Promise<ProbeResult> {
  // Try HTTPS first, then HTTP
  for (const proto of ["https", "http"]) {
    const url = `${proto}://${hostname}`;
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);

      const res = await fetch(url, {
        signal: controller.signal,
        redirect: "follow",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (compatible; CMMCExposureProof/1.0; +https://cinderlabs.ai)",
        },
      });
      clearTimeout(timeout);

      const headersObj: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        headersObj[k.toLowerCase()] = v;
      });

      // Read limited body for title and login detection
      const body = await res.text().then((t) => t.slice(0, 50000));
      const title = extractTitle(body);
      const hasLogin = detectLoginPage(body);

      return {
        hostname,
        url: res.url || url,
        statusCode: res.status,
        title,
        headers: headersObj,
        hasLogin,
      };
    } catch {
      continue;
    }
  }

  return {
    hostname,
    url: `https://${hostname}`,
    statusCode: null,
    title: null,
    headers: {},
    hasLogin: false,
    error: "Host unreachable",
  };
}

// ---- Build findings ----

function buildFinding(probe: ProbeResult): Finding | null {
  if (probe.statusCode === null) return null;

  const category = classifyAsset(probe.hostname, probe.title);
  const missingHeaders = checkMissingHeaders(probe.headers);
  const hasLogin = probe.hasLogin;
  const tlsIssues = probe.url.startsWith("http://");

  // Skip very boring findings — generic web presence with decent headers
  if (category === "General Web Presence" && missingHeaders.length <= 2 && !hasLogin && !tlsIssues) {
    return null;
  }

  const evidence: string[] = [];
  if (probe.statusCode) evidence.push(`HTTP ${probe.statusCode} response`);
  if (probe.title) evidence.push(`Page title: "${probe.title}"`);
  if (hasLogin) evidence.push("Login form detected on page");
  if (missingHeaders.length > 0) evidence.push(`Missing security headers: ${missingHeaders.join(", ")}`);
  if (tlsIssues) evidence.push("Served over HTTP (no HTTPS redirect)");

  let confidence: Confidence = "Needs Validation";
  if (hasLogin || category === "Admin / Management Surface") {
    confidence = "Confirmed";
  } else if (category === "Authentication Surface" || category === "Remote Access Surface") {
    confidence = "Likely";
  }

  const cmmcConcerns = mapConcerns(category, missingHeaders, hasLogin, tlsIssues);

  let summary = "";
  if (hasLogin) {
    summary = `Authentication surface detected at ${probe.hostname} — login form present.`;
  } else if (category === "Admin / Management Surface") {
    summary = `Administrative interface detected at ${probe.hostname}.`;
  } else if (category === "Remote Access Surface") {
    summary = `Remote access entry point detected at ${probe.hostname}.`;
  } else if (missingHeaders.length >= 4) {
    summary = `${probe.hostname} is missing ${missingHeaders.length} recommended security headers.`;
  } else {
    summary = `Public-facing asset at ${probe.hostname} with security header gaps.`;
  }

  return {
    asset: probe.hostname,
    category,
    url: probe.url,
    title: probe.title,
    statusCode: probe.statusCode,
    headers: probe.headers,
    missingHeaders,
    evidence,
    confidence,
    cmmcConcerns,
    summary,
  };
}

// ---- Generate executive summary ----

function generateExecutiveSummary(domain: string, findings: Finding[], subdomainCount: number): string {
  if (findings.length === 0) {
    return `External reconnaissance of ${domain} identified ${subdomainCount} certificate-associated hostnames. No significant externally observable findings were generated from the assets probed. This may indicate strong external posture or that key assets are not publicly discoverable.`;
  }

  const authCount = findings.filter(
    (f) => f.category === "Authentication Surface"
  ).length;
  const adminCount = findings.filter(
    (f) => f.category === "Admin / Management Surface"
  ).length;
  const remoteCount = findings.filter(
    (f) => f.category === "Remote Access Surface"
  ).length;
  const headerIssues = findings.filter(
    (f) => f.missingHeaders.length >= 3
  ).length;

  const parts: string[] = [];
  parts.push(
    `External reconnaissance of ${domain} identified ${subdomainCount} certificate-associated hostnames.`
  );

  const assetParts: string[] = [];
  if (authCount > 0) assetParts.push(`${authCount} authentication surface${authCount > 1 ? "s" : ""}`);
  if (adminCount > 0) assetParts.push(`${adminCount} administrative interface${adminCount > 1 ? "s" : ""}`);
  if (remoteCount > 0) assetParts.push(`${remoteCount} remote access entry point${remoteCount > 1 ? "s" : ""}`);

  if (assetParts.length > 0) {
    parts.push(
      `We identified ${findings.length} noteworthy public-facing assets, including ${assetParts.join(", ")}, that could create CMMC assessment scrutiny.`
    );
  } else {
    parts.push(
      `We identified ${findings.length} public-facing assets with security configuration gaps that could create CMMC assessment scrutiny.`
    );
  }

  if (headerIssues > 0) {
    parts.push(
      `${headerIssues} asset${headerIssues > 1 ? "s" : ""} showed notable security header deficiencies.`
    );
  }

  return parts.join(" ");
}

// ---- Main scan function ----

export async function runScan(input: string): Promise<ScanResult> {
  const start = Date.now();

  // Normalize input — determine if it's a domain or company name
  let domain: string;
  let inputType: "domain" | "company_name";

  const trimmed = input.trim().toLowerCase();

  if (trimmed.includes(".") && !trimmed.includes(" ")) {
    // Looks like a domain
    domain = trimmed.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
    inputType = "domain";
  } else {
    // Treat as company name — try to derive domain
    inputType = "company_name";
    // Simple heuristic: companyname.com
    domain = trimmed.replace(/[^a-z0-9]/g, "") + ".com";

    // Try to verify the domain resolves by probing it
    const check = await probeHost(domain);
    if (check.statusCode === null) {
      // Try with hyphens preserved
      domain = trimmed.replace(/\s+/g, "").replace(/[^a-z0-9-]/g, "") + ".com";
    }
  }

  // Discover subdomains
  const allSubdomains = await discoverSubdomains(domain);
  const prioritized = prioritizeSubdomains(allSubdomains, domain);

  // Probe top subdomains in parallel (batched)
  const BATCH_SIZE = 5;
  const probeResults: ProbeResult[] = [];

  for (let i = 0; i < prioritized.length; i += BATCH_SIZE) {
    const batch = prioritized.slice(i, i + BATCH_SIZE);
    const results = await Promise.all(batch.map((h) => probeHost(h)));
    probeResults.push(...results);
  }

  // Build findings
  const findings: Finding[] = [];
  for (const probe of probeResults) {
    const finding = buildFinding(probe);
    if (finding) findings.push(finding);
  }

  // Sort: Confirmed first, then Likely, then Needs Validation
  const confidenceOrder: Record<string, number> = {
    Confirmed: 0,
    Likely: 1,
    "Needs Validation": 2,
  };
  findings.sort((a, b) => confidenceOrder[a.confidence] - confidenceOrder[b.confidence]);

  // Generate report elements
  const hasAuth = findings.some((f) => f.category === "Authentication Surface");
  const hasAdmin = findings.some((f) => f.category === "Admin / Management Surface");
  const hasRemote = findings.some((f) => f.category === "Remote Access Surface");
  const hasMissing = findings.some((f) => f.missingHeaders.length >= 3);
  const hasTls = findings.some((f) => f.url.startsWith("http://"));

  const redFlags = generateRedFlags(hasAuth, hasAdmin, hasRemote, hasMissing, hasTls, allSubdomains.length);
  const nextSteps = generateNextSteps(findings);
  const executiveSummary = generateExecutiveSummary(domain, findings, allSubdomains.length);

  // Aggregate CMMC concerns
  const seenConcerns = new Set<string>();
  const cmmcMappingSummary = findings
    .flatMap((f) => f.cmmcConcerns)
    .filter((c) => {
      const key = `${c.family}:${c.summary}`;
      if (seenConcerns.has(key)) return false;
      seenConcerns.add(key);
      return true;
    });

  return {
    domain,
    inputType,
    originalInput: input,
    scanTimestamp: new Date().toISOString(),
    durationMs: Date.now() - start,
    subdomainsDiscovered: allSubdomains.length,
    assetsProbed: probeResults.length,
    findings,
    redFlags,
    nextSteps,
    executiveSummary,
    cmmcMappingSummary,
  };
}
