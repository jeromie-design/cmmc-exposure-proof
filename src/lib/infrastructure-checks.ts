import * as tls from "tls";
import {
  TLSAnalysis,
  CookieSecurity,
  ServerDisclosure,
  CORSAnalysis,
  RobotsExposure,
  DirectoryListing,
  InfrastructureChecks,
  CMMCConcern,
} from "./types";

// ── Known outdated / vulnerable software versions ──

const KNOWN_VULNERABLE: Record<string, { minSafe: string; cve?: string }> = {
  apache: { minSafe: "2.4.58", cve: "CVE-2023-45802" },
  nginx: { minSafe: "1.25.3", cve: "CVE-2023-44487" },
  "microsoft-iis": { minSafe: "10.0", cve: "CVE-2023-36899" },
  openssl: { minSafe: "3.1.4", cve: "CVE-2023-5678" },
  php: { minSafe: "8.2.12", cve: "CVE-2023-3824" },
};

function versionCompare(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na < nb) return -1;
    if (na > nb) return 1;
  }
  return 0;
}

// ── Sensitive path patterns for robots.txt ──

const SENSITIVE_PATTERNS = [
  /admin/i, /login/i, /dashboard/i, /api/i, /internal/i,
  /staging/i, /dev/i, /test/i, /backup/i, /config/i,
  /\.env/i, /\.git/i, /wp-admin/i, /phpmyadmin/i,
  /console/i, /portal/i, /private/i, /secret/i,
  /upload/i, /database/i, /\.sql/i, /cgi-bin/i,
];

// ── TLS Analysis ──

export async function analyzeTLS(hostname: string): Promise<TLSAnalysis> {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      resolve({
        grade: "N/A",
        protocol: null,
        certIssuer: null,
        certExpiry: null,
        certDaysLeft: null,
        hasHSTS: false,
        hstsMaxAge: null,
        issues: ["TLS connection timed out"],
        fipsCompliant: false,
        summary: `Could not establish TLS connection to ${hostname}.`,
      });
    }, 8000);

    try {
      const socket = tls.connect(
        {
          host: hostname,
          port: 443,
          servername: hostname,
          rejectUnauthorized: false,
          timeout: 7000,
        },
        () => {
          clearTimeout(timeout);
          const issues: string[] = [];

          // Protocol
          const protocol = socket.getProtocol() || "unknown";
          const isWeakProtocol = ["TLSv1", "TLSv1.1", "SSLv3"].includes(protocol);
          if (isWeakProtocol) {
            issues.push(`Weak TLS protocol: ${protocol} — should use TLS 1.2 or higher`);
          }

          // Certificate
          const cert = socket.getPeerCertificate();
          const certIssuer = cert?.issuer ? (cert.issuer.O || cert.issuer.CN || "Unknown") : null;
          const certExpiry = cert?.valid_to || null;
          let certDaysLeft: number | null = null;

          if (certExpiry) {
            const expiryDate = new Date(certExpiry);
            certDaysLeft = Math.floor((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
            if (certDaysLeft < 0) {
              issues.push(`SSL certificate EXPIRED ${Math.abs(certDaysLeft)} days ago`);
            } else if (certDaysLeft < 30) {
              issues.push(`SSL certificate expires in ${certDaysLeft} days — renewal needed`);
            } else if (certDaysLeft < 90) {
              issues.push(`SSL certificate expires in ${certDaysLeft} days`);
            }
          }

          // Self-signed check
          if (cert?.issuer && cert?.subject) {
            if (cert.issuer.CN === cert.subject.CN && cert.issuer.O === cert.subject.O) {
              issues.push("Self-signed certificate detected — not trusted by browsers");
            }
          }

          // Cipher suite
          const cipher = socket.getCipher();
          const cipherName = cipher?.name || "unknown";
          const fipsCompliant = !cipherName.includes("RC4") &&
            !cipherName.includes("DES") &&
            !cipherName.includes("NULL") &&
            !cipherName.includes("EXPORT") &&
            (protocol === "TLSv1.2" || protocol === "TLSv1.3");

          if (cipherName.includes("RC4")) {
            issues.push("RC4 cipher detected — known weak cipher");
          }
          if (cipherName.includes("DES") && !cipherName.includes("3DES")) {
            issues.push("DES cipher detected — known weak cipher");
          }
          if (!fipsCompliant) {
            issues.push("Cipher/protocol combination may not meet FIPS 140-2 requirements");
          }

          // Grade
          let grade: TLSAnalysis["grade"] = "A";
          if (certDaysLeft !== null && certDaysLeft < 0) grade = "F";
          else if (isWeakProtocol) grade = "D";
          else if (cipherName.includes("RC4") || cipherName.includes("DES")) grade = "D";
          else if (!fipsCompliant) grade = "C";
          else if (certDaysLeft !== null && certDaysLeft < 30) grade = "B";
          else if (issues.length > 0) grade = "B";

          socket.end();

          const summary = grade === "A"
            ? `${hostname} has strong TLS configuration (${protocol}, FIPS-compatible).`
            : `${hostname} TLS grade: ${grade} — ${issues.length} issue${issues.length !== 1 ? "s" : ""} detected.`;

          resolve({
            grade,
            protocol,
            certIssuer,
            certExpiry,
            certDaysLeft,
            hasHSTS: false, // Set by caller from HTTP headers
            hstsMaxAge: null,
            issues,
            fipsCompliant,
            summary,
          });
        }
      );

      socket.on("error", () => {
        clearTimeout(timeout);
        resolve({
          grade: "F",
          protocol: null,
          certIssuer: null,
          certExpiry: null,
          certDaysLeft: null,
          hasHSTS: false,
          hstsMaxAge: null,
          issues: ["TLS connection failed — site may not support HTTPS"],
          fipsCompliant: false,
          summary: `${hostname} does not appear to support TLS/HTTPS.`,
        });
      });
    } catch {
      clearTimeout(timeout);
      resolve({
        grade: "N/A",
        protocol: null,
        certIssuer: null,
        certExpiry: null,
        certDaysLeft: null,
        hasHSTS: false,
        hstsMaxAge: null,
        issues: ["TLS analysis error"],
        fipsCompliant: false,
        summary: `Could not analyze TLS for ${hostname}.`,
      });
    }
  });
}

// ── Cookie Security Analysis ──

export function analyzeCookies(headers: Record<string, string>): CookieSecurity {
  const setCookieHeader = headers["set-cookie"] || "";
  if (!setCookieHeader) {
    return { totalCookies: 0, insecureCookies: [], summary: "No cookies set by this asset." };
  }

  // set-cookie headers may be combined with commas by some proxies
  const cookies = setCookieHeader.split(/,(?=[^ ])/);
  const insecure: CookieSecurity["insecureCookies"] = [];

  for (const cookie of cookies) {
    const parts = cookie.trim().split(";");
    const nameValue = parts[0]?.trim() || "";
    const name = nameValue.split("=")[0]?.trim() || "unknown";
    const flags = cookie.toLowerCase();
    const issues: string[] = [];

    if (!flags.includes("secure")) issues.push("Missing Secure flag — cookie sent over HTTP");
    if (!flags.includes("httponly")) issues.push("Missing HttpOnly flag — accessible to JavaScript");
    if (!flags.includes("samesite")) issues.push("Missing SameSite attribute — CSRF risk");

    if (issues.length > 0) {
      insecure.push({ name, issues });
    }
  }

  const summary = insecure.length > 0
    ? `${insecure.length} of ${cookies.length} cookie${cookies.length > 1 ? "s" : ""} missing security flags.`
    : `All ${cookies.length} cookie${cookies.length > 1 ? "s" : ""} have proper security flags.`;

  return { totalCookies: cookies.length, insecureCookies: insecure, summary };
}

// ── Server Version Disclosure ──

export function analyzeServerDisclosure(headers: Record<string, string>): ServerDisclosure {
  const serverHeader = headers["server"] || null;
  const poweredBy = headers["x-powered-by"] || null;
  const issues: string[] = [];
  const detected: ServerDisclosure["detectedSoftware"] = [];

  // Parse server header
  if (serverHeader) {
    const versionMatch = serverHeader.match(/^(\w[\w-]*)\/?(\d[\d.]*)?/i);
    if (versionMatch) {
      const name = versionMatch[1].toLowerCase();
      const version = versionMatch[2] || null;
      const known = KNOWN_VULNERABLE[name];
      let outdated = false;
      let cve: string | undefined;

      if (known && version && versionCompare(version, known.minSafe) < 0) {
        outdated = true;
        cve = known.cve;
        issues.push(`${versionMatch[1]} ${version} is outdated — update to ${known.minSafe}+ (${cve})`);
      }

      detected.push({ name: versionMatch[1], version, outdated, cve });
    }
    issues.push(`Server header discloses: "${serverHeader}" — consider removing or obfuscating`);
  }

  // Parse X-Powered-By
  if (poweredBy) {
    const versionMatch = poweredBy.match(/^(\w[\w-]*)\/?(\d[\d.]*)?/i);
    if (versionMatch) {
      const name = versionMatch[1].toLowerCase();
      const version = versionMatch[2] || null;
      const known = KNOWN_VULNERABLE[name];
      let outdated = false;
      let cve: string | undefined;

      if (known && version && versionCompare(version, known.minSafe) < 0) {
        outdated = true;
        cve = known.cve;
        issues.push(`${versionMatch[1]} ${version} is outdated (${cve})`);
      }

      detected.push({ name: versionMatch[1], version, outdated, cve });
    }
    issues.push(`X-Powered-By header discloses: "${poweredBy}" — should be removed`);
  }

  // Check other disclosure headers
  const aspNet = headers["x-aspnet-version"] || headers["x-aspnetmvc-version"];
  if (aspNet) {
    issues.push(`ASP.NET version disclosed: ${aspNet}`);
    detected.push({ name: "ASP.NET", version: aspNet, outdated: false });
  }

  const summary = issues.length > 0
    ? `Server technology disclosure detected — ${detected.length} software component${detected.length !== 1 ? "s" : ""} identified.`
    : "No server version disclosure detected.";

  return { serverHeader, poweredBy, detectedSoftware: detected, issues, summary };
}

// ── CORS Analysis ──

export function analyzeCORS(headers: Record<string, string>): CORSAnalysis {
  const origin = headers["access-control-allow-origin"] || null;
  const credentials = headers["access-control-allow-credentials"]?.toLowerCase() === "true";
  const issues: string[] = [];

  const hasWildcard = origin === "*";

  if (hasWildcard) {
    issues.push("CORS allows all origins (Access-Control-Allow-Origin: *) — any website can make requests");
    if (credentials) {
      issues.push("CRITICAL: Wildcard origin with credentials enabled — allows credential theft from any site");
    }
  }

  if (origin && origin !== "*" && credentials) {
    issues.push("CORS allows credentials from specific origin — verify this is intentional");
  }

  const summary = issues.length > 0
    ? `CORS misconfiguration detected — ${issues.length} issue${issues.length !== 1 ? "s" : ""}.`
    : origin ? "CORS configured with specific origin restrictions." : "No CORS headers present.";

  return { hasWildcard, allowCredentials: credentials, origins: origin, issues, summary };
}

// ── Robots.txt / Sitemap Analysis ──

export async function analyzeRobots(domain: string): Promise<RobotsExposure> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const res = await fetch(`https://${domain}/robots.txt`, {
      signal: controller.signal,
      headers: { "User-Agent": "Mozilla/5.0 (compatible; CMMCExposureProof/1.0)" },
    });
    clearTimeout(timeout);

    if (!res.ok || res.status === 404) {
      return { found: false, disallowedPaths: [], sitemapUrls: [], sensitivePathsExposed: [], issues: [], summary: "No robots.txt found." };
    }

    const text = await res.text();
    const lines = text.split("\n");
    const disallowed: string[] = [];
    const sitemaps: string[] = [];
    const sensitive: string[] = [];
    const issues: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.toLowerCase().startsWith("disallow:")) {
        const path = trimmed.slice(9).trim();
        if (path && path !== "/") {
          disallowed.push(path);
          if (SENSITIVE_PATTERNS.some((p) => p.test(path))) {
            sensitive.push(path);
          }
        }
      }
      if (trimmed.toLowerCase().startsWith("sitemap:")) {
        sitemaps.push(trimmed.slice(8).trim());
      }
    }

    if (sensitive.length > 0) {
      issues.push(`robots.txt reveals ${sensitive.length} sensitive path${sensitive.length > 1 ? "s" : ""}: ${sensitive.slice(0, 5).join(", ")}`);
    }
    if (sitemaps.length > 0) {
      issues.push(`${sitemaps.length} sitemap URL${sitemaps.length > 1 ? "s" : ""} disclosed`);
    }

    const summary = issues.length > 0
      ? `robots.txt exposes ${sensitive.length} sensitive path${sensitive.length !== 1 ? "s" : ""} and ${sitemaps.length} sitemap${sitemaps.length !== 1 ? "s" : ""}.`
      : `robots.txt found with ${disallowed.length} disallowed path${disallowed.length !== 1 ? "s" : ""} — no sensitive exposure.`;

    return { found: true, disallowedPaths: disallowed, sitemapUrls: sitemaps, sensitivePathsExposed: sensitive, issues, summary };
  } catch {
    return { found: false, disallowedPaths: [], sitemapUrls: [], sensitivePathsExposed: [], issues: [], summary: "Could not fetch robots.txt." };
  }
}

// ── Directory Listing Detection ──

export function detectDirectoryListing(html: string, url: string): boolean {
  const lower = html.toLowerCase();
  return (
    (lower.includes("index of /") || lower.includes("directory listing") || lower.includes("[to parent directory]")) &&
    lower.includes("<a href")
  );
}

// ── HSTS from headers ──

export function extractHSTS(headers: Record<string, string>): { hasHSTS: boolean; maxAge: number | null } {
  const hsts = headers["strict-transport-security"];
  if (!hsts) return { hasHSTS: false, maxAge: null };
  const match = hsts.match(/max-age=(\d+)/i);
  return { hasHSTS: true, maxAge: match ? parseInt(match[1]) : null };
}

// ── CMMC mappings for infrastructure checks ──

export function mapInfrastructureConcerns(
  tlsResults: TLSAnalysis[],
  cookies: CookieSecurity,
  server: ServerDisclosure,
  cors: CORSAnalysis,
  robots: RobotsExposure,
  dirListings: DirectoryListing
): CMMCConcern[] {
  const concerns: CMMCConcern[] = [];

  // TLS issues → SC.L2-3.13.8, SC.L2-3.13.11
  const hasTlsIssues = tlsResults.some((t) => t.grade !== "A" && t.grade !== "N/A");
  if (hasTlsIssues) {
    concerns.push({
      family: "SC",
      familyName: "System & Communications Protection",
      summary: "TLS/SSL configuration weaknesses on public-facing assets",
      rationale: "Weak TLS protocols, expiring certificates, or non-FIPS ciphers may fail assessor scrutiny for cryptographic protection of CUI in transit (SC.L2-3.13.8) and FIPS-validated cryptography requirements (SC.L2-3.13.11).",
    });
  }

  // Non-FIPS ciphers → SC.L2-3.13.11
  const hasNonFips = tlsResults.some((t) => !t.fipsCompliant && t.grade !== "N/A");
  if (hasNonFips) {
    concerns.push({
      family: "SC",
      familyName: "System & Communications Protection",
      summary: "Non-FIPS validated cryptographic mechanisms detected",
      rationale: "CMMC Level 2 requires FIPS-validated cryptography for protecting CUI. Non-compliant cipher suites on public-facing assets will likely be flagged by assessors (SC.L2-3.13.11).",
    });
  }

  // Cookie security → SC.L2-3.13.8, IA.L2-3.5.2
  if (cookies.insecureCookies.length > 0) {
    concerns.push({
      family: "SC",
      familyName: "System & Communications Protection",
      summary: "Session cookies missing security attributes",
      rationale: "Cookies without Secure, HttpOnly, or SameSite flags expose sessions to interception, XSS theft, and CSRF attacks — relevant to session authenticity and CUI protection controls (SC.L2-3.13.8, IA.L2-3.5.2).",
    });
  }

  // Server disclosure → CM.L2-3.4.7, SI.L2-3.14.1
  if (server.issues.length > 0) {
    concerns.push({
      family: "CM",
      familyName: "Configuration Management",
      summary: "Server software version disclosure in HTTP headers",
      rationale: "Exposing server versions helps attackers target known vulnerabilities. This relates to restricting nonessential functionality and maintaining security baselines (CM.L2-3.4.7, CM.L2-3.4.1).",
    });
  }

  // Outdated software → SI.L2-3.14.1
  if (server.detectedSoftware.some((s) => s.outdated)) {
    concerns.push({
      family: "SI",
      familyName: "System & Information Integrity",
      summary: "Outdated software with known vulnerabilities detected",
      rationale: "Running software with known CVEs indicates gaps in flaw remediation and patch management processes (SI.L2-3.14.1). Assessors will ask about vulnerability scanning and remediation timelines.",
    });
  }

  // CORS → AC.L2-3.1.3, SC.L2-3.13.1
  if (cors.issues.length > 0) {
    concerns.push({
      family: "AC",
      familyName: "Access Control",
      summary: "CORS misconfiguration allows cross-origin access",
      rationale: "Wildcard CORS policies allow any website to make authenticated requests, potentially accessing CUI. This relates to controlling information flow and access enforcement (AC.L2-3.1.3, SC.L2-3.13.1).",
    });
  }

  // Robots.txt sensitive paths → AC.L2-3.1.22
  if (robots.sensitivePathsExposed.length > 0) {
    concerns.push({
      family: "AC",
      familyName: "Access Control",
      summary: "Sensitive paths disclosed in robots.txt",
      rationale: "robots.txt reveals internal paths like admin panels, APIs, or staging environments. While intended to hide from search engines, it actually serves as a roadmap for attackers. Relates to controlling publicly accessible content (AC.L2-3.1.22).",
    });
  }

  // Directory listings → AC.L2-3.1.22, CM.L2-3.4.7
  if (dirListings.found) {
    concerns.push({
      family: "AC",
      familyName: "Access Control",
      summary: "Open directory listings expose file structures",
      rationale: "Directory listings allow anyone to browse server file structures, potentially revealing sensitive files, backup archives, or configuration data. Relates to controlling publicly accessible content and nonessential functionality (AC.L2-3.1.22, CM.L2-3.4.7).",
    });
  }

  return concerns;
}

// ── Run all infrastructure checks ──

export async function runInfrastructureChecks(
  domain: string,
  probeResults: { hostname: string; url: string; statusCode: number | null; headers: Record<string, string>; html?: string }[]
): Promise<InfrastructureChecks> {
  // Get unique hostnames that responded
  const liveHosts = probeResults.filter((p) => p.statusCode !== null);
  const uniqueHosts = [...new Set(liveHosts.map((p) => p.hostname))];

  // TLS analysis — check top 5 hosts
  const tlsHosts = uniqueHosts.slice(0, 5);
  const tlsResults = await Promise.all(tlsHosts.map((h) => analyzeTLS(h)));

  // Enrich TLS results with HSTS from HTTP headers
  for (let i = 0; i < tlsHosts.length; i++) {
    const probe = liveHosts.find((p) => p.hostname === tlsHosts[i]);
    if (probe) {
      const hsts = extractHSTS(probe.headers);
      tlsResults[i].hasHSTS = hsts.hasHSTS;
      tlsResults[i].hstsMaxAge = hsts.maxAge;
      if (!hsts.hasHSTS && tlsResults[i].grade !== "N/A") {
        tlsResults[i].issues.push("No HSTS header — browsers may connect over HTTP first");
        if (tlsResults[i].grade === "A") tlsResults[i].grade = "B";
      } else if (hsts.maxAge !== null && hsts.maxAge < 31536000) {
        tlsResults[i].issues.push(`HSTS max-age is ${hsts.maxAge}s — recommend at least 1 year (31536000s)`);
      }
    }
  }

  // Cookie analysis — aggregate from all probes
  const allCookieIssues: CookieSecurity["insecureCookies"] = [];
  let totalCookies = 0;
  for (const probe of liveHosts) {
    const cookies = analyzeCookies(probe.headers);
    totalCookies += cookies.totalCookies;
    allCookieIssues.push(...cookies.insecureCookies);
  }
  const cookieSecurity: CookieSecurity = {
    totalCookies,
    insecureCookies: allCookieIssues,
    summary: allCookieIssues.length > 0
      ? `${allCookieIssues.length} cookie${allCookieIssues.length > 1 ? "s" : ""} across ${liveHosts.length} assets missing security flags.`
      : totalCookies > 0
        ? `All ${totalCookies} cookies have proper security flags.`
        : "No cookies detected across scanned assets.",
  };

  // Server disclosure — aggregate worst case
  const serverResults = liveHosts.map((p) => analyzeServerDisclosure(p.headers));
  const allServerIssues = serverResults.flatMap((s) => s.issues);
  const allDetected = serverResults.flatMap((s) => s.detectedSoftware);
  // Deduplicate
  const seenSoftware = new Set<string>();
  const uniqueDetected = allDetected.filter((s) => {
    const key = `${s.name}:${s.version}`;
    if (seenSoftware.has(key)) return false;
    seenSoftware.add(key);
    return true;
  });
  const uniqueIssues = [...new Set(allServerIssues)];

  const serverDisclosure: ServerDisclosure = {
    serverHeader: serverResults.find((s) => s.serverHeader)?.serverHeader || null,
    poweredBy: serverResults.find((s) => s.poweredBy)?.poweredBy || null,
    detectedSoftware: uniqueDetected,
    issues: uniqueIssues.slice(0, 8),
    summary: uniqueDetected.length > 0
      ? `${uniqueDetected.length} software component${uniqueDetected.length > 1 ? "s" : ""} disclosed via HTTP headers.`
      : "No server version disclosure detected.",
  };

  // CORS — check all probes, aggregate worst
  const corsResults = liveHosts.map((p) => analyzeCORS(p.headers));
  const worstCors = corsResults.find((c) => c.hasWildcard && c.allowCredentials) ||
    corsResults.find((c) => c.hasWildcard) ||
    corsResults.find((c) => c.issues.length > 0) ||
    { hasWildcard: false, allowCredentials: false, origins: null, issues: [], summary: "No CORS issues detected." };

  // Robots.txt
  const robotsExposure = await analyzeRobots(domain);

  // Directory listings — check HTML for dir listing indicators
  const dirUrls: string[] = [];
  for (const probe of liveHosts) {
    if (probe.html && detectDirectoryListing(probe.html, probe.url)) {
      dirUrls.push(probe.url);
    }
  }
  const directoryListings: DirectoryListing = {
    found: dirUrls.length > 0,
    urls: dirUrls,
    summary: dirUrls.length > 0
      ? `${dirUrls.length} open directory listing${dirUrls.length > 1 ? "s" : ""} detected.`
      : "No open directory listings detected.",
  };

  // CMMC concerns
  const cmmcConcerns = mapInfrastructureConcerns(
    tlsResults, cookieSecurity, serverDisclosure, worstCors, robotsExposure, directoryListings
  );

  // Total new issues
  const totalNewIssues =
    tlsResults.reduce((sum, t) => sum + t.issues.length, 0) +
    allCookieIssues.length +
    uniqueIssues.length +
    worstCors.issues.length +
    robotsExposure.issues.length +
    dirUrls.length;

  // Overall grade
  const worstTls = tlsResults.reduce((worst, t) => {
    const order = { F: 0, D: 1, C: 2, B: 3, A: 4, "N/A": 5 };
    return order[t.grade] < order[worst.grade] ? t : worst;
  }, tlsResults[0] || { grade: "N/A" as const });

  let overallGrade = "A";
  if (worstTls.grade === "F" || serverDisclosure.detectedSoftware.some((s) => s.outdated)) overallGrade = "F";
  else if (worstTls.grade === "D" || (worstCors.hasWildcard && worstCors.allowCredentials)) overallGrade = "D";
  else if (worstTls.grade === "C" || worstCors.hasWildcard || dirUrls.length > 0) overallGrade = "C";
  else if (worstTls.grade === "B" || allCookieIssues.length > 0 || robotsExposure.sensitivePathsExposed.length > 0) overallGrade = "B";

  return {
    tlsAnalysis: tlsResults,
    cookieSecurity,
    serverDisclosure,
    corsIssues: worstCors,
    robotsExposure,
    directoryListings,
    overallGrade,
    totalNewIssues,
    cmmcConcerns,
  };
}
