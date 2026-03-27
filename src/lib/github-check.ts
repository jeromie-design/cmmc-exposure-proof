export interface GitHubExposure {
  orgFound: boolean;
  orgName: string | null;
  orgProfile: { publicRepos: number; avatarUrl: string; description: string | null } | null;
  repos: GitHubRepo[];
  codeFindings: CodeFinding[];
  summary: string;
  cmmcConcerns: { family: string; familyName: string; summary: string; rationale: string }[];
}

export interface GitHubRepo {
  name: string;
  fullName: string;
  url: string;
  description: string | null;
  language: string | null;
  stars: number;
  forks: number;
  updatedAt: string;
  isForked: boolean;
  topics: string[];
  concerns: string[]; // Why this repo is interesting
}

export interface CodeFinding {
  type: "credential_pattern" | "config_exposure" | "internal_reference" | "sensitive_file" | "domain_reference";
  file: string;
  repo: string;
  repoUrl: string;
  snippet: string;
  confidence: "Confirmed" | "Likely" | "Needs Validation";
  description: string;
}

// Patterns that indicate sensitive content
const SENSITIVE_PATTERNS = [
  { query: "password", type: "credential_pattern" as const, desc: "Hardcoded password reference" },
  { query: "api_key", type: "credential_pattern" as const, desc: "API key reference" },
  { query: "apikey", type: "credential_pattern" as const, desc: "API key reference" },
  { query: "secret_key", type: "credential_pattern" as const, desc: "Secret key reference" },
  { query: "aws_access_key", type: "credential_pattern" as const, desc: "AWS access key reference" },
  { query: "private_key", type: "credential_pattern" as const, desc: "Private key reference" },
  { query: ".env", type: "sensitive_file" as const, desc: "Environment configuration file" },
  { query: "BEGIN RSA PRIVATE", type: "credential_pattern" as const, desc: "RSA private key" },
  { query: "jdbc:", type: "config_exposure" as const, desc: "Database connection string" },
  { query: "mongodb+srv", type: "config_exposure" as const, desc: "MongoDB connection string" },
  { query: "smtp_pass", type: "credential_pattern" as const, desc: "SMTP credentials" },
  { query: "authorization: Bearer", type: "credential_pattern" as const, desc: "Hardcoded auth token" },
];

// File names that are concerning if public
const SENSITIVE_FILES = [
  ".env", ".env.production", ".env.local",
  "credentials.json", "secrets.yaml", "secrets.yml",
  "id_rsa", "id_ed25519", ".htpasswd",
  "wp-config.php", "database.yml", "config.json",
];

const GITHUB_API = "https://api.github.com";

function getHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "CMMCExposureProof/1.0",
  };
  const token = process.env.GITHUB_TOKEN;
  if (token) {
    headers.Authorization = `token ${token}`;
  }
  return headers;
}

async function ghFetch(url: string): Promise<Response | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: getHeaders(),
    });
    clearTimeout(timeout);
    return res;
  } catch {
    return null;
  }
}

// Try to find the GitHub org for a domain/company
async function findOrg(domain: string, companyName?: string): Promise<{ login: string; data: Record<string, unknown> } | null> {
  // Try domain-based org name (e.g., "acme.com" -> "acme")
  const baseName = domain.replace(/\.[^.]+$/, "").replace(/[^a-zA-Z0-9-]/g, "");
  const candidates = [baseName];

  // Also try with common suffixes removed
  if (baseName.endsWith("-inc") || baseName.endsWith("-llc") || baseName.endsWith("-corp")) {
    candidates.push(baseName.replace(/-(inc|llc|corp)$/, ""));
  }

  // Try company name variations if provided
  if (companyName) {
    const clean = companyName.toLowerCase().replace(/[^a-z0-9\s-]/g, "").trim();
    candidates.push(clean.replace(/\s+/g, "-"));
    candidates.push(clean.replace(/\s+/g, ""));
  }

  // Direct org lookup
  for (const candidate of candidates) {
    const res = await ghFetch(`${GITHUB_API}/orgs/${encodeURIComponent(candidate)}`);
    if (res && res.ok) {
      const data = await res.json();
      return { login: data.login, data };
    }
  }

  // Try search API as fallback
  const searchRes = await ghFetch(
    `${GITHUB_API}/search/users?q=${encodeURIComponent(baseName)}+type:org&per_page=3`
  );
  if (searchRes && searchRes.ok) {
    const data = await searchRes.json();
    if (data.items?.length > 0) {
      // Check if any match closely
      for (const item of data.items) {
        const login = (item.login as string).toLowerCase();
        if (login === baseName || login.includes(baseName) || baseName.includes(login)) {
          // Fetch full org data
          const orgRes = await ghFetch(`${GITHUB_API}/orgs/${item.login}`);
          if (orgRes && orgRes.ok) {
            const orgData = await orgRes.json();
            return { login: item.login, data: orgData };
          }
        }
      }
    }
  }

  return null;
}

// Get public repos for an org
async function getOrgRepos(orgLogin: string): Promise<GitHubRepo[]> {
  const res = await ghFetch(
    `${GITHUB_API}/orgs/${encodeURIComponent(orgLogin)}/repos?sort=updated&per_page=30&type=public`
  );
  if (!res || !res.ok) return [];

  const data = await res.json();
  if (!Array.isArray(data)) return [];

  return data.map((repo: Record<string, unknown>) => {
    const concerns: string[] = [];
    const name = ((repo.name as string) || "").toLowerCase();
    const desc = ((repo.description as string) || "").toLowerCase();
    const combined = `${name} ${desc}`;

    // Flag repos with concerning names
    if (combined.includes("internal") || combined.includes("private") || combined.includes("intranet")) {
      concerns.push("Repo name/description suggests internal tooling exposed publicly");
    }
    if (combined.includes("config") || combined.includes("infrastructure") || combined.includes("terraform") || combined.includes("ansible")) {
      concerns.push("Infrastructure-as-code or configuration repository — may expose architecture details");
    }
    if (combined.includes("deploy") || combined.includes("ci-cd") || combined.includes("pipeline")) {
      concerns.push("Deployment pipeline repository — may contain infrastructure references");
    }
    if (combined.includes("secret") || combined.includes("credential") || combined.includes("password")) {
      concerns.push("Repository name suggests sensitive content");
    }
    if (combined.includes("api") && (combined.includes("key") || combined.includes("token"))) {
      concerns.push("Repository may contain API key or token references");
    }
    if (combined.includes("legacy") || combined.includes("deprecated") || combined.includes("old")) {
      concerns.push("Legacy/deprecated repository — may contain outdated credentials or unpatched code");
    }

    return {
      name: repo.name as string,
      fullName: repo.full_name as string,
      url: repo.html_url as string,
      description: repo.description as string | null,
      language: repo.language as string | null,
      stars: (repo.stargazers_count as number) || 0,
      forks: (repo.forks_count as number) || 0,
      updatedAt: repo.updated_at as string,
      isForked: repo.fork as boolean,
      topics: (repo.topics as string[]) || [],
      concerns,
    };
  });
}

// Search code for domain references and sensitive patterns
async function searchCode(domain: string, orgLogin?: string): Promise<CodeFinding[]> {
  const findings: CodeFinding[] = [];
  const seenFiles = new Set<string>();

  // Search for the domain in all public code
  const domainRes = await ghFetch(
    `${GITHUB_API}/search/code?q=${encodeURIComponent(domain)}+in:file&per_page=10`
  );
  if (domainRes && domainRes.ok) {
    const data = await domainRes.json();
    if (data.items) {
      for (const item of data.items.slice(0, 8)) {
        const fileKey = `${item.repository?.full_name}/${item.path}`;
        if (seenFiles.has(fileKey)) continue;
        seenFiles.add(fileKey);

        const fileName = (item.name as string || "").toLowerCase();
        const filePath = (item.path as string || "").toLowerCase();
        let type: CodeFinding["type"] = "domain_reference";
        let confidence: CodeFinding["confidence"] = "Needs Validation";
        let desc = `Domain '${domain}' referenced in public code`;

        // Check if this is in a sensitive file
        if (SENSITIVE_FILES.some((sf) => fileName === sf || filePath.includes(sf))) {
          type = "sensitive_file";
          confidence = "Confirmed";
          desc = `Domain found in sensitive configuration file (${item.name})`;
        } else if (filePath.includes("config") || filePath.includes(".env") || filePath.includes("secret")) {
          type = "config_exposure";
          confidence = "Likely";
          desc = `Domain found in configuration file that may expose internal details`;
        }

        findings.push({
          type,
          file: item.path as string,
          repo: item.repository?.full_name as string,
          repoUrl: item.repository?.html_url as string,
          snippet: item.name as string,
          confidence,
          description: desc,
        });
      }
    }
  }

  // If we found an org, search for sensitive patterns in their repos
  if (orgLogin) {
    // Only do a few targeted searches to stay within rate limits
    const targetPatterns = SENSITIVE_PATTERNS.slice(0, 4);
    for (const pattern of targetPatterns) {
      const res = await ghFetch(
        `${GITHUB_API}/search/code?q=${encodeURIComponent(pattern.query)}+org:${encodeURIComponent(orgLogin)}+in:file&per_page=3`
      );
      if (res && res.ok) {
        const data = await res.json();
        if (data.items) {
          for (const item of data.items.slice(0, 2)) {
            const fileKey = `${item.repository?.full_name}/${item.path}`;
            if (seenFiles.has(fileKey)) continue;
            seenFiles.add(fileKey);

            findings.push({
              type: pattern.type,
              file: item.path as string,
              repo: item.repository?.full_name as string,
              repoUrl: item.repository?.html_url as string,
              snippet: item.name as string,
              confidence: "Needs Validation",
              description: `${pattern.desc} found in organization repository`,
            });
          }
        }
      }

      // Small delay to respect rate limits
      await new Promise((r) => setTimeout(r, 1000));
    }
  }

  // Search for sensitive files with the org name
  for (const sensitiveFile of SENSITIVE_FILES.slice(0, 3)) {
    const sfRes = await ghFetch(
      `${GITHUB_API}/search/code?q=${encodeURIComponent(domain)}+filename:${encodeURIComponent(sensitiveFile)}&per_page=3`
    );
    if (sfRes && sfRes.ok) {
      const data = await sfRes.json();
      if (data.items) {
        for (const item of data.items.slice(0, 2)) {
          const fileKey = `${item.repository?.full_name}/${item.path}`;
          if (seenFiles.has(fileKey)) continue;
          seenFiles.add(fileKey);

          findings.push({
            type: "sensitive_file",
            file: item.path as string,
            repo: item.repository?.full_name as string,
            repoUrl: item.repository?.html_url as string,
            snippet: item.name as string,
            confidence: "Likely",
            description: `Domain referenced in sensitive file type (${sensitiveFile})`,
          });
        }
      }
    }
    await new Promise((r) => setTimeout(r, 500));
  }

  return findings;
}

function buildCmmcConcerns(
  repos: GitHubRepo[],
  codeFindings: CodeFinding[]
): GitHubExposure["cmmcConcerns"] {
  const concerns: GitHubExposure["cmmcConcerns"] = [];
  const hasCredentials = codeFindings.some((f) => f.type === "credential_pattern");
  const hasConfig = codeFindings.some((f) => f.type === "config_exposure" || f.type === "sensitive_file");
  const hasInfraRepos = repos.some((r) => r.concerns.length > 0);
  const hasDomainRefs = codeFindings.some((f) => f.type === "domain_reference");

  if (hasCredentials) {
    concerns.push({
      family: "IA",
      familyName: "Identification & Authentication",
      summary: "Potential credential exposure in public repositories",
      rationale:
        "References to credentials, API keys, or secrets in public code may indicate inadequate authenticator management practices. Assessors may scrutinize credential lifecycle controls (IA.L2-3.5.7, IA.L2-3.5.8).",
    });
    concerns.push({
      family: "AC",
      familyName: "Access Control",
      summary: "Access control credentials potentially exposed publicly",
      rationale:
        "Hardcoded or committed credentials could allow unauthorized access to organizational systems if the credentials are still active (AC.L2-3.1.1, AC.L2-3.1.2).",
    });
  }

  if (hasConfig) {
    concerns.push({
      family: "CM",
      familyName: "Configuration Management",
      summary: "Configuration data exposed in public repositories",
      rationale:
        "Public configuration files may reveal system architecture, internal hostnames, database endpoints, or service dependencies. This creates scrutiny around baseline configuration protection (CM.L2-3.4.1, CM.L2-3.4.6).",
    });
    concerns.push({
      family: "SC",
      familyName: "System & Communications Protection",
      summary: "Internal system details exposed through public code",
      rationale:
        "Configuration files in public repositories may disclose network architecture, internal endpoints, or communication patterns that could aid reconnaissance (SC.L2-3.13.1, SC.L2-3.13.2).",
    });
  }

  if (hasInfraRepos) {
    concerns.push({
      family: "CM",
      familyName: "Configuration Management",
      summary: "Infrastructure or deployment code in public repositories",
      rationale:
        "Public IaC or deployment repositories may expose infrastructure patterns, security group rules, or service configurations that an assessor would expect to be protected (CM.L2-3.4.2, CM.L2-3.4.6).",
    });
  }

  if (hasDomainRefs) {
    concerns.push({
      family: "RA",
      familyName: "Risk Assessment",
      summary: "Organizational domain referenced in public codebases",
      rationale:
        "Domain references in public repositories may expose internal URLs, API endpoints, or service details. This is relevant to attack surface management and risk assessment practices (RA.L2-3.11.2, RA.L2-3.11.3).",
    });
  }

  if (repos.length > 0) {
    concerns.push({
      family: "AU",
      familyName: "Audit & Accountability",
      summary: "Public repository change history may expose sensitive information",
      rationale:
        "Git commit history in public repos may contain sensitive data even if later removed. Assessors may ask about code review processes and commit hygiene practices (AU.L2-3.3.1).",
    });
  }

  return concerns;
}

export async function checkGitHub(domain: string, companyName?: string): Promise<GitHubExposure> {
  // Find the org
  const org = await findOrg(domain, companyName);

  // Get repos if org found
  let repos: GitHubRepo[] = [];
  if (org) {
    repos = await getOrgRepos(org.login);
  }

  // Search for code references (regardless of whether org was found)
  const codeFindings = await searchCode(domain, org?.login);

  // Build CMMC concerns
  const cmmcConcerns = buildCmmcConcerns(repos, codeFindings);

  // Filter repos to only interesting ones (with concerns, or infra/config related)
  const interestingRepos = repos.filter(
    (r) => r.concerns.length > 0 || r.language === "HCL" || r.language === "Shell"
  );
  // Also include top repos by stars for general visibility
  const topRepos = repos
    .filter((r) => !interestingRepos.includes(r))
    .sort((a, b) => b.stars - a.stars)
    .slice(0, 5);
  const reportRepos = [...interestingRepos, ...topRepos].slice(0, 15);

  // Build summary
  let summary: string;
  if (!org && codeFindings.length === 0) {
    summary = `No GitHub organization was identified for ${domain}, and no public code references to this domain were found.`;
  } else if (!org && codeFindings.length > 0) {
    summary = `No GitHub organization was identified for ${domain}, but ${codeFindings.length} public code reference${codeFindings.length > 1 ? "s" : ""} to this domain ${codeFindings.length > 1 ? "were" : "was"} found across GitHub.`;
  } else if (org && codeFindings.length === 0) {
    summary = `GitHub organization "${org.login}" was identified with ${repos.length} public repositor${repos.length !== 1 ? "ies" : "y"}. No sensitive code findings were detected.`;
  } else {
    const credCount = codeFindings.filter((f) => f.type === "credential_pattern").length;
    const configCount = codeFindings.filter((f) => f.type === "config_exposure" || f.type === "sensitive_file").length;
    const parts: string[] = [`GitHub organization "${org!.login}" was identified with ${repos.length} public repositories.`];
    if (credCount > 0) {
      parts.push(`${credCount} potential credential exposure${credCount > 1 ? "s" : ""} detected.`);
    }
    if (configCount > 0) {
      parts.push(`${configCount} configuration file${configCount > 1 ? "s" : ""} with domain references found.`);
    }
    if (interestingRepos.length > 0) {
      parts.push(`${interestingRepos.length} repositor${interestingRepos.length > 1 ? "ies" : "y"} flagged for review.`);
    }
    summary = parts.join(" ");
  }

  return {
    orgFound: !!org,
    orgName: org?.login || null,
    orgProfile: org
      ? {
          publicRepos: (org.data.public_repos as number) || 0,
          avatarUrl: (org.data.avatar_url as string) || "",
          description: (org.data.description as string) || null,
        }
      : null,
    repos: reportRepos,
    codeFindings,
    summary,
    cmmcConcerns,
  };
}
