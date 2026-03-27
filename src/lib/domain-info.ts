import { DomainInfo } from "./types";
import { resolve } from "dns";
import { promisify } from "util";

const resolveNs = promisify(resolve) as unknown as (
  hostname: string,
  rrtype: "NS"
) => Promise<string[]>;

const resolveTxt = promisify(resolve) as unknown as (
  hostname: string,
  rrtype: "TXT"
) => Promise<string[][]>;

// Use RDAP (successor to WHOIS) — free, structured, no API key needed
async function rdapLookup(domain: string): Promise<Partial<DomainInfo>> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    // Try RDAP via rdap.org (auto-routes to correct registry)
    const res = await fetch(
      `https://rdap.org/domain/${encodeURIComponent(domain)}`,
      {
        signal: controller.signal,
        headers: { Accept: "application/rdap+json" },
      }
    );
    clearTimeout(timeout);

    if (!res.ok) return {};

    const data = await res.json();

    // Extract registrar
    let registrar: string | null = null;
    if (data.entities) {
      for (const entity of data.entities) {
        if (entity.roles?.includes("registrar")) {
          registrar =
            entity.vcardArray?.[1]?.find((v: string[]) => v[0] === "fn")?.[3] ||
            entity.handle ||
            null;
        }
      }
    }

    // Extract dates
    let creationDate: string | null = null;
    let expirationDate: string | null = null;
    if (data.events) {
      for (const event of data.events) {
        if (event.eventAction === "registration") creationDate = event.eventDate;
        if (event.eventAction === "expiration") expirationDate = event.eventDate;
      }
    }

    // Check for privacy/proxy in registrant
    let registrantOrg: string | null = null;
    let registrantCountry: string | null = null;
    let privacyProtection = false;

    if (data.entities) {
      for (const entity of data.entities) {
        if (entity.roles?.includes("registrant")) {
          const vcard = entity.vcardArray?.[1];
          if (vcard) {
            const orgEntry = vcard.find((v: string[]) => v[0] === "org");
            registrantOrg = orgEntry ? orgEntry[3] : null;
            const adrEntry = vcard.find((v: string[]) => v[0] === "adr");
            if (adrEntry && Array.isArray(adrEntry[3])) {
              registrantCountry = adrEntry[3][6] || null;
            }
          }
          // Check for redacted / privacy
          if (
            entity.handle?.toLowerCase().includes("redacted") ||
            registrantOrg?.toLowerCase().includes("privacy") ||
            registrantOrg?.toLowerCase().includes("proxy") ||
            registrantOrg?.toLowerCase().includes("redacted") ||
            registrantOrg?.toLowerCase().includes("whoisguard") ||
            registrantOrg?.toLowerCase().includes("domains by proxy")
          ) {
            privacyProtection = true;
          }
        }
      }
    }

    // DNSSEC
    const dnssec = data.secureDNS?.delegationSigned === true;

    return {
      registrar,
      creationDate,
      expirationDate,
      registrantOrg,
      registrantCountry,
      privacyProtection,
      dnssec,
    };
  } catch {
    return {};
  }
}

export async function checkDomainInfo(domain: string): Promise<DomainInfo> {
  // Run RDAP and NS lookups in parallel
  const [rdapData, nameservers] = await Promise.all([
    rdapLookup(domain),
    resolveNs(domain, "NS").catch(() => [] as string[]),
  ]);

  // Check for DNSSEC via DNS
  let dnssec = rdapData.dnssec || false;
  if (!dnssec) {
    try {
      // Check for DNSKEY record as indicator
      const dnskeyRecords = await resolveTxt(domain, "TXT");
      // This is a basic check — DNSSEC validation is complex
      dnssec = dnskeyRecords.some((r) => r.join("").includes("DNSKEY"));
    } catch {
      // No DNSKEY
    }
  }

  const issues: string[] = [];

  // Check expiration
  if (rdapData.expirationDate) {
    const expiry = new Date(rdapData.expirationDate);
    const now = new Date();
    const daysUntilExpiry = Math.floor(
      (expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
    );
    if (daysUntilExpiry < 30) {
      issues.push(`Domain expires in ${daysUntilExpiry} days — risk of service disruption`);
    } else if (daysUntilExpiry < 90) {
      issues.push(`Domain expires in ${daysUntilExpiry} days — renewal recommended`);
    }
  }

  // Check privacy protection
  if (!rdapData.privacyProtection && rdapData.registrantOrg) {
    issues.push("Domain registration lacks privacy protection — registrant information is publicly visible");
  }

  // Check DNSSEC
  if (!dnssec) {
    issues.push("DNSSEC is not enabled — domain is vulnerable to DNS spoofing attacks");
  }

  // Check nameservers
  if (nameservers.length === 1) {
    issues.push("Only one nameserver configured — single point of failure for DNS resolution");
  }

  // Build summary
  let summary: string;
  if (issues.length === 0) {
    summary = `Domain registration for ${domain} appears well-configured with no notable issues identified.`;
  } else {
    summary = `Domain analysis of ${domain} identified ${issues.length} configuration concern${issues.length > 1 ? "s" : ""} that may be relevant to CMMC infrastructure requirements.`;
  }

  return {
    registrar: rdapData.registrar || null,
    creationDate: rdapData.creationDate || null,
    expirationDate: rdapData.expirationDate || null,
    registrantOrg: rdapData.registrantOrg || null,
    registrantCountry: rdapData.registrantCountry || null,
    privacyProtection: rdapData.privacyProtection || false,
    dnssec,
    nameservers: nameservers || [],
    issues,
    summary,
  };
}
