import { EmailSecurity } from "./types";
import { resolve } from "dns";
import { promisify } from "util";

const resolveTxt = promisify(resolve) as unknown as (
  hostname: string,
  rrtype: "TXT"
) => Promise<string[][]>;

async function queryTxt(domain: string): Promise<string[]> {
  try {
    const records = await resolveTxt(domain, "TXT");
    return records.map((r) => r.join(""));
  } catch {
    return [];
  }
}

export async function checkEmailSecurity(domain: string): Promise<EmailSecurity> {
  // SPF check
  const spfRecords = await queryTxt(domain);
  const spfRecord = spfRecords.find((r) => r.toLowerCase().startsWith("v=spf1"));
  const spfIssues: string[] = [];

  if (!spfRecord) {
    spfIssues.push("No SPF record found — email spoofing risk");
  } else {
    if (spfRecord.includes("+all")) {
      spfIssues.push("SPF record uses +all (permits any sender) — effectively no protection");
    }
    if (spfRecord.includes("~all")) {
      spfIssues.push("SPF record uses ~all (soft fail) — spoofed emails may still be delivered");
    }
    if (!spfRecord.includes("-all") && !spfRecord.includes("~all") && !spfRecord.includes("+all")) {
      if (!spfRecord.includes("?all")) {
        // Check if it ends properly
      } else {
        spfIssues.push("SPF record uses ?all (neutral) — no enforcement");
      }
    }
  }

  // DMARC check
  const dmarcRecords = await queryTxt(`_dmarc.${domain}`);
  const dmarcRecord = dmarcRecords.find((r) => r.toLowerCase().startsWith("v=dmarc1"));
  const dmarcIssues: string[] = [];
  let dmarcPolicy: string | null = null;

  if (!dmarcRecord) {
    dmarcIssues.push("No DMARC record found — no email authentication policy enforcement");
  } else {
    const policyMatch = dmarcRecord.match(/p=(\w+)/);
    dmarcPolicy = policyMatch ? policyMatch[1] : null;
    if (dmarcPolicy === "none") {
      dmarcIssues.push("DMARC policy is 'none' — monitoring only, no enforcement");
    }
    if (!dmarcRecord.includes("rua=")) {
      dmarcIssues.push("No DMARC aggregate reporting (rua) configured");
    }
    const pctMatch = dmarcRecord.match(/pct=(\d+)/);
    if (pctMatch && parseInt(pctMatch[1]) < 100) {
      dmarcIssues.push(`DMARC only applies to ${pctMatch[1]}% of messages`);
    }
  }

  // DKIM — we can only check for common selectors since DKIM requires knowing the selector
  const commonSelectors = ["default", "google", "selector1", "selector2", "k1", "s1", "s2", "dkim", "mail"];
  let dkimFound = false;
  let dkimSelector: string | null = null;

  for (const sel of commonSelectors) {
    const dkimRecords = await queryTxt(`${sel}._domainkey.${domain}`);
    const dkimRecord = dkimRecords.find((r) => r.includes("v=DKIM1") || r.includes("k=rsa") || r.includes("p="));
    if (dkimRecord) {
      dkimFound = true;
      dkimSelector = sel;
      break;
    }
  }

  const dkimIssues: string[] = [];
  if (!dkimFound) {
    dkimIssues.push("No DKIM record found for common selectors — email integrity cannot be verified by recipients");
  }

  // Overall rating
  let overallRating: EmailSecurity["overallRating"];
  const hasSpf = !!spfRecord;
  const hasDmarc = !!dmarcRecord;
  const dmarcEnforced = dmarcPolicy === "reject" || dmarcPolicy === "quarantine";

  if (hasSpf && hasDmarc && dmarcEnforced && dkimFound) {
    overallRating = "Good";
  } else if (hasSpf && hasDmarc) {
    overallRating = "Partial";
  } else if (hasSpf || hasDmarc) {
    overallRating = "Weak";
  } else {
    overallRating = "Missing";
  }

  // Summary
  const allIssues = [...spfIssues, ...dmarcIssues, ...dkimIssues];
  let summary: string;
  if (overallRating === "Good") {
    summary = `Email authentication for ${domain} appears well-configured with SPF, DKIM, and an enforcing DMARC policy.`;
  } else if (overallRating === "Partial") {
    summary = `Email authentication for ${domain} is partially configured. ${allIssues.length} issue${allIssues.length !== 1 ? "s" : ""} identified that may create assessor scrutiny.`;
  } else if (overallRating === "Weak") {
    summary = `Email authentication for ${domain} has significant gaps. ${allIssues.length} issue${allIssues.length !== 1 ? "s" : ""} identified that could contribute to CMMC concerns around communication protection.`;
  } else {
    summary = `No email authentication records (SPF, DKIM, DMARC) were found for ${domain}. This creates significant exposure to email spoofing and phishing.`;
  }

  return {
    spf: { found: hasSpf, record: spfRecord || null, issues: spfIssues },
    dkim: { found: dkimFound, selector: dkimSelector, issues: dkimIssues },
    dmarc: { found: hasDmarc, record: dmarcRecord || null, policy: dmarcPolicy, issues: dmarcIssues },
    overallRating,
    summary,
  };
}
