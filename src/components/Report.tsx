"use client";

import { useState } from "react";
import { ScanResult, Finding, CMMCConcern, LeadInfo, EmailSecurity, BreachInfo, DomainInfo } from "@/lib/types";

interface Props {
  result: ScanResult;
  lead: LeadInfo;
  onReset: () => void;
}

function ConfidenceBadge({ level }: { level: string }) {
  const cls =
    level === "Confirmed"
      ? "badge-confirmed"
      : level === "Likely"
      ? "badge-likely"
      : "badge-needs-validation";
  return (
    <span className={`${cls} px-2 py-0.5 rounded text-xs font-medium`}>
      {level}
    </span>
  );
}

function CategoryIcon({ category }: { category: string }) {
  if (category.includes("Authentication")) return <span>&#x1F512;</span>;
  if (category.includes("Admin")) return <span>&#x2699;&#xFE0F;</span>;
  if (category.includes("Remote")) return <span>&#x1F310;</span>;
  return <span>&#x1F4C4;</span>;
}

function RatingBadge({ rating }: { rating: string }) {
  const colorMap: Record<string, string> = {
    Good: "bg-green-500/15 text-green-400 border-green-500/30",
    Partial: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    Weak: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    Missing: "bg-red-500/15 text-red-400 border-red-500/30",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium border ${colorMap[rating] || colorMap.Missing}`}>
      {rating}
    </span>
  );
}

function FindingCard({ finding, index }: { finding: Finding; index: number }) {
  return (
    <div className="finding-card border border-[var(--border)] rounded-lg p-5 bg-[var(--bg-card)]">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-[var(--text-secondary)] text-sm font-mono">
            #{index + 1}
          </span>
          <CategoryIcon category={finding.category} />
          <span className="text-xs text-[var(--text-secondary)] border border-[var(--border)] rounded px-2 py-0.5">
            {finding.category}
          </span>
        </div>
        <ConfidenceBadge level={finding.confidence} />
      </div>

      <h3 className="font-semibold mb-1 text-[var(--text-primary)]">
        {finding.asset}
      </h3>
      <p className="text-sm text-[var(--text-secondary)] mb-3">
        {finding.summary}
      </p>

      {/* Evidence */}
      <div className="mb-3">
        <p className="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide mb-1">
          Evidence
        </p>
        <ul className="space-y-1">
          {finding.evidence.map((e, i) => (
            <li key={i} className="text-sm text-[var(--text-secondary)] flex items-start gap-2">
              <span className="text-[var(--accent)] mt-0.5">&bull;</span>
              <span>{e}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* URL */}
      <div className="text-xs text-[var(--text-secondary)] font-mono break-all mb-3">
        {finding.url}
      </div>

      {/* Missing headers */}
      {finding.missingHeaders.length > 0 && (
        <div className="mb-3">
          <p className="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide mb-1">
            Missing Headers
          </p>
          <div className="flex flex-wrap gap-1">
            {finding.missingHeaders.map((h) => (
              <span
                key={h}
                className="text-xs bg-[var(--bg-secondary)] border border-[var(--border)] rounded px-2 py-0.5 font-mono"
              >
                {h}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* CMMC Concerns */}
      {finding.cmmcConcerns.length > 0 && (
        <div>
          <p className="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide mb-1">
            CMMC-Relevant Concerns
          </p>
          <div className="space-y-2">
            {finding.cmmcConcerns.slice(0, 3).map((c, i) => (
              <div key={i} className="text-sm border-l-2 border-[var(--accent)] pl-3">
                <span className="font-mono text-[var(--accent)] text-xs">
                  {c.family}
                </span>{" "}
                <span className="text-[var(--text-secondary)]">
                  {c.summary}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CMMCMappingSection({ concerns }: { concerns: CMMCConcern[] }) {
  const grouped: Record<string, CMMCConcern[]> = {};
  for (const c of concerns) {
    if (!grouped[c.family]) grouped[c.family] = [];
    grouped[c.family].push(c);
  }

  return (
    <div className="space-y-4">
      {Object.entries(grouped).map(([family, items]) => (
        <div
          key={family}
          className="border border-[var(--border)] rounded-lg p-4 bg-[var(--bg-card)]"
        >
          <div className="flex items-center gap-2 mb-2">
            <span className="font-mono text-[var(--accent)] font-bold">
              {family}
            </span>
            <span className="text-sm text-[var(--text-secondary)]">
              {items[0].familyName}
            </span>
          </div>
          <div className="space-y-2">
            {items.map((c, i) => (
              <div key={i} className="text-sm">
                <p className="text-[var(--text-primary)] font-medium mb-0.5">
                  {c.summary}
                </p>
                <p className="text-[var(--text-secondary)] text-xs">
                  {c.rationale}
                </p>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function EmailSecuritySection({ data }: { data: EmailSecurity }) {
  const checks = [
    { label: "SPF", found: data.spf.found, record: data.spf.record, issues: data.spf.issues },
    { label: "DKIM", found: data.dkim.found, record: data.dkim.selector ? `Selector: ${data.dkim.selector}` : null, issues: data.dkim.issues },
    { label: "DMARC", found: data.dmarc.found, record: data.dmarc.record, issues: data.dmarc.issues },
  ];

  return (
    <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--bg-card)]">
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm text-[var(--text-secondary)]">{data.summary}</p>
        <RatingBadge rating={data.overallRating} />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {checks.map((check) => (
          <div key={check.label} className="border border-[var(--border)] rounded-lg p-3 bg-[var(--bg-secondary)]">
            <div className="flex items-center justify-between mb-2">
              <span className="font-mono font-bold text-sm">{check.label}</span>
              <span className={`w-2 h-2 rounded-full ${check.found ? "bg-green-400" : "bg-red-400"}`} />
            </div>
            {check.record && (
              <p className="text-xs text-[var(--text-secondary)] font-mono break-all mb-2 max-h-16 overflow-y-auto">
                {check.record}
              </p>
            )}
            {check.issues.length > 0 && (
              <div className="space-y-1">
                {check.issues.map((issue, i) => (
                  <p key={i} className="text-xs text-[var(--warning)]">{issue}</p>
                ))}
              </div>
            )}
            {check.issues.length === 0 && check.found && (
              <p className="text-xs text-green-400">Configured correctly</p>
            )}
          </div>
        ))}
      </div>
      {(data.overallRating !== "Good") && (
        <div className="mt-3 text-sm border-l-2 border-[var(--warning)] pl-3">
          <span className="font-mono text-[var(--warning)] text-xs">SC</span>{" "}
          <span className="text-[var(--text-secondary)]">
            This may create assessor scrutiny around email communication protection and anti-spoofing controls (SC.L2-3.13.1, SC.L2-3.13.8).
          </span>
        </div>
      )}
    </div>
  );
}

function BreachSection({ data }: { data: BreachInfo }) {
  if (data.totalBreaches === 0) {
    return (
      <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--bg-card)]">
        <div className="flex items-center gap-2 mb-2">
          <span className="w-2 h-2 rounded-full bg-green-400" />
          <p className="text-sm text-[var(--text-secondary)]">{data.summary}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--bg-card)]">
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm text-[var(--text-secondary)]">{data.summary}</p>
        <span className="badge-confirmed px-2 py-0.5 rounded text-xs font-medium">
          {data.totalBreaches} Breach{data.totalBreaches > 1 ? "es" : ""}
        </span>
      </div>
      <div className="space-y-2">
        {data.breaches.slice(0, 5).map((breach, i) => (
          <div key={i} className="flex items-center justify-between border border-[var(--border)] rounded p-3 bg-[var(--bg-secondary)]">
            <div>
              <p className="text-sm font-medium text-[var(--text-primary)]">{breach.name}</p>
              <p className="text-xs text-[var(--text-secondary)]">
                {breach.date} &bull; {breach.pwnCount.toLocaleString()} accounts
              </p>
            </div>
            <div className="flex flex-wrap gap-1 ml-4">
              {breach.dataClasses.slice(0, 3).map((dc) => (
                <span key={dc} className="text-xs bg-[var(--bg-primary)] border border-[var(--border)] rounded px-1.5 py-0.5">
                  {dc}
                </span>
              ))}
              {breach.dataClasses.length > 3 && (
                <span className="text-xs text-[var(--text-secondary)]">+{breach.dataClasses.length - 3}</span>
              )}
            </div>
          </div>
        ))}
        {data.breaches.length > 5 && (
          <p className="text-xs text-[var(--text-secondary)] text-center pt-1">
            +{data.breaches.length - 5} additional breaches
          </p>
        )}
      </div>
      <div className="mt-3 text-sm border-l-2 border-[var(--danger)] pl-3">
        <span className="font-mono text-[var(--danger)] text-xs">IR / IA</span>{" "}
        <span className="text-[var(--text-secondary)]">
          Known breaches may create assessor scrutiny around incident response procedures, credential management, and continuous monitoring practices.
        </span>
      </div>
    </div>
  );
}

function DomainInfoSection({ data }: { data: DomainInfo }) {
  return (
    <div className="border border-[var(--border)] rounded-lg p-5 bg-[var(--bg-card)]">
      <p className="text-sm text-[var(--text-secondary)] mb-4">{data.summary}</p>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
        {data.registrar && (
          <div className="text-sm">
            <p className="text-xs text-[var(--text-secondary)] uppercase tracking-wide">Registrar</p>
            <p className="text-[var(--text-primary)] font-medium truncate">{data.registrar}</p>
          </div>
        )}
        {data.creationDate && (
          <div className="text-sm">
            <p className="text-xs text-[var(--text-secondary)] uppercase tracking-wide">Registered</p>
            <p className="text-[var(--text-primary)] font-medium">{new Date(data.creationDate).toLocaleDateString()}</p>
          </div>
        )}
        {data.expirationDate && (
          <div className="text-sm">
            <p className="text-xs text-[var(--text-secondary)] uppercase tracking-wide">Expires</p>
            <p className="text-[var(--text-primary)] font-medium">{new Date(data.expirationDate).toLocaleDateString()}</p>
          </div>
        )}
        <div className="text-sm">
          <p className="text-xs text-[var(--text-secondary)] uppercase tracking-wide">DNSSEC</p>
          <p className={`font-medium ${data.dnssec ? "text-green-400" : "text-[var(--warning)]"}`}>
            {data.dnssec ? "Enabled" : "Not Enabled"}
          </p>
        </div>
      </div>
      <div className="flex flex-wrap gap-2 mb-3">
        <span className={`text-xs px-2 py-0.5 rounded border ${data.privacyProtection ? "border-green-500/30 text-green-400" : "border-[var(--warning)]/30 text-[var(--warning)]"}`}>
          {data.privacyProtection ? "Privacy Protection Active" : "No Privacy Protection"}
        </span>
        <span className="text-xs px-2 py-0.5 rounded border border-[var(--border)] text-[var(--text-secondary)]">
          {data.nameservers.length} Nameserver{data.nameservers.length !== 1 ? "s" : ""}
        </span>
      </div>
      {data.issues.length > 0 && (
        <div className="space-y-1 mt-3">
          {data.issues.map((issue, i) => (
            <p key={i} className="text-xs text-[var(--warning)] flex items-start gap-2">
              <span className="mt-0.5">&#x26A0;</span>
              <span>{issue}</span>
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

function copyEmailSummary(result: ScanResult, lead: LeadInfo) {
  const lines: string[] = [
    `CMMC Exposure Proof — ${result.domain}`,
    `Prepared for: ${lead.name}${lead.company ? ` (${lead.company})` : ""}`,
    `Scan Date: ${new Date(result.scanTimestamp).toLocaleDateString()}`,
    "",
    "EXECUTIVE SUMMARY",
    result.executiveSummary,
    "",
    `FINDINGS: ${result.findings.length}`,
  ];

  for (const f of result.findings) {
    lines.push(`\n- [${f.confidence}] ${f.asset} — ${f.summary}`);
  }

  if (result.emailSecurity) {
    lines.push(`\nEMAIL SECURITY: ${result.emailSecurity.overallRating}`);
    lines.push(result.emailSecurity.summary);
  }

  if (result.breachInfo && result.breachInfo.totalBreaches > 0) {
    lines.push(`\nBREACH EXPOSURE: ${result.breachInfo.totalBreaches} known breaches`);
    lines.push(result.breachInfo.summary);
  }

  lines.push("\nASSESSOR RED FLAGS");
  for (const rf of result.redFlags) {
    lines.push(`- ${rf}`);
  }

  lines.push("\nNEXT STEPS");
  for (const ns of result.nextSteps) {
    lines.push(`- ${ns}`);
  }

  lines.push(
    "\n---\nThese findings are externally observable only. In a 30-minute review, we can validate whether they represent real CMMC risk, false positives, or quick remediation opportunities.\n\nCinderLabs — cinderlabs.ai"
  );

  navigator.clipboard.writeText(lines.join("\n"));
}

function CTASection({ result, lead }: { result: ScanResult; lead: LeadInfo }) {
  const [status, setStatus] = useState<"idle" | "sending" | "sent" | "error">("idle");

  async function handleRequestReview() {
    setStatus("sending");
    try {
      const res = await fetch("/api/request-review", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          lead,
          scanSummary: {
            domain: result.domain,
            findingCount: result.findings.length,
            breachCount: result.breachInfo?.totalBreaches || 0,
            emailRating: result.emailSecurity?.overallRating || "N/A",
            executiveSummary: result.executiveSummary,
            findings: result.findings.map((f) => `[${f.confidence}] ${f.asset} — ${f.summary}`),
            redFlags: result.redFlags,
          },
        }),
      });
      if (res.ok) {
        setStatus("sent");
      } else {
        setStatus("error");
      }
    } catch {
      setStatus("error");
    }
  }

  if (status === "sent") {
    return (
      <section className="bg-gradient-to-r from-[var(--bg-card)] to-[var(--bg-secondary)] border border-[var(--success)]/30 rounded-lg p-8 text-center">
        <div className="w-14 h-14 rounded-full bg-[var(--success)]/20 flex items-center justify-center mx-auto mb-4">
          <span className="text-3xl">&#x2705;</span>
        </div>
        <h2 className="text-xl font-semibold mb-3">
          Review requested
        </h2>
        <p className="text-[var(--text-secondary)] max-w-xl mx-auto">
          We&apos;ve received your request and sent a confirmation to <strong className="text-[var(--text-primary)]">{lead.email}</strong>.
          A member of our team will reach out within <strong className="text-[var(--text-primary)]">24 business hours</strong> to
          walk through your findings and identify quick wins.
        </p>
      </section>
    );
  }

  return (
    <section className="bg-gradient-to-r from-[var(--bg-card)] to-[var(--bg-secondary)] border border-[var(--border)] rounded-lg p-8 text-center">
      <h2 className="text-xl font-semibold mb-3">
        Want to validate these findings?
      </h2>
      <p className="text-[var(--text-secondary)] max-w-xl mx-auto mb-6">
        These findings are externally observable only. In a 30-minute review,
        we can validate whether they represent real CMMC risk, false
        positives, or quick remediation opportunities.
      </p>
      <button
        onClick={handleRequestReview}
        disabled={status === "sending"}
        className="inline-block px-6 py-3 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white font-medium rounded-lg transition-colors disabled:opacity-50"
      >
        {status === "sending" ? "Requesting…" : "Schedule a Review with CinderLabs"}
      </button>
      {status === "error" && (
        <p className="text-[var(--danger)] text-sm mt-3">
          Something went wrong. Please try again or email us at info@cinderlabs.ai.
        </p>
      )}
    </section>
  );
}

export default function Report({ result, lead, onReset }: Props) {
  const scanDate = new Date(result.scanTimestamp).toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  // Count total issues across all new checks
  const emailIssueCount = result.emailSecurity
    ? result.emailSecurity.spf.issues.length +
      result.emailSecurity.dkim.issues.length +
      result.emailSecurity.dmarc.issues.length
    : 0;
  const totalIssues = result.findings.length + emailIssueCount +
    (result.breachInfo?.totalBreaches || 0) +
    (result.domainInfo?.issues.length || 0);

  return (
    <div className="min-h-screen" id="report-root">
      {/* Header */}
      <header className="border-b border-[var(--border)] px-6 py-4 sticky top-0 bg-[var(--bg-primary)] z-40 no-print">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-[var(--accent)] flex items-center justify-center font-bold text-sm">
              CL
            </div>
            <span className="text-[var(--text-secondary)] text-sm font-medium">
              CMMC Exposure Proof&#8482;
            </span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => copyEmailSummary(result, lead)}
              className="px-3 py-1.5 text-sm border border-[var(--border)] rounded hover:border-[var(--accent)] transition-colors"
              title="Copy a text summary to clipboard"
            >
              Copy Summary
            </button>
            <button
              onClick={() => window.print()}
              className="px-3 py-1.5 text-sm border border-[var(--border)] rounded hover:border-[var(--accent)] transition-colors"
              title="Print or save as PDF"
            >
              Export PDF
            </button>
            <button
              onClick={onReset}
              className="px-3 py-1.5 text-sm bg-[var(--accent)] text-white rounded hover:bg-[var(--accent-hover)] transition-colors"
            >
              New Scan
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-8 space-y-10">
        {/* Report header */}
        <div>
          <div className="flex items-center gap-2 text-sm text-[var(--text-secondary)] mb-2">
            <span>External Exposure Report</span>
            <span>&mdash;</span>
            <span>{scanDate}</span>
            {lead.name && (
              <>
                <span>&mdash;</span>
                <span>Prepared for {lead.name}</span>
              </>
            )}
          </div>
          <h1 className="text-3xl font-bold mb-1">{result.domain}</h1>
          <div className="flex items-center gap-4 text-sm text-[var(--text-secondary)] flex-wrap">
            <span>{result.subdomainsDiscovered} hostnames discovered</span>
            <span>&bull;</span>
            <span>{result.assetsProbed} assets probed</span>
            <span>&bull;</span>
            <span>{totalIssues} total issues</span>
            <span>&bull;</span>
            <span>{(result.durationMs / 1000).toFixed(1)}s</span>
          </div>
        </div>

        {/* Executive Summary */}
        <section>
          <h2 className="text-xl font-semibold mb-3 flex items-center gap-2">
            <span className="w-1 h-6 bg-[var(--accent)] rounded" />
            Executive Summary
          </h2>
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-5">
            <p className="text-[var(--text-primary)] leading-relaxed">
              {result.executiveSummary}
            </p>
          </div>
        </section>

        {/* Stats bar */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {[
            {
              label: "Confirmed",
              value: result.findings.filter((f) => f.confidence === "Confirmed").length,
              color: "var(--danger)",
            },
            {
              label: "Likely",
              value: result.findings.filter((f) => f.confidence === "Likely").length,
              color: "var(--warning)",
            },
            {
              label: "Needs Validation",
              value: result.findings.filter((f) => f.confidence === "Needs Validation").length,
              color: "var(--accent)",
            },
            {
              label: "CMMC Families",
              value: new Set(result.cmmcMappingSummary.map((c) => c.family)).size,
              color: "var(--text-primary)",
            },
            {
              label: "Known Breaches",
              value: result.breachInfo?.totalBreaches || 0,
              color: result.breachInfo?.totalBreaches ? "var(--danger)" : "var(--success)",
            },
          ].map((s) => (
            <div
              key={s.label}
              className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 text-center"
            >
              <p className="text-2xl font-bold" style={{ color: s.color }}>
                {s.value}
              </p>
              <p className="text-xs text-[var(--text-secondary)] mt-1">{s.label}</p>
            </div>
          ))}
        </div>

        {/* Email Security */}
        {result.emailSecurity && (
          <section>
            <h2 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <span className="w-1 h-6 bg-[var(--accent)] rounded" />
              Email Authentication
            </h2>
            <EmailSecuritySection data={result.emailSecurity} />
          </section>
        )}

        {/* Breach Exposure */}
        {result.breachInfo && (
          <section>
            <h2 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <span className={`w-1 h-6 rounded ${result.breachInfo.totalBreaches > 0 ? "bg-[var(--danger)]" : "bg-[var(--success)]"}`} />
              Breach Exposure
            </h2>
            <BreachSection data={result.breachInfo} />
          </section>
        )}

        {/* Domain Infrastructure */}
        {result.domainInfo && (
          <section>
            <h2 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <span className="w-1 h-6 bg-[var(--accent)] rounded" />
              Domain Infrastructure
            </h2>
            <DomainInfoSection data={result.domainInfo} />
          </section>
        )}

        {/* Findings */}
        {result.findings.length > 0 && (
          <section>
            <h2 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <span className="w-1 h-6 bg-[var(--accent)] rounded" />
              External Asset Findings
            </h2>
            <div className="space-y-4">
              {result.findings.map((f, i) => (
                <FindingCard key={f.asset} finding={f} index={i} />
              ))}
            </div>
          </section>
        )}

        {/* CMMC Mapping */}
        {result.cmmcMappingSummary.length > 0 && (
          <section>
            <h2 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <span className="w-1 h-6 bg-[var(--accent)] rounded" />
              CMMC-Relevant Concern Mapping
            </h2>
            <p className="text-sm text-[var(--text-secondary)] mb-4">
              These mappings indicate areas where external findings may create
              assessor scrutiny. They do not represent compliance determinations.
            </p>
            <CMMCMappingSection concerns={result.cmmcMappingSummary} />
          </section>
        )}

        {/* Assessor Red Flags */}
        {result.redFlags.length > 0 && (
          <section>
            <h2 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <span className="w-1 h-6 bg-[var(--danger)] rounded" />
              Assessor Red Flags
            </h2>
            <p className="text-sm text-[var(--text-secondary)] mb-4">
              Questions a CMMC assessor or compliance lead might raise based on
              these external findings.
            </p>
            <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-5 space-y-3">
              {result.redFlags.map((rf, i) => (
                <div key={i} className="flex items-start gap-3">
                  <span className="text-[var(--danger)] font-bold mt-0.5">?</span>
                  <p className="text-sm text-[var(--text-primary)]">{rf}</p>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Next Steps */}
        <section>
          <h2 className="text-xl font-semibold mb-3 flex items-center gap-2">
            <span className="w-1 h-6 bg-[var(--success)] rounded" />
            Immediate Next Steps
          </h2>
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-5 space-y-2">
            {result.nextSteps.map((ns, i) => (
              <div key={i} className="flex items-start gap-3">
                <span className="text-[var(--success)] font-bold">{i + 1}.</span>
                <p className="text-sm text-[var(--text-primary)]">{ns}</p>
              </div>
            ))}
          </div>
        </section>

        {/* CTA */}
        <CTASection result={result} lead={lead} />

        {/* Methodology note */}
        <div className="text-xs text-[var(--text-secondary)] border-t border-[var(--border)] pt-6 space-y-2">
          <p>
            <strong>Methodology:</strong> This report was generated using
            passive, non-intrusive external checks including certificate
            transparency log analysis, DNS resolution, HTTP response inspection,
            security header evaluation, email authentication record analysis (SPF/DKIM/DMARC),
            public breach database queries, and domain registration analysis.
            No port scanning, vulnerability exploitation, or internal network access was performed.
          </p>
          <p>
            <strong>Limitations:</strong> External-only analysis cannot
            determine internal security controls, MFA enforcement, or actual
            compliance posture. Breach data reflects public disclosures and may not
            include all incidents. Findings should be validated by qualified
            personnel before remediation.
          </p>
          <p>
            &copy; {new Date().getFullYear()} CinderLabs. CMMC Exposure Proof
            is not a substitute for a formal C3PAO assessment.
          </p>
        </div>
      </main>
    </div>
  );
}
