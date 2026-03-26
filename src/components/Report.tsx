"use client";

import { ScanResult, Finding, CMMCConcern } from "@/lib/types";

interface Props {
  result: ScanResult;
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
  // Group by family
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

function copyEmailSummary(result: ScanResult) {
  const lines: string[] = [
    `CMMC Exposure Proof — ${result.domain}`,
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

export default function Report({ result, onReset }: Props) {
  const scanDate = new Date(result.scanTimestamp).toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  return (
    <div className="min-h-screen">
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
              onClick={() => copyEmailSummary(result)}
              className="px-3 py-1.5 text-sm border border-[var(--border)] rounded hover:border-[var(--accent)] transition-colors"
            >
              Copy Summary
            </button>
            <button
              onClick={() => window.print()}
              className="px-3 py-1.5 text-sm border border-[var(--border)] rounded hover:border-[var(--accent)] transition-colors"
            >
              Print / PDF
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
          </div>
          <h1 className="text-3xl font-bold mb-1">{result.domain}</h1>
          <div className="flex items-center gap-4 text-sm text-[var(--text-secondary)]">
            <span>{result.subdomainsDiscovered} hostnames discovered</span>
            <span>&bull;</span>
            <span>{result.assetsProbed} assets probed</span>
            <span>&bull;</span>
            <span>{result.findings.length} findings</span>
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
        {result.findings.length > 0 && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
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
                label: "CMMC Families Affected",
                value: new Set(result.cmmcMappingSummary.map((c) => c.family)).size,
                color: "var(--text-primary)",
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
        )}

        {/* Findings */}
        {result.findings.length > 0 && (
          <section>
            <h2 className="text-xl font-semibold mb-3 flex items-center gap-2">
              <span className="w-1 h-6 bg-[var(--accent)] rounded" />
              Confirmed External Findings
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
        <section className="bg-gradient-to-r from-[var(--bg-card)] to-[var(--bg-secondary)] border border-[var(--border)] rounded-lg p-8 text-center">
          <h2 className="text-xl font-semibold mb-3">
            Want to validate these findings?
          </h2>
          <p className="text-[var(--text-secondary)] max-w-xl mx-auto mb-6">
            These findings are externally observable only. In a 30-minute review,
            we can validate whether they represent real CMMC risk, false
            positives, or quick remediation opportunities.
          </p>
          <a
            href="https://cinderlabs.ai"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-block px-6 py-3 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white font-medium rounded-lg transition-colors"
          >
            Schedule a Review with CinderLabs
          </a>
        </section>

        {/* Methodology note */}
        <div className="text-xs text-[var(--text-secondary)] border-t border-[var(--border)] pt-6 space-y-2">
          <p>
            <strong>Methodology:</strong> This report was generated using
            passive, non-intrusive external checks including certificate
            transparency log analysis, DNS resolution, HTTP response inspection,
            and security header evaluation. No port scanning, vulnerability
            exploitation, or internal network access was performed.
          </p>
          <p>
            <strong>Limitations:</strong> External-only analysis cannot
            determine internal security controls, MFA enforcement, or actual
            compliance posture. Findings should be validated by qualified
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
