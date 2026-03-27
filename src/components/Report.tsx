"use client";

import { useState } from "react";
import Image from "next/image";
import { ScanResult, Finding, CMMCConcern, LeadInfo, EmailSecurity, BreachInfo, DomainInfo, GitHubExposure } from "@/lib/types";

interface Props {
  result: ScanResult;
  lead: LeadInfo;
  onReset: () => void;
}

/* ─── Utility Components ─── */

function ConfidenceBadge({ level }: { level: string }) {
  const styles: Record<string, string> = {
    Confirmed: "bg-red-500/10 text-red-400 border-red-500/20",
    Likely: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    "Needs Validation": "bg-slate-500/10 text-slate-400 border-slate-500/20",
  };
  return (
    <span className={`px-2.5 py-1 rounded-md text-[11px] font-semibold uppercase tracking-wider border ${styles[level] || styles["Needs Validation"]}`}>
      {level}
    </span>
  );
}

function SeverityDot({ level }: { level: string }) {
  const color = level === "Confirmed" ? "bg-red-500" : level === "Likely" ? "bg-amber-500" : "bg-slate-500";
  return <span className={`inline-block w-2 h-2 rounded-full ${color}`} />;
}

function SectionHeader({ children, accent = "var(--accent)" }: { children: React.ReactNode; accent?: string }) {
  return (
    <div className="flex items-center gap-3 mb-5">
      <div className="w-1 h-7 rounded-full" style={{ background: accent }} />
      <h2 className="text-[22px] font-bold tracking-tight text-[var(--text-primary)]">{children}</h2>
    </div>
  );
}

function Divider() {
  return <div className="border-t border-[var(--border)] my-10" />;
}

/* ─── Risk Score Ring ─── */

function RiskScoreRing({ findings, emailRating, breachCount, githubFindings }: {
  findings: Finding[];
  emailRating: string;
  breachCount: number;
  githubFindings: number;
}) {
  // Simple weighted score: Confirmed=3, Likely=2, NeedsValidation=1
  let score = 0;
  score += findings.filter(f => f.confidence === "Confirmed").length * 3;
  score += findings.filter(f => f.confidence === "Likely").length * 2;
  score += findings.filter(f => f.confidence === "Needs Validation").length * 1;
  if (emailRating === "Weak" || emailRating === "Missing") score += 2;
  else if (emailRating === "Partial") score += 1;
  score += breachCount > 0 ? 3 : 0;
  score += githubFindings > 0 ? 2 : 0;

  const maxScore = 20;
  const normalized = Math.min(score / maxScore, 1);
  const label = normalized >= 0.6 ? "High" : normalized >= 0.3 ? "Moderate" : "Low";
  const color = normalized >= 0.6 ? "#ef4444" : normalized >= 0.3 ? "#f59e0b" : "#10b981";

  const circumference = 2 * Math.PI * 54;
  const filled = circumference * normalized;

  return (
    <div className="flex flex-col items-center">
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r="54" fill="none" stroke="var(--border)" strokeWidth="8" />
        <circle
          cx="70" cy="70" r="54" fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={`${filled} ${circumference}`}
          strokeDashoffset={circumference * 0.25}
          strokeLinecap="round"
          transform="rotate(-90 70 70)"
          style={{ transition: "stroke-dasharray 1s ease" }}
        />
        <text x="70" y="65" textAnchor="middle" fill={color} fontSize="28" fontWeight="bold">{Math.round(normalized * 100)}</text>
        <text x="70" y="85" textAnchor="middle" fill="var(--text-secondary)" fontSize="11" fontWeight="500">{label} Exposure</text>
      </svg>
    </div>
  );
}

/* ─── Stat Card ─── */

function StatCard({ value, label, color }: { value: number | string; label: string; color: string }) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 text-center">
      <p className="text-3xl font-bold tabular-nums" style={{ color }}>{value}</p>
      <p className="text-[11px] text-[var(--text-secondary)] mt-1.5 uppercase tracking-wider font-medium">{label}</p>
    </div>
  );
}

/* ─── Email Security ─── */

function EmailSecuritySection({ data }: { data: EmailSecurity }) {
  const checks = [
    { label: "SPF", found: data.spf.found, record: data.spf.record, issues: data.spf.issues },
    { label: "DKIM", found: data.dkim.found, record: data.dkim.selector ? `Selector: ${data.dkim.selector}` : null, issues: data.dkim.issues },
    { label: "DMARC", found: data.dmarc.found, record: data.dmarc.record, issues: data.dmarc.issues },
  ];
  const ratingColor: Record<string, string> = {
    Good: "text-green-400 bg-green-500/10 border-green-500/20",
    Partial: "text-amber-400 bg-amber-500/10 border-amber-500/20",
    Weak: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    Missing: "text-red-400 bg-red-500/10 border-red-500/20",
  };

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-6 space-y-5">
      <div className="flex items-center justify-between">
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed flex-1 pr-4">{data.summary}</p>
        <span className={`px-3 py-1 rounded-lg text-xs font-bold uppercase tracking-wider border ${ratingColor[data.overallRating] || ratingColor.Missing}`}>
          {data.overallRating}
        </span>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {checks.map((check) => (
          <div key={check.label} className="rounded-lg p-4 bg-[var(--bg-secondary)] border border-[var(--border)]">
            <div className="flex items-center justify-between mb-3">
              <span className="font-mono font-bold text-sm text-[var(--text-primary)]">{check.label}</span>
              <span className={`w-2.5 h-2.5 rounded-full ${check.found ? "bg-green-400" : "bg-red-400"}`} />
            </div>
            {check.record && (
              <p className="text-[10px] text-[var(--text-secondary)] font-mono break-all mb-3 max-h-14 overflow-y-auto leading-relaxed opacity-70">{check.record}</p>
            )}
            {check.issues.length > 0 ? (
              <div className="space-y-1">
                {check.issues.map((issue, i) => (
                  <p key={i} className="text-xs text-amber-400/90 leading-snug">{issue}</p>
                ))}
              </div>
            ) : check.found ? (
              <p className="text-xs text-green-400/80">Configured correctly</p>
            ) : null}
          </div>
        ))}
      </div>
      {data.cmmcConcerns && data.cmmcConcerns.length > 0 && (
        <div className="pt-3 border-t border-[var(--border)]">
          {data.cmmcConcerns.map((c, i) => (
            <div key={i} className="flex items-start gap-2 text-sm">
              <span className="font-mono text-[var(--accent)] text-xs font-bold mt-0.5">{c.family}</span>
              <span className="text-[var(--text-secondary)] text-xs leading-relaxed">{c.summary}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ─── Breach Section ─── */

function BreachSection({ data }: { data: BreachInfo }) {
  if (data.totalBreaches === 0) {
    return (
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-6">
        <div className="flex items-center gap-3">
          <span className="w-2.5 h-2.5 rounded-full bg-green-400" />
          <p className="text-sm text-[var(--text-secondary)]">{data.summary}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-6 space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-[var(--text-secondary)] flex-1 pr-4">{data.summary}</p>
        <span className="bg-red-500/10 text-red-400 border border-red-500/20 px-3 py-1 rounded-lg text-xs font-bold uppercase tracking-wider">
          {data.totalBreaches} Breach{data.totalBreaches > 1 ? "es" : ""}
        </span>
      </div>
      <div className="space-y-2">
        {data.breaches.slice(0, 5).map((breach, i) => (
          <div key={i} className="flex items-center justify-between rounded-lg p-3 bg-[var(--bg-secondary)] border border-[var(--border)]">
            <div>
              <p className="text-sm font-semibold text-[var(--text-primary)]">{breach.name}</p>
              <p className="text-xs text-[var(--text-secondary)] mt-0.5">{breach.date} &bull; {breach.pwnCount.toLocaleString()} accounts</p>
            </div>
            <div className="flex flex-wrap gap-1 ml-4 justify-end">
              {breach.dataClasses.slice(0, 3).map((dc) => (
                <span key={dc} className="text-[10px] bg-[var(--bg-primary)] border border-[var(--border)] rounded px-1.5 py-0.5 text-[var(--text-secondary)]">{dc}</span>
              ))}
              {breach.dataClasses.length > 3 && (
                <span className="text-[10px] text-[var(--text-secondary)]">+{breach.dataClasses.length - 3}</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── Domain Info ─── */

function DomainInfoSection({ data }: { data: DomainInfo }) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-6 space-y-4">
      <p className="text-sm text-[var(--text-secondary)]">{data.summary}</p>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {data.registrar && (
          <div>
            <p className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider font-medium mb-1">Registrar</p>
            <p className="text-sm text-[var(--text-primary)] font-medium truncate">{data.registrar}</p>
          </div>
        )}
        {data.creationDate && (
          <div>
            <p className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider font-medium mb-1">Registered</p>
            <p className="text-sm text-[var(--text-primary)] font-medium">{new Date(data.creationDate).toLocaleDateString()}</p>
          </div>
        )}
        {data.expirationDate && (
          <div>
            <p className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider font-medium mb-1">Expires</p>
            <p className="text-sm text-[var(--text-primary)] font-medium">{new Date(data.expirationDate).toLocaleDateString()}</p>
          </div>
        )}
        <div>
          <p className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider font-medium mb-1">DNSSEC</p>
          <p className={`text-sm font-medium ${data.dnssec ? "text-green-400" : "text-amber-400"}`}>
            {data.dnssec ? "Enabled" : "Not Enabled"}
          </p>
        </div>
      </div>
      {data.issues.length > 0 && (
        <div className="space-y-1.5 pt-3 border-t border-[var(--border)]">
          {data.issues.map((issue, i) => (
            <p key={i} className="text-xs text-amber-400/90 flex items-start gap-2 leading-snug">
              <span className="mt-0.5 text-[10px]">&#x26A0;</span>
              <span>{issue}</span>
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

/* ─── GitHub Section ─── */

function GitHubSection({ data }: { data: GitHubExposure }) {
  if (!data.orgFound && data.codeFindings.length === 0) {
    return (
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-6">
        <div className="flex items-center gap-3">
          <span className="w-2.5 h-2.5 rounded-full bg-green-400" />
          <p className="text-sm text-[var(--text-secondary)]">{data.summary}</p>
        </div>
      </div>
    );
  }

  const flaggedRepos = data.repos.filter(r => r.concerns.length > 0);
  const otherRepos = data.repos.filter(r => r.concerns.length === 0);

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-6 space-y-5">
      <div className="flex items-center justify-between">
        <p className="text-sm text-[var(--text-secondary)] flex-1 pr-4">{data.summary}</p>
        {data.orgFound && (
          <span className="text-xs px-3 py-1 rounded-lg border border-[var(--accent)]/30 text-[var(--accent)] font-semibold">
            {data.orgName}
          </span>
        )}
      </div>

      {/* Code findings */}
      {data.codeFindings.length > 0 && (
        <div>
          <p className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider font-semibold mb-3">Code Exposure Findings</p>
          <div className="space-y-2">
            {data.codeFindings.map((f, i) => (
              <div key={i} className="rounded-lg p-4 bg-[var(--bg-secondary)] border border-[var(--border)]">
                <div className="flex items-start justify-between mb-2">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--bg-primary)] border border-[var(--border)] text-[var(--text-secondary)] uppercase">
                    {f.type.replace(/_/g, " ")}
                  </span>
                  <ConfidenceBadge level={f.confidence} />
                </div>
                <p className="text-sm text-[var(--text-primary)] font-medium leading-snug">{f.description}</p>
                <p className="text-[10px] text-[var(--text-secondary)] font-mono mt-2 opacity-60">{f.repo}/{f.file}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Flagged repos */}
      {flaggedRepos.length > 0 && (
        <div>
          <p className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider font-semibold mb-3">Flagged Repositories</p>
          <div className="space-y-2">
            {flaggedRepos.slice(0, 6).map((repo, i) => (
              <div key={i} className="rounded-lg p-3 bg-[var(--bg-secondary)] border border-[var(--border)]">
                <div className="flex items-center justify-between mb-1">
                  <p className="text-sm font-semibold text-[var(--text-primary)] font-mono">{repo.fullName}</p>
                  {repo.language && <span className="text-[10px] text-[var(--text-secondary)]">{repo.language}</span>}
                </div>
                {repo.description && <p className="text-xs text-[var(--text-secondary)] mb-2 leading-relaxed">{repo.description}</p>}
                {repo.concerns.map((concern, ci) => (
                  <p key={ci} className="text-xs text-amber-400/90 flex items-start gap-2 leading-snug">
                    <span className="mt-0.5 text-[10px]">&#x26A0;</span>
                    <span>{concern}</span>
                  </p>
                ))}
              </div>
            ))}
            {flaggedRepos.length > 6 && (
              <p className="text-xs text-[var(--text-secondary)] text-center py-2">
                + {flaggedRepos.length - 6} more flagged repositories
              </p>
            )}
          </div>
        </div>
      )}

      {/* Other repos grid */}
      {data.orgFound && otherRepos.length > 0 && (
        <div>
          <p className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider font-semibold mb-3">
            Public Repositories ({data.orgProfile?.publicRepos || data.repos.length})
          </p>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
            {otherRepos.slice(0, 6).map((repo, i) => (
              <div key={i} className="rounded-lg p-2.5 bg-[var(--bg-secondary)] border border-[var(--border)]">
                <p className="font-mono text-xs text-[var(--text-primary)] truncate">{repo.name}</p>
                <p className="text-[10px] text-[var(--text-secondary)] truncate mt-0.5">{repo.description || "No description"}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* CMMC concerns */}
      {data.cmmcConcerns.length > 0 && (
        <div className="pt-3 border-t border-[var(--border)] space-y-1.5">
          {data.cmmcConcerns.slice(0, 3).map((c, i) => (
            <div key={i} className="flex items-start gap-2 text-sm">
              <span className="font-mono text-[var(--accent)] text-xs font-bold mt-0.5">{c.family}</span>
              <span className="text-[var(--text-secondary)] text-xs leading-relaxed">{c.summary}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ─── Finding Card ─── */

function FindingCard({ finding, index }: { finding: Finding; index: number }) {
  const categoryColors: Record<string, string> = {
    "Authentication Surface": "border-l-red-500",
    "Admin / Management Surface": "border-l-orange-500",
    "Remote Access Surface": "border-l-amber-500",
    "General Web Presence": "border-l-slate-500",
    "Unknown / Needs Review": "border-l-slate-600",
  };
  const borderClass = categoryColors[finding.category] || "border-l-slate-500";

  return (
    <div className={`finding-card bg-[var(--bg-card)] border border-[var(--border)] ${borderClass} border-l-[3px] rounded-xl p-6 space-y-4`}>
      {/* Header row */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <span className="text-[var(--text-secondary)] text-xs font-mono bg-[var(--bg-secondary)] px-2 py-0.5 rounded">#{index + 1}</span>
          <span className="text-[10px] text-[var(--text-secondary)] border border-[var(--border)] rounded-md px-2 py-0.5 uppercase tracking-wider font-medium">
            {finding.category}
          </span>
        </div>
        <ConfidenceBadge level={finding.confidence} />
      </div>

      {/* Asset name + summary */}
      <div>
        <h3 className="text-lg font-bold text-[var(--text-primary)] mb-1">{finding.asset}</h3>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">{finding.summary}</p>
      </div>

      {/* Evidence */}
      <div>
        <p className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider font-semibold mb-2">Evidence</p>
        <ul className="space-y-1.5">
          {finding.evidence.map((e, i) => (
            <li key={i} className="text-sm text-[var(--text-secondary)] flex items-start gap-2 leading-snug">
              <SeverityDot level={finding.confidence} />
              <span className="mt-[-2px]">{e}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* URL */}
      <p className="text-[10px] text-[var(--text-secondary)] font-mono break-all opacity-50">{finding.url}</p>

      {/* Missing headers */}
      {finding.missingHeaders.length > 0 && (
        <div>
          <p className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider font-semibold mb-2">Missing Security Headers</p>
          <div className="flex flex-wrap gap-1.5">
            {finding.missingHeaders.map((h) => (
              <span key={h} className="text-[10px] bg-red-500/5 border border-red-500/15 text-red-400/80 rounded-md px-2 py-0.5 font-mono">{h}</span>
            ))}
          </div>
        </div>
      )}

      {/* CMMC mapping */}
      {finding.cmmcConcerns.length > 0 && (
        <div className="pt-3 border-t border-[var(--border)]">
          <p className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider font-semibold mb-2">CMMC-Relevant Concerns</p>
          <div className="space-y-1.5">
            {finding.cmmcConcerns.slice(0, 3).map((c, i) => (
              <div key={i} className="flex items-start gap-2">
                <span className="font-mono text-[var(--accent)] text-[10px] font-bold mt-0.5 shrink-0">{c.family}</span>
                <span className="text-xs text-[var(--text-secondary)] leading-relaxed">{c.summary}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── CMMC Mapping ─── */

function CMMCMappingSection({ concerns }: { concerns: CMMCConcern[] }) {
  const grouped: Record<string, CMMCConcern[]> = {};
  for (const c of concerns) {
    if (!grouped[c.family]) grouped[c.family] = [];
    grouped[c.family].push(c);
  }

  const familyColors: Record<string, string> = {
    AC: "border-l-red-500", IA: "border-l-orange-500", SC: "border-l-amber-500",
    CM: "border-l-yellow-500", RA: "border-l-blue-500", AU: "border-l-purple-500",
    IR: "border-l-pink-500", PE: "border-l-teal-500", SI: "border-l-cyan-500",
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {Object.entries(grouped).map(([family, items]) => (
        <div key={family} className={`bg-[var(--bg-card)] border border-[var(--border)] ${familyColors[family] || "border-l-slate-500"} border-l-[3px] rounded-xl p-5`}>
          <div className="flex items-center gap-2 mb-3">
            <span className="font-mono text-[var(--accent)] font-bold text-sm">{family}</span>
            <span className="text-xs text-[var(--text-secondary)] font-medium">{items[0].familyName}</span>
          </div>
          <div className="space-y-3">
            {items.map((c, i) => (
              <div key={i}>
                <p className="text-sm text-[var(--text-primary)] font-semibold mb-0.5 leading-snug">{c.summary}</p>
                <p className="text-xs text-[var(--text-secondary)] leading-relaxed">{c.rationale}</p>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── CTA Section ─── */

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
            githubFindings: result.githubExposure?.codeFindings.length || 0,
            executiveSummary: result.executiveSummary,
            findings: result.findings.map(f => `[${f.confidence}] ${f.asset} — ${f.summary}`),
            redFlags: result.redFlags,
          },
        }),
      });
      if (res.ok) setStatus("sent");
      else setStatus("error");
    } catch {
      setStatus("error");
    }
  }

  if (status === "sent") {
    return (
      <section className="rounded-2xl border border-green-500/20 bg-gradient-to-br from-green-500/5 to-transparent p-10 text-center">
        <div className="w-16 h-16 rounded-full bg-green-500/10 border border-green-500/20 flex items-center justify-center mx-auto mb-5">
          <svg className="w-8 h-8 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <h2 className="text-2xl font-bold mb-3">Thank you for your interest</h2>
        <p className="text-[var(--text-secondary)] max-w-lg mx-auto leading-relaxed">
          We&apos;ve sent a confirmation to <strong className="text-[var(--text-primary)]">{lead.email}</strong>.
          A member of our team will be in touch within <strong className="text-[var(--text-primary)]">24 business hours</strong> to
          walk through your findings and identify remediation opportunities.
        </p>
      </section>
    );
  }

  return (
    <section className="rounded-2xl border border-[var(--border)] bg-gradient-to-br from-[var(--accent)]/5 via-[var(--bg-card)] to-[var(--bg-secondary)] p-10 text-center">
      <Image src="/logo.png" alt="CinderLabs" width={48} height={48} className="mx-auto mb-4 rounded-lg" />
      <h2 className="text-2xl font-bold mb-3">Want to validate these findings?</h2>
      <p className="text-[var(--text-secondary)] max-w-lg mx-auto mb-8 leading-relaxed">
        These findings are externally observable only. In a 30-minute review,
        we can validate whether they represent real CMMC risk, false
        positives, or quick remediation opportunities.
      </p>
      <button
        onClick={handleRequestReview}
        disabled={status === "sending"}
        className="px-8 py-3.5 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white font-semibold rounded-xl transition-all disabled:opacity-50 text-base shadow-lg shadow-[var(--accent)]/20"
      >
        {status === "sending" ? "Requesting…" : "Schedule a Review with CinderLabs"}
      </button>
      {status === "error" && (
        <p className="text-red-400 text-sm mt-4">Something went wrong. Please try again or email info@cinderlabs.ai.</p>
      )}
    </section>
  );
}

/* ─── Copy Email Summary ─── */

function copyEmailSummary(result: ScanResult, lead: LeadInfo) {
  const lines: string[] = [
    `CMMC EXPOSURE PROOF™ — EXTERNAL ASSESSMENT REPORT`,
    `═══════════════════════════════════════════════════`,
    ``,
    `Target: ${result.domain}`,
    `Prepared for: ${lead.name}${lead.company ? ` | ${lead.company}` : ""}`,
    `Date: ${new Date(result.scanTimestamp).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}`,
    `Scan Duration: ${(result.durationMs / 1000).toFixed(1)}s`,
    ``,
    `EXECUTIVE SUMMARY`,
    `─────────────────`,
    result.executiveSummary,
    ``,
    `KEY METRICS`,
    `───────────`,
    `• ${result.subdomainsDiscovered} hostnames discovered`,
    `• ${result.assetsProbed} assets probed`,
    `• ${result.findings.length} external findings`,
    `• ${new Set(result.cmmcMappingSummary.map(c => c.family)).size} CMMC practice families affected`,
    result.breachInfo ? `• ${result.breachInfo.totalBreaches} known breach exposures` : "",
    result.githubExposure ? `• ${result.githubExposure.codeFindings.length} code exposure findings` : "",
  ].filter(Boolean);

  lines.push(``, `FINDINGS`, `────────`);
  for (const f of result.findings) {
    lines.push(`\n[${f.confidence}] ${f.asset}`, `  ${f.summary}`, `  URL: ${f.url}`);
  }

  lines.push(``, `ASSESSOR RED FLAGS`, `──────────────────`);
  for (const rf of result.redFlags) lines.push(`• ${rf}`);

  lines.push(``, `NEXT STEPS`, `──────────`);
  result.nextSteps.forEach((ns, i) => lines.push(`${i + 1}. ${ns}`));

  lines.push(
    ``, `═══════════════════════════════════════════════════`,
    `These findings are externally observable only.`,
    `CinderLabs — cinderlabs.ai`,
  );

  navigator.clipboard.writeText(lines.join("\n"));
}

/* ─── Main Report ─── */

export default function Report({ result, lead, onReset }: Props) {
  const [copied, setCopied] = useState(false);
  const scanDate = new Date(result.scanTimestamp).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

  const totalIssues = result.findings.length +
    (result.emailSecurity ? result.emailSecurity.spf.issues.length + result.emailSecurity.dkim.issues.length + result.emailSecurity.dmarc.issues.length : 0) +
    (result.breachInfo?.totalBreaches || 0) +
    (result.domainInfo?.issues.length || 0) +
    (result.githubExposure?.codeFindings.length || 0);

  function handleCopy() {
    copyEmailSummary(result, lead);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="min-h-screen bg-[var(--bg-primary)]" id="report-root">
      {/* ─── Sticky Nav ─── */}
      <header className="border-b border-[var(--border)] px-6 py-3 sticky top-0 bg-[var(--bg-primary)]/95 backdrop-blur z-40 no-print">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Image src="/logo.png" alt="CinderLabs" width={28} height={28} className="rounded" />
            <span className="text-[var(--text-secondary)] text-sm font-semibold">CMMC Exposure Proof&#8482;</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={handleCopy} className="px-3 py-1.5 text-xs border border-[var(--border)] rounded-lg hover:border-[var(--accent)] transition-colors text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
              {copied ? "Copied!" : "Copy Summary"}
            </button>
            <button onClick={() => window.print()} className="px-3 py-1.5 text-xs border border-[var(--border)] rounded-lg hover:border-[var(--accent)] transition-colors text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
              Export PDF
            </button>
            <button onClick={onReset} className="px-4 py-1.5 text-xs bg-[var(--accent)] text-white rounded-lg hover:bg-[var(--accent-hover)] transition-colors font-semibold">
              New Scan
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-10">
        {/* ─── Report Cover ─── */}
        <section className="mb-12">
          <div className="rounded-2xl border border-[var(--border)] bg-gradient-to-br from-[var(--bg-card)] via-[var(--bg-secondary)] to-[var(--bg-primary)] p-10 md:p-14">
            <div className="flex items-start justify-between mb-8">
              <div className="flex items-center gap-4">
                <Image src="/logo.png" alt="CinderLabs" width={52} height={52} className="rounded-xl" />
                <div>
                  <p className="text-[var(--accent)] text-xs font-bold uppercase tracking-[0.2em]">CinderLabs</p>
                  <p className="text-[10px] text-[var(--text-secondary)] mt-0.5">Cybersecurity &amp; AI Risk</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider font-medium">Report Date</p>
                <p className="text-sm text-[var(--text-primary)] font-medium">{scanDate}</p>
              </div>
            </div>

            <p className="text-[var(--accent)] text-[10px] font-bold uppercase tracking-[0.25em] mb-3">External Exposure Assessment</p>
            <h1 className="text-4xl md:text-5xl font-bold tracking-tight text-[var(--text-primary)] mb-3">{result.domain}</h1>

            <div className="flex items-center gap-4 text-sm text-[var(--text-secondary)] mb-8 flex-wrap">
              <span>{result.subdomainsDiscovered} hostnames</span>
              <span className="opacity-30">|</span>
              <span>{result.assetsProbed} assets probed</span>
              <span className="opacity-30">|</span>
              <span>{totalIssues} total issues</span>
              <span className="opacity-30">|</span>
              <span>{(result.durationMs / 1000).toFixed(1)}s scan</span>
            </div>

            {lead.name && (
              <div className="pt-6 border-t border-[var(--border)] flex items-center justify-between flex-wrap gap-4">
                <div>
                  <p className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider font-medium mb-1">Prepared For</p>
                  <p className="text-[var(--text-primary)] font-semibold">{lead.name}</p>
                  {lead.company && <p className="text-xs text-[var(--text-secondary)]">{lead.company}</p>}
                </div>
                <p className="text-[10px] text-[var(--text-secondary)]">
                  CMMC Exposure Proof&#8482; &mdash; External Only &mdash; Not a C3PAO Assessment
                </p>
              </div>
            )}
          </div>
        </section>

        {/* ─── Executive Summary + Risk Score ─── */}
        <section className="mb-10">
          <SectionHeader>Executive Summary</SectionHeader>
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-6 md:p-8">
            <div className="flex flex-col md:flex-row gap-8 items-start">
              <div className="flex-1">
                <p className="text-[var(--text-primary)] text-base leading-[1.8]">{result.executiveSummary}</p>
              </div>
              <div className="shrink-0">
                <RiskScoreRing
                  findings={result.findings}
                  emailRating={result.emailSecurity?.overallRating || "Good"}
                  breachCount={result.breachInfo?.totalBreaches || 0}
                  githubFindings={result.githubExposure?.codeFindings.length || 0}
                />
              </div>
            </div>
          </div>
        </section>

        {/* ─── Stats ─── */}
        <section className="mb-10">
          <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
            <StatCard value={result.findings.filter(f => f.confidence === "Confirmed").length} label="Confirmed" color="var(--danger)" />
            <StatCard value={result.findings.filter(f => f.confidence === "Likely").length} label="Likely" color="var(--warning)" />
            <StatCard value={result.findings.filter(f => f.confidence === "Needs Validation").length} label="Needs Review" color="var(--text-secondary)" />
            <StatCard value={new Set(result.cmmcMappingSummary.map(c => c.family)).size} label="CMMC Families" color="var(--accent)" />
            <StatCard value={result.breachInfo?.totalBreaches || 0} label="Breaches" color={result.breachInfo?.totalBreaches ? "var(--danger)" : "var(--success)"} />
            <StatCard value={result.githubExposure?.codeFindings.length || 0} label="Code Findings" color={result.githubExposure?.codeFindings.length ? "var(--warning)" : "var(--success)"} />
          </div>
        </section>

        <Divider />

        {/* ─── Email Authentication ─── */}
        {result.emailSecurity && (
          <section className="mb-10">
            <SectionHeader>Email Authentication</SectionHeader>
            <EmailSecuritySection data={result.emailSecurity} />
          </section>
        )}

        {/* ─── Breach Exposure ─── */}
        {result.breachInfo && (
          <section className="mb-10">
            <SectionHeader accent={result.breachInfo.totalBreaches > 0 ? "#ef4444" : "#10b981"}>
              Breach Exposure
            </SectionHeader>
            <BreachSection data={result.breachInfo} />
          </section>
        )}

        {/* ─── GitHub Exposure ─── */}
        {result.githubExposure && (
          <section className="mb-10">
            <SectionHeader accent={result.githubExposure.codeFindings.length > 0 ? "#f59e0b" : "#10b981"}>
              GitHub &amp; Code Exposure
            </SectionHeader>
            <GitHubSection data={result.githubExposure} />
          </section>
        )}

        {/* ─── Domain Infrastructure ─── */}
        {result.domainInfo && (
          <section className="mb-10">
            <SectionHeader>Domain Infrastructure</SectionHeader>
            <DomainInfoSection data={result.domainInfo} />
          </section>
        )}

        <Divider />

        {/* ─── External Asset Findings ─── */}
        {result.findings.length > 0 && (
          <section className="mb-10">
            <SectionHeader>External Asset Findings</SectionHeader>
            <div className="space-y-4">
              {result.findings.map((f, i) => (
                <FindingCard key={f.asset} finding={f} index={i} />
              ))}
            </div>
          </section>
        )}

        <Divider />

        {/* ─── CMMC Mapping ─── */}
        {result.cmmcMappingSummary.length > 0 && (
          <section className="mb-10">
            <SectionHeader>CMMC-Relevant Concern Mapping</SectionHeader>
            <p className="text-sm text-[var(--text-secondary)] mb-5 leading-relaxed">
              These mappings indicate areas where external findings may create
              assessor scrutiny. They do not represent compliance determinations.
            </p>
            <CMMCMappingSection concerns={result.cmmcMappingSummary} />
          </section>
        )}

        <Divider />

        {/* ─── Assessor Red Flags ─── */}
        {result.redFlags.length > 0 && (
          <section className="mb-10">
            <SectionHeader accent="#ef4444">Assessor Red Flags</SectionHeader>
            <p className="text-sm text-[var(--text-secondary)] mb-5 leading-relaxed">
              Questions a CMMC assessor or compliance lead might raise based on these findings.
            </p>
            <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-6 space-y-4">
              {result.redFlags.map((rf, i) => (
                <div key={i} className="flex items-start gap-3">
                  <span className="text-red-400 font-bold text-lg leading-none mt-[-1px]">?</span>
                  <p className="text-sm text-[var(--text-primary)] leading-relaxed">{rf}</p>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* ─── Next Steps ─── */}
        <section className="mb-12">
          <SectionHeader accent="#10b981">Immediate Next Steps</SectionHeader>
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-6 space-y-3">
            {result.nextSteps.map((ns, i) => (
              <div key={i} className="flex items-start gap-4">
                <span className="text-green-400 font-bold text-sm w-6 text-right shrink-0">{i + 1}.</span>
                <p className="text-sm text-[var(--text-primary)] leading-relaxed">{ns}</p>
              </div>
            ))}
          </div>
        </section>

        <Divider />

        {/* ─── CTA ─── */}
        <section className="mb-12">
          <CTASection result={result} lead={lead} />
        </section>

        {/* ─── Methodology Footer ─── */}
        <footer className="text-xs text-[var(--text-secondary)] space-y-3 pb-10">
          <div className="flex items-center gap-3 mb-4">
            <Image src="/logo.png" alt="CinderLabs" width={20} height={20} className="rounded opacity-50" />
            <span className="text-[10px] uppercase tracking-wider font-medium opacity-50">CinderLabs &mdash; CMMC Exposure Proof&#8482;</span>
          </div>
          <p className="leading-relaxed">
            <strong className="text-[var(--text-primary)]">Methodology:</strong> This report was generated using
            passive, non-intrusive external checks including certificate
            transparency log analysis, DNS resolution, HTTP response inspection,
            security header evaluation, email authentication record analysis (SPF/DKIM/DMARC),
            public breach database queries, domain registration analysis (RDAP),
            and public GitHub repository / code search analysis.
            No port scanning, vulnerability exploitation, or internal network access was performed.
          </p>
          <p className="leading-relaxed">
            <strong className="text-[var(--text-primary)]">Limitations:</strong> External-only analysis cannot
            determine internal security controls, MFA enforcement, or actual
            compliance posture. Breach data reflects public disclosures and may not
            include all incidents. GitHub analysis covers public repositories only.
            Findings should be validated by qualified personnel before remediation.
          </p>
          <p className="pt-4 border-t border-[var(--border)] opacity-60">
            &copy; {new Date().getFullYear()} CinderLabs. CMMC Exposure Proof
            is not a substitute for a formal C3PAO assessment.
          </p>
        </footer>
      </main>
    </div>
  );
}
