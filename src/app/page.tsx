"use client";

import { useState } from "react";
import { ScanResult, LeadInfo } from "@/lib/types";
import Report from "@/components/Report";
import Image from "next/image";

const LOADING_MESSAGES = [
  "Querying certificate transparency logs…",
  "Resolving discovered hostnames…",
  "Checking email authentication (SPF/DKIM/DMARC)…",
  "Querying breach databases…",
  "Analyzing domain registration…",
  "Scanning public GitHub repositories…",
  "Probing public-facing assets…",
  "Inspecting security headers…",
  "Detecting authentication surfaces…",
  "Mapping findings to CMMC practice families…",
  "Generating assessor-ready report…",
];

export default function Home() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");

  // Lead gate state
  const [showGate, setShowGate] = useState(false);
  const [lead, setLead] = useState<LeadInfo>({ name: "", email: "", company: "", title: "" });
  const [gateError, setGateError] = useState("");
  const [pendingResult, setPendingResult] = useState<ScanResult | null>(null);

  async function handleScan() {
    if (!input.trim()) return;

    setLoading(true);
    setError("");
    setResult(null);
    setPendingResult(null);
    setShowGate(false);

    let msgIdx = 0;
    setLoadingMsg(LOADING_MESSAGES[0]);
    const interval = setInterval(() => {
      msgIdx = Math.min(msgIdx + 1, LOADING_MESSAGES.length - 1);
      setLoadingMsg(LOADING_MESSAGES[msgIdx]);
    }, 3500);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: input.trim() }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || "Scan failed.");
      } else {
        setPendingResult(data);
        setShowGate(true);
        setLead((prev) => ({ ...prev, company: input.trim() }));
      }
    } catch {
      setError("Network error. Please try again.");
    } finally {
      clearInterval(interval);
      setLoading(false);
    }
  }

  function handleGateSubmit() {
    if (!lead.name.trim() || !lead.email.trim()) {
      setGateError("Name and work email are required.");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(lead.email)) {
      setGateError("Please enter a valid email address.");
      return;
    }
    const personalDomains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com", "mail.com", "protonmail.com"];
    const emailDomain = lead.email.split("@")[1]?.toLowerCase();
    if (personalDomains.includes(emailDomain)) {
      setGateError("Please use your work email address.");
      return;
    }

    setGateError("");

    // Fire lead to API (non-blocking)
    if (pendingResult) {
      fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: input.trim(), lead }),
      }).catch(() => {});
    }

    setResult(pendingResult);
    setShowGate(false);
  }

  if (result) {
    return (
      <Report
        result={result}
        lead={lead}
        onReset={() => {
          setResult(null);
          setPendingResult(null);
          setInput("");
          setLead({ name: "", email: "", company: "", title: "" });
        }}
      />
    );
  }

  return (
    <div className="min-h-screen flex flex-col">
      {loading && <div className="scan-line" />}

      {/* Header */}
      <header className="border-b border-[var(--border)] px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Image src="/logo.png" alt="CinderLabs" width={36} height={36} className="rounded" />
            <span className="text-[var(--text-secondary)] text-sm font-medium">
              CinderLabs
            </span>
          </div>
          <a
            href="https://cinderlabs.ai"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[var(--text-secondary)] text-sm hover:text-[var(--accent)] transition-colors"
          >
            cinderlabs.ai
          </a>
        </div>
      </header>

      {/* Main */}
      <main className="flex-1 flex items-center justify-center px-6">
        <div className="max-w-2xl w-full text-center">
          {/* Email Gate Modal */}
          {showGate && (
            <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
              <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl max-w-md w-full p-8">
                <div className="mb-6">
                  <Image src="/logo.png" alt="CinderLabs" width={48} height={48} className="mx-auto mb-4 rounded" />
                  <h2 className="text-xl font-bold mb-2">Your report is ready</h2>
                  <p className="text-[var(--text-secondary)] text-sm">
                    We found <strong className="text-[var(--text-primary)]">{pendingResult?.findings.length || 0} findings</strong> for{" "}
                    <strong className="text-[var(--text-primary)]">{pendingResult?.domain}</strong>.
                    Enter your details to view the full report.
                  </p>
                </div>

                <div className="space-y-3">
                  <input
                    type="text"
                    placeholder="Full name *"
                    value={lead.name}
                    onChange={(e) => setLead({ ...lead, name: e.target.value })}
                    className="w-full px-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-lg text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent)] text-sm"
                  />
                  <input
                    type="email"
                    placeholder="Work email *"
                    value={lead.email}
                    onChange={(e) => setLead({ ...lead, email: e.target.value })}
                    className="w-full px-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-lg text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent)] text-sm"
                  />
                  <input
                    type="text"
                    placeholder="Company"
                    value={lead.company}
                    onChange={(e) => setLead({ ...lead, company: e.target.value })}
                    className="w-full px-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-lg text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent)] text-sm"
                  />
                  <input
                    type="text"
                    placeholder="Title (optional)"
                    value={lead.title}
                    onChange={(e) => setLead({ ...lead, title: e.target.value })}
                    className="w-full px-4 py-2.5 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-lg text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent)] text-sm"
                  />
                </div>

                {gateError && (
                  <p className="text-[var(--danger)] text-xs mt-2">{gateError}</p>
                )}

                <button
                  onClick={handleGateSubmit}
                  className="w-full mt-4 px-6 py-3 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white font-medium rounded-lg transition-colors"
                >
                  View Report
                </button>
                <p className="text-[var(--text-secondary)] text-xs mt-3 text-center">
                  No spam. Your data stays private.
                </p>
              </div>
            </div>
          )}

          {/* Logo + Title */}
          <Image src="/logo.png" alt="CinderLabs" width={72} height={72} className="mx-auto mb-6 rounded-lg" />
          <h1 className="text-4xl font-bold mb-3 tracking-tight">
            CMMC Exposure Proof
            <span className="text-[var(--accent)]">&#8482;</span>
          </h1>
          <p className="text-[var(--text-secondary)] text-lg mb-2">
            Evidence an assessor could already flag.
          </p>
          <p className="text-[var(--text-secondary)] text-sm mb-10 max-w-lg mx-auto">
            Enter a company domain or name. We&apos;ll check public-facing assets,
            email authentication, breach exposure, code repositories, and security posture
            &mdash; mapped to CMMC-relevant concerns using only external evidence.
          </p>

          {/* Input */}
          <div className="flex gap-3 max-w-lg mx-auto mb-4">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !loading && handleScan()}
              placeholder="e.g. acme-defense.com or Acme Defense Corp"
              disabled={loading}
              className="flex-1 px-4 py-3 bg-[var(--bg-card)] border border-[var(--border)] rounded-lg text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent)] transition-colors disabled:opacity-50"
            />
            <button
              onClick={handleScan}
              disabled={loading || !input.trim()}
              className="px-6 py-3 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
            >
              {loading ? "Scanning…" : "Run Report"}
            </button>
          </div>

          {/* Error */}
          {error && (
            <p className="text-[var(--danger)] text-sm mb-4">{error}</p>
          )}

          {/* Loading state */}
          {loading && (
            <div className="mt-8 space-y-4">
              <div className="flex items-center justify-center gap-3">
                <div className="w-2 h-2 rounded-full bg-[var(--accent)] animate-pulse-glow" />
                <p className="text-[var(--text-secondary)] text-sm animate-pulse-glow">
                  {loadingMsg}
                </p>
              </div>
              <div className="w-64 mx-auto h-1 bg-[var(--bg-card)] rounded overflow-hidden">
                <div
                  className="h-full bg-[var(--accent)] rounded transition-all duration-[30000ms] ease-linear"
                  style={{ width: "90%" }}
                />
              </div>
            </div>
          )}

          {/* Disclaimer */}
          <p className="text-[var(--text-secondary)] text-xs mt-10 max-w-md mx-auto">
            This tool performs passive, non-intrusive external checks only. No
            port scanning, vulnerability exploitation, or internal network access
            is performed.
          </p>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-[var(--border)] px-6 py-4 text-center text-[var(--text-secondary)] text-xs">
        &copy; {new Date().getFullYear()} CinderLabs. CMMC Exposure Proof is a
        free external assessment tool. Not a substitute for a formal C3PAO assessment.
      </footer>
    </div>
  );
}
