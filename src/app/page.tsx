"use client";

import { useState } from "react";
import { ScanResult } from "@/lib/types";
import Report from "@/components/Report";

const LOADING_MESSAGES = [
  "Querying certificate transparency logs…",
  "Resolving discovered hostnames…",
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

  async function handleScan() {
    if (!input.trim()) return;

    setLoading(true);
    setError("");
    setResult(null);

    // Cycle loading messages
    let msgIdx = 0;
    setLoadingMsg(LOADING_MESSAGES[0]);
    const interval = setInterval(() => {
      msgIdx = Math.min(msgIdx + 1, LOADING_MESSAGES.length - 1);
      setLoadingMsg(LOADING_MESSAGES[msgIdx]);
    }, 4000);

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
        setResult(data);
      }
    } catch {
      setError("Network error. Please try again.");
    } finally {
      clearInterval(interval);
      setLoading(false);
    }
  }

  // If we have results, show the report
  if (result) {
    return (
      <Report
        result={result}
        onReset={() => {
          setResult(null);
          setInput("");
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
            <div className="w-8 h-8 rounded bg-[var(--accent)] flex items-center justify-center font-bold text-sm">
              CL
            </div>
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
          {/* Title */}
          <h1 className="text-4xl font-bold mb-3 tracking-tight">
            CMMC Exposure Proof
            <span className="text-[var(--accent)]">&#8482;</span>
          </h1>
          <p className="text-[var(--text-secondary)] text-lg mb-2">
            Evidence an assessor could already flag.
          </p>
          <p className="text-[var(--text-secondary)] text-sm mb-10 max-w-lg mx-auto">
            Enter a company domain or name. We&apos;ll check public-facing assets,
            security posture signals, and map findings to CMMC-relevant concerns
            &mdash; using only externally observable evidence.
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
