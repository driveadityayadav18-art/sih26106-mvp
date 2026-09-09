"use client";

import React, { useState, useEffect } from "react";
import { Shield, Plus, Download } from "lucide-react";
import { GradientButton } from "@/components/ui/gradient-button";

interface NavbarProps {
  apiBaseUrl?: string;
  activeCaseId?: string;
  onNewScan?: () => void;
}

// ── Health-check sub-component ────────────────────────────────────────────────

type BackendStatus = "checking" | "online" | "offline";

function BackendStatusPill({
  apiBaseUrl,
  formattedHost,
}: {
  apiBaseUrl: string;
  formattedHost: string;
}) {
  const [status, setStatus] = useState<BackendStatus>("checking");

  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch(`${apiBaseUrl}/api/v1/health`, {
          signal: AbortSignal.timeout(3000),
        });
        setStatus(res.ok ? "online" : "offline");
      } catch {
        setStatus("offline");
      }
    };

    check();
    const interval = setInterval(check, 30_000);
    return () => clearInterval(interval);
  }, [apiBaseUrl]);

  const dotClass =
    status === "checking"
      ? "bg-zinc-500"
      : status === "online"
      ? "bg-emerald-500 animate-pulse"
      : "bg-red-500 animate-pulse";

  const label =
    status === "checking"
      ? "Connecting…"
      : status === "online"
      ? "Online"
      : "Offline";

  const labelClass =
    status === "checking"
      ? "text-zinc-400"
      : status === "online"
      ? "text-emerald-400"
      : "text-red-400";

  return (
    <div className="bg-zinc-900 border border-zinc-800/80 px-3 py-1 rounded-md flex items-center gap-2 text-xs font-sans text-zinc-400 select-none">
      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${dotClass}`} />
      <span>Backend:</span>
      <span className="text-zinc-200 font-mono text-[11px]">
        {formattedHost || "localhost:8000"}
      </span>
      <span className={`font-medium ${labelClass}`}>{label}</span>
    </div>
  );
}

// ── Main Navbar ───────────────────────────────────────────────────────────────

export function Navbar({
  apiBaseUrl = "http://localhost:8000",
  activeCaseId,
  onNewScan,
}: NavbarProps) {
  const formattedHost = apiBaseUrl.replace(/^https?:\/\//, "");

  return (
    <header className="sticky top-0 z-30 h-14 bg-[#09090B] border-b border-zinc-800/80 px-6 flex items-center justify-between">
      {/* Brand Section (Left) */}
      <div className="flex items-center">
        {/* Shield Logo Icon */}
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-amber-500/20 to-amber-900/40 border border-amber-500/30 flex items-center justify-center text-[#D47E30] shadow-xs flex-shrink-0">
          <Shield className="w-4 h-4 stroke-[2.2]" />
        </div>

        {/* Brand Name */}
        <span className="font-sans font-semibold text-sm text-zinc-100 tracking-tight ml-3">
          TraceShield AI
        </span>

        {/* Vertical Divider */}
        <div className="h-4 w-[1px] bg-zinc-800 mx-3 hidden sm:block" />

        {/* Breadcrumb Pill */}
        <div className="hidden sm:inline-flex items-center text-xs font-sans text-zinc-400 bg-zinc-900/60 border border-zinc-800/60 px-2.5 py-1 rounded-md select-none">
          Email Threat Investigation
        </div>
      </div>

      {/* Control Section (Right) */}
      <div className="flex items-center gap-3">
        {/* Backend Status Pill — real health check */}
        <BackendStatusPill apiBaseUrl={apiBaseUrl} formattedHost={formattedHost} />

        {/* Download Forensic Report Group */}
        {activeCaseId && (
          <div className="flex items-center">
            <button
              onClick={() => {
                window.open(
                  `${apiBaseUrl}/api/v1/cases/${encodeURIComponent(activeCaseId)}/report?format=html`,
                  "_blank",
                  "noopener,noreferrer"
                );
              }}
              className="h-9 px-3 rounded-l-lg bg-[#141416] hover:bg-[#2A2118] border border-[#D47E30]/50 hover:border-[#D47E30] text-xs font-sans font-semibold text-[#FDFBD4] hover:text-white transition-all duration-150 flex items-center gap-1.5 cursor-pointer shadow-xs"
              title="Download/Open Forensic Report (HTML / Printable PDF)"
            >
              <Download className="w-3.5 h-3.5 text-[#D47E30]" />
              <span className="hidden sm:inline">Download Forensic Report</span>
              <span className="sm:hidden">Report</span>
            </button>
            <button
              onClick={() => {
                window.open(
                  `${apiBaseUrl}/api/v1/cases/${encodeURIComponent(activeCaseId)}/report?format=json`,
                  "_blank",
                  "noopener,noreferrer"
                );
              }}
              className="h-9 px-2.5 rounded-r-lg bg-[#141416] hover:bg-[#2A2118] border-y border-r border-[#D47E30]/50 hover:border-[#D47E30] text-xs font-mono font-bold text-[#D47E30] hover:text-white transition-all duration-150 flex items-center cursor-pointer shadow-xs"
              title="Download Forensic Report (JSON)"
            >
              JSON
            </button>
          </div>
        )}

        {/* Primary Action Button */}
        <GradientButton
          onClick={onNewScan}
          size="default"
          className="h-9 px-4 text-xs font-medium font-sans flex items-center gap-1.5 cursor-pointer shadow-sm"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Scan</span>
        </GradientButton>
      </div>
    </header>
  );
}

export default Navbar;
