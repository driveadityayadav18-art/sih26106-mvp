"use client";

import React from "react";
import { Shield, Plus } from "lucide-react";
import { GradientButton } from "@/components/ui/gradient-button";

interface NavbarProps {
  apiBaseUrl?: string;
  onNewScan?: () => void;
}

export function Navbar({
  apiBaseUrl = "http://localhost:8000",
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
        {/* Backend Status Pill */}
        <div className="bg-zinc-900 border border-zinc-800/80 px-3 py-1 rounded-md flex items-center gap-2 text-xs font-sans text-zinc-400 select-none">
          <span className="w-2 h-2 rounded-full bg-[#D47E30] animate-pulse flex-shrink-0" />
          <span>Backend:</span>
          <span className="text-zinc-200 font-mono text-[11px]">
            {formattedHost || "localhost:8000"}
          </span>
        </div>

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
