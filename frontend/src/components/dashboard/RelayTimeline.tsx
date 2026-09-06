"use client";

import React, { useState } from "react";
import {
  Server,
  ArrowDown,
  Clock,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Shield,
  ShieldCheck,
  ShieldAlert,
  HelpCircle,
  Network,
  Info,
} from "lucide-react";
import { ReceivedHop } from "@/types/case";
import { Badge } from "@/components/ui/badge";

interface RelayTimelineProps {
  hops?: ReceivedHop[] | null;
  earliestReliableObservable?: string | null;
  limitations?: string[];
  className?: string;
}

export function RelayTimeline({
  hops = [],
  earliestReliableObservable,
  limitations = [],
  className = "",
}: RelayTimelineProps) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [expandedHops, setExpandedHops] = useState<Record<number, boolean>>({});

  const handleCopy = (text: string, key: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const toggleExpand = (index: number) => {
    setExpandedHops((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const safeHops = hops || [];

  return (
    <section
      className={`bg-[#141416] border border-zinc-800/80 rounded-xl overflow-hidden shadow-sm ${className}`}
    >
      {/* Section Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-6 py-4 border-b border-zinc-800/80 bg-[#141416]">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-[#D47E30]/10 border border-[#D47E30]/20 text-[#D47E30]">
            <Network className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-sans font-semibold text-sm tracking-tight text-zinc-200">
                Observed Relay Path
              </h3>
              <span className="px-2 py-0.5 text-[11px] font-mono font-medium rounded-full bg-zinc-800/80 text-zinc-300 border border-zinc-700/50">
                {safeHops.length} {safeHops.length === 1 ? "Hop" : "Hops"}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1.5 text-xs font-sans text-zinc-400">
          <Info className="w-3.5 h-3.5 flex-shrink-0 text-[#D47E30]" />
          <span>Chronological Received chain (earliest origin to destination)</span>
        </div>
      </div>

      {/* Limitations banner if present */}
      {limitations.length > 0 && (
        <div className="px-6 py-2.5 bg-amber-500/10 border-b border-amber-500/20 flex items-start gap-2 text-xs text-amber-300">
          <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div>
            {limitations.map((lim, i) => (
              <p key={i}>{lim}</p>
            ))}
          </div>
        </div>
      )}

      {/* Timeline Content */}
      <div className="p-6">
        {safeHops.length === 0 ? (
          <div className="py-12 flex flex-col items-center justify-center text-center">
            <div className="w-12 h-12 rounded-full bg-zinc-900/90 border border-zinc-800 flex items-center justify-center text-zinc-500 mb-3">
              <Network className="w-6 h-6 opacity-40" />
            </div>
            <p className="text-sm font-medium text-zinc-300">No Relay Hops Extracted</p>
            <p className="text-xs text-zinc-500 mt-1 max-w-sm">
              No observable Received headers were found in this message or the headers could not be parsed.
            </p>
          </div>
        ) : (
          <div className="relative pl-6 space-y-6 before:absolute before:left-[19px] before:top-3 before:bottom-3 before:w-0.5 before:bg-gradient-to-b before:from-[#D47E30] before:via-zinc-700 before:to-zinc-800">
            {safeHops.map((hop, i) => {
              const isFirst = i === 0;
              const isLast = i === safeHops.length - 1;
              const isExpanded = !!expandedHops[hop.index];

              return (
                <div key={hop.index || i} className="relative group">
                  {/* Timeline Node Icon */}
                  <div
                    className={`absolute -left-[30px] top-3.5 w-6 h-6 rounded-full flex items-center justify-center text-xs font-mono font-bold transition-transform duration-200 group-hover:scale-110 ${
                      isFirst
                        ? "bg-[#D47E30] text-black ring-4 ring-[#D47E30]/20 shadow-md shadow-[#D47E30]/30"
                        : isLast
                        ? "bg-emerald-500/20 border-2 border-emerald-500 text-emerald-400 ring-4 ring-emerald-500/10"
                        : "bg-[#1E1E22] border border-zinc-600 text-zinc-300 ring-4 ring-zinc-900"
                    }`}
                  >
                    {hop.index}
                  </div>

                  {/* Hop Content Card */}
                  <div className="bg-[#18181B]/80 hover:bg-[#1C1C20] transition-colors border border-zinc-800/90 hover:border-zinc-700/80 rounded-xl p-4.5 shadow-sm space-y-3.5">
                    {/* Top Row: Meta badges and Timestamp */}
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
                          Hop #{hop.index}
                        </span>

                        {isFirst && (
                          <Badge
                            variant="outline"
                            className="bg-[#D47E30]/15 text-[#D47E30] border-[#D47E30]/40 text-[10px] py-0 px-2 font-medium tracking-wide"
                          >
                            Earliest Observable
                          </Badge>
                        )}

                        {isLast && safeHops.length > 1 && (
                          <Badge
                            variant="outline"
                            className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-[10px] py-0 px-2 font-medium"
                          >
                            Final Destination Hop
                          </Badge>
                        )}

                        {hop.with_protocol && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-zinc-800/80 text-zinc-300 border border-zinc-700/60 uppercase">
                            {hop.with_protocol}
                          </span>
                        )}

                        {hop.trust && hop.trust !== "unknown" && (
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-mono flex items-center gap-1 border ${
                              hop.trust === "trusted"
                                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                                : "bg-red-500/10 text-red-400 border-red-500/30"
                            }`}
                          >
                            {hop.trust === "trusted" ? (
                              <ShieldCheck className="w-3 h-3" />
                            ) : (
                              <ShieldAlert className="w-3 h-3" />
                            )}
                            {hop.trust}
                          </span>
                        )}
                      </div>

                      {/* Timestamp */}
                      {hop.timestamp && (
                        <div className="flex items-center gap-1 text-xs font-mono text-zinc-400">
                          <Clock className="w-3 h-3 text-zinc-500" />
                          <span>{hop.timestamp}</span>
                        </div>
                      )}
                    </div>

                    {/* Hop Flow Details Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-11 gap-3 items-center bg-[#121214]/60 p-3 rounded-lg border border-zinc-800/60 text-xs">
                      {/* From Host & IP */}
                      <div className="md:col-span-5 space-y-1">
                        <div className="text-[10px] uppercase font-sans font-semibold tracking-wider text-zinc-400">
                          From (Sending MTA)
                        </div>
                        <div className="font-mono text-zinc-200 break-all font-medium">
                          {hop.from_host || <span className="text-zinc-500 italic">None specified</span>}
                        </div>
                        {hop.from_ip ? (
                          <div className="flex items-center gap-1.5 pt-0.5">
                            <span className="font-mono text-[11px] px-1.5 py-0.5 bg-[#202024] text-[#FDFBD4] rounded border border-zinc-700/60 select-all">
                              {hop.from_ip}
                            </span>
                            <button
                              type="button"
                              onClick={() => handleCopy(hop.from_ip!, `ip-from-${hop.index}`)}
                              className="p-1 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 rounded transition-colors"
                              title="Copy IP"
                            >
                              {copiedKey === `ip-from-${hop.index}` ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        ) : null}
                      </div>

                      {/* Flow Arrow */}
                      <div className="md:col-span-1 flex justify-center py-1 md:py-0">
                        <div className="w-6 h-6 rounded-full bg-zinc-800/60 border border-zinc-700/50 flex items-center justify-center text-zinc-400">
                          <ArrowDown className="w-3.5 h-3.5 md:-rotate-90" />
                        </div>
                      </div>

                      {/* By Host & IP */}
                      <div className="md:col-span-5 space-y-1">
                        <div className="text-[10px] uppercase font-sans font-semibold tracking-wider text-zinc-400">
                          By (Receiving MTA)
                        </div>
                        <div className="font-mono text-zinc-200 break-all font-medium">
                          {hop.by_host || <span className="text-zinc-500 italic">None specified</span>}
                        </div>
                        {hop.by_ip ? (
                          <div className="flex items-center gap-1.5 pt-0.5">
                            <span className="font-mono text-[11px] px-1.5 py-0.5 bg-[#202024] text-zinc-300 rounded border border-zinc-700/60 select-all">
                              {hop.by_ip}
                            </span>
                            <button
                              type="button"
                              onClick={() => handleCopy(hop.by_ip!, `ip-by-${hop.index}`)}
                              className="p-1 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 rounded transition-colors"
                              title="Copy IP"
                            >
                              {copiedKey === `ip-by-${hop.index}` ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        ) : null}
                      </div>
                    </div>

                    {/* Raw Received Header Toggle */}
                    {hop.raw && (
                      <div className="pt-0.5">
                        <button
                          type="button"
                          onClick={() => toggleExpand(hop.index)}
                          className="flex items-center gap-1 text-[11px] font-sans text-zinc-400 hover:text-zinc-200 transition-colors"
                        >
                          {isExpanded ? (
                            <>
                              <ChevronUp className="w-3 h-3" />
                              <span>Hide raw header</span>
                            </>
                          ) : (
                            <>
                              <ChevronDown className="w-3 h-3" />
                              <span>View raw header</span>
                            </>
                          )}
                        </button>

                        {isExpanded && (
                          <div className="mt-2 relative">
                            <pre className="p-3 bg-[#0E0E10] border border-zinc-800/80 rounded-lg text-[11px] font-mono text-zinc-300 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed select-all">
                              {hop.raw}
                            </pre>
                            <button
                              type="button"
                              onClick={() => handleCopy(hop.raw, `raw-${hop.index}`)}
                              className="absolute top-2 right-2 p-1.5 bg-zinc-800/80 hover:bg-zinc-700 text-zinc-300 rounded border border-zinc-700 transition-colors flex items-center gap-1 text-[10px]"
                              title="Copy raw header"
                            >
                              {copiedKey === `raw-${hop.index}` ? (
                                <>
                                  <Check className="w-3 h-3 text-emerald-400" />
                                  <span className="text-emerald-400">Copied</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  <span>Copy</span>
                                </>
                              )}
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
}

export default RelayTimeline;
