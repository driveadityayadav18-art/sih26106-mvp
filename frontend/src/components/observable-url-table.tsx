"use client";

import React, { useState } from "react";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import {
  AlertTriangle,
  Copy,
  Check,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  X,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Globe,
  Server,
  FileCode,
  Info,
} from "lucide-react";
import { InfrastructureData, ReasonCode } from "@/types/case";

interface ObservableUrlTableProps {
  urls: string[];
  fromAddress?: string | null;
  reasonCodes?: ReasonCode[];
  infrastructure?: InfrastructureData;
}

const TRUSTED_DOMAINS = [
  "google.com",
  "youtube.com",
  "twitter.com",
  "x.com",
  "linkedin.com",
  "techcrunch.com",
  "github.com",
  "microsoft.com",
  "apple.com",
  "facebook.com",
  "instagram.com",
  "beehiiv.com",
  "mailchimp.com",
  "substack.com",
  "w3.org",
];

export function defangUrl(url: string): string {
  if (!url) return "";
  return url
    .replace(/^https?:\/\//i, (match) =>
      match.toLowerCase().startsWith("https") ? "hxxps://" : "hxxp://"
    )
    .replace(/\./g, "[.]");
}

export function extractDomain(url: string): string {
  if (!url) return "";
  try {
    const cleaned = url.trim();
    const withoutProto = cleaned.replace(/^[a-zA-Z]+:\/\//, "");
    const hostWithPort = withoutProto.split("/")[0].split("?")[0].split("#")[0];
    const host = hostWithPort.split("@").pop()?.split(":")[0] || "";
    return host.toLowerCase();
  } catch {
    return "";
  }
}

export function extractEmailDomain(email?: string | null): string {
  if (!email || !email.includes("@")) return "";
  return email.split("@").pop()?.trim().toLowerCase() || "";
}

export function isDomainTrusted(domain: string): boolean {
  if (!domain) return false;
  const d = domain.toLowerCase().trim();
  return TRUSTED_DOMAINS.some(
    (trusted) => d === trusted || d.endsWith("." + trusted)
  );
}

export function unpackTrampolineUrl(url: string): {
  isTrampoline: boolean;
  isObfuscated: boolean;
  targetDomain: string;
  targetUrl: string;
} {
  if (!url) return { isTrampoline: false, isObfuscated: false, targetDomain: "", targetUrl: "" };
  try {
    const isObf = /%[0-9a-fA-F]{2}/.test(url);
    const parsed = new URL(url);
    for (const param of ["q", "url", "dest", "target", "redirect", "r", "link", "goto"]) {
      const val = parsed.searchParams.get(param);
      if (val) {
        let curr = val.trim();
        for (let i = 0; i < 3; i++) {
          try {
            const unq = decodeURIComponent(curr);
            if (unq !== curr) {
              curr = unq;
            } else {
              break;
            }
          } catch {
            break;
          }
        }
        if (/^https?:\/\//i.test(curr)) {
          const targetHost = extractDomain(curr);
          return {
            isTrampoline: true,
            isObfuscated: isObf,
            targetDomain: targetHost,
            targetUrl: curr,
          };
        }
      }
    }
    return { isTrampoline: false, isObfuscated: isObf, targetDomain: "", targetUrl: "" };
  } catch {
    return { isTrampoline: false, isObfuscated: false, targetDomain: "", targetUrl: "" };
  }
}

export function ObservableUrlTable({
  urls = [],
  fromAddress,
  reasonCodes = [],
  infrastructure,
}: ObservableUrlTableProps) {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [copiedDrawerType, setCopiedDrawerType] = useState<string | null>(null);
  const [selectedUrlIndex, setSelectedUrlIndex] = useState<number | null>(null);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 5;

  if (!urls || urls.length === 0) {
    return null;
  }

  const fromDomain = extractEmailDomain(fromAddress);

  const getUrlStatus = (url: string): "SUSPICIOUS_URL" | "CLEAN" => {
    const trampoline = unpackTrampolineUrl(url);
    if (trampoline.isTrampoline && trampoline.targetDomain) {
      if (
        !isDomainTrusted(trampoline.targetDomain) &&
        (!fromDomain || (trampoline.targetDomain !== fromDomain && !trampoline.targetDomain.endsWith("." + fromDomain)))
      ) {
        return "SUSPICIOUS_URL";
      }
    }

    const domain = extractDomain(url);
    if (!domain) return "SUSPICIOUS_URL";

    if (isDomainTrusted(domain)) {
      return "CLEAN";
    }

    if (fromDomain && (domain === fromDomain || domain.endsWith("." + fromDomain))) {
      return "CLEAN";
    }

    const hasSuspiciousReason = reasonCodes.some(
      (rc) =>
        rc.code === "SUSPICIOUS_URL" ||
        rc.evidence_path.includes("urls")
    );

    if (hasSuspiciousReason) {
      return "SUSPICIOUS_URL";
    }

    return "SUSPICIOUS_URL";
  };

  const handleCopy = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleDrawerCopy = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedDrawerType(type);
    setTimeout(() => setCopiedDrawerType(null), 2000);
  };

  const totalUrls = urls.length;
  const totalPages = Math.ceil(totalUrls / pageSize);
  const validPage = Math.max(1, Math.min(currentPage, totalPages));
  const startIndex = (validPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, totalUrls);
  const paginatedUrls = urls.slice(startIndex, endIndex);

  const selectedUrl =
    selectedUrlIndex !== null ? urls[selectedUrlIndex] : null;
  const selectedDomain = selectedUrl ? extractDomain(selectedUrl) : "";
  const selectedStatus = selectedUrl ? getUrlStatus(selectedUrl) : "CLEAN";
  const selectedDefanged = selectedUrl ? defangUrl(selectedUrl) : "";
  const selectedTrampoline = selectedUrl
    ? unpackTrampolineUrl(selectedUrl)
    : { isTrampoline: false, isObfuscated: false, targetDomain: "", targetUrl: "" };

  const selectedGeo = selectedDomain
    ? infrastructure?.geo?.find(
        (g) =>
          g.indicator.toLowerCase() === selectedDomain ||
          selectedDomain.includes(g.indicator.toLowerCase())
      )
    : null;

  return (
    <section className="bg-[#141416] border border-zinc-800/80 rounded-xl overflow-hidden shadow-sm">
      {/* Section Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-6 py-4 border-b border-zinc-800/80 bg-[#141416]">
        <h3 className="font-sans font-semibold text-sm tracking-tight text-zinc-200">
          Observable Body URLs ({totalUrls})
        </h3>
        <div className="flex items-center gap-1.5 text-xs font-sans text-[#D47E30] font-medium">
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
          <span>Defanged text display only • Links disabled for security</span>
        </div>
      </div>

      {/* High Density Shadcn Table */}
      <div className="overflow-x-auto">
        <Table>
          <TableHeader className="bg-[#121417]/80">
            <TableRow className="border-b border-[#2A231D] hover:bg-transparent">
              <TableHead className="w-[150px] font-sans text-[11px] font-medium uppercase tracking-wider text-zinc-400">
                Status
              </TableHead>
              <TableHead className="font-sans text-[11px] font-medium uppercase tracking-wider text-zinc-400">
                Observable URL Payload
              </TableHead>
              <TableHead className="w-[170px] font-sans text-[11px] font-medium uppercase tracking-wider text-zinc-400">
                Context / Location
              </TableHead>
              <TableHead className="w-[100px] text-right font-sans text-[11px] font-medium uppercase tracking-wider text-zinc-400">
                Actions
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody className="divide-y divide-[#2A231D]">
            {paginatedUrls.map((url, localIdx) => {
              const globalIdx = startIndex + localIdx;
              const status = getUrlStatus(url);
              const defanged = defangUrl(url);
              const isCopied = copiedIndex === globalIdx;
              const trampoline = unpackTrampolineUrl(url);

              return (
                <TableRow
                  key={globalIdx}
                  className="bg-[#1A1C20] hover:bg-[#22252B] border-b border-[#2A231D] transition-colors group"
                >
                  {/* Status Column */}
                  <TableCell>
                    {status === "SUSPICIOUS_URL" ? (
                      <Badge
                        variant="suspicious_url"
                        className="font-sans text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 shadow-none"
                      >
                        SUSPICIOUS_URL
                      </Badge>
                    ) : (
                      <Badge
                        variant="clean"
                        className="font-sans text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 shadow-none"
                      >
                        CLEAN
                      </Badge>
                    )}
                  </TableCell>

                  {/* URL Column: strictly mono for raw URL string */}
                  <TableCell className="max-w-lg">
                    <div className="flex flex-col gap-1">
                      <span
                        className="font-mono text-xs text-[#FDFBD4] truncate max-w-lg block select-all cursor-text"
                        title={defanged}
                      >
                        {defanged}
                      </span>
                      {trampoline.isTrampoline && (
                        <div className="flex items-center gap-1 text-[10px] font-mono text-[#E06D53]">
                          <span className="font-sans font-semibold uppercase tracking-wider text-[9px] bg-[#E06D53]/20 px-1 py-0.5 rounded border border-[#E06D53]/40 text-[#E06D53] shrink-0">
                            Unmasked Destination:
                          </span>
                          <span className="truncate max-w-sm" title={defangUrl(trampoline.targetUrl)}>
                            {defangUrl(trampoline.targetUrl)}
                          </span>
                        </div>
                      )}
                    </div>
                  </TableCell>

                  {/* Context / Location Column */}
                  <TableCell>
                    <span className="text-[10px] font-sans font-medium uppercase text-zinc-400 bg-[#121417] px-2 py-1 rounded border border-[#2A231D] inline-block">
                      OBSERVED IN BODY
                    </span>
                  </TableCell>

                  {/* Actions Column */}
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      {/* Copy Defanged URL */}
                      <button
                        onClick={() => handleCopy(defanged, globalIdx)}
                        className="p-1.5 rounded-md bg-[#121417] hover:bg-[#2A2118] border border-[#2A231D] hover:border-[#8D5A2B] text-zinc-400 hover:text-[#FDFBD4] transition-all cursor-pointer"
                        title={isCopied ? "Copied defanged URL!" : "Copy Defanged URL"}
                        aria-label="Copy Defanged URL"
                      >
                        {isCopied ? (
                          <Check className="w-3.5 h-3.5 text-[#7EC876]" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>

                      {/* ExternalLink Drawer Trigger */}
                      <button
                        onClick={() => setSelectedUrlIndex(globalIdx)}
                        className="p-1.5 rounded-md bg-[#121417] hover:bg-[#2A2118] border border-[#2A231D] hover:border-[#D47E30] text-zinc-400 hover:text-[#D47E30] transition-all cursor-pointer"
                        title="Open Observable Payload Inspector"
                        aria-label="Inspect Observable Payload"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>

      {/* Pagination Footer */}
      <div className="px-6 py-3 bg-[#141416] border-t border-zinc-800/80 flex flex-wrap items-center justify-between gap-3 text-xs font-sans text-zinc-400">
        <div>
          Showing {startIndex + 1}-{endIndex} of {totalUrls} URLs
        </div>

        <div className="flex items-center gap-2 font-sans">
          <span className="text-[11px] text-zinc-400">
            Page {validPage} of {totalPages || 1}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setCurrentPage((p) => Math.max(p - 1, 1))}
              disabled={validPage <= 1}
              className="p-1 rounded bg-[#1A1C20] hover:bg-[#22252B] border border-[#2A231D] disabled:opacity-40 disabled:hover:bg-[#1A1C20] text-zinc-300 transition-colors cursor-pointer disabled:cursor-not-allowed"
              title="Previous Page"
              aria-label="Previous Page"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setCurrentPage((p) => Math.min(p + 1, totalPages))}
              disabled={validPage >= totalPages}
              className="p-1 rounded bg-[#1A1C20] hover:bg-[#22252B] border border-[#2A231D] disabled:opacity-40 disabled:hover:bg-[#1A1C20] text-zinc-300 transition-colors cursor-pointer disabled:cursor-not-allowed"
              title="Next Page"
              aria-label="Next Page"
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Observable Payload Inspector Slide-Over Drawer */}
      {selectedUrl && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-xs transition-opacity animate-in fade-in duration-200">
          <div
            className="w-full max-w-xl bg-[#141416] border-l border-[#2E2722] text-[#F4F4F5] h-full flex flex-col shadow-2xl overflow-y-auto animate-in slide-in-from-right duration-250 font-sans"
            role="dialog"
            aria-modal="true"
          >
            {/* Drawer Header */}
            <div className="p-6 border-b border-[#2E2722] bg-[#1A1C20] flex items-start justify-between gap-4 sticky top-0 z-10">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-[#D47E30]"></span>
                  <h4 className="font-sans font-semibold text-sm text-zinc-100">
                    Observable Payload Inspector
                  </h4>
                </div>
                <p className="text-xs font-sans text-zinc-400">
                  Technical signal decomposition & sandbox safe analysis
                </p>
              </div>
              <button
                onClick={() => setSelectedUrlIndex(null)}
                className="p-1.5 rounded-lg bg-[#121417] hover:bg-[#2A2118] border border-[#2A231D] text-zinc-400 hover:text-zinc-100 transition-colors cursor-pointer"
                title="Close Drawer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Drawer Body */}
            <div className="p-6 space-y-6 flex-1">
              {/* Classification & Context Badges */}
              <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-lg bg-[#1A1C20] border border-[#2A231D]">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-sans text-zinc-400">Verdict:</span>
                  {selectedStatus === "SUSPICIOUS_URL" ? (
                    <Badge
                      variant="suspicious_url"
                      className="text-xs font-sans font-bold tracking-wider px-2.5 py-0.5 shadow-none"
                    >
                      SUSPICIOUS_URL
                    </Badge>
                  ) : (
                    <Badge
                      variant="clean"
                      className="text-xs font-sans font-bold tracking-wider px-2.5 py-0.5 shadow-none"
                    >
                      CLEAN
                    </Badge>
                  )}
                </div>
                <span className="text-[10px] font-sans font-medium uppercase text-zinc-400 bg-[#121417] px-2 py-1 rounded border border-[#2A231D]">
                  OBSERVED IN BODY
                </span>
              </div>

              {/* Unmasked Trampoline Phishing Destination Card */}
              {selectedTrampoline.isTrampoline && (
                <div className="p-4 rounded-lg bg-[#2A1715] border border-[#E06D53]/60 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-sans font-semibold uppercase tracking-wider text-[#E06D53] flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      Unmasked Phishing Destination (Trampoline Wrapper)
                    </span>
                    <button
                      onClick={() =>
                        handleDrawerCopy(
                          defangUrl(selectedTrampoline.targetUrl),
                          "unmasked"
                        )
                      }
                      className="inline-flex items-center gap-1 text-[11px] font-sans font-medium text-[#E06D53] hover:text-[#FDFBD4] cursor-pointer"
                    >
                      {copiedDrawerType === "unmasked" ? (
                        <>
                          <Check className="w-3 h-3 text-[#7EC876]" />
                          <span className="text-[#7EC876]">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy Destination</span>
                        </>
                      )}
                    </button>
                  </div>
                  <div className="p-3 bg-[#1A0F0D] border border-[#E06D53]/30 rounded-lg font-mono text-xs text-[#FDFBD4] break-all select-all leading-relaxed">
                    {defangUrl(selectedTrampoline.targetUrl)}
                  </div>
                  <p className="text-[11px] font-sans text-zinc-300">
                    Host &apos;<span className="font-mono text-zinc-200">{selectedDomain}</span>&apos; was utilized as an open redirect trampoline to bypass standard URL perimeter filters and route victims to unaligned host &apos;<span className="font-mono text-[#FDFBD4]">{selectedTrampoline.targetDomain}</span>&apos;.
                  </p>
                </div>
              )}

              {/* Defanged Payload Display */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-zinc-400">
                    Defanged IOC String (Safe Representation)
                  </span>
                  <button
                    onClick={() =>
                      handleDrawerCopy(selectedDefanged, "defanged")
                    }
                    className="inline-flex items-center gap-1 text-[11px] font-sans font-medium text-[#D47E30] hover:text-[#FDFBD4] cursor-pointer"
                  >
                    {copiedDrawerType === "defanged" ? (
                      <>
                        <Check className="w-3 h-3 text-[#7EC876]" />
                        <span className="text-[#7EC876]">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Copy Defanged</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="p-3.5 bg-[#121417] border border-[#2A231D] rounded-lg font-mono text-xs text-[#FDFBD4] break-all select-all leading-relaxed">
                  {selectedDefanged}
                </div>
              </div>

              {/* Raw Payload Display with Security Notice */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-zinc-400">
                    Raw Observable URL (Execution Disabled)
                  </span>
                  <button
                    onClick={() => handleDrawerCopy(selectedUrl, "raw")}
                    className="inline-flex items-center gap-1 text-[11px] font-sans font-medium text-zinc-400 hover:text-zinc-100 cursor-pointer"
                  >
                    {copiedDrawerType === "raw" ? (
                      <>
                        <Check className="w-3 h-3 text-[#7EC876]" />
                        <span className="text-[#7EC876]">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Copy Raw</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="p-3 bg-[#09090B] border border-[#27272A] rounded-lg font-mono text-xs text-zinc-400 break-all select-all">
                  {selectedUrl}
                </div>
              </div>

              {/* Deconstructed Technical Attributes Grid */}
              <div className="space-y-2">
                <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-zinc-400">
                  Deconstructed URL Attributes
                </span>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  {/* Host / Domain */}
                  <div className="p-3 rounded-lg bg-[#1A1C20] border border-[#2A231D]">
                    <div className="flex items-center gap-1.5 text-[10px] font-sans font-medium text-zinc-400 uppercase mb-1">
                      <Globe className="w-3 h-3 text-[#D47E30]" />
                      <span>Target Host</span>
                    </div>
                    <p className="font-mono text-xs font-bold text-[#FDFBD4] break-all">
                      {selectedDomain || "Unknown"}
                    </p>
                  </div>

                  {/* Protocol */}
                  <div className="p-3 rounded-lg bg-[#1A1C20] border border-[#2A231D]">
                    <div className="flex items-center gap-1.5 text-[10px] font-sans font-medium text-zinc-400 uppercase mb-1">
                      <Server className="w-3 h-3 text-[#D47E30]" />
                      <span>Protocol</span>
                    </div>
                    <p className="font-mono text-xs font-bold text-[#FDFBD4]">
                      {selectedUrl.startsWith("https://")
                        ? "HTTPS (TLS)"
                        : "HTTP (Insecure)"}
                    </p>
                  </div>

                  {/* Character Length */}
                  <div className="p-3 rounded-lg bg-[#1A1C20] border border-[#2A231D]">
                    <div className="flex items-center gap-1.5 text-[10px] font-sans font-medium text-zinc-400 uppercase mb-1">
                      <FileCode className="w-3 h-3 text-[#D47E30]" />
                      <span>Payload Length</span>
                    </div>
                    <p className="font-mono text-xs font-bold text-[#FDFBD4]">
                      {selectedUrl.length} characters
                    </p>
                  </div>

                  {/* Domain Trust Category */}
                  <div className="p-3 rounded-lg bg-[#1A1C20] border border-[#2A231D]">
                    <div className="flex items-center gap-1.5 text-[10px] font-sans font-medium text-zinc-400 uppercase mb-1">
                      <Shield className="w-3 h-3 text-[#D47E30]" />
                      <span>Domain Category</span>
                    </div>
                    <p className="font-sans text-xs font-semibold text-zinc-200">
                      {isDomainTrusted(selectedDomain)
                        ? "Known Trusted"
                        : fromDomain && selectedDomain === fromDomain
                        ? "Internal Match"
                        : "Untrusted External"}
                    </p>
                  </div>
                </div>
              </div>

              {/* Infrastructure Intelligence Correlation */}
              {selectedGeo ? (
                <div className="p-4 rounded-lg bg-[#1A1C20] border border-[#2A231D] space-y-2">
                  <div className="flex items-center gap-2 text-xs font-sans font-semibold text-[#D47E30] uppercase">
                    <Globe className="w-3.5 h-3.5" />
                    <span>Correlated Geo & Provider Intel</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs pt-1">
                    <div>
                      <span className="text-[10px] font-sans font-medium text-zinc-400 block">Location:</span>
                      <span className="text-zinc-200 font-sans font-medium">
                        {selectedGeo.city ? `${selectedGeo.city}, ` : ""}
                        {selectedGeo.country || "Unknown"}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] font-sans font-medium text-zinc-400 block">Provider:</span>
                      <span className="text-zinc-200 font-mono text-xs">
                        {selectedGeo.provider || "demo_cache"}
                      </span>
                    </div>
                  </div>
                  {selectedGeo.accuracy_caveat && (
                    <p className="text-[11px] font-sans text-zinc-400 italic pt-1 border-t border-[#2A231D]">
                      {selectedGeo.accuracy_caveat}
                    </p>
                  )}
                </div>
              ) : null}

              {/* Risk Rationale Explanation */}
              <div className="p-4 rounded-lg bg-[#121417] border border-[#2A231D] space-y-2">
                <div className="flex items-center gap-2 text-xs font-sans font-semibold text-zinc-200 uppercase">
                  {selectedStatus === "SUSPICIOUS_URL" ? (
                    <ShieldAlert className="w-4 h-4 text-[#E06D53]" />
                  ) : (
                    <ShieldCheck className="w-4 h-4 text-[#7EC876]" />
                  )}
                  <span>Detection Engine Analysis</span>
                </div>
                <p className="text-xs font-sans text-zinc-300 leading-relaxed">
                  {selectedStatus === "SUSPICIOUS_URL"
                    ? `Domain '${selectedDomain}' differs from the visible sender domain '${fromDomain || "unknown"}' and is not in the trusted domain whitelist. Such external endpoints frequently host credential harvesting forms or secondary malware payloads.`
                    : `Domain '${selectedDomain}' is verified as an authenticated organizational domain or known trusted ecosystem provider.`}
                </p>
              </div>

              {/* Security Caveat Banner */}
              <div className="flex items-start gap-2.5 p-3 rounded-lg bg-[#2A2118] border border-[#D47E30]/30 text-xs font-sans text-[#D47E30]">
                <Info className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <p className="leading-snug">
                  All active links in this console are deliberately defanged and non-clickable to prevent accidental browser redirection or zero-day exploitation.
                </p>
              </div>
            </div>

            {/* Drawer Footer Actions */}
            <div className="p-6 border-t border-[#2E2722] bg-[#1A1C20] flex items-center justify-between gap-3 sticky bottom-0">
              <button
                onClick={() => setSelectedUrlIndex(null)}
                className="px-4 py-2 rounded-lg bg-[#121417] hover:bg-[#2A2118] border border-[#2A231D] text-xs font-sans font-medium text-zinc-300 transition-colors cursor-pointer"
              >
                Close Inspector
              </button>
              <button
                onClick={() => handleDrawerCopy(selectedDefanged, "defanged_bottom")}
                className="px-4 py-2 rounded-lg bg-[#D47E30] hover:bg-[#D47E30]/90 text-black font-sans font-semibold text-xs transition-colors flex items-center gap-1.5 cursor-pointer shadow-sm"
              >
                {copiedDrawerType === "defanged_bottom" ? (
                  <>
                    <Check className="w-3.5 h-3.5" />
                    <span>Copied Defanged IOC</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy Defanged IOC</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

export default ObservableUrlTable;
