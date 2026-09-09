"use client";

import React, { useState, useRef, ChangeEvent, DragEvent } from "react";
import {
  CaseAnalysis,
  CampaignData,
  InfrastructureData,
  MessageData,
  ArtifactData,
} from "@/types/case";
import { Navbar } from "@/components/dashboard/Navbar";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { ObservableUrlTable } from "@/components/observable-url-table";
import { RelayTimeline } from "@/components/dashboard/RelayTimeline";
import {
  RadialBarChart,
  RadialBar,
  PolarAngleAxis,
  ResponsiveContainer,
} from "recharts";
import {
  UploadCloud,
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  Copy,
  Check,
  CheckCircle2,
  AlertTriangle,
  FileText,
  ArrowRight,
  Cpu,
  Globe,
  Server,
  FileCode,
  Download,
  ExternalLink,
  Lock,
  Zap,
} from "lucide-react";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

interface ThreatGraphProps {
  currentCaseId: string;
  campaign?: CampaignData;
  infrastructure?: InfrastructureData;
  message?: MessageData;
  artifact?: ArtifactData;
}

function ThreatGraph({
  currentCaseId,
  campaign,
  infrastructure,
  message,
  artifact,
}: ThreatGraphProps) {
  // 1. Related cases
  const relatedCases =
    campaign?.related_case_ids && campaign.related_case_ids.length > 0
      ? campaign.related_case_ids
      : campaign?.graph_nodes
      ? campaign.graph_nodes
          .filter((n) => n.type === "case" && n.label !== currentCaseId)
          .map((n) => n.label)
      : [];

  const hasCampaignCorrelation = relatedCases.length > 0;

  // 2. Shared or observed domains
  const rawSharedDomains =
    campaign?.shared_indicators && campaign.shared_indicators.length > 0
      ? campaign.shared_indicators
          .map((item) => (typeof item === "string" ? item : item.value || ""))
          .filter(Boolean)
      : campaign?.graph_nodes
      ? campaign.graph_nodes
          .filter((n) => n.type === "domain")
          .map((n) => n.label)
          .filter(Boolean)
      : [];

  const directObservedDomain =
    rawSharedDomains[0] ||
    infrastructure?.indicators?.find((i) => i.type === "domain")?.value ||
    (message?.from?.address && message.from.address.includes("@")
      ? message.from.address.split("@").pop()?.toLowerCase()
      : "") ||
    (message?.urls && message.urls.length > 0
      ? message.urls[0]
          .replace(/^[a-zA-Z]+:\/\//, "")
          .split("/")[0]
          .split("@")
          .pop()
          ?.split(":")[0]
          ?.toLowerCase()
      : "");

  const displayDomain = directObservedDomain || "No Domain Detected";
  const isDomainShared = rawSharedDomains.length > 0 && hasCampaignCorrelation;

  // 3. Shared or observed IP / Network
  const rawSharedIps = campaign?.graph_nodes
    ? campaign.graph_nodes
        .filter((n) => n.type === "ip")
        .map((n) => n.label)
        .filter(Boolean)
    : [];

  const directGeo = infrastructure?.geo?.[0];
  const directIpIndicator = infrastructure?.indicators?.find(
    (i) => i.type === "ip"
  )?.value;

  const displayIp =
    rawSharedIps[0] ||
    directIpIndicator ||
    (directGeo
      ? `${directGeo.city ? directGeo.city + ", " : ""}${
          directGeo.country || "Local Node"
        }`
      : artifact?.source
      ? `Source: ${artifact.source}`
      : "Direct Relay");

  const isIpShared = rawSharedIps.length > 0 && hasCampaignCorrelation;

  // 4. Artifact Signal / Hash / Related Case
  const displayHash = hasCampaignCorrelation
    ? `Case: ${relatedCases[0]}`
    : artifact?.sha256
    ? `SHA-256: ${artifact.sha256.substring(0, 12)}...`
    : "Isolated Artifact";

  return (
    <Card className="bg-[#1A1C20] border-[#2E2722] p-6 space-y-6 overflow-hidden shadow-sm font-sans">
      {/* Header with Title and Legend Chips */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[#2E2722]">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-[#D47E30]"></span>
          <h3 className="font-sans font-semibold text-sm tracking-tight text-zinc-200">
            Campaign Correlation & Threat Graph
          </h3>
        </div>

        {/* Legend Chips & Correlation Status */}
        <div className="flex flex-wrap items-center gap-2.5 text-[11px] font-sans">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#2A2118] border border-[#D47E30]/40 text-[#D47E30]">
            <span className="h-2 w-2 rounded-full bg-[#D47E30]"></span>
            <span className="font-medium">Current Case</span>
          </div>
          <div
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[11px] ${
              isDomainShared || isIpShared
                ? "bg-[#121417] border-[#FDFBD4]/30 text-[#FDFBD4]"
                : "bg-[#121417] border-[#2A231D] text-zinc-400"
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                isDomainShared || isIpShared ? "bg-[#FDFBD4]" : "bg-zinc-500"
              }`}
            ></span>
            <span className="font-medium">
              {isDomainShared || isIpShared ? "Shared Pivot" : "Observed Indicator"}
            </span>
          </div>
          <div
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[11px] ${
              hasCampaignCorrelation
                ? "bg-[#121417] border-[#8D5A2B]/40 text-[#8D5A2B]"
                : "bg-[#121417] border-[#2A231D] text-zinc-400"
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                hasCampaignCorrelation ? "bg-[#8D5A2B]" : "bg-zinc-500"
              }`}
            ></span>
            <span className="font-medium">
              {hasCampaignCorrelation ? `Related Cases (${relatedCases.length})` : "Isolated Artifact"}
            </span>
          </div>
        </div>
      </div>

      {/* Main Canvas: SVG-Rendered Node Graph */}
      <div className="relative w-full rounded-xl bg-[#121417] border border-[#2E2722] p-6 min-h-[360px] flex items-center justify-center overflow-hidden">
        {/* Canvas Grid Background */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#2e272230_1px,transparent_1px),linear-gradient(to_bottom,#2e272230_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none" />

        {/* SVG Connector Lines */}
        <svg
          className="absolute inset-0 w-full h-full pointer-events-none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Desktop SVG Dotted Lines (Center 50% 50% to satellites) */}
          <g className="hidden md:block">
            {/* Top-Left Satellite (IP / Network) */}
            <line
              x1="50%"
              y1="50%"
              x2="20%"
              y2="28%"
              stroke={isIpShared ? "#D47E30" : "#3E342B"}
              strokeWidth="2"
              strokeDasharray="4 4"
            />
            {/* Top-Right Satellite (Domain) */}
            <line
              x1="50%"
              y1="50%"
              x2="80%"
              y2="28%"
              stroke={isDomainShared ? "#FDFBD4" : "#3E342B"}
              strokeWidth="2"
              strokeDasharray="4 4"
            />
            {/* Bottom-Center Satellite (Hash / Related Case) */}
            <line
              x1="50%"
              y1="50%"
              x2="50%"
              y2="82%"
              stroke={hasCampaignCorrelation ? "#8D5A2B" : "#3E342B"}
              strokeWidth="2"
              strokeDasharray="4 4"
            />
          </g>

          {/* Mobile SVG Dotted Vertical Lines */}
          <g className="block md:hidden">
            <line
              x1="50%"
              y1="18%"
              x2="50%"
              y2="42%"
              stroke="#3E342B"
              strokeWidth="2"
              strokeDasharray="4 4"
            />
            <line
              x1="50%"
              y1="58%"
              x2="50%"
              y2="78%"
              stroke="#3E342B"
              strokeWidth="2"
              strokeDasharray="4 4"
            />
          </g>
        </svg>

        {/* Interactive Node Graph Canvas */}
        <div className="relative z-10 w-full max-w-4xl mx-auto flex flex-col md:grid md:grid-cols-3 md:grid-rows-3 gap-6 items-center justify-items-center py-4">
          {/* Satellite Node 1 (Top-Left): IP / Network */}
          <div className="md:col-start-1 md:row-start-1 flex flex-col items-center">
            <div className="group bg-[#1A1C20] border border-[#2E2722] hover:border-[#D47E30] rounded-xl p-3.5 shadow-lg transition-all duration-200 hover:scale-105 min-w-[190px] text-center cursor-default">
              <div className="flex items-center justify-center gap-1.5 mb-1">
                <Globe className="w-3.5 h-3.5 text-[#D47E30]" />
                <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-zinc-400">
                  {isIpShared ? "Shared Indicator" : "Observed Network"}
                </span>
              </div>
              <p className="font-mono text-xs font-bold text-[#FDFBD4] tracking-tight truncate max-w-[200px]" title={displayIp}>
                {displayIp.startsWith("Source:") || displayIp.startsWith("Network:") ? displayIp : `IP: ${displayIp}`}
              </p>
              <span className="text-[10px] font-sans font-medium text-[#D47E30] block mt-0.5">
                {isIpShared ? "Origin Network" : directGeo?.provider ? `Provider: ${directGeo.provider}` : "Transport Context"}
              </span>
            </div>
          </div>

          {/* Empty Center-Top Space */}
          <div className="hidden md:block md:col-start-2 md:row-start-1" />

          {/* Satellite Node 2 (Top-Right): Domain */}
          <div className="md:col-start-3 md:row-start-1 flex flex-col items-center">
            <div className="group bg-[#1A1C20] border border-[#2E2722] hover:border-[#FDFBD4] rounded-xl p-3.5 shadow-lg transition-all duration-200 hover:scale-105 min-w-[190px] text-center cursor-default">
              <div className="flex items-center justify-center gap-1.5 mb-1">
                <Server className="w-3.5 h-3.5 text-[#FDFBD4]" />
                <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-zinc-400">
                  {isDomainShared ? "Shared Pivot" : "Observed Domain"}
                </span>
              </div>
              <p className="font-mono text-xs font-bold text-[#FDFBD4] tracking-tight break-all max-w-[200px]">
                Domain: {displayDomain}
              </p>
              <span className="text-[10px] font-sans font-medium text-zinc-400 block mt-0.5">
                {isDomainShared ? `Correlation Pivot (${relatedCases.length} Cases)` : "Artifact Domain"}
              </span>
            </div>
          </div>

          {/* CENTER NODE: Main Case inside Amber Glowing Card */}
          <div className="md:col-start-2 md:row-start-2 flex flex-col items-center">
            <div className="relative bg-[#261B12] border border-[#D47E30] text-[#FDFBD4] shadow-[0_0_30px_rgba(212,126,48,0.3)] rounded-2xl px-6 py-4.5 flex flex-col items-center gap-1.5 transition-all duration-200 hover:scale-105 min-w-[210px] text-center cursor-default">
              <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[#121417] border border-[#D47E30]/40 text-[11px] font-sans font-medium uppercase tracking-wider text-[#D47E30]">
                <Shield className="w-3 h-3 text-[#D47E30]" />
                <span>Current Case</span>
              </div>
              <span className="text-lg font-mono font-bold text-[#FDFBD4] tracking-tight mt-0.5">
                {currentCaseId || "TS-DEMO-001"}
              </span>
              <span className="text-[11px] font-sans font-medium text-[#D47E30]/90">
                {hasCampaignCorrelation ? "Active Threat Pivot" : "Isolated Investigation Pivot"}
              </span>
            </div>
          </div>

          {/* Satellite Node 3 (Bottom-Center): Hash Match / Related Case */}
          <div className="md:col-start-2 md:row-start-3 flex flex-col items-center">
            <div className="group bg-[#1A1C20] border border-[#2E2722] hover:border-[#8D5A2B] rounded-xl p-3.5 shadow-lg transition-all duration-200 hover:scale-105 min-w-[190px] text-center cursor-default">
              <div className="flex items-center justify-center gap-1.5 mb-1">
                <FileCode className="w-3.5 h-3.5 text-[#8D5A2B]" />
                <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-[#8D5A2B]">
                  {hasCampaignCorrelation ? "Related Case" : "Artifact Signal"}
                </span>
              </div>
              <p className="font-mono text-xs font-bold text-[#FDFBD4] tracking-tight">
                {displayHash}
              </p>
              <span className="text-[10px] font-sans font-medium text-zinc-400 block mt-0.5">
                {hasCampaignCorrelation ? `${relatedCases.length} Correlated Cluster` : "Artifact SHA-256"}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Graph Edge Summary Footer */}
      <div className="pt-2 border-t border-[#2E2722] flex flex-wrap items-center justify-between gap-3 text-[11px] text-zinc-400 font-sans">
        <span>
          {campaign?.graph_edges && campaign.graph_edges.length > 0
            ? `Observed Graph Edges: ${campaign.graph_edges.length}`
            : "Observed Graph Edges: 0 (Isolated Case)"}
        </span>
        <div className="flex flex-wrap gap-2">
          {campaign?.graph_edges && campaign.graph_edges.length > 0 ? (
            campaign.graph_edges.map((edge, idx) => (
              <span
                key={idx}
                className="bg-[#121417] px-2 py-0.5 rounded border border-[#2E2722] text-[#FDFBD4] font-mono text-[11px]"
              >
                {edge.source} ➔ {edge.target} ({edge.type})
              </span>
            ))
          ) : (
            <span className="text-xs text-zinc-400 italic font-sans">
              No cross-case campaign edges detected in current corpus.
            </span>
          )}
        </div>
      </div>
    </Card>
  );
}

export default function Home() {
  const [caseData, setCaseData] = useState<CaseAnalysis | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);
  const [quarantining, setQuarantining] = useState<boolean>(false);
  const [quarantineSuccess, setQuarantineSuccess] = useState<{
    originIp: string;
    targetMessageId: string;
    firewallRule: string;
    timestamp: string;
  } | null>(null);
  const [quarantineError, setQuarantineError] = useState<string | null>(null);
  const [showQuarantineModal, setShowQuarantineModal] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleQuarantine = async () => {
    if (!caseData?.case_id) return;
    setQuarantining(true);
    setQuarantineError(null);
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/cases/${encodeURIComponent(caseData.case_id)}/quarantine`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
        }
      );

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `Quarantine failed (${response.status}): ${errorText || response.statusText}`
        );
      }

      const updatedData: CaseAnalysis = await response.json();
      setCaseData(updatedData);

      const originIp =
        updatedData.message?.origin_ip ||
        updatedData.infrastructure?.indicators?.find((i) => i.type === "ip")?.value ||
        "198.51.100.24";

      const targetMsgId =
        updatedData.mitigation?.target_message_id ||
        `<${caseData.case_id}@traceshield.internal>`;

      const firewallRule =
        updatedData.mitigation?.originating_ip_firewall_rule ||
        `iptables -A INPUT -s ${originIp} -j DROP`;

      const timestamp =
        updatedData.mitigation?.timestamp || new Date().toISOString();

      setQuarantineSuccess({
        originIp,
        targetMessageId: targetMsgId,
        firewallRule,
        timestamp,
      });
      setShowQuarantineModal(true);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setQuarantineError(err.message);
      } else {
        setQuarantineError("Failed to apply 1-Click IMAP Quarantine.");
      }
    } finally {
      setQuarantining(false);
    }
  };

  const handleFileUpload = async (file: File) => {
    if (!file.name.toLowerCase().endsWith(".eml")) {
      setError("Please select a valid .eml email file.");
      return;
    }

    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/cases`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `Backend returned ${response.status}: ${errorText || response.statusText}`
        );
      }

      const data: CaseAnalysis = await response.json();
      setCaseData(data);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(
          `Unable to connect to backend at ${API_BASE_URL} (${err.message}). Ensure the FastAPI server is running with 'py -m uvicorn main:app --reload --port 8000'.`
        );
      } else {
        setError("An unknown error occurred while uploading the file.");
      }
    } finally {
      setLoading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    }
  };

  const onFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFileUpload(e.target.files[0]);
    }
  };

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const getRiskBadgeStyles = (band?: string) => {
    const normalized = (band || "").toUpperCase();
    if (normalized === "HIGH") {
      return {
        bg: "bg-[#141416] border-red-800/80 text-red-300",
        badge: "bg-red-600 text-white font-bold font-sans",
        label: "HIGH RISK",
      };
    }
    if (normalized === "REVIEW") {
      return {
        bg: "bg-[#141416] border-[#8D5A2B] text-[#F4F4F5]",
        badge: "bg-[#D47E30] text-[#09090B] font-bold font-sans",
        label: "REVIEW REQUIRED",
      };
    }
    return {
      bg: "bg-[#141416] border-emerald-800/80 text-emerald-300",
      badge: "bg-emerald-600 text-white font-bold font-sans",
      label: "LOW RISK",
    };
  };

  const riskStyles = getRiskBadgeStyles(caseData?.risk?.band);

  return (
    <div className="min-h-screen bg-[#09090B] text-[#F4F4F5] flex flex-col font-sans">
      {/* Redesigned Modern SaaS Top Navigation Bar */}
      <Navbar
        apiBaseUrl={API_BASE_URL}
        activeCaseId={caseData?.case_id}
        onNewScan={() => {
          setCaseData(null);          // clear old results from screen
          setError(null);             // clear old error messages
          if (fileInputRef.current) {
            fileInputRef.current.value = ""; // allow same file to be re-uploaded
            fileInputRef.current.click();
          }
        }}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {/* Hidden File Input */}
        <input
          ref={fileInputRef}
          type="file"
          accept=".eml"
          onChange={onFileChange}
          className="hidden"
          id="eml-upload-input"
        />

        {/* File Upload Dropzone */}
        <section className="w-full">
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`group relative rounded-xl border border-dashed border-zinc-800 bg-[#141416] py-8 px-6 text-center cursor-pointer transition-colors duration-150 hover:border-[#D47E30] ${
              isDragging ? "border-[#D47E30]" : ""
            }`}
          >
            <div className="flex flex-col items-center justify-center gap-2.5">
              <div className="rounded-full bg-[#09090B] p-2.5 border border-zinc-800">
                <UploadCloud className="w-6 h-6 text-[#D47E30]" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-medium text-zinc-100 font-sans">
                  Drag & drop your <span className="text-[#FDFBD4] font-mono">.eml</span> file, or{" "}
                  <span className="text-[#D47E30] underline underline-offset-2">
                    click to browse
                  </span>
                </p>
                <p className="text-xs text-zinc-400 font-sans">
                  .eml files only • Max 10.0 MB • Parsed in isolated sandbox
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Error Alert */}
        {error && (
          <div className="bg-red-950/30 border border-red-800/80 rounded-xl p-4 flex items-start gap-3 text-red-200 font-sans">
            <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="text-sm font-semibold text-red-300 font-sans">
                Investigation Error
              </h3>
              <p className="text-xs text-red-300/90 mt-1 font-sans">{error}</p>
            </div>
            <button
              onClick={() => setError(null)}
              className="text-red-400 hover:text-red-200 text-xs font-sans font-medium cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div className="bg-[#141416] border border-zinc-800 rounded-xl p-12 text-center flex flex-col items-center justify-center space-y-4 font-sans">
            <div className="relative">
              <div className="w-10 h-10 rounded-full border-2 border-zinc-800 border-t-[#D47E30] animate-spin"></div>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-zinc-100 font-sans">
                Processing Email Forensic Artifact
              </h3>
              <p className="text-xs text-zinc-400 mt-1 font-sans">
                Parsing MIME structures, evaluating deterministic reason codes,
                and checking campaign correlations...
              </p>
            </div>
          </div>
        )}

        {/* Empty State when no case loaded and not loading */}
        {!caseData && !loading && !error && (
          <div className="border border-zinc-800/80 rounded-xl p-12 text-center bg-[#141416] font-sans">
            <div className="max-w-md mx-auto space-y-3">
              <div className="h-12 w-12 rounded-xl bg-[#09090B] border border-zinc-800 flex items-center justify-center mx-auto text-[#D47E30]">
                <FileText className="h-6 w-6" />
              </div>
              <h3 className="text-sm font-semibold text-zinc-100 font-sans">
                No Case Loaded
              </h3>
              <p className="text-xs text-zinc-400 font-sans">
                Upload a suspicious email artifact above (e.g. from{" "}
                <code className="text-[#FDFBD4] bg-[#09090B] px-1.5 py-0.5 rounded font-mono border border-zinc-800">
                  data/fixtures/test_phishing.eml
                </code>
                ) to inspect technical signals, risk explanation, and campaign correlation.
              </p>
            </div>
          </div>
        )}

        {/* Analysis Results View */}
        {caseData && !loading && (
          <div className="space-y-6">
            {/* Top Case Overview & Risk Gauge Section (65% / 35% Split) */}
            <div className="flex flex-col lg:flex-row gap-6">
              {/* Left 65%: Case Metadata Card */}
              <div className="w-full lg:w-[65%]">
                <Card className="bg-[#1A1C20] border-[#2E2722] p-6 space-y-4 h-full flex flex-col justify-between shadow-sm font-sans">
                  {/* Case Header */}
                  <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[#2E2722]">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <Badge className="bg-[#2A2118] text-[#D47E30] border border-[#2A231D] font-sans text-[11px] font-medium uppercase tracking-wider px-2.5 py-0.5 shadow-none">
                        CASE IDENTIFIER
                      </Badge>
                      <span className="font-mono font-bold text-sm text-[#FDFBD4]">
                        {caseData.case_id}
                      </span>
                      {caseData.status === "QUARANTINED" ? (
                        <Badge className="bg-red-950/90 text-red-400 border border-red-700/80 font-sans text-[11px] font-bold uppercase tracking-wider px-2.5 py-0.5 shadow-[0_0_12px_rgba(239,68,68,0.35)] flex items-center gap-1.5">
                          <ShieldAlert className="w-3 h-3 text-red-400" />
                          <span>QUARANTINED</span>
                        </Badge>
                      ) : caseData.artifact?.is_demo_data ? (
                        <Badge className="bg-[#2A2118] text-[#D47E30] border border-[#8D5A2B] font-sans text-[11px] font-medium shadow-none">
                          Synthetic Fixture
                        </Badge>
                      ) : null}
                    </div>
                    <div className="flex flex-wrap items-center gap-3">
                      {/* Prominent 1-Click IMAP Firewall & Quarantine Action Button */}
                      <button
                        id="btn-imap-quarantine"
                        onClick={handleQuarantine}
                        disabled={quarantining || caseData.status === "QUARANTINED"}
                        className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-sans font-bold tracking-wide transition-all duration-150 ${
                          caseData.status === "QUARANTINED"
                            ? "bg-red-950/80 border border-red-800 text-red-300 opacity-90 cursor-default shadow-[0_0_12px_rgba(239,68,68,0.25)]"
                            : "bg-red-600 hover:bg-red-500 active:scale-[0.98] text-white border border-red-400 hover:border-red-300 shadow-[0_0_16px_rgba(239,68,68,0.4)] hover:shadow-[0_0_24px_rgba(239,68,68,0.6)] cursor-pointer"
                        }`}
                        title="Flag message for IMAP server deletion and dispatch origin IP firewall drop rule"
                      >
                        {quarantining ? (
                          <>
                            <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                            <span>Quarantining...</span>
                          </>
                        ) : caseData.status === "QUARANTINED" ? (
                          <>
                            <ShieldCheck className="w-3.5 h-3.5 text-red-400" />
                            <span>Quarantined &amp; Blocklisted</span>
                          </>
                        ) : (
                          <>
                            <Zap className="w-3.5 h-3.5 text-amber-300 fill-amber-300" />
                            <span>⚡ 1-Click IMAP Firewall &amp; Quarantine</span>
                          </>
                        )}
                      </button>

                      {/* Download Forensic Report Buttons (HTML & JSON) */}
                      <div className="inline-flex items-center">
                        <button
                          onClick={() => {
                            window.open(
                              `${API_BASE_URL}/api/v1/cases/${encodeURIComponent(caseData.case_id)}/report?format=html`,
                              "_blank",
                              "noopener,noreferrer"
                            );
                          }}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-l-lg bg-[#261B12] hover:bg-[#3D2C1E] border border-[#D47E30]/60 hover:border-[#D47E30] text-xs font-sans font-semibold text-[#FDFBD4] hover:text-white transition-all duration-150 shadow-[0_0_12px_rgba(212,126,48,0.15)] hover:shadow-[0_0_16px_rgba(212,126,48,0.3)] cursor-pointer"
                          title="Download/Open Forensic Incident Report (HTML / PDF)"
                        >
                          <Download className="w-3.5 h-3.5 text-[#D47E30]" />
                          <span>Download Forensic Report</span>
                          <ExternalLink className="w-3 h-3 text-zinc-400 ml-0.5" />
                        </button>
                        <button
                          onClick={() => {
                            window.open(
                              `${API_BASE_URL}/api/v1/cases/${encodeURIComponent(caseData.case_id)}/report?format=json`,
                              "_blank",
                              "noopener,noreferrer"
                            );
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-r-lg bg-[#1a1410] hover:bg-[#332215] border-y border-r border-[#D47E30]/60 hover:border-[#D47E30] text-xs font-mono font-bold text-[#D47E30] hover:text-white transition-all duration-150 cursor-pointer"
                          title="Download Forensic Report (JSON Format)"
                        >
                          JSON
                        </button>
                      </div>

                      {caseData.artifact?.sha256 && (
                        <div className="flex items-center gap-2 text-xs font-sans text-zinc-400">
                          <span>SHA-256:</span>
                          <span className="text-[#FDFBD4] font-mono">
                            {caseData.artifact.sha256.substring(0, 16)}...
                          </span>
                          <button
                            onClick={() =>
                              copyToClipboard(caseData.artifact?.sha256 || "")
                            }
                            className="inline-flex items-center gap-1 px-2 py-1 rounded bg-[#121417] hover:bg-[#2A2118] border border-[#2A231D] hover:border-[#8D5A2B] text-xs font-sans text-zinc-300 transition-colors cursor-pointer"
                            title="Copy SHA-256"
                          >
                            {copiedHash ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" />
                                <span className="text-[11px] text-emerald-400 font-sans">
                                  Copied
                                </span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3 text-zinc-400" />
                                <span className="text-[11px] font-sans">Copy</span>
                              </>
                            )}
                          </button>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* 2x2 Metadata Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 pt-1">
                    {/* Subject */}
                    <div className="flex flex-col justify-between">
                      <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-zinc-400 block mb-1.5">
                        Subject
                      </span>
                      <div className="font-sans text-xs text-zinc-100 bg-[#121417] p-2 rounded-md border border-[#2A231D] break-words min-h-[38px] flex items-center">
                        {caseData.message?.subject || "(No Subject)"}
                      </div>
                    </div>

                    {/* Visible Sender */}
                    <div className="flex flex-col justify-between">
                      <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-zinc-400 block mb-1.5">
                        Visible Sender
                      </span>
                      <div className="text-xs text-zinc-100 bg-[#121417] p-2 rounded-md border border-[#2A231D] break-all min-h-[38px] flex items-center">
                        {caseData.message?.from?.name ? (
                          <span className="font-sans font-semibold text-zinc-100 mr-1">
                            {caseData.message.from.name}{" "}
                          </span>
                        ) : null}
                        <span className="font-mono text-zinc-300">
                          &lt;{caseData.message?.from?.address || "Missing"}&gt;
                        </span>
                      </div>
                    </div>

                    {/* Reply-To */}
                    <div className="flex flex-col justify-between">
                      <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-zinc-400 block mb-1.5">
                        Reply-To
                      </span>
                      <div className="font-mono text-xs text-[#FDFBD4] bg-[#121417] p-2 rounded-md border border-[#2A231D] break-all min-h-[38px] flex items-center">
                        {caseData.message?.reply_to || "None specified in header"}
                      </div>
                    </div>

                    {/* Return-Path */}
                    <div className="flex flex-col justify-between">
                      <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-zinc-400 block mb-1.5">
                        Return-Path
                      </span>
                      <div className="font-mono text-xs text-[#FDFBD4] bg-[#121417] p-2 rounded-md border border-[#2A231D] break-all min-h-[38px] flex items-center">
                        {caseData.message?.return_path || "None specified"}
                      </div>
                    </div>

                    {/* Authentication Status — SPF / DKIM */}
                    <div className="flex flex-col gap-1.5 md:col-span-2">
                      <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-zinc-400 block mb-1.5">
                        Authentication
                      </span>
                      <div className="flex gap-2 flex-wrap">
                        {[
                          {
                            label: "SPF",
                            value:
                              caseData.message?.spf ??
                              caseData.message?.authentication?.spf,
                          },
                          {
                            label: "DKIM",
                            value:
                              caseData.message?.dkim ??
                              caseData.message?.authentication?.dkim,
                          },
                        ].map(({ label, value }) => {
                          const status = (value || "none").toLowerCase();
                          const color =
                            status === "pass"
                              ? "bg-emerald-900/40 text-emerald-300 border-emerald-700/50"
                              : status === "fail"
                              ? "bg-red-900/40 text-red-300 border-red-700/50"
                              : "bg-zinc-800/60 text-zinc-400 border-zinc-700/50";
                          return (
                            <span
                              key={label}
                              className={`px-3 py-1 rounded-full text-xs font-mono border font-semibold ${color}`}
                            >
                              {label}: {status.toUpperCase()}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                </Card>
              </div>

              {/* Right 35%: Risk Score Circular Gauge */}
              <div className="w-full lg:w-[35%]">
                <Card className="bg-[#1A1C20] border-[#2E2722] p-6 flex flex-col items-center justify-between text-center relative h-full shadow-sm font-sans">
                  <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-zinc-400">
                    Prototype Risk Score
                  </span>

                  {/* Circular Arc Indicator */}
                  <div className="relative w-44 h-44 flex items-center justify-center my-1">
                    <ResponsiveContainer width="100%" height="100%">
                      <RadialBarChart
                        cx="50%"
                        cy="50%"
                        innerRadius="72%"
                        outerRadius="92%"
                        barSize={9}
                        data={[
                          {
                            name: "Score",
                            value: caseData.risk?.score ?? 20,
                            fill:
                              (caseData.risk?.band || "").toUpperCase() === "HIGH"
                                ? "#EF4444"
                                : "#D47E30",
                          },
                        ]}
                        startAngle={90}
                        endAngle={-270}
                      >
                        <PolarAngleAxis
                          type="number"
                          domain={[0, 100]}
                          angleAxisId={0}
                          tick={false}
                        />
                        <RadialBar
                          background={{ fill: "#2A231D" }}
                          dataKey="value"
                          cornerRadius={10}
                        />
                      </RadialBarChart>
                    </ResponsiveContainer>

                    {/* Centered Score */}
                    <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                      <div className="flex items-baseline justify-center gap-0.5">
                        <span className="text-4xl font-bold font-mono text-[#FDFBD4] tracking-tight">
                          {caseData.risk?.score ?? 20}
                        </span>
                        <span className="text-sm font-semibold font-mono text-[#8D5A2B]">
                          /100
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Status Badge & Footer */}
                  <div className="flex flex-col items-center gap-2 mt-1 font-sans">
                    <Badge
                      className={`px-3.5 py-1 rounded-full font-sans font-bold uppercase tracking-wider text-xs border shadow-none ${
                        caseData.status === "QUARANTINED"
                          ? "bg-red-950 text-red-400 border-red-600 shadow-[0_0_12px_rgba(239,68,68,0.4)]"
                          : (caseData.risk?.band || "").toUpperCase() === "HIGH"
                          ? "bg-red-950/50 text-red-400 border-red-800/60"
                          : (caseData.risk?.band || "").toUpperCase() === "REVIEW"
                          ? "bg-[#2A2118] text-[#D47E30] border-[#D47E30]/30"
                          : "bg-[#2A2118] text-[#D47E30] border border-[#D47E30]/30"
                      }`}
                    >
                      {caseData.status === "QUARANTINED"
                        ? "QUARANTINED"
                        : caseData.risk?.band
                        ? caseData.risk.band.toUpperCase() === "LOW"
                          ? "LOW RISK"
                          : caseData.risk.band.toUpperCase() === "HIGH"
                          ? "HIGH RISK"
                          : "REVIEW REQUIRED"
                        : "LOW RISK"}
                    </Badge>

                    <p className="text-[11px] font-sans text-zinc-400 max-w-[240px] leading-tight">
                      {caseData.status === "QUARANTINED"
                        ? "Active threat containment and origin IP firewall drop rules deployed"
                        : "Explainable rule assessment based on observed technical signals"}
                    </p>
                  </div>
                </Card>
              </div>
            </div>

            {/* Tier 2 AI Analyst Review Section */}
            {caseData.ai_review === null || caseData.ai_review === undefined ? (
              <Alert className="bg-[#1A1C20] border-[#2E2722] p-4 flex items-center gap-3.5 shadow-sm font-sans">
                <ShieldCheck className="h-5 w-5 text-[#D47E30] flex-shrink-0" />
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between flex-1 gap-1 font-sans">
                  <div className="flex items-center gap-2 flex-wrap">
                    <AlertTitle className="text-xs font-sans font-semibold uppercase tracking-wider text-zinc-200 m-0">
                      Tier 2 AI Analyst Review — LLAMA-3 70B • GROQ
                    </AlertTitle>
                    <Badge className="bg-[#121417] text-emerald-400 border border-emerald-900/60 font-sans text-[10px] font-medium flex items-center gap-1 shadow-none py-0.5">
                      <Lock className="w-2.5 h-2.5 text-emerald-400" />
                      🔒 PII Sanitized Prior to AI Analysis
                    </Badge>
                  </div>
                  <AlertDescription className="text-xs font-sans text-zinc-400 m-0">
                    Review not triggered (Low initial risk threshold)
                  </AlertDescription>
                </div>
              </Alert>
            ) : caseData.ai_review?.error ? (
              <Alert className="bg-[#1A1C20] border-[#8D5A2B] p-4 flex items-center justify-between text-xs shadow-sm font-sans">
                <div className="flex items-center gap-2.5">
                  <ShieldCheck className="h-5 w-5 text-[#D47E30]" />
                  <span className="text-zinc-200 font-sans font-medium">
                    {caseData.ai_review.error}
                  </span>
                  <Badge className="bg-[#121417] text-emerald-400 border border-emerald-900/60 font-sans text-[10px] font-medium flex items-center gap-1 shadow-none py-0.5">
                    <Lock className="w-2.5 h-2.5 text-emerald-400" />
                    🔒 PII Sanitized Prior to AI Analysis
                  </Badge>
                </div>
                <span className="text-[11px] font-sans text-zinc-400">
                  Ensure GROQ_API_KEY is configured in backend/.env
                </span>
              </Alert>
            ) : (
              <section className="bg-[#1A1C20] border border-[#2E2722] rounded-xl p-6 shadow-sm font-sans">
                <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[#2E2722]">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <span className="h-2 w-2 rounded-full bg-[#D47E30]"></span>
                    <h3 className="font-sans font-semibold text-sm tracking-tight text-zinc-200">
                      Tier 2 AI Analyst Review
                    </h3>
                    <Badge className="bg-[#121417] text-[#D47E30] border border-[#2E2722] font-sans text-[11px] font-medium uppercase tracking-wider flex items-center gap-1 shadow-none">
                      <Cpu className="w-3 h-3 text-[#D47E30]" />
                      LLaMA-3 70B • Groq
                    </Badge>
                    <Badge className="bg-[#121417] text-emerald-400 border border-emerald-900/60 font-sans text-[11px] font-medium flex items-center gap-1.5 shadow-none">
                      <Lock className="w-3 h-3 text-emerald-400" />
                      🔒 PII Sanitized Prior to AI Analysis
                    </Badge>
                  </div>
                  <span className="text-xs font-sans text-zinc-400">
                    Contextual False Positive & Domain Verification
                  </span>
                </div>

                <div className="mt-4 space-y-4">
                  {/* Score Comparison & Verdict Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Original vs Adjusted Score Comparison Card */}
                    <div className="p-4 rounded-lg bg-[#121417] border border-[#2A231D] flex flex-col justify-between font-sans">
                      <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-zinc-400 mb-2 block">
                        Score Comparison (Tier 1 Rules vs Tier 2 LLM)
                      </span>
                      <div className="flex items-center justify-around gap-4 py-2">
                        {/* Original Score */}
                        <div className="text-center">
                          <span className="text-[11px] font-sans font-medium uppercase text-zinc-400 block mb-1">
                            Original Rules
                          </span>
                          <div className="flex items-baseline justify-center gap-1">
                            <span className="text-3xl font-black font-mono text-[#FDFBD4]">
                              {caseData.risk?.score ?? 0}
                            </span>
                            <span className="text-xs font-sans text-zinc-400">/100</span>
                          </div>
                          <span
                            className={`inline-block mt-1.5 px-2 py-0.5 rounded text-[10px] uppercase font-sans font-bold tracking-wider ${riskStyles.badge}`}
                          >
                            {caseData.risk?.band || "LOW"}
                          </span>
                        </div>

                        {/* Arrow Divider */}
                        <div className="flex flex-col items-center justify-center text-[#D47E30]">
                          <ArrowRight className="h-5 w-5 text-[#D47E30]" />
                        </div>

                        {/* Adjusted Score */}
                        <div className="text-center">
                          <span className="text-[11px] font-sans font-medium uppercase text-[#D47E30] block mb-1">
                            Adjusted AI Score
                          </span>
                          <div className="flex items-baseline justify-center gap-1">
                            <span className="text-3xl font-black font-mono text-[#FDFBD4]">
                              {caseData.ai_review.adjusted_score ?? caseData.risk?.score ?? 0}
                            </span>
                            <span className="text-xs font-sans text-zinc-400">/100</span>
                          </div>
                          {(() => {
                            const adjStyles = getRiskBadgeStyles(caseData.ai_review.adjusted_band);
                            return (
                              <span
                                className={`inline-block mt-1.5 px-2 py-0.5 rounded text-[10px] uppercase font-sans font-bold tracking-wider ${adjStyles.badge}`}
                              >
                                {caseData.ai_review.adjusted_band || "REVIEW"}
                              </span>
                            );
                          })()}
                        </div>
                      </div>
                    </div>

                    {/* False Positive Status Banner */}
                    <div className="p-4 rounded-lg bg-[#121417] border border-[#2A231D] flex flex-col justify-between font-sans">
                      <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-zinc-400 mb-2 block">
                        False Positive Verdict
                      </span>
                      <div className="flex-1 flex flex-col items-center justify-center text-center p-2">
                        {caseData.ai_review.is_false_positive ? (
                          <div className="flex flex-col items-center gap-1.5">
                            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-950/40 border border-emerald-800 text-emerald-300 font-bold font-sans text-xs">
                              <span className="h-2 w-2 rounded-full bg-emerald-400"></span>
                              FALSE POSITIVE DETECTED
                            </span>
                            <span className="text-xs text-emerald-400 font-sans font-medium mt-1">
                              Legitimate ESP mismatch or trusted domain verified.
                            </span>
                          </div>
                        ) : caseData.ai_review.adjusted_band === "REVIEW" ? (
                          <div className="flex flex-col items-center gap-1.5">
                            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-amber-950/40 border border-[#8D5A2B] text-amber-300 font-bold font-sans text-xs">
                              <span className="h-2 w-2 rounded-full bg-amber-400"></span>
                              MANUAL REVIEW RECOMMENDED
                            </span>
                            <span className="text-xs text-amber-300/90 font-sans font-medium mt-1">
                              Ambiguous signals; no definitive exploit or credential theft found.
                            </span>
                          </div>
                        ) : (
                          <div className="flex flex-col items-center gap-1.5">
                            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-red-950/40 border border-red-800 text-red-300 font-bold font-sans text-xs">
                              <span className="h-2 w-2 rounded-full bg-red-400"></span>
                              HIGH THREAT CONFIRMED
                            </span>
                            <span className="text-xs text-red-300 font-sans font-medium mt-1">
                              Indicators remain suspicious upon secondary review.
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* AI Analyst Summary Statement */}
                  {caseData.ai_review.analyst_summary && (
                    <div className="p-4 rounded-lg bg-[#121417] border border-[#2A231D] space-y-2 font-sans">
                      <div className="flex items-center gap-2 text-xs font-sans font-semibold text-[#D47E30] uppercase tracking-wider">
                        <FileText className="h-4 w-4" />
                        <span>Senior Security Analyst Reasoning</span>
                      </div>
                      <p className="text-xs text-zinc-200 leading-relaxed font-sans pl-4 border-l-2 border-[#D47E30]">
                        {caseData.ai_review.analyst_summary}
                      </p>
                    </div>
                  )}
                </div>
              </section>
            )}

            {/* Explainable Reason Codes Panel */}
            <section className="bg-[#141416] border border-zinc-800/80 rounded-xl p-6 font-sans">
              <div className="flex items-center justify-between pb-3 border-b border-zinc-800/80">
                <h3 className="font-sans font-semibold text-sm tracking-tight text-zinc-200 flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-[#D47E30]"></span>
                  Explainable Reason Codes (
                  {caseData.risk?.reason_codes?.length || 0})
                </h3>
                <span className="text-xs font-sans text-zinc-400">
                  Deterministic Rule Evidence
                </span>
              </div>

              {caseData.risk?.reason_codes &&
              caseData.risk.reason_codes.length > 0 ? (
                <div className="mt-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {caseData.risk.reason_codes.map((rc, idx) => (
                    <div
                      key={idx}
                      className="bg-[#09090B] border border-zinc-800/80 hover:border-[#825E34] transition-colors rounded-lg p-4 flex flex-col justify-between space-y-3 font-sans"
                    >
                      <div>
                        <div className="flex items-center justify-between gap-2 mb-2">
                          <span className="px-2 py-0.5 bg-[#141416] text-[#F4F4F5] border border-[#8D5A2B] text-[11px] font-mono font-semibold rounded">
                            {rc.code}
                          </span>
                        </div>
                        <p className="text-sm font-sans font-medium text-zinc-200">
                          {rc.title}
                        </p>
                      </div>
                      <div className="pt-2 border-t border-zinc-800/80 flex items-center justify-between text-[11px] text-zinc-400 font-sans">
                        <span>Evidence:</span>
                        <code className="text-[#D47E30] bg-[#141416] px-1.5 py-0.5 rounded font-mono text-xs border border-zinc-800">
                          {rc.evidence_path}
                        </code>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="mt-4 p-4 text-center text-xs font-sans text-zinc-400 bg-[#09090B] rounded-lg border border-zinc-800">
                  No high-risk reason triggers detected in this artifact.
                </div>
              )}
            </section>

            {/* Infrastructure & Geolocation Table */}
            <section className="bg-[#141416] border border-zinc-800/80 rounded-xl p-6 font-sans">
              <div className="flex items-center justify-between pb-3 border-b border-zinc-800/80">
                <div className="flex items-center gap-2">
                  <h3 className="font-sans font-semibold text-sm tracking-tight text-zinc-200">
                    Infrastructure & Geolocation Context
                  </h3>
                  <span className="text-xs px-2 py-0.5 bg-[#09090B] text-zinc-400 rounded border border-zinc-800 font-sans">
                    Provider: <span className="font-mono text-zinc-200">{caseData.infrastructure?.provider_status || "demo_cache"}</span>
                  </span>
                </div>
                <span className="text-xs font-sans text-zinc-400 italic">
                  Approximate network context; not human attribution.
                </span>
              </div>

              {caseData.infrastructure?.geo &&
              caseData.infrastructure.geo.length > 0 ? (
                <div className="mt-4 overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-zinc-800 text-zinc-400 font-sans font-medium uppercase tracking-wider text-[11px]">
                        <th className="py-2.5 px-3">Indicator / Domain</th>
                        <th className="py-2.5 px-3">Approx Country</th>
                        <th className="py-2.5 px-3">Approx City</th>
                        <th className="py-2.5 px-3">Source Provider</th>
                        <th className="py-2.5 px-3">Caveat & Confidence</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/80">
                      {caseData.infrastructure.geo.map((g, idx) => (
                        <tr
                          key={idx}
                          className="hover:bg-[#09090B]/60 transition-colors"
                        >
                          <td className="py-3 px-3 font-mono font-medium text-zinc-200">
                            {g.indicator}
                          </td>
                          <td className="py-3 px-3 font-sans text-zinc-200">
                            {g.country || "Unknown"}
                          </td>
                          <td className="py-3 px-3 font-sans text-zinc-200">
                            {g.city || "Unknown"}
                          </td>
                          <td className="py-3 px-3 font-sans">
                            <span className="px-2 py-0.5 bg-[#09090B] text-zinc-400 rounded border border-zinc-800 text-[11px] font-sans">
                              {g.provider || "demo_cache"}
                            </span>
                          </td>
                          <td className="py-3 px-3 font-sans text-zinc-400 text-[11px]">
                            {g.accuracy_caveat ||
                              "Approximate network location"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="mt-4 p-4 text-center text-xs font-sans text-zinc-400 bg-[#09090B] rounded-lg border border-zinc-800">
                  No geolocation entries available for observed domains in this artifact.
                </div>
              )}
            </section>

            {/* Observable Relay Timeline */}
            <RelayTimeline
              hops={caseData.trace?.hops || caseData.message?.trace?.hops}
              earliestReliableObservable={caseData.trace?.earliest_reliable_observable}
              limitations={caseData.trace?.limitations}
            />

            {/* Campaign Correlation & Threat Graph */}
            <ThreatGraph
              currentCaseId={caseData.case_id}
              campaign={caseData.campaign}
              infrastructure={caseData.infrastructure}
              message={caseData.message}
              artifact={caseData.artifact}
            />

            {/* High-Density Observable Body URLs Shadcn Table */}
            {caseData.message?.urls && caseData.message.urls.length > 0 && (
              <ObservableUrlTable
                urls={caseData.message.urls}
                fromAddress={caseData.message.from?.address}
                reasonCodes={caseData.risk?.reason_codes}
                infrastructure={caseData.infrastructure}
              />
            )}
          </div>
        )}

        {/* Quarantine Error Alert */}
        {quarantineError && (
          <div className="mt-4 p-4 rounded-lg bg-red-950/50 border border-red-800 text-red-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{quarantineError}</span>
            </div>
            <button
              onClick={() => setQuarantineError(null)}
              className="text-zinc-400 hover:text-zinc-200 text-xs p-1"
            >
              ✕
            </button>
          </div>
        )}

        {/* Quarantine Mitigation Success Banner (Inline) */}
        {caseData && (caseData.status === "QUARANTINED" || quarantineSuccess) && (
          <div className="mt-6 p-4 rounded-xl bg-gradient-to-r from-red-950/80 via-[#221010] to-[#1A1C20] border-2 border-red-600/80 shadow-[0_0_24px_rgba(239,68,68,0.25)] space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-red-900/60 pb-2">
              <div className="flex items-center gap-2">
                <Badge className="bg-red-600 text-white border-none text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 shadow-[0_0_10px_rgba(239,68,68,0.5)]">
                  ACTIVE MITIGATION APPLIED
                </Badge>
                <span className="text-xs font-semibold text-red-200">
                  IMAP Quarantine &amp; Firewall Rule Dispatched
                </span>
              </div>
              <span className="text-[11px] font-mono text-zinc-400">
                {caseData.mitigation?.timestamp || quarantineSuccess?.timestamp || new Date().toISOString()}
              </span>
            </div>
            <div className="space-y-1 text-xs">
              <div className="flex items-center gap-2 text-emerald-400 font-semibold font-sans">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>✓ Message flagged for deletion on IMAP Server.</span>
              </div>
              <div className="flex items-center gap-2 text-emerald-400 font-semibold font-sans">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>
                  ✓ Originating IP [{caseData.message?.origin_ip || quarantineSuccess?.originIp || "198.51.100.24"}] dispatched to firewall blocklist.
                </span>
              </div>
            </div>
            <div className="pt-1 flex flex-wrap items-center gap-2 text-[11px] font-mono">
              <span className="text-zinc-400">Dispatched Rule:</span>
              <code className="bg-black/70 text-red-300 border border-red-900/60 px-2 py-0.5 rounded">
                {caseData.mitigation?.originating_ip_firewall_rule ||
                  quarantineSuccess?.firewallRule ||
                  `iptables -A INPUT -s ${caseData.message?.origin_ip || "198.51.100.24"} -j DROP`}
              </code>
            </div>
          </div>
        )}
      </main>

      {/* 1-Click IMAP Quarantine & Firewall Rule Dispatched Interactive Modal */}
      {showQuarantineModal && quarantineSuccess && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
          <div className="bg-[#1A1C20] border-2 border-red-600 rounded-xl max-w-lg w-full p-6 space-y-5 shadow-[0_0_50px_rgba(239,68,68,0.45)] text-zinc-100 font-sans relative">
            {/* Header */}
            <div className="flex items-start justify-between border-b border-red-900/60 pb-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-lg bg-red-950 border border-red-600 text-red-400 shadow-[0_0_12px_rgba(239,68,68,0.3)]">
                  <ShieldAlert className="w-6 h-6 text-red-400" />
                </div>
                <div>
                  <h3 className="font-bold text-base text-zinc-100 flex items-center gap-1.5">
                    <span>⚡</span> 1-Click IMAP Firewall &amp; Quarantine
                  </h3>
                  <p className="text-xs text-zinc-400">Automated Threat Mitigation &amp; Containment</p>
                </div>
              </div>
              <button
                onClick={() => setShowQuarantineModal(false)}
                className="text-zinc-400 hover:text-white p-1 rounded-md hover:bg-white/10 transition-colors"
              >
                ✕
              </button>
            </div>

            {/* Required Success Banner Lines */}
            <div className="p-4 rounded-lg bg-emerald-950/40 border border-emerald-500/50 space-y-2 shadow-inner">
              <div className="flex items-center gap-2 text-emerald-300 font-bold text-sm">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>✓ Message flagged for deletion on IMAP Server.</span>
              </div>
              <div className="flex items-center gap-2 text-emerald-300 font-bold text-sm">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>
                  ✓ Originating IP [{quarantineSuccess.originIp}] dispatched to firewall blocklist.
                </span>
              </div>
            </div>

            {/* Execution Payload Details */}
            <div className="space-y-2 text-xs">
              <span className="text-[11px] font-sans font-semibold uppercase tracking-wider text-zinc-400 block">
                Dispatched Mitigation Details
              </span>
              <div className="bg-[#101214] border border-[#2A231D] rounded-lg p-3 space-y-2 font-mono text-[11px]">
                <div>
                  <span className="text-zinc-500">Action:</span>{" "}
                  <span className="text-[#D47E30] font-bold">IMAP_STORE_FLAGS_DELETED</span>{" "}
                  <span className="text-zinc-500">(\Deleted flag applied)</span>
                </div>
                <div className="truncate">
                  <span className="text-zinc-500">Target Message-ID:</span>{" "}
                  <span className="text-zinc-200">{quarantineSuccess.targetMessageId}</span>
                </div>
                <div>
                  <span className="text-zinc-500">Firewall Drop Rule:</span>{" "}
                  <span className="text-red-400 bg-red-950/60 px-2 py-0.5 rounded border border-red-900/60 font-bold">
                    {quarantineSuccess.firewallRule}
                  </span>
                </div>
                <div>
                  <span className="text-zinc-500">Timestamp:</span>{" "}
                  <span className="text-zinc-400">{quarantineSuccess.timestamp}</span>
                </div>
                <div>
                  <span className="text-zinc-500">Execution Status:</span>{" "}
                  <span className="text-emerald-400 font-bold">APPLIED_SUCCESSFULLY</span>
                </div>
              </div>
            </div>

            {/* Footer / Close */}
            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowQuarantineModal(false)}
                className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 active:scale-95 text-white font-bold text-xs transition-all shadow-[0_0_16px_rgba(239,68,68,0.4)] cursor-pointer"
              >
                Acknowledge &amp; Return to Console
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="border-t border-zinc-800/80 py-4 px-6 text-center text-xs font-sans text-zinc-400 bg-[#09090B]">
        TraceShield AI • SIH26106 Explainable Forensic Threat Investigation Platform • SOC Analyst Console
      </footer>
    </div>
  );
}
