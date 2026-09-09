export interface FromAddress {
  name: string | null;
  address: string | null;
}

export interface ReceivedHop {
  index: number;
  raw: string;
  from_host?: string | null;
  from_ip?: string | null;
  by_host?: string | null;
  by_ip?: string | null;
  with_protocol?: string | null;
  timestamp?: string | null;
  parse_status?: string;
  trust?: string;
  is_tor?: boolean;
  is_proxy?: boolean;
  anonymizer_type?: string | null;
  confidence_score?: number | null;
}

export type TraceHop = ReceivedHop;

export interface TraceData {
  hops?: ReceivedHop[];
  earliest_reliable_observable?: string | null;
  limitations?: string[];
}

export interface MessageData {
  from?: FromAddress | null;
  reply_to?: string | null;
  return_path?: string | null;
  message_id?: string | null;
  origin_ip?: string | null;
  subject?: string | null;
  urls?: string[];
  spf?: string | null;
  dkim?: string | null;
  dmarc?: string | null;
  authentication?: {
    spf?: string | null;
    dkim?: string | null;
    dmarc?: string | null;
    compauth?: string | null;
  } | null;
  trace?: TraceData;
}

export interface ReasonCode {
  code: string;
  title: string;
  evidence_path: string;
}

export interface RiskData {
  score: number;
  band: "HIGH" | "REVIEW" | "LOW" | string;
  reason_codes: ReasonCode[];
}

export interface GeoData {
  indicator: string;
  country?: string | null;
  city?: string | null;
  provider?: string | null;
  accuracy_caveat?: string | null;
}

export interface IndicatorData {
  type: string;
  value: string;
  source?: string;
}

export interface InfrastructureData {
  indicators?: IndicatorData[];
  geo?: GeoData[];
  provider_status?: string;
}

export interface SharedIndicator {
  type?: string;
  value?: string;
  relationship?: string;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  source?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
  evidence?: string[];
}

export interface CampaignData {
  related_case_ids?: string[];
  shared_indicators?: (SharedIndicator | string)[];
  graph_nodes?: GraphNode[];
  graph_edges?: GraphEdge[];
}

export interface ArtifactData {
  filename?: string;
  sha256?: string;
  received_at?: string;
  source?: string;
  is_demo_data?: boolean;
}

export interface PrivacyAuditData {
  pii_sanitized?: boolean;
  masked_entities_count?: number;
  cards_redacted?: number;
  phones_redacted?: number;
  emails_redacted?: number;
  aadhaar_redacted?: number;
  pii_detected?: boolean;
}

export interface AIReviewData {
  is_false_positive?: boolean;
  adjusted_score?: number;
  adjusted_band?: "LOW" | "REVIEW" | "HIGH" | string;
  analyst_summary?: string;
  error?: string;
  privacy_audit?: PrivacyAuditData;
}

export interface MitigationLog {
  action: string;
  target_message_id: string;
  originating_ip_firewall_rule: string;
  timestamp: string;
  status: string;
}

export interface CaseAnalysis {
  case_id: string;
  status?: "ACTIVE" | "QUARANTINED" | string;
  artifact?: ArtifactData;
  message?: MessageData;
  risk: RiskData;
  ai_review?: AIReviewData | null;
  privacy_audit?: PrivacyAuditData;
  infrastructure?: InfrastructureData;
  campaign?: CampaignData;
  trace?: TraceData;
  mitigation?: MitigationLog;
  mitigation_log?: MitigationLog;
}

