export interface FromAddress {
  name: string | null;
  address: string | null;
}

export interface MessageData {
  from?: FromAddress | null;
  reply_to?: string | null;
  return_path?: string | null;
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

export interface AIReviewData {
  is_false_positive?: boolean;
  adjusted_score?: number;
  adjusted_band?: "LOW" | "REVIEW" | "HIGH" | string;
  analyst_summary?: string;
  error?: string;
}

export interface CaseAnalysis {
  case_id: string;
  artifact?: ArtifactData;
  message?: MessageData;
  risk: RiskData;
  ai_review?: AIReviewData | null;
  infrastructure?: InfrastructureData;
  campaign?: CampaignData;
}
