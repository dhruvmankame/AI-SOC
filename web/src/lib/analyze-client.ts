const BASE = import.meta.env["VITE_ANALYZE_API"] || "http://127.0.0.1:8787";

export type Phase =
  | "queued"
  | "collecting"
  | "hypothesizing"
  | "verifying"
  | "reporting"
  | "done_with_report"
  | "done_no_report"
  | "error";

export type JobIncident = {
  incidentId: string;
  code: string;
  title: string;
  attackType: string;
  risk: number;
  phase: Phase;
  error?: string;
};

export type Job = {
  jobId: string;
  batchId: string;
  status: "parsing" | "inserting" | "investigating" | "complete";
  incidents: JobIncident[];
};

export type AnalyzeAlert = {
  title: string;
  severity: string;
  confidence: number;
  detector: string;
  entity: string;
  correlationCount: number;
  contributions: Record<string, number>;
};

export type AnalyzeStats = {
  storedEvents: number;
  signals: number;
  alerts: number;
  incidents: number;
  processingMs: number;
  sourceFilename: string;
};

export type Standardization = {
  source_columns: number;
  source_column_names: string[];
  canonical_mapping: Record<string, string | null>;
  label_column_present: boolean;
  rows_read: number;
  rows_standardized: number;
  rows_dropped_unparseable_timestamp: number;
  incidents_discovered: number;
  incidents_truncated: number;
  attack_classes: {
    attack_class: string;
    annotated_flows: number;
    corroborated_by_detector: number;
    corroboration_pct: number;
  }[];
};

export type AttackAssessment = {
  hypothesis_id: string;
  statement: string;
  technique: string;
  confidence_pct: number;
  detector_component: number;
  entailment_component: number;
  basis: "behavioural" | "behavioural+annotation" | "annotation-only";
  corroborated_by_detector: boolean;
  top_detector: string | null;
  cited_evidence: string[];
};

export type AnalyzeResponse = {
  batchId: string;
  jobId: string;
  incidents: Omit<JobIncident, "phase">[];
  alerts: AnalyzeAlert[];
  stats: AnalyzeStats;
  standardization?: Standardization | null;
  eval?: {
    tp?: number;
    fp?: number;
    fn?: number;
    tn?: number;
    precision?: number;
    recall?: number;
    f1?: number;
  } | null;
};

export type UploadProgress = {
  loaded: number;
  total: number;
  percent: number;
};

export function analyzeFile(
  file: File,
  onProgress?: (progress: UploadProgress) => void,
): Promise<AnalyzeResponse> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const form = new FormData();
    form.append("file", file);

    xhr.open("POST", `${BASE}/api/analyze`);

    xhr.upload.onprogress = (event) => {
      if (!event.lengthComputable) return;
      const percent = Math.min(100, Math.round((event.loaded / event.total) * 100));
      onProgress?.({ loaded: event.loaded, total: event.total, percent });
    };

    xhr.onerror = () => {
      reject(new Error("The local analysis service is unavailable. Check the agents service and CORS settings."));
    };

    xhr.onload = () => {
      let body: any = {};
      try {
        body = xhr.responseText ? JSON.parse(xhr.responseText) : {};
      } catch {
        body = {};
      }
      if (xhr.status < 200 || xhr.status >= 300) {
        reject(new Error(body.error || `Analysis request failed (${xhr.status})`));
        return;
      }
      resolve(body as AnalyzeResponse);
    };

    xhr.send(form);
  });
}

async function parse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export async function fetchJob(id: string): Promise<Job> {
  return parse<Job>(await fetch(`${BASE}/api/jobs/${encodeURIComponent(id)}`, { cache: "no-store" }));
}

export const phaseLabels: Record<Phase, string> = {
  queued: "Queued",
  collecting: "Collecting evidence",
  hypothesizing: "Forming hypotheses",
  verifying: "Verifying against evidence",
  reporting: "Writing report",
  done_with_report: "Verified report ready",
  done_no_report: "Claims rejected",
  error: "Investigation error",
};

export const phaseProgress: Record<Phase, number> = {
  queued: 5,
  collecting: 25,
  hypothesizing: 45,
  verifying: 65,
  reporting: 85,
  done_with_report: 100,
  done_no_report: 100,
  error: 100,
};

export const isTerminal = (phase: Phase) =>
  ["done_with_report", "done_no_report", "error"].includes(phase);
