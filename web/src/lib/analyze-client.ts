// Preserves the source project's local-only analysis workflow; no public backend is assumed.
const BASE = import.meta.env['VITE_ANALYZE_API'] || "http://localhost:8787";
export type Phase = "queued" | "collecting" | "hypothesizing" | "verifying" | "reporting" | "done_with_report" | "done_no_report" | "error";
export type JobIncident = { incidentId: string; code: string; title: string; attackType: string; risk: number; phase: Phase; error?: string };
export type Job = { jobId: string; batchId: string; status: string; incidents: JobIncident[] };
export type AnalyzeResponse = { batchId: string; jobId: string; incidents: Omit<JobIncident,"phase">[] };
async function parse<T>(response: Response): Promise<T> { if (!response.ok) { const body = await response.json().catch(() => ({})); throw new Error(body.error || `Request failed (${response.status})`); } return response.json() as Promise<T>; }
export async function analyzeFile(file: File) { const form = new FormData(); form.append("file", file); try { return await parse<AnalyzeResponse>(await fetch(`${BASE}/api/analyze`, { method: "POST", body: form })); } catch (error) { if (error instanceof TypeError) throw new Error("The local analysis service is unavailable. Start the AI-SOC agents service on your machine and try again."); throw error; } }
export async function fetchJob(id: string) { return parse<Job>(await fetch(`${BASE}/api/jobs/${encodeURIComponent(id)}`)); }
export const phaseLabels: Record<Phase,string> = { queued:"Queued",collecting:"Collecting evidence",hypothesizing:"Forming hypotheses",verifying:"Verifying against evidence",reporting:"Writing report",done_with_report:"Report ready",done_no_report:"No report — claims rejected",error:"Investigation error" };
export const phaseProgress: Record<Phase,number> = { queued:5,collecting:25,hypothesizing:45,verifying:65,reporting:85,done_with_report:100,done_no_report:100,error:100 };
export const isTerminal = (phase: Phase) => ["done_with_report","done_no_report","error"].includes(phase);
