export const ACTIVE_BATCH_KEY = "ai-soc-active-batch";
export const ACTIVE_BATCH_EVENT = "ai-soc-active-batch-changed";
export type ActiveBatchId = string | "seed";

export function getActiveBatchId(): ActiveBatchId {
  if (typeof window === "undefined") return "seed";
  return (window.localStorage.getItem(ACTIVE_BATCH_KEY) || "seed") as ActiveBatchId;
}

export function setActiveBatchId(batchId: ActiveBatchId): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(ACTIVE_BATCH_KEY, batchId);
  window.dispatchEvent(new CustomEvent(ACTIVE_BATCH_EVENT, { detail: batchId }));
}
