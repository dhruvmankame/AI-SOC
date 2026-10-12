from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class EvidenceFact(BaseModel):
    fact: str = Field(description="One compact, checkable factual statement grounded in the cited events.")
    kind: Literal["event", "derived", "intel"]
    source_event_ids: list[str] = Field(description="Real event_id values from the provided events; non-empty.")
    confidence: float = Field(ge=0, le=1)


class EvidenceOut(BaseModel):
    evidence: list[EvidenceFact]


class HypothesisDraft(BaseModel):
    statement: str
    technique: str = Field(description="Single MITRE ATT&CK technique id, e.g. T1110.")
    citations: list[str] = Field(description="evidence_id values supporting the statement.")
    confidence: float = Field(ge=0, le=1)
    recommended_actions: list[str]


class HypothesisOut(BaseModel):
    hypotheses: list[HypothesisDraft] = Field(max_length=6)


class VerifierVerdict(BaseModel):
    hypothesis_id: str
    supported: bool
    evidence_strength: float = Field(ge=0, le=1)
    reason: str


class VerifierOut(BaseModel):
    verdicts: list[VerifierVerdict]


class ReportOut(BaseModel):
    summary: str
    narrative: str
    recommended_actions: list[str]
