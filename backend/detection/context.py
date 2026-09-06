"""Optional detection input supplied by Person 1/5, not a shared API schema."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ReusedIndicator:
    indicator_type: str
    value: str
    related_case_ids: List[str] = field(default_factory=list)
    source: str = ""


@dataclass
class DetectionContext:
    reused_indicators: List[ReusedIndicator] = field(default_factory=list)
    current_case_id: Optional[str] = None
