"""Evidence-related data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

@dataclass
class EvidenceItem:
    """External evidence item."""

    source_type: str
    source_url: str
    title: str
    published_at: str
    reliability: str
    snippet: str
    claims: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert an external evidence object back to a dictionary."""
        return asdict(self)
