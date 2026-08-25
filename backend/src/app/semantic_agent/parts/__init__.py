"""Part-based semantic parsing, validation, operations, and recomposition.

Public API:
  parse_semantic_parts   – deterministic parser per vulnerability
  validate_semantic_parts – check operations are legal on given parts
  apply_part_operations  – execute operations against base_parts
  recompose_semantic_parts – rebuild the full payload from parts
  compare_semantic_delta  – diff base vs candidate parts
  preserves_base_goal    – check that attack/verification target is intact
  semantic_part_directions – generate part-level direction catalogue
  SUPPORTED_VULNERABILITIES – which vulns support part-based iteration
"""

from __future__ import annotations

from app.semantic_agent.parts.parser import parse_semantic_parts
from app.semantic_agent.parts.validator import validate_semantic_parts
from app.semantic_agent.parts.operations import apply_part_operations
from app.semantic_agent.parts.composer import (
    recompose_semantic_parts,
    compare_semantic_delta,
    preserves_base_goal,
)
from app.semantic_agent.parts.directions import semantic_part_directions

SUPPORTED_VULNERABILITIES = {"command-injection", "sql-injection", "xss", "file-upload"}

__all__ = [
    "parse_semantic_parts",
    "validate_semantic_parts",
    "apply_part_operations",
    "recompose_semantic_parts",
    "compare_semantic_delta",
    "preserves_base_goal",
    "semantic_part_directions",
    "SUPPORTED_VULNERABILITIES",
]
