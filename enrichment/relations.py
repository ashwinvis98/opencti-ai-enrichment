"""Relationship type and direction resolution.

A relationship's validity depends on BOTH endpoint types, so a fixed type
per detected category is wrong whenever the source entity cannot originate
it. _REL_MATRIX is derived from OpenCTI's own stixCoreRelationshipsMapping
rather than from the STIX spec, because the platform is what rejects the
mutation. Concretely: a Vulnerability has no outgoing typed relationships,
so the correct edge is 'Attack-Pattern targets Vulnerability' - reversed."""
import re


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def is_valid_cve(value) -> bool:
    """True if the string is a well-formed CVE identifier."""
    return bool(_CVE_RE.match(str(value or "").strip()))


# MITRE ATT&CK technique IDs are T#### with an optional .### sub-technique.
# Rejects malformed/hallucinated ids like 'T352'/'T367' (only 3 digits).
_MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def is_valid_mitre_id(value) -> bool:
    """True if the string is a well-formed MITRE ATT&CK technique id."""
    return bool(_MITRE_RE.match(str(value or "").strip().upper()))


# ---------------------------------------------------------------------------
# Relationship-type resolver — keeps the graph STIX/OpenCTI-valid.
#
# A relationship's validity depends on BOTH endpoint types, so a fixed rel type
# per detected category is wrong when the *source* entity being enriched cannot
# originate that relationship (most importantly a Vulnerability, which has no
# outgoing typed relationships and must instead be the target of one).
#
# _REL_MATRIX is the subset of OpenCTI's stixCoreRelationshipsMapping for the
# (source_type -> target_type) pairs this connector actually produces. Ordered
# most-canonical first. 'related-to' is intentionally omitted: it is allowed
# between ANY two entities and is used as the universal fallback.
# ---------------------------------------------------------------------------

_REL_MATRIX = {
    ("Intrusion-Set", "Attack-Pattern"): ["uses"],
    ("Intrusion-Set", "Malware"): ["uses"],
    ("Intrusion-Set", "Tool"): ["uses"],
    ("Intrusion-Set", "Organization"): ["targets"],
    ("Intrusion-Set", "Sector"): ["targets"],
    ("Intrusion-Set", "Country"): ["targets"],
    ("Threat-Actor-Group", "Attack-Pattern"): ["uses"],
    ("Threat-Actor-Group", "Malware"): ["uses"],
    ("Threat-Actor-Group", "Tool"): ["uses"],
    ("Threat-Actor-Group", "Organization"): ["targets"],
    ("Threat-Actor-Group", "Sector"): ["targets"],
    ("Threat-Actor-Group", "Country"): ["targets"],
    ("Malware", "Attack-Pattern"): ["uses"],
    ("Malware", "Tool"): ["uses"],
    ("Malware", "Organization"): ["targets"],
    ("Malware", "Sector"): ["targets"],
    ("Malware", "Country"): ["targets"],
    ("Campaign", "Attack-Pattern"): ["uses"],
    ("Campaign", "Malware"): ["uses"],
    ("Campaign", "Tool"): ["uses"],
    ("Campaign", "Organization"): ["targets"],
    ("Campaign", "Sector"): ["targets"],
    ("Campaign", "Country"): ["targets"],
    ("Campaign", "Vulnerability"): ["targets"],
    # Reverse edges so a Vulnerability-as-source enrichment points the OTHER way.
    ("Attack-Pattern", "Vulnerability"): ["targets"],
    ("Malware", "Vulnerability"): ["exploits", "targets"],
}


def resolve_rel(source_type: "str | None", target_type: "str | None",
                preferred: str) -> tuple:
    """Return (relationship_type, reverse) for a source->target edge.

    - 'related-to' is universally valid; keep it as-is (neutral semantics).
    - If the preferred typed rel is valid in the forward direction, keep it.
    - Otherwise, if a typed rel exists in the REVERSE direction (target->source)
      and the endpoints are different types, reverse the edge and use it (e.g.
      Vulnerability + Attack-Pattern -> 'Attack-Pattern targets Vulnerability').
    - Otherwise fall back to the always-valid 'related-to'.
    When reverse is True the caller must swap fromId/toId.
    """
    if preferred == "related-to" or not source_type or not target_type:
        return preferred, False
    fwd = _REL_MATRIX.get((source_type, target_type)) or []
    if preferred in fwd:
        return preferred, False
    if source_type != target_type:
        rev = _REL_MATRIX.get((target_type, source_type)) or []
        if rev:
            return rev[0], True
    if fwd:
        return fwd[0], False
    return "related-to", False

