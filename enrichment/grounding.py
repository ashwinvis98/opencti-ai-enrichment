"""Groundedness: a deterministic hallucination check, with no model call.

Before the connector may CREATE an entity, the name must be traceable to
the text that was actually analysed. Deliberately tolerant in five tiers,
because a strict substring test false-alarms on exactly the legitimate
variations that matter (corporate suffixes, word order, acronyms).

LIMIT, stated plainly: this stops the MODEL inventing a name. It cannot
stop a SOURCE inventing one - a fabricated identifier that appears verbatim
in the feed's own text passes. That is why CVEs are lookup-only."""
import re
from .orgs import _ORG_SUFFIX


# ---------------------------------------------------------------------------
# Groundedness — deterministic hallucination check (no model involved).
#
# The single most damaging failure mode for a knowledge graph is an entity that
# cannot be traced back to the source material. Before the connector is allowed
# to CREATE a new entity, we require that the name is actually supported by the
# text we analysed. This is a cheap, reference-free check: no extra LLM call.
#
# Deliberately tolerant, because a strict substring test produces false alarms:
#   - case/punctuation/whitespace differences         ("LockBit" vs "lockbit")
#   - corporate suffixes                              ("Acme Ltd" vs "Acme")
#   - acronyms the analyst legitimately expanded      ("NAWA" vs the full name)
#   - multi-word names where all tokens appear
# Linking to an entity that ALREADY exists is not gated: that is reversible and
# search-grounded enrichment may legitimately add known entities not named in
# the text. Only creation demands evidence.
# ---------------------------------------------------------------------------
_GROUND_PUNCT_RE = re.compile(r"[^a-z0-9]+")
_STOPWORD_TOKENS = frozenset({
    "the", "of", "and", "for", "in", "on", "at", "to", "a", "an", "de", "la",
})


def _grounding_haystack(text) -> str:
    """Normalise source text once, for repeated groundedness checks."""
    return _GROUND_PUNCT_RE.sub(" ", str(text or "").lower()).strip()


def _acronym_of(haystack_words: list, length: int) -> set:
    """All acronyms formed by `length` consecutive words in the source."""
    out = set()
    for i in range(len(haystack_words) - length + 1):
        window = haystack_words[i:i + length]
        out.add("".join(w[0] for w in window if w))
    return out


def is_grounded(name, haystack_norm: str) -> bool:
    """True if `name` is supported by the (already normalised) source text."""
    n = _GROUND_PUNCT_RE.sub(" ", str(name or "").lower()).strip()
    if not n or not haystack_norm:
        return False
    # 1) direct match on the normalised text
    if n in haystack_norm:
        return True
    words = [w for w in n.split() if w]
    hay_words = haystack_norm.split()
    # 2) drop corporate suffixes/stopwords, then re-test as a phrase
    core = [w for w in words if w not in _ORG_SUFFIX and w not in _STOPWORD_TOKENS]
    if core and " ".join(core) in haystack_norm:
        return True
    # 3) all significant tokens present somewhere (word-order tolerant)
    if core and len(core) > 1:
        hay_set = set(hay_words)
        if all(w in hay_set for w in core):
            return True
    # 4) acronym expanded in the source ("NAWA" <- National Atmospheric and ...)
    if len(words) == 1 and 2 <= len(n) <= 6 and n.isalnum():
        if n in _acronym_of(hay_words, len(n)):
            return True
        # tolerate stopwords inside the expansion (e.g. "DoW" from
        # "Department of Waterways" -> significant words only)
        significant = [w for w in hay_words if w not in _STOPWORD_TOKENS]
        if n in _acronym_of(significant, len(n)):
            return True
    # 5) single long token appearing inside a source word (e.g. "qilin" in
    #    "qilinransomware") — conservative: require >= 5 chars
    if len(words) == 1 and len(n) >= 5:
        if any(n in w for w in hay_words):
            return True
    return False

