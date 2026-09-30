"""Organisation identity: keys, acronyms, and title-derived canonicalisation.

Victim organisations arrive under many spellings of one name. _org_key is a
sorted token-set key so word order does not matter; the acronym helpers
generate BOTH preposition variants because real acronyms are inconsistent
(DOW keeps the 'of', NIH drops it); and the title helpers use the source
report's own title as evidence, which is better than any generator."""
import re
from .names import _norm_name, _LEET_MAP

# Legal-form suffixes that mark a COMPANY. Deliberately excludes "group",
# "holdings", "team" and "as": those appear in canonical threat-actor names
# (Lazarus Group, Equation Group) and must not be misread as corporate.
_LEGAL_FORM_SUFFIX = frozenset({
    "inc", "incorporated", "llc", "l.l.c", "ltd", "limited", "corp",
    "corporation", "company", "gmbh", "srl", "sa", "ag", "plc", "pty",
    "bv", "oy", "ab", "spa", "kk", "llp", "lp", "sarl", "nv", "kg", "co",
})

# ---------------------------------------------------------------------------
# Organisation (victim) dedup key — folds corporate suffixes, parenthetical
# country tags, domains, stopwords and word-order so name variants of the same
# org collapse together (e.g. "UK Office for Waterways" == "Office for
# Waterways (UK)", "Larkfield Technologies" == "larkfield.com"). Token-SET based, so it
# is order-insensitive; used only as a secondary match after exact/alias.
# ---------------------------------------------------------------------------
_ORG_SUFFIX = frozenset({
    "inc", "incorporated", "llc", "l.l.c", "ltd", "limited", "corp", "corporation",
    "co", "company", "gmbh", "srl", "sa", "ag", "plc", "pty", "group", "holdings",
    "holding", "bv", "oy", "ab", "spa", "kk", "llp", "lp", "sarl", "nv", "as", "kg",
    "technologies", "technology", "solutions", "systems", "international", "global",
    "worldwide", "enterprises", "industries", "services", "consulting", "labs",
})
_ORG_STOP = frozenset({"for", "the", "of", "and", "a", "an", "de", "la", "le", "und"})
_ORG_COUNTRY = frozenset({
    "uk", "us", "usa", "eu", "uae", "u.s", "u.s.a", "u.k", "canada", "australia",
    "germany", "france", "japan", "india", "china", "korea", "brazil", "spain",
    "italy", "mexico", "netherlands", "singapore", "russia",
})
# A real domain ends in a TLD-shaped label. Requiring alphabetic TLD (and no
# trailing dot) stops company names punctuated with legal forms — "Acme Co. Ltd."
# — from being mistaken for domains, which previously mangled their dedup key
# and defeated variant matching entirely.
_DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9-]*(\.[a-z0-9-]+)*\.[a-z]{2,24}$")


def _looks_like_domain(compact: str) -> bool:
    if not _DOMAIN_RE.match(compact):
        return False
    last_label = compact.rsplit(".", 1)[-1]
    # "…co.ltd", "…gmbh" etc. are legal forms, not TLDs.
    return last_label not in _ORG_SUFFIX and last_label not in _LEGAL_FORM_SUFFIX


def _org_key(value) -> str:
    n = _norm_name(value)
    n = re.sub(r"\(.*?\)", " ", n)                     # drop parentheticals
    compact = n.replace(" ", "")
    if _looks_like_domain(compact):                     # domain -> first label
        n = compact.split(".")[0]
    n = n.translate(_LEET_MAP)
    tokens = [t for t in re.split(r"[^a-z0-9]+", n) if t]
    sig = [t for t in tokens if t not in _ORG_SUFFIX and t not in _ORG_STOP and t not in _ORG_COUNTRY]
    if not sig:
        sig = tokens
    return "".join(sorted(sig))


def _org_acronyms(value) -> set:
    """Candidate acronyms for an organisation name.

    Real-world acronyms are inconsistent about prepositions — "Department of
    Waterways" is DOW (keeps "of") while "National Institutes of Hydrology" is NIH
    (drops it) — so BOTH forms are generated and either may match.
    """
    n = re.sub(r"\(.*?\)", " ", _norm_name(value))
    tokens = [t for t in re.split(r"[^a-z0-9]+", n) if t]
    if len(tokens) < 2:
        return set()
    sig = [t for t in tokens
           if t not in _ORG_SUFFIX and t not in _ORG_STOP and t not in _ORG_COUNTRY]
    keep_stop = [t for t in tokens
                 if t not in _ORG_SUFFIX and t not in _ORG_COUNTRY]
    out = set()
    for group in (sig, keep_stop):
        if len(group) >= 2:
            out.add("".join(t[0] for t in group))
    return {a for a in out if len(a) >= 2}


def _org_acronym(value) -> str:
    """Primary (significant-words-only) acronym, used when writing an alias.

    "National Atmospheric and Water Agency" -> "nawa"
    "National Institutes of Hydrology"                 -> "nih"
    Returns "" when there is nothing meaningful to abbreviate.
    """
    n = re.sub(r"\(.*?\)", " ", _norm_name(value))
    tokens = [t for t in re.split(r"[^a-z0-9]+", n) if t]
    sig = [t for t in tokens
           if t not in _ORG_SUFFIX and t not in _ORG_STOP and t not in _ORG_COUNTRY]
    if len(sig) < 2:
        return ""
    return "".join(t[0] for t in sig)


def _is_acronym_form(value) -> bool:
    """True if the name looks like an acronym rather than a full name."""
    n = _norm_name(value)
    tokens = [t for t in re.split(r"[^a-z0-9]+", n) if t]
    return len(tokens) == 1 and 2 <= len(tokens[0]) <= 6


def org_variants_match(a, b) -> bool:
    """True if two organisation names denote the same org.

    Beyond the token-set org key, folds the acronym/expansion case that produced
    duplicate creates in measurement ("NAWA" vs its full name, "DOW" vs
    "Department of Waterways"). Only ever compares an acronym-shaped name against a
    multi-word name, so unrelated short names are not collapsed.
    """
    ka, kb = _org_key(a), _org_key(b)
    if ka and ka == kb:
        return True
    for short, full in ((a, b), (b, a)):
        if _is_acronym_form(short):
            if _norm_name(short).strip() in _org_acronyms(full):
                return True
    return False


# ---------------------------------------------------------------------------
# Partial / truncated organisation names.
#
# org_variants_match handles reorderings and clean acronyms, but the gold sample
# exposed two shapes it cannot see, each of which created a duplicate beside the
# full name:
#   - HEAD TRUNCATION: "Brightwell" for "Brightwell Mess-Regeltechnik GmbH".
#   - ACRONYM DECLARED IN THE SOURCE TITLE: "HEPL" where the report is titled
#     "… has published a new victim: Harbour Enviro (HEPL)". _org_acronyms
#     cannot produce "hepl" from "Harbour Enviro" — but the title states the
#     equivalence outright, which is far better evidence than any generator.
# ---------------------------------------------------------------------------

# A leading token shorter than this is not distinctive enough to treat as a
# truncation of a longer name (guards against folding on a common first word).
_MIN_HEAD_TOKEN = 5


def _org_sig_tokens(value) -> list:
    """Significant, order-preserving tokens of an organisation name."""
    n = re.sub(r"\(.*?\)", " ", _norm_name(value))
    tokens = [t for t in re.split(r"[^a-z0-9]+", n) if t]
    sig = [t for t in tokens
           if t not in _ORG_SUFFIX and t not in _ORG_STOP and t not in _ORG_COUNTRY]
    return sig or tokens


def org_partial_match(short, full) -> bool:
    """True if `short` is a head-truncation of `full` (same organisation).

    Requires `short` to be strictly shorter, to be a leading token prefix of
    `full`, and its first token to be distinctive (>= 5 chars) — so "Brightwell"
    folds into "Brightwell Mess-Regeltechnik GmbH" while a generic leading
    word cannot drag two unrelated organisations together.
    """
    s, f = _org_sig_tokens(short), _org_sig_tokens(full)
    if not s or not f or len(s) >= len(f):
        return False
    if len(s[0]) < _MIN_HEAD_TOKEN:
        return False
    return f[: len(s)] == s


# "Full Name (ABBREV)" or "(ABBREV) Full Name" as written in a report title.
_TITLE_PAREN_RE = re.compile(r"([^():;|]{3,90}?)\s*\(\s*([^()]{2,40}?)\s*\)")
# Trim a captured left-hand side back to the actual name: report titles prefix
# it with narrative ("… has published a new victim: Harbour Enviro").
_TITLE_LEAD_SPLIT_RE = re.compile(r".*[:;|\u2013\u2014]\s*")


def _title_abbrev_pairs(title) -> list:
    """Extract (full_name, abbreviation) pairs declared in a source title.

    Only returns a pair when the abbreviation is initials-compatible with the
    full name, so "(CVE-2026-1234)" or "(US)" are not mistaken for an acronym.
    """
    raw = str(title or "")
    if not raw or "(" not in raw:
        return []
    pairs = []
    for left, inner in _TITLE_PAREN_RE.findall(raw):
        full = _TITLE_LEAD_SPLIT_RE.sub("", left).strip(" ,-\u2013\u2014")
        abbrev = inner.strip()
        if not full or not abbrev:
            continue
        sig = _org_sig_tokens(full)
        # A plausible org name, and an acronym-shaped abbreviation.
        if not (1 < len(sig) <= 8):
            continue
        a_norm = _norm_name(abbrev)
        if " " in a_norm or not (2 <= len(a_norm) <= 12) or not a_norm.isalnum():
            continue
        initials = "".join(t[0] for t in sig)
        # The abbreviation must agree with the initials for as far as the
        # shorter of the two goes ("harbour enviro" -> "he" vs "hepl").
        n = min(len(initials), len(a_norm))
        if n < 2 or initials[:n] != a_norm[:n]:
            continue
        pairs.append((full, abbrev))
    return pairs


def canonical_name_from_title(name, title) -> str:
    """Return the fuller form of `name` when the source title declares it.

    "HEPL" + "… new victim: Harbour Enviro (HEPL)" -> "Harbour Enviro".
    Returns "" when the title says nothing about this name.
    """
    target = _norm_name(name)
    if not target:
        return ""
    for full, abbrev in _title_abbrev_pairs(title):
        if _norm_name(abbrev) == target and _norm_name(full) != target:
            return full
    return ""


# Narrative words that mark a title as a news headline rather than a bare
# organisation name. A headline must never be used AS an entity name.
_HEADLINE_MARKERS = (
    "report", "reports", "reported", "disclose", "discloses", "disclosed",
    "breach", "breaches", "confirm", "confirms", "confirmed", "expose",
    "exposes", "exposed", "affecting", "following", "involving", "suffers",
    "suffered", "hit", "targets", "targeting", "targeted", "claims", "claimed",
    "announces", "investigating", "notifies", "warns", "says", "amid", "after",
    "data", "incident", "attack", "ransomware", "leak", "leaks", "victim",
    "victims", "roundup", "alleged", "update", "analysis", "campaign",
)


def victim_name_from_title(title) -> str:
    """Extract a bare organisation name from a leak-post title, or "".

    Leak-site feeds title posts either as the victim name alone
    ("Brightwell Mess-Regeltechnik GmbH") or after a lead-in
    ("DYSPHOR1A has published a new victim: Calder Telecom"). News headlines
    ("US-Based … Reports Data Breach Affecting …") are NOT organisation names and
    are rejected, so a headline can never become an entity.
    """
    raw = str(title or "").strip()
    if not raw:
        return ""
    # Take the segment after the last lead-in separator, which is where the
    # victim name sits in the "published a new victim: X" convention.
    if ":" in raw:
        raw = raw.rsplit(":", 1)[-1].strip()
    # Drop a trailing parenthetical acronym: "Harbour Enviro (HEPL)".
    raw = re.sub(r"\s*\([^()]{1,40}\)\s*$", "", raw).strip(" .,-")
    if not raw:
        return ""
    tokens = [t for t in re.split(r"[^a-z0-9]+", _norm_name(raw)) if t]
    if not (1 <= len(tokens) <= 8):
        return ""
    if any(t in _HEADLINE_MARKERS for t in tokens):
        return ""
    return raw

