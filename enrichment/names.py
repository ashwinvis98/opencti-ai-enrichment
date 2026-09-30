"""Name normalisation and dedup keys.

Three layers of increasing aggression:
  _norm_name  lowercase, strip, collapse whitespace
  _dedup_key  + leetspeak fold, punctuation fold, trailing org suffixes
  _base_key   + malware-type suffixes and version designators

Deliberately conservative: single-character leet substitutions only, so
'sandstorm' and 'standstorm' stay distinct."""
import re

# ---------------------------------------------------------------------------
# Dedup / quality gate — name normalisation and generic-descriptor rejection.
#
# These are the guardrails that make entity CREATION safe. Detection (the
# "brain") is never gated by these; only whether a detected name is allowed to
# resolve/create an entity in the graph.
# ---------------------------------------------------------------------------

# Leetspeak → alphabetic folding for dedup key generation (Cl0p == Clop,
# sh1ny == shiny). Deliberately conservative: single-character substitutions
# only, so distinct names that differ by an inserted/removed letter
# (e.g. "sandstorm" vs "standstorm") are NOT collapsed together.
_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "@": "a", "$": "s",
})

# Trailing organisational suffixes stripped for the dedup key so that
# "Lazarus" and "Lazarus Group" collapse to the same key. Applied ONLY inside
# the dedup key (never used to rename or merge entities automatically).
_SUFFIX_TOKENS = ("group", "team", "gang", "crew", "the")

# Exact normalised names that are always generic (never create/link).
_GENERIC_EXACT = frozenset({
    "unknown", "n/a", "na", "none", "various", "multiple", "other", "others",
    "tbd", "unidentified", "unattributed", "adversary", "adversaries",
    "attacker", "attackers", "threat actor", "threat actors", "actor", "actors",
    "hackers", "cybercriminals", "cyber criminals", "criminals",
})

# Substrings that mark a name as a generic descriptor rather than a proper name.
# NOTE: deliberately does NOT include bare "group"/"team"/"actor" — real names
# contain those (Equation Group, Lazarus Group). Only descriptor phrases.
_GENERIC_MARKERS = (
    "state-sponsored", "state sponsored", "nation-state", "nation state",
    "based threat actor", "based threat actors", "based actors", "based group",
    "cybercriminal", "cyber criminal", "financially motivated",
    "ransomware operators", "ransomware affiliates", "affiliates",
    "unidentified", "unattributed", "unknown ", "several ", "various ",
    "multiple ", "threat actors", "threat-actors",
    # Descriptive phrases Gemini emits instead of a malware/tool NAME. These are
    # capability descriptions, not named families, and each one would become a
    # single-use orphan entity (observed: "custom Python exploit scripts",
    # "Reverse SSH Tunneling Tool", "Gmail-stealing Chrome extension", "AI C2").
    "custom ", "bespoke ", "in-house ", "homemade ", "unnamed ",
    "exploit script", "exploit kit script", "reverse shell", "reverse ssh",
    "reverse-tunnel", "reverse tunnel", "web shell", "webshell",
    "browser extension", "chrome extension", "firefox extension",
    "-stealing", " stealer script", "powershell script", "python script",
    "batch script", "shell script", "vbs script", "macro document",
    "phishing kit", "phishing page", "phishing email", "phishing site",
)


def _norm_name(value) -> str:
    """Lowercase, strip, collapse internal whitespace."""
    return " ".join(str(value or "").strip().lower().split())


def _dedup_key(value) -> str:
    """Aggressive-but-conservative key for duplicate detection.

    Folds case, whitespace, leetspeak, punctuation and trailing org suffixes.
    Used to catch clop/cl0p/Cl0p and shiny/sh1ny as the same key, WITHOUT
    collapsing genuinely different names (sandstorm vs standstorm stay distinct).
    """
    n = _norm_name(value).translate(_LEET_MAP)
    tokens = [t for t in re.split(r"[^a-z0-9]+", n) if t]
    while tokens and tokens[-1] in _SUFFIX_TOKENS:
        tokens.pop()
    return "".join(tokens)


# Suffix tokens stripped for CROSS-TYPE matching so "Qilin" (actor) and
# "Qilin Ransomware" (malware) resolve to the same base ("qilin").
_TYPE_SUFFIX_TOKENS = _SUFFIX_TOKENS + (
    "ransomware", "malware", "stealer", "infostealer", "loader", "rat",
    "trojan", "backdoor", "botnet", "worm", "wiper", "downloader", "dropper",
    "operation", "campaign",
)


# Trailing version/release designators. "LockBit 5.0" is a release of the
# LockBit brand, not a separate adversary, but _base_key previously kept the
# version and so reported a would-create Intrusion-Set beside the existing
# entity. Stripped for cross-type resolution only.
#
# Two shapes are unambiguous versions and always stripped: a dotted number
# ("5.0", "3.1.2") and a v-prefixed number ("v2", "v3.0"). A BARE trailing
# integer is stripped only when the remaining base is long enough to be a name,
# because for short designators the number IS the name — "APT 28", "FIN 7" and
# "TA 505" must never collapse to "apt" / "fin" / "ta".
_VERSION_SUFFIX_RE = re.compile(r"\s+(?:v\s*\d+(?:\.\d+)*|\d+(?:\.\d+)+)\s*$")
_BARE_INT_SUFFIX_RE = re.compile(r"\s+\d+\s*$")
_MIN_BASE_FOR_INT_STRIP = 5


def _strip_version_suffix(value: str) -> str:
    """Remove one trailing version designator from an already-normalised name."""
    stripped = _VERSION_SUFFIX_RE.sub("", value)
    if stripped != value:
        return stripped.strip()
    stripped = _BARE_INT_SUFFIX_RE.sub("", value).strip()
    if stripped != value.strip() and len(stripped.replace(" ", "")) >= _MIN_BASE_FOR_INT_STRIP:
        return stripped
    return value


def _base_key(value) -> str:
    """Cross-type dedup key: like _dedup_key but also strips malware-ish type
    suffixes and version designators, so an actor name, its malware-family name
    and a versioned release all collapse to one base ("Qilin" == "Qilin
    Ransomware"; "LockBit" == "LockBit 5.0" == "LockBit 5.0 Ransomware")."""
    # Version stripping MUST precede leetspeak folding: _LEET_MAP maps digits to
    # letters (5 -> s, 0 -> o), which would silently turn "5.0" into "s.o" and
    # hide the version entirely.
    n = _norm_name(value)
    # Alternate between the two suffix classes so interleaved forms reduce
    # fully ("LockBit 5.0 Ransomware"). Bounded so a pathological name cannot spin.
    for _ in range(6):
        before = n
        n = _strip_version_suffix(n)
        tokens = [t for t in re.split(r"[^a-z0-9]+", n) if t]
        while tokens and tokens[-1] in _TYPE_SUFFIX_TOKENS:
            tokens.pop()
        n = " ".join(tokens)
        if n == before:
            break
    return n.translate(_LEET_MAP).replace(" ", "")

