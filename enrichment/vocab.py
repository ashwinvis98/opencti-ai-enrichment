"""STIX open-vocabulary normalisers.

Map free-text model output onto the closest valid STIX 2.1 vocabulary term.
Invalid terms are DROPPED, never coerced into the nearest option - a wrong
controlled value is harder to spot later than a missing one."""
from .names import _norm_name

# ---------------------------------------------------------------------------
# STIX open-vocabulary normalisers — map free-text Gemini output to the closest
# valid STIX 2.1 vocabulary term (invalid terms are dropped, not forced).
# ---------------------------------------------------------------------------

_MALWARE_TYPE_OV = frozenset({
    "adware", "backdoor", "bot", "bootkit", "ddos", "downloader", "dropper",
    "exploit-kit", "keylogger", "ransomware", "remote-access-trojan",
    "resource-exploitation", "rogue-security-software", "rootkit",
    "screen-capture", "spyware", "trojan", "virus", "webshell", "wiper", "worm",
})
_MALWARE_TYPE_SYNONYMS = {
    "rat": "remote-access-trojan", "remote access trojan": "remote-access-trojan",
    "infostealer": "spyware", "info-stealer": "spyware", "stealer": "spyware",
    "info stealer": "spyware", "loader": "downloader", "cryptominer": "resource-exploitation",
    "miner": "resource-exploitation", "coinminer": "resource-exploitation",
    "web shell": "webshell", "web-shell": "webshell", "crypter": "trojan",
    "banker": "trojan", "banking trojan": "trojan", "botnet": "bot",
}
_TOOL_TYPE_OV = frozenset({
    "denial-of-service", "exploitation", "information-gathering", "network-capture",
    "credential-exploitation", "remote-access", "vulnerability-scanning", "unknown",
})
_TOOL_TYPE_SYNONYMS = {
    "rmm": "remote-access", "remote monitoring": "remote-access",
    "remote administration": "remote-access", "remote access": "remote-access",
    "scanner": "vulnerability-scanning", "network scanner": "network-capture",
    "port scanner": "vulnerability-scanning", "recon": "information-gathering",
    "reconnaissance": "information-gathering", "credential": "credential-exploitation",
    "exploit": "exploitation", "ddos": "denial-of-service",
}
_MOTIVATION_OV = frozenset({
    "accidental", "coercion", "dominance", "ideology", "notoriety",
    "organizational-gain", "personal-gain", "personal-satisfaction", "revenge",
    "unpredictable",
})
_MOTIVATION_SYNONYMS = {
    "financial": "personal-gain", "financial gain": "personal-gain",
    "money": "personal-gain", "profit": "personal-gain",
    "espionage": "organizational-gain", "state": "organizational-gain",
    "hacktivism": "ideology", "hacktivist": "ideology", "political": "ideology",
    "destruction": "dominance", "sabotage": "dominance", "fame": "notoriety",
}
_SOPHISTICATION_OV = frozenset({
    "none", "minimal", "intermediate", "advanced", "expert", "innovator", "strategic",
})
_RESOURCE_LEVEL_OV = frozenset({
    "individual", "club", "contest", "team", "organization", "government",
})


def _map_vocab(value, valid: frozenset, synonyms: dict) -> "str | None":
    v = _norm_name(value).replace(" ", "-")
    if v in valid:
        return v
    plain = _norm_name(value)
    if plain in synonyms:
        return synonyms[plain]
    if v in synonyms:
        return synonyms[v]
    return None


def normalize_malware_types(values) -> list:
    out = []
    for v in values or []:
        m = _map_vocab(v, _MALWARE_TYPE_OV, _MALWARE_TYPE_SYNONYMS)
        if m and m not in out:
            out.append(m)
    return out


def normalize_tool_types(values) -> list:
    out = []
    for v in values or []:
        m = _map_vocab(v, _TOOL_TYPE_OV, _TOOL_TYPE_SYNONYMS)
        if m and m not in out:
            out.append(m)
    return out


def normalize_motivation(value) -> "str | None":
    return _map_vocab(value, _MOTIVATION_OV, _MOTIVATION_SYNONYMS)


def normalize_sophistication(value) -> "str | None":
    v = _norm_name(value)
    return v if v in _SOPHISTICATION_OV else None


def normalize_resource_level(value) -> "str | None":
    v = _norm_name(value)
    return v if v in _RESOURCE_LEVEL_OV else None


def coerce_names(value) -> list:
    """Coerce a list that may contain strings OR objects ({'name'/'product': ...})
    into a clean list of non-empty name strings. Defends against Gemini returning
    objects where strings were requested (a real production crash source)."""
    out = []
    for a in value or []:
        if isinstance(a, dict):
            nm = a.get("name") or a.get("product") or ""
        else:
            nm = str(a) if a is not None else ""
        if nm and nm.strip():
            out.append(nm.strip())
    return out

